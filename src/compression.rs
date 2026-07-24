//! Safe ownership and length-checked wrappers around `WolvenKit`'s Kraken DLL.
#![allow(
    unsafe_code,
    reason = "this module is the isolated FFI boundary to the pinned Kraken C ABI"
)]

use libloading::Library;
use std::{ffi::OsStr, os::raw::c_int};
use thiserror::Error;

type CompressFn = unsafe extern "system" fn(*const u8, i64, *mut u8, c_int) -> c_int;
type DecompressFn = unsafe extern "system" fn(*const u8, i64, *mut u8, i64) -> c_int;
const NATIVE_GUARD_BYTES: usize = 64;

#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("could not load Kraken library: {0}")]
    Library(#[from] libloading::Error),
    #[error("input or output is too large for Kraken")]
    TooLarge,
    #[error("Kraken returned invalid output size {actual}, expected at most {maximum}")]
    InvalidSize { actual: c_int, maximum: usize },
    #[error("Kraken decompressed {actual} bytes, expected {expected}")]
    WrongSize { actual: c_int, expected: usize },
    #[error("Kraken round-trip validation produced different bytes")]
    ValidationMismatch,
}

pub(crate) struct Kraken {
    _library: Library,
    compress_fn: CompressFn,
    decompress_fn: DecompressFn,
}

impl Kraken {
    pub(crate) fn load(path: &OsStr) -> Result<Self, CompressionError> {
        // SAFETY: Loading a user-selected native library is inherently an FFI
        // operation. The library is retained for at least as long as the copied
        // function pointers, and both symbols use WolvenKit's declared ABI.
        let library = unsafe { Library::new(path)? };
        // SAFETY: Symbol names and signatures match KrakenNative.cs in the
        // pinned WolvenKit source. Pointers remain valid because `library` is owned.
        let compress_fn = unsafe { *library.get::<CompressFn>(b"Kraken_Compress\0")? };
        // SAFETY: Same lifetime and ABI invariant as `Kraken_Compress`.
        let decompress_fn = unsafe { *library.get::<DecompressFn>(b"Kraken_Decompress\0")? };
        Ok(Self {
            _library: library,
            compress_fn,
            decompress_fn,
        })
    }

    pub(crate) fn compress_validated(&self, input: &[u8]) -> Result<Vec<u8>, CompressionError> {
        let input_len = i64::try_from(input.len()).map_err(|_| CompressionError::TooLarge)?;
        let capacity = compressed_buffer_capacity(input.len())?;
        let mut output = vec![0_u8; capacity];
        // SAFETY: The exact WolvenKit-required output capacity is allocated,
        // both slices remain live and non-overlapping, and input length is exact.
        let actual =
            unsafe { (self.compress_fn)(input.as_ptr(), input_len, output.as_mut_ptr(), 4) };
        let size = usize::try_from(actual).map_err(|_| CompressionError::InvalidSize {
            actual,
            maximum: capacity,
        })?;
        if size == 0 || size > capacity {
            return Err(CompressionError::InvalidSize {
                actual,
                maximum: capacity,
            });
        }
        output.truncate(size);
        if self.decompress(&output, input.len())? != input {
            return Err(CompressionError::ValidationMismatch);
        }
        Ok(output)
    }

    pub(crate) fn decompress(
        &self,
        input: &[u8],
        expected_size: usize,
    ) -> Result<Vec<u8>, CompressionError> {
        let input_len = i64::try_from(input.len()).map_err(|_| CompressionError::TooLarge)?;
        let output_len = i64::try_from(expected_size).map_err(|_| CompressionError::TooLarge)?;
        let guarded_input_len = input
            .len()
            .checked_add(NATIVE_GUARD_BYTES)
            .ok_or(CompressionError::TooLarge)?;
        let mut guarded_input = Vec::with_capacity(guarded_input_len);
        guarded_input.extend_from_slice(input);
        guarded_input.resize(guarded_input_len, 0);
        let guarded_output_len = expected_size
            .checked_add(NATIVE_GUARD_BYTES)
            .ok_or(CompressionError::TooLarge)?;
        let mut output = vec![0_u8; guarded_output_len];
        // SAFETY: Input and output point to live, non-overlapping allocations
        // with 64-byte guards for the native decoder's documented speculative
        // boundary accesses. The ABI still receives the exact logical lengths.
        let actual = unsafe {
            (self.decompress_fn)(
                guarded_input.as_ptr(),
                input_len,
                output.as_mut_ptr(),
                output_len,
            )
        };
        if actual != c_int::try_from(expected_size).map_err(|_| CompressionError::TooLarge)? {
            return Err(CompressionError::WrongSize {
                actual,
                expected: expected_size,
            });
        }
        output.truncate(expected_size);
        Ok(output)
    }
}

fn compressed_buffer_capacity(input_len: usize) -> Result<usize, CompressionError> {
    let count = u64::try_from(input_len).map_err(|_| CompressionError::TooLarge)?;
    let biased = count
        .checked_add(0x3ffff)
        .ok_or(CompressionError::TooLarge)?;
    let signed_adjustment = ((biased >> 31) & 1) * 0x3ffff;
    let blocks = biased
        .checked_add(signed_adjustment)
        .ok_or(CompressionError::TooLarge)?
        >> 12;
    let capacity = blocks
        .checked_mul(0x112)
        .and_then(|overhead| overhead.checked_add(count))
        .ok_or(CompressionError::TooLarge)?;
    usize::try_from(capacity).map_err(|_| CompressionError::TooLarge)
}

#[cfg(test)]
mod tests {
    use super::{Kraken, compressed_buffer_capacity};
    use std::{env, path::PathBuf};

    #[test]
    fn wolvenkit_capacity_should_scale_beyond_sixty_four_kibibytes() {
        let capacity = compressed_buffer_capacity(12 * 1024 * 1024).unwrap();
        assert!(capacity > 12 * 1024 * 1024 + 64 * 1024);
    }

    #[test]
    fn kraken_should_round_trip_payload_larger_than_old_allocation() {
        let Some(path) = env::var_os("KRAKEN_DLL").map(PathBuf::from) else {
            return;
        };
        if !path.is_file() {
            return;
        }
        let payload: Vec<u8> = (0..12 * 1024 * 1024)
            .map(|index| u8::try_from((index * 31 + index / 4096) & 0xff).unwrap())
            .collect();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let compressed = kraken.compress_validated(&payload).unwrap();
        assert!(compressed.len() < payload.len());
    }

    #[test]
    #[ignore = "clean-room framing probe; requires KRAKEN_DLL"]
    fn verify_candidate_raw_frames() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        for size in [
            1_usize, 2, 255, 256, 65_535, 65_536, 262_143, 262_144, 262_145, 524_288,
        ] {
            let payload: Vec<u8> = (0..size)
                .map(|index| index.wrapping_mul(73).to_le_bytes()[0])
                .collect();
            let mut framed = Vec::with_capacity(size + size.div_ceil(262_144) * 2);
            for block in payload.chunks(262_144) {
                framed.extend_from_slice(&[0xcc, 0x06]);
                framed.extend_from_slice(block);
            }
            assert_eq!(
                kraken.decompress(&framed, payload.len()).unwrap(),
                payload,
                "raw frame size {size}"
            );
        }
    }

    #[test]
    #[ignore = "clean-room stored-quantum probe; requires KRAKEN_DLL"]
    fn verify_candidate_stored_quantum() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let payload: Vec<u8> = (0..65_536_usize)
            .map(|index| index.wrapping_mul(73).to_le_bytes()[0])
            .collect();
        for block_header in [[0x8c, 0x06], [0x0c, 0x06]] {
            let mut framed = Vec::with_capacity(payload.len() + 5);
            framed.extend_from_slice(&block_header);
            framed.extend_from_slice(&[0x00, 0xff, 0xff]);
            framed.extend_from_slice(&payload);
            assert_eq!(
                kraken.decompress(&framed, payload.len()).unwrap(),
                payload,
                "stored quantum with block header {block_header:02x?}"
            );
        }
    }

    #[test]
    #[ignore = "clean-room specification vector; requires KRAKEN_DLL"]
    fn native_decoder_accepts_entropy_rle_vector() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let stream = [
            0x8c, 0x06, 0x00, 0x00, 0x05, 0x30, 0x00, 0x3c, 0x00, 0x01, 0xa5,
        ];
        assert_eq!(kraken.decompress(&stream, 16).unwrap(), vec![0xa5; 16]);
    }

    #[test]
    #[ignore = "clean-room differential test; requires KRAKEN_DLL"]
    fn clean_room_decodes_native_period_eight_streams() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let seed = [0x00, 0x49, 0x92, 0xdb, 0x24, 0x6d, 0xb6, 0x00];
        for size in [288_usize, 300, 352, 512, 1024, 4096, 65_536, 131_072] {
            let payload: Vec<u8> = seed.iter().copied().cycle().take(size).collect();
            let encoded = kraken.compress_validated(&payload).unwrap();
            assert_eq!(
                crate::kraken::decode(&encoded, size),
                Ok(payload),
                "native stream of {size} bytes"
            );
        }
    }

    #[test]
    #[ignore = "clean-room differential test; requires KRAKEN_DLL"]
    fn clean_room_decodes_native_legacy_distance_streams() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        for period in [9_usize, 16, 24, 32, 64, 128, 256, 384, 512, 768, 1024] {
            let mut state = 0x243f_6a88_85a3_08d3_u64;
            let seed: Vec<u8> = (0..period)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()[3]
                })
                .collect();
            let size = period.saturating_mul(2).max(255);
            let payload: Vec<u8> = seed.into_iter().cycle().take(size).collect();
            let encoded = kraken.compress_validated(&payload).unwrap();
            assert_eq!(
                crate::kraken::decode(&encoded, size),
                Ok(payload),
                "native stream with period {period}"
            );
        }
    }

    #[test]
    #[ignore = "clean-room differential test; requires KRAKEN_DLL"]
    fn clean_room_decodes_native_common_lz_streams() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let cases: [(&str, Vec<u8>); 4] = [
            (
                "ramp",
                (0..131_072_usize)
                    .map(|index| index.to_le_bytes()[0])
                    .collect(),
            ),
            (
                "ramp-two-chunk",
                (0..262_144_usize)
                    .map(|index| index.to_le_bytes()[0])
                    .collect(),
            ),
            (
                "text",
                b"the quick brown fox jumps over the lazy dog\n"
                    .iter()
                    .copied()
                    .cycle()
                    .take(131_072)
                    .collect(),
            ),
            (
                "text-two-chunk",
                b"the quick brown fox jumps over the lazy dog\n"
                    .iter()
                    .copied()
                    .cycle()
                    .take(262_144)
                    .collect(),
            ),
        ];
        for (name, payload) in cases {
            let encoded = kraken.compress_validated(&payload).unwrap();
            assert_eq!(
                crate::kraken::decode(&encoded, payload.len()),
                Ok(payload),
                "{name} stream"
            );
        }
    }

    #[test]
    #[ignore = "clean-room compatibility test; requires KRAKEN_DLL"]
    #[expect(
        clippy::too_many_lines,
        reason = "one compatibility matrix shares expensive native-library setup"
    )]
    fn native_decoder_accepts_clean_room_encoder() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let block: Vec<u8> = (0..262_144_usize)
            .map(|index| {
                let mut value = u64::try_from(index).unwrap().wrapping_add(1);
                value ^= value << 13;
                value ^= value >> 7;
                value ^= value << 17;
                value.to_le_bytes()[0]
            })
            .collect();
        let period_seed = [0x00, 0x49, 0x92, 0xdb, 0x24, 0x6d, 0xb6, 0x00];
        let period: Vec<u8> = period_seed
            .iter()
            .copied()
            .cycle()
            .take(262_144 + 512)
            .collect();
        let generic_seed: Vec<u8> = (0..97_u8)
            .map(|value| value.wrapping_mul(73).wrapping_add(19))
            .collect();
        let generic_period: Vec<u8> = generic_seed
            .iter()
            .copied()
            .cycle()
            .take(262_144 + 512)
            .collect();
        let mut generic_state = 0x243f_6a88_u32;
        let generic_large_seed: Vec<u8> = (0..4_093)
            .map(|_| {
                generic_state ^= generic_state << 13;
                generic_state ^= generic_state >> 17;
                generic_state ^= generic_state << 5;
                generic_state.to_le_bytes()[0]
            })
            .collect();
        let generic_large_period: Vec<u8> = generic_large_seed
            .iter()
            .copied()
            .cycle()
            .take(262_144 + 512)
            .collect();
        let mut multi_offset = Vec::new();
        for &(seed, count) in &[
            (0x243f_6a88_u32, 8_usize),
            (0x85a3_08d3, 64),
            (0x1319_8a2e, 80),
            (0x85a3_08d3, 64),
            (0x0370_7344, 96),
            (0x1319_8a2e, 80),
            (0x0370_7344, 96),
        ] {
            let mut state = seed;
            multi_offset.extend((0..count).map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[0]
            }));
        }
        let entropy_cases = [2_u8, 3, 4, 5, 8, 16, 32, 64, 128].map(|alphabet| {
            let mut state = 0x510e_527f_u32 ^ u32::from(alphabet);
            (0..262_144 + 512)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    let base = if alphabet <= 16 { 100 } else { 0 };
                    base + state.to_le_bytes()[0] % alphabet
                })
                .collect::<Vec<_>>()
        });
        let sparse_entropy_cases =
            [&[1_u8, 200][..], &[0_u8, 7, 255], &[0_u8, 5, 100, 255]].map(|symbols| {
                let mut state = 0x1f83_d9ab_u32;
                (0..262_144 + 512)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 17;
                        state ^= state << 5;
                        symbols[usize::try_from(state).unwrap() % symbols.len()]
                    })
                    .collect::<Vec<_>>()
            });
        for (case_index, payload) in [
            block.clone(),
            vec![0x5a; 262_144],
            [block.as_slice(), vec![0xa5; 262_144].as_slice()].concat(),
            period,
            generic_period,
            generic_large_period,
            multi_offset,
        ]
        .into_iter()
        .chain(entropy_cases)
        .chain(sparse_entropy_cases)
        .enumerate()
        {
            let encoded = crate::kraken::encode(&payload);
            let decoded = kraken.decompress(&encoded, payload.len()).unwrap();
            let first_difference = decoded
                .iter()
                .zip(&payload)
                .position(|(left, right)| left != right);
            assert!(
                decoded == payload,
                "encoder compatibility case {case_index}, first difference {first_difference:?}"
            );
        }
    }

    #[test]
    #[ignore = "clean-room differential test; requires KRAKEN_DLL"]
    fn clean_room_decodes_native_contiguous_new_huffman_tables() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        for &(alphabet, start) in &[
            (5_u8, 0_u8),
            (5, 1),
            (5, 7),
            (5, 31),
            (5, 127),
            (5, 250),
            (8_u8, 0_u8),
            (8, 1),
            (8, 7),
            (8, 31),
            (8, 127),
            (8, 247),
            (16, 0),
            (16, 1),
            (16, 15),
            (16, 127),
            (16, 239),
        ] {
            let payload: Vec<u8> = (0..128)
                .map(|index| start + u8::try_from(index % usize::from(alphabet)).unwrap())
                .collect();
            let encoded = kraken.compress_validated(&payload).unwrap();
            assert_eq!(
                crate::kraken::decode(&encoded, payload.len()),
                Ok(payload),
                "alphabet {alphabet}, start {start}"
            );
        }
    }

    #[test]
    #[ignore = "clean-room nonuniform Huffman differential test; requires KRAKEN_DLL"]
    fn clean_room_decodes_native_nonuniform_five_symbol_tables() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        for weights in [
            [1_u32, 1, 1, 1, 1],
            [2, 1, 1, 1, 1],
            [4, 2, 1, 1, 1],
            [8, 4, 2, 1, 1],
            [5, 4, 3, 2, 1],
        ] {
            let total: u32 = weights.iter().sum();
            let mut state = 0x510e_527f_u32 ^ total;
            let payload: Vec<u8> = (0..4_096)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    let mut selection = state % total;
                    for (symbol, &weight) in weights.iter().enumerate() {
                        if selection < weight {
                            return u8::try_from(symbol).unwrap();
                        }
                        selection -= weight;
                    }
                    unreachable!()
                })
                .collect();
            let encoded = kraken.compress_validated(&payload).unwrap();
            assert_eq!(
                crate::kraken::decode(&encoded, payload.len()),
                Ok(payload),
                "weights {weights:?}"
            );
        }
    }

    #[test]
    #[ignore = "clean-room type-4 Huffman differential test; requires KRAKEN_DLL"]
    fn clean_room_decodes_native_type_four_huffman_partitions() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        for &alphabet in &[5_u8, 8, 16, 32, 64, 128] {
            let mut state = 0x6a09_e667_u32 ^ u32::from(alphabet);
            let payload: Vec<u8> = (0..131_072)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state.to_le_bytes()[0] % alphabet
                })
                .collect();
            let encoded = kraken.compress_validated(&payload).unwrap();
            assert_eq!(
                crate::kraken::decode(&encoded, payload.len()),
                Ok(payload),
                "alphabet {alphabet}"
            );
        }
    }

    #[test]
    #[ignore = "clean-room whole-match probe; requires KRAKEN_DLL"]
    fn print_oracle_whole_match_quantums() {
        use std::fmt::Write as _;

        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        let block: Vec<u8> = (0..262_144)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[3]
            })
            .collect();
        let mut changed = block.clone();
        changed[17] ^= 1;
        let cases = [
            ("repeat2", [block.as_slice(), block.as_slice()].concat()),
            (
                "repeat3",
                [block.as_slice(), block.as_slice(), block.as_slice()].concat(),
            ),
            ("changed", [block.as_slice(), changed.as_slice()].concat()),
        ];
        for (name, payload) in cases {
            let encoded = kraken.compress_validated(&payload).unwrap();
            let mut tail = String::new();
            for byte in encoded.iter().skip(262_130) {
                write!(&mut tail, "{byte:02x}").unwrap();
            }
            println!("{name}: encoded={} tail={tail}", encoded.len());
        }
    }

    #[test]
    #[ignore = "clean-room entropy classifier; requires KRAKEN_DLL"]
    #[expect(
        clippy::too_many_lines,
        reason = "the ignored oracle probe keeps its local parser isolated from production code"
    )]
    fn print_oracle_entropy_envelopes() {
        use std::fmt::Write as _;

        fn array_header(input: &[u8]) -> Option<(u8, usize, usize, usize)> {
            let first = *input.first()?;
            let kind = (first >> 4) & 7;
            if kind == 0 {
                if first >= 0x80 {
                    let word = u16::from_be_bytes([*input.first()?, *input.get(1)?]);
                    return Some((
                        kind,
                        2,
                        usize::from(word & 0x0fff),
                        usize::from(word & 0x0fff),
                    ));
                }
                let word = u32::from_be_bytes([0, *input.first()?, *input.get(1)?, *input.get(2)?]);
                return Some((
                    kind,
                    3,
                    usize::try_from(word).ok()?,
                    usize::try_from(word).ok()?,
                ));
            }
            if first >= 0x80 {
                let word = u32::from_be_bytes([0, *input.first()?, *input.get(1)?, *input.get(2)?]);
                let compressed = usize::try_from(word & 0x3ff).ok()?;
                let decoded = compressed + usize::try_from((word >> 10) & 0x3ff).ok()? + 1;
                Some((kind, 3, compressed, decoded))
            } else {
                let word = u32::from_be_bytes([
                    *input.get(1)?,
                    *input.get(2)?,
                    *input.get(3)?,
                    *input.get(4)?,
                ]);
                let compressed = usize::try_from(word & 0x3_ffff).ok()?;
                let decoded =
                    usize::try_from(((word >> 18) | (u32::from(first) << 14)) & 0x3_ffff).ok()? + 1;
                Some((kind, 5, compressed, decoded))
            }
        }

        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let mut random_state = 0x9e37_79b9_7f4a_7c15_u64;
        let random: Vec<u8> = (0..131_072)
            .map(|_| {
                random_state ^= random_state << 13;
                random_state ^= random_state >> 7;
                random_state ^= random_state << 17;
                random_state.to_le_bytes()[2]
            })
            .collect();
        let mut cases = vec![
            ("zeros".to_owned(), vec![0; 131_072]),
            (
                "ramp".to_owned(),
                (0..131_072_usize)
                    .map(|index| index.to_le_bytes()[0])
                    .collect(),
            ),
            (
                "text".to_owned(),
                b"the quick brown fox jumps over the lazy dog\n"
                    .iter()
                    .copied()
                    .cycle()
                    .take(131_072)
                    .collect(),
            ),
            ("random".to_owned(), random),
        ];
        for period in [8_usize, 16, 32, 44, 64, 128, 256, 512, 1024] {
            let seed: Vec<u8> = (0..period)
                .map(|index| index.wrapping_mul(73).wrapping_add(index / 7).to_le_bytes()[0])
                .collect();
            cases.push((
                format!("period-{period}"),
                seed.into_iter().cycle().take(131_072).collect(),
            ));
        }
        for (name, payload) in cases {
            let encoded = kraken.compress_validated(&payload).unwrap();
            if encoded.starts_with(&[0xcc, 0x06]) {
                println!("{name}: outer raw");
                continue;
            }
            if encoded.get(2..5) == Some(&[0x07, 0xff, 0xff]) {
                println!("{name}: memset");
                continue;
            }
            let quantum_size = usize::from(encoded[2]) << 16
                | usize::from(encoded[3]) << 8
                | usize::from(encoded[4]);
            let quantum = &encoded[5..=5 + quantum_size];
            let chunk_header = u32::from_be_bytes([0, quantum[0], quantum[1], quantum[2]]);
            if chunk_header & 0x80_0000 == 0 {
                println!("{name}: entropy {:?}", array_header(quantum));
                continue;
            }
            let lz_size = usize::try_from(chunk_header & 0x7_ffff).unwrap();
            let lz = &quantum[3..3 + lz_size];
            let arrays = if payload.len() == 131_072 {
                &lz[8..]
            } else {
                lz
            };
            let mut hex = String::new();
            for byte in lz {
                write!(&mut hex, "{byte:02x}").unwrap();
            }
            println!(
                "{name}: head={:02x?} lz={lz_size} literal={:?} bytes={hex}",
                &encoded[..encoded.len().min(8)],
                array_header(arrays)
            );
        }
    }

    #[test]
    #[ignore = "clean-room extended-length classifier; requires KRAKEN_DLL"]
    fn print_oracle_extended_lengths() {
        fn array_span(input: &[u8]) -> Option<usize> {
            let first = *input.first()?;
            let kind = (first >> 4) & 7;
            if kind == 0 {
                if first >= 0x80 {
                    let word = u16::from_be_bytes([*input.first()?, *input.get(1)?]);
                    return Some(2 + usize::from(word & 0x0fff));
                }
                let word = u32::from_be_bytes([0, *input.first()?, *input.get(1)?, *input.get(2)?]);
                return usize::try_from(word).ok()?.checked_add(3);
            }
            let (header, compressed) = if first >= 0x80 {
                let word = u32::from_be_bytes([0, *input.first()?, *input.get(1)?, *input.get(2)?]);
                (3_usize, usize::try_from(word & 0x3ff).ok()?)
            } else {
                let word = u32::from_be_bytes([
                    *input.get(1)?,
                    *input.get(2)?,
                    *input.get(3)?,
                    *input.get(4)?,
                ]);
                (5_usize, usize::try_from(word & 0x3_ffff).ok()?)
            };
            header.checked_add(compressed)
        }

        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let seed = [0x00, 0x49, 0x92, 0xdb, 0x24, 0x6d, 0xb6, 0x00];
        for size in (283_usize..=400).chain([512, 640, 768, 1024, 4096, 16_384, 65_536, 131_072]) {
            let payload: Vec<u8> = seed.iter().copied().cycle().take(size).collect();
            let encoded = kraken.compress_validated(&payload).unwrap();
            if encoded.starts_with(&[0xcc, 0x06]) || encoded.get(2..5) == Some(&[7, 0xff, 0xff]) {
                println!("size={size} non-lz");
                continue;
            }
            let quantum_size = ((usize::from(encoded[2]) << 16
                | usize::from(encoded[3]) << 8
                | usize::from(encoded[4]))
                & 0x3_ffff)
                + 1;
            let quantum = &encoded[5..5 + quantum_size];
            let chunk_size = usize::try_from(
                u32::from_be_bytes([0, quantum[0], quantum[1], quantum[2]]) & 0x7_ffff,
            )
            .unwrap();
            if chunk_size + 3 > quantum.len() {
                println!("size={size} entropy-or-other");
                continue;
            }
            let lz = &quantum[3..3 + chunk_size];
            let mut cursor = 8_usize;
            for _ in 0..4 {
                cursor += array_span(&lz[cursor..]).unwrap();
            }
            println!("size={size} lz={} suffix={:02x?}", lz.len(), &lz[cursor..]);
        }
    }

    #[test]
    #[ignore = "clean-room legacy-distance classifier; requires KRAKEN_DLL"]
    fn print_oracle_legacy_distances() {
        fn stored_array(input: &[u8]) -> Option<(usize, &[u8])> {
            let first = *input.first()?;
            if (first >> 4) & 7 != 0 {
                return None;
            }
            let (header, size) = if first >= 0x80 {
                let word = u16::from_be_bytes([*input.first()?, *input.get(1)?]);
                (2_usize, usize::from(word & 0x0fff))
            } else {
                let word = u32::from_be_bytes([0, *input.first()?, *input.get(1)?, *input.get(2)?]);
                (3_usize, usize::try_from(word).ok()?)
            };
            let end = header.checked_add(size)?;
            Some((end, input.get(header..end)?))
        }

        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        for period in [
            9_usize, 10, 12, 16, 20, 24, 32, 40, 44, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024,
        ] {
            let mut state = 0x243f_6a88_85a3_08d3_u64;
            let seed: Vec<u8> = (0..period)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()[3]
                })
                .collect();
            let output_size = period.saturating_mul(2).max(255);
            let payload: Vec<u8> = seed.into_iter().cycle().take(output_size).collect();
            let encoded = kraken.compress_validated(&payload).unwrap();
            if encoded.starts_with(&[0xcc, 0x06]) {
                println!("period={period} raw");
                continue;
            }
            let quantum_size = ((usize::from(encoded[2]) << 16
                | usize::from(encoded[3]) << 8
                | usize::from(encoded[4]))
                & 0x3_ffff)
                + 1;
            let quantum = &encoded[5..5 + quantum_size];
            let chunk_size = usize::try_from(
                u32::from_be_bytes([0, quantum[0], quantum[1], quantum[2]]) & 0x7_ffff,
            )
            .unwrap();
            if chunk_size + 3 > quantum.len() {
                println!("period={period} entropy");
                continue;
            }
            let lz = &quantum[3..3 + chunk_size];
            let mut cursor = 8_usize;
            let Some((literal_span, _)) = stored_array(&lz[cursor..]) else {
                println!("period={period} compressed-arrays");
                continue;
            };
            cursor += literal_span;
            let (command_span, commands) = stored_array(&lz[cursor..]).unwrap();
            cursor += command_span;
            let (offset_span, offsets) = stored_array(&lz[cursor..]).unwrap();
            cursor += offset_span;
            let (length_span, lengths) = stored_array(&lz[cursor..]).unwrap();
            cursor += length_span;
            println!(
                "period={period} commands={commands:02x?} offsets={offsets:02x?} lengths={lengths:02x?} suffix={:02x?}",
                &lz[cursor..]
            );
        }
    }

    #[test]
    #[ignore = "clean-room small entropy classifier; requires KRAKEN_DLL"]
    #[expect(
        clippy::too_many_lines,
        reason = "the ignored oracle probe keeps its labeled input matrix together"
    )]
    fn print_oracle_small_entropy_streams() {
        use std::fmt::Write as _;

        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let mut cases = Vec::new();
        for &size in &[32_usize, 64, 128, 255, 256] {
            for &alphabet in &[2_u8, 3, 4, 5, 8, 16, 32] {
                cases.push((
                    format!("alphabet{alphabet}-{size}"),
                    (0..size)
                        .map(|index| u8::try_from(index % usize::from(alphabet)).unwrap())
                        .collect::<Vec<_>>(),
                ));
            }
        }
        cases.push((
            "skewed-128".to_owned(),
            (0..128_usize)
                .map(|index| u8::from(index % 17 == 0))
                .collect(),
        ));
        for &(left, right) in &[(0_u8, 2_u8), (1, 2), (10, 200), (127, 255)] {
            cases.push((
                format!("pair-{left}-{right}"),
                [left, right].into_iter().cycle().take(128).collect(),
            ));
        }
        for &symbols in &[
            [0_u8, 1_u8, 3_u8],
            [1, 2, 3],
            [10, 20, 200],
            [126, 127, 255],
            [0, 1, 4],
            [0, 1, 10],
            [0, 1, 255],
            [0, 2, 255],
            [0, 10, 255],
            [1, 254, 255],
            [10, 254, 255],
        ] {
            cases.push((
                format!("triple-{}-{}-{}", symbols[0], symbols[1], symbols[2]),
                symbols.into_iter().cycle().take(128).collect(),
            ));
        }
        for &symbols in &[
            [0_u8, 1_u8, 2_u8, 4_u8],
            [1, 2, 3, 4],
            [10, 20, 30, 200],
            [125, 126, 127, 255],
            [0, 1, 2, 10],
            [0, 1, 10, 255],
            [0, 1, 254, 255],
            [0, 10, 254, 255],
            [1, 253, 254, 255],
            [10, 253, 254, 255],
        ] {
            cases.push((
                format!(
                    "quad-{}-{}-{}-{}",
                    symbols[0], symbols[1], symbols[2], symbols[3]
                ),
                symbols.into_iter().cycle().take(128).collect(),
            ));
        }
        let mut binary_state = 0x9e37_79b9_u32;
        cases.push((
            "binary-random-128".to_owned(),
            (0..128)
                .map(|_| {
                    binary_state ^= binary_state << 13;
                    binary_state ^= binary_state >> 17;
                    binary_state ^= binary_state << 5;
                    binary_state.to_le_bytes()[0] & 1
                })
                .collect(),
        ));
        let mut triple_random: Vec<u8> = (0..128_usize)
            .map(|index| u8::try_from(index % 3).unwrap())
            .collect();
        let mut triple_state = 0x243f_6a88_u32;
        for index in (1..triple_random.len()).rev() {
            triple_state ^= triple_state << 13;
            triple_state ^= triple_state >> 17;
            triple_state ^= triple_state << 5;
            triple_random.swap(index, usize::try_from(triple_state).unwrap() % (index + 1));
        }
        cases.push(("triple-random-128".to_owned(), triple_random));
        let mut quad_random: Vec<u8> = (0..128_usize)
            .map(|index| u8::try_from(index % 4).unwrap())
            .collect();
        let mut quad_state = 0xb7e1_5163_u32;
        for index in (1..quad_random.len()).rev() {
            quad_state ^= quad_state << 13;
            quad_state ^= quad_state >> 17;
            quad_state ^= quad_state << 5;
            quad_random.swap(index, usize::try_from(quad_state).unwrap() % (index + 1));
        }
        cases.push(("quad-random-128".to_owned(), quad_random));
        for &(start, alphabet) in &[(1_u8, 5_u8), (10, 5), (1, 8), (10, 8), (1, 16), (100, 16)] {
            cases.push((
                format!("shifted{start}-alphabet{alphabet}-128"),
                (0..128)
                    .map(|index| start + u8::try_from(index % usize::from(alphabet)).unwrap())
                    .collect(),
            ));
        }
        for &(alphabet, seed) in &[(5_u8, 0xa409_3822_u32), (8, 0x299f_31d0)] {
            let mut values: Vec<u8> = (0..128)
                .map(|index| u8::try_from(index % usize::from(alphabet)).unwrap())
                .collect();
            let mut state = seed;
            for index in (1..values.len()).rev() {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                values.swap(index, usize::try_from(state).unwrap() % (index + 1));
            }
            cases.push((format!("alphabet{alphabet}-random-128"), values));
        }
        for (name, payload) in cases {
            let encoded = kraken.compress_validated(&payload).unwrap();
            let mut hex = String::new();
            for byte in &encoded {
                write!(&mut hex, "{byte:02x}").unwrap();
            }
            println!(
                "{name} decoded={} encoded={} {hex}",
                payload.len(),
                encoded.len()
            );
        }
    }

    #[test]
    #[ignore = "clean-room new Huffman table probe; requires KRAKEN_DLL"]
    fn print_oracle_new_huffman_tables() {
        use std::fmt::Write as _;

        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        for &alphabet in &[5_u8, 8, 16] {
            let stream_bytes = if alphabet == 5 {
                39
            } else {
                let bits = usize::try_from(alphabet.ilog2()).unwrap();
                [43_usize, 42, 43]
                    .into_iter()
                    .map(|symbols| symbols.saturating_mul(bits).div_ceil(8))
                    .sum::<usize>()
            };
            for start in 0_u8..=u8::MAX - alphabet {
                let payload: Vec<u8> = (0..128)
                    .map(|index| start + u8::try_from(index % usize::from(alphabet)).unwrap())
                    .collect();
                let encoded = kraken.compress_validated(&payload).unwrap();
                if encoded.get(5).is_none_or(|byte| (byte >> 4) & 7 != 2) {
                    continue;
                }
                let table_start = 10;
                let table_end = encoded.len() - stream_bytes - 2;
                let mut hex = String::new();
                for byte in &encoded[table_start..table_end] {
                    write!(&mut hex, "{byte:02x}").unwrap();
                }
                println!("alphabet={alphabet} start={start} table={hex}");
            }
        }
        let sets = [
            [0_u8, 1, 2, 3, 4, 5, 6, 8],
            [0, 1, 2, 3, 4, 5, 7, 8],
            [0, 1, 2, 3, 4, 6, 7, 8],
            [0, 1, 2, 3, 5, 6, 7, 8],
            [0, 1, 2, 4, 5, 6, 7, 8],
            [0, 1, 3, 4, 5, 6, 7, 8],
            [0, 2, 3, 4, 5, 6, 7, 8],
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0, 8, 16, 24, 32, 40, 48, 56],
            [0, 32, 64, 96, 128, 160, 192, 224],
        ];
        for symbols in sets {
            let payload: Vec<u8> = symbols.into_iter().cycle().take(128).collect();
            let encoded = kraken.compress_validated(&payload).unwrap();
            let table_end = encoded.len() - 50 - 2;
            let mut hex = String::new();
            for byte in &encoded[10..table_end] {
                write!(&mut hex, "{byte:02x}").unwrap();
            }
            println!("symbols={symbols:02x?} table={hex}");
        }
    }

    #[test]
    #[ignore = "clean-room large Huffman partition probe; requires KRAKEN_DLL"]
    fn print_oracle_large_entropy_partitions() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        for &alphabet in &[5_u8, 8, 16, 32, 64, 128] {
            let mut state = 0x6a09_e667_u32 ^ u32::from(alphabet);
            let payload: Vec<u8> = (0..131_072)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state.to_le_bytes()[0] % alphabet
                })
                .collect();
            let encoded = kraken.compress_validated(&payload).unwrap();
            println!(
                "alphabet={alphabet} encoded={} head={:02x?}",
                encoded.len(),
                &encoded[..encoded.len().min(48)]
            );
        }
    }

    #[test]
    #[ignore = "clean-room tANS selection probe; requires KRAKEN_DLL"]
    fn print_oracle_tans_selections() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        for &size in &[512_usize, 4_096, 131_072] {
            for alphabet in 2_u16..=128 {
                for &skew in &[1_u32, 2, 4, 8, 16, 32] {
                    let mut state =
                        0xbb67_ae85_u32 ^ u32::from(alphabet) ^ u32::try_from(size).unwrap() ^ skew;
                    let payload: Vec<u8> = (0..size)
                        .map(|_| {
                            state ^= state << 13;
                            state ^= state >> 17;
                            state ^= state << 5;
                            let sample = state % (u32::from(alphabet) + skew - 1);
                            u8::try_from(if sample < skew { 0 } else { sample - skew + 1 }).unwrap()
                        })
                        .collect();
                    let encoded = kraken.compress_validated(&payload).unwrap();
                    if encoded.get(..2) != Some(&[0x8c, 0x06]) {
                        continue;
                    }
                    let Some(&first) = encoded.get(5) else {
                        continue;
                    };
                    if first & 0x80 == 0 && (first >> 4) & 7 == 1 {
                        println!(
                            "size={size} alphabet={alphabet} skew={skew} encoded={} head={:02x?}",
                            encoded.len(),
                            &encoded[..encoded.len().min(48)]
                        );
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "clean-room embedded entropy-array probe; requires KRAKEN_DLL and KRAKEN_FIXTURE"]
    fn print_oracle_embedded_entropy_array() {
        use std::fmt::Write as _;

        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let fixture = env::var_os("KRAKEN_FIXTURE").map(PathBuf::from).unwrap();
        let array_offset: usize = env::var("KRAKEN_ARRAY_OFFSET").unwrap().parse().unwrap();
        let input = std::fs::read(fixture).unwrap();
        let first = input[array_offset];
        assert!(first < 0x80 && (1..=5).contains(&((first >> 4) & 7)));
        let word = u32::from_be_bytes([
            input[array_offset + 1],
            input[array_offset + 2],
            input[array_offset + 3],
            input[array_offset + 4],
        ]);
        let compressed_size = usize::try_from(word & 0x3_ffff).unwrap();
        let decoded_size =
            usize::try_from(((word >> 18) | (u32::from(first) << 14)) & 0x3_ffff).unwrap() + 1;
        let envelope = &input[array_offset..array_offset + 5 + compressed_size];
        let mut framed = vec![0x8c, 0x06];
        let quantum_size = u32::try_from(envelope.len() - 1).unwrap();
        framed.extend_from_slice(&quantum_size.to_be_bytes()[1..]);
        framed.extend_from_slice(envelope);
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let decoded = kraken.decompress(&framed, decoded_size).unwrap();
        let mut frequencies = [0_usize; 256];
        for &symbol in &decoded {
            frequencies[usize::from(symbol)] += 1;
        }
        let mut summary = String::new();
        for (symbol, count) in frequencies.into_iter().enumerate() {
            if count != 0 {
                write!(&mut summary, "{symbol:02x}:{count},").unwrap();
            }
        }
        let recompressed = kraken.compress_validated(&decoded).unwrap();
        println!(
            "type={} compressed={compressed_size} decoded={decoded_size} frequencies={summary}",
            (first >> 4) & 7
        );
        println!(
            "original_head={:02x?} recompressed_head={:02x?}",
            &envelope[..envelope.len().min(96)],
            &recompressed[..recompressed.len().min(96)]
        );
    }

    #[test]
    #[ignore = "clean-room real-corpus differential test; requires KRAKEN_DLL and KRAKEN_FIXTURE"]
    fn clean_room_decodes_real_kraken_fixture() {
        let path = env::var_os("KRAKEN_DLL").map(PathBuf::from).unwrap();
        let fixture = env::var_os("KRAKEN_FIXTURE").map(PathBuf::from).unwrap();
        let decoded_size: usize = env::var("KRAKEN_FIXTURE_SIZE").unwrap().parse().unwrap();
        let encoded = std::fs::read(fixture).unwrap();
        let kraken = Kraken::load(path.as_os_str()).unwrap();
        let native = kraken.decompress(&encoded, decoded_size).unwrap();

        assert_eq!(crate::kraken::decode(&encoded, decoded_size), Ok(native));
    }
}
