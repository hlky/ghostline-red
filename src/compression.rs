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
        let mut output = vec![0_u8; expected_size];
        // SAFETY: Input and output point to live, non-overlapping slices. Exact
        // allocated lengths are supplied and Kraken is required to honor them.
        let actual = unsafe {
            (self.decompress_fn)(input.as_ptr(), input_len, output.as_mut_ptr(), output_len)
        };
        if actual != c_int::try_from(expected_size).map_err(|_| CompressionError::TooLarge)? {
            return Err(CompressionError::WrongSize {
                actual,
                expected: expected_size,
            });
        }
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
    #[ignore = "clean-room compatibility test; requires KRAKEN_DLL"]
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
        for payload in [
            block.clone(),
            vec![0x5a; 262_144],
            [block.as_slice(), vec![0xa5; 262_144].as_slice()].concat(),
        ] {
            let encoded = crate::kraken::encode(&payload);
            assert_eq!(kraken.decompress(&encoded, payload.len()).unwrap(), payload);
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
        for (name, payload) in [
            ("repeat2", [block.as_slice(), block.as_slice()].concat()),
            (
                "repeat3",
                [block.as_slice(), block.as_slice(), block.as_slice()].concat(),
            ),
            ("changed", [block.as_slice(), changed.as_slice()].concat()),
        ] {
            let encoded = kraken.compress_validated(&payload).unwrap();
            let mut tail = String::new();
            for byte in encoded.iter().skip(262_130) {
                write!(&mut tail, "{byte:02x}").unwrap();
            }
            println!("{name}: encoded={} tail={tail}", encoded.len());
        }
    }
}
