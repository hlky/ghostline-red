//! Implements the DLL-free subset of the Oodle Kraken byte stream.
//!
//! Streams are divided into independent 256 KiB blocks. This module emits
//! standards-compatible raw blocks and compact constant-byte blocks. The
//! decoder accepts those block forms plus stored compressed-block quantums and
//! rejects entropy-coded quantums until their bounded decoder is implemented.

use thiserror::Error;

const BLOCK_SIZE: usize = 256 * 1024;
const CHUNK_SIZE: usize = 128 * 1024;
const RAW_BLOCK_HEADER: [u8; 2] = [0xcc, 0x06];
const COMPRESSED_BLOCK_HEADER: [u8; 2] = [0x8c, 0x06];
const MEMSET_QUANTUM: [u8; 3] = [0x07, 0xff, 0xff];
const MAX_ARRAY_RECURSION: usize = 16;

/// Reports malformed or unsupported Kraken streams.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KrakenError {
    /// The encoded stream ended before the declared output was complete.
    #[error("truncated Kraken stream at byte {offset}")]
    Truncated { offset: usize },
    /// A block header does not identify a supported Kraken block.
    #[error("invalid Kraken block header at byte {offset}")]
    InvalidHeader { offset: usize },
    /// The stream uses a compressed quantum not implemented by this backend.
    #[error("unsupported compressed Kraken quantum at byte {offset}")]
    UnsupportedQuantum { offset: usize },
    /// A compressed quantum or inner chunk violates the format grammar.
    #[error("invalid Kraken quantum at byte {offset}")]
    InvalidQuantum { offset: usize },
    /// A byte-array entropy envelope violates the format grammar.
    #[error("invalid Kraken byte array at byte {offset}")]
    InvalidArray { offset: usize },
    /// The decoder produced a different amount of data than requested.
    #[error("Kraken stream has trailing data at byte {offset}")]
    TrailingData { offset: usize },
}

/// Encodes bytes as a compatible Kraken stream without proprietary code.
///
/// Constant blocks use Kraken's compact memset quantum. Other blocks are
/// emitted verbatim using the format's uncompressed block representation.
#[must_use]
pub fn encode(input: &[u8]) -> Vec<u8> {
    if input.len() >= 288
        && input.get(8..).is_some_and(|tail| {
            tail.iter()
                .zip(input.iter())
                .all(|(left, right)| left == right)
        })
        && input.windows(2).any(|pair| pair[0] != pair[1])
    {
        return encode_period_eight_stream(input);
    }
    let mut output = Vec::with_capacity(
        input
            .len()
            .saturating_add(input.len().div_ceil(BLOCK_SIZE) * 2),
    );
    for block in input.chunks(BLOCK_SIZE) {
        if let Some(&value) = block.first()
            && block.iter().all(|byte| *byte == value)
        {
            output.extend_from_slice(&COMPRESSED_BLOCK_HEADER);
            output.extend_from_slice(&MEMSET_QUANTUM);
            output.push(value);
        } else {
            output.extend_from_slice(&RAW_BLOCK_HEADER);
            output.extend_from_slice(block);
        }
    }
    output
}

fn encode_period_eight_stream(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut absolute_offset = 0_usize;
    for block in input.chunks(BLOCK_SIZE) {
        let encoded_block = encode_period_eight_block(block, absolute_offset);
        if encoded_block.len() < block.len() + RAW_BLOCK_HEADER.len() {
            output.extend_from_slice(&encoded_block);
        } else {
            output.extend_from_slice(&RAW_BLOCK_HEADER);
            output.extend_from_slice(block);
        }
        absolute_offset += block.len();
    }
    output
}

fn encode_period_eight_block(block: &[u8], absolute_offset: usize) -> Vec<u8> {
    let mut quantum = Vec::new();
    let mut chunk_offset = 0_usize;
    for chunk in block.chunks(CHUNK_SIZE) {
        let has_initial_history = absolute_offset + chunk_offset == 0;
        let minimum = if has_initial_history { 288 } else { 280 };
        if chunk.len() < minimum {
            write_be24(
                &mut quantum,
                0x80_0000 | u32::try_from(chunk.len()).unwrap_or(u32::MAX),
            );
            quantum.extend_from_slice(chunk);
            chunk_offset += chunk.len();
            continue;
        }

        let final_literals = &chunk[chunk.len() - 8..];
        let match_length = chunk.len() - 8 - usize::from(has_initial_history) * 8;
        let extended_length = match_length - 272;
        let mut lz = Vec::new();
        if has_initial_history {
            lz.extend_from_slice(&chunk[..8]);
        }
        encode_stored_array(&mut lz, final_literals);
        encode_stored_array(&mut lz, &[0x7c]);
        encode_stored_array(&mut lz, &[]);
        encode_stored_array(&mut lz, &[0xff]);
        lz.extend_from_slice(&encode_extended_length(extended_length));
        lz.push(0x40);

        write_be24(
            &mut quantum,
            0x88_0000 | u32::try_from(lz.len()).unwrap_or(u32::MAX),
        );
        quantum.extend_from_slice(&lz);
        chunk_offset += chunk.len();
    }

    let mut output = Vec::with_capacity(quantum.len() + 5);
    output.extend_from_slice(&COMPRESSED_BLOCK_HEADER);
    write_be24(
        &mut output,
        u32::try_from(quantum.len().saturating_sub(1)).unwrap_or(u32::MAX),
    );
    output.extend_from_slice(&quantum);
    output
}

fn encode_stored_array(output: &mut Vec<u8>, bytes: &[u8]) {
    write_be24(output, u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    output.extend_from_slice(bytes);
}

fn encode_extended_length(value: usize) -> Vec<u8> {
    let mut tier = 0_u32;
    let mut base = 0_usize;
    while value >= base + (1_usize << (tier + 6)) {
        base += 1_usize << (tier + 6);
        tier += 1;
    }
    let payload = value - base;
    let mut bits = Vec::with_capacity(usize::try_from(tier * 2 + 7).unwrap_or(64));
    bits.resize(usize::try_from(tier).unwrap_or(0), false);
    bits.push(true);
    for shift in (0..tier + 6).rev() {
        bits.push((payload >> shift) & 1 != 0);
    }
    let mut output = vec![0_u8; bits.len().div_ceil(8)];
    for (index, bit) in bits.into_iter().enumerate() {
        if bit {
            output[index / 8] |= 1 << (7 - index % 8);
        }
    }
    output
}

fn write_be24(output: &mut Vec<u8>, value: u32) {
    let bytes = value.to_be_bytes();
    output.extend_from_slice(&bytes[1..]);
}

/// Decodes raw blocks, constant-byte blocks, and stored quantums.
///
/// `decoded_size` is authoritative because raw Kraken block headers do not
/// carry their uncompressed length.
///
/// # Errors
///
/// Returns [`KrakenError`] for truncated input, invalid headers, trailing
/// bytes, or compressed entropy quanta not yet supported by this backend.
#[expect(
    clippy::too_many_lines,
    reason = "the framing state machine stays linear so cursor movement remains auditable"
)]
pub fn decode(input: &[u8], decoded_size: usize) -> Result<Vec<u8>, KrakenError> {
    let mut input_offset = 0_usize;
    let mut output = Vec::with_capacity(decoded_size);
    while output.len() < decoded_size {
        let block_size = (decoded_size - output.len()).min(BLOCK_SIZE);
        let header = input
            .get(input_offset..input_offset + 2)
            .ok_or(KrakenError::Truncated {
                offset: input_offset,
            })?;
        input_offset += 2;
        if header[1] & 0x7f != 0x06 || header[0] & 0x3f != 0x0c {
            return Err(KrakenError::InvalidHeader {
                offset: input_offset - 2,
            });
        }
        let checksummed = header[1] & 0x80 != 0;
        if matches!(header[0], 0x4c | 0xcc) {
            let end = input_offset
                .checked_add(block_size)
                .ok_or(KrakenError::Truncated {
                    offset: input_offset,
                })?;
            output.extend_from_slice(input.get(input_offset..end).ok_or(
                KrakenError::Truncated {
                    offset: input_offset,
                },
            )?);
            input_offset = end;
            continue;
        }
        if header[0] & 0x40 != 0 {
            return Err(KrakenError::InvalidHeader {
                offset: input_offset - 2,
            });
        }
        let quantum = input
            .get(input_offset..input_offset + 3)
            .ok_or(KrakenError::Truncated {
                offset: input_offset,
            })?;
        if quantum != MEMSET_QUANTUM {
            let quantum_header =
                u32::from(quantum[0]) << 16 | u32::from(quantum[1]) << 8 | u32::from(quantum[2]);
            let stored_size = usize::try_from((quantum_header & 0x3_ffff) + 1).map_err(|_| {
                KrakenError::UnsupportedQuantum {
                    offset: input_offset,
                }
            })?;
            let normal_quantum = quantum_header & 0x3_ffff != 0x3_ffff && quantum_header >> 20 == 0;
            if normal_quantum && stored_size == block_size {
                input_offset += 3;
                if checksummed {
                    input_offset = input_offset.checked_add(3).ok_or(KrakenError::Truncated {
                        offset: input_offset,
                    })?;
                    if input_offset > input.len() {
                        return Err(KrakenError::Truncated {
                            offset: input.len(),
                        });
                    }
                }
                let end = input_offset
                    .checked_add(stored_size)
                    .ok_or(KrakenError::Truncated {
                        offset: input_offset,
                    })?;
                output.extend_from_slice(input.get(input_offset..end).ok_or(
                    KrakenError::Truncated {
                        offset: input_offset,
                    },
                )?);
                input_offset = end;
                continue;
            }
            if normal_quantum && stored_size < block_size {
                input_offset += 3;
                if checksummed {
                    input_offset = input_offset.checked_add(3).ok_or(KrakenError::Truncated {
                        offset: input_offset,
                    })?;
                    if input_offset > input.len() {
                        return Err(KrakenError::Truncated {
                            offset: input.len(),
                        });
                    }
                }
                let end = input_offset
                    .checked_add(stored_size)
                    .ok_or(KrakenError::Truncated {
                        offset: input_offset,
                    })?;
                let payload = input.get(input_offset..end).ok_or(KrakenError::Truncated {
                    offset: input_offset,
                })?;
                decode_quantum(payload, block_size, &mut output, input_offset)?;
                input_offset = end;
                continue;
            }
            return Err(KrakenError::UnsupportedQuantum {
                offset: input_offset,
            });
        }
        if checksummed {
            return Err(KrakenError::InvalidQuantum {
                offset: input_offset,
            });
        }
        input_offset += 3;
        let value = *input.get(input_offset).ok_or(KrakenError::Truncated {
            offset: input_offset,
        })?;
        input_offset += 1;
        output.resize(output.len() + block_size, value);
    }
    if input_offset != input.len() {
        return Err(KrakenError::TrailingData {
            offset: input_offset,
        });
    }
    Ok(output)
}

fn decode_quantum(
    payload: &[u8],
    output_size: usize,
    output: &mut Vec<u8>,
    stream_offset: usize,
) -> Result<(), KrakenError> {
    let output_end = output
        .len()
        .checked_add(output_size)
        .ok_or(KrakenError::InvalidQuantum {
            offset: stream_offset,
        })?;
    let mut cursor = Cursor::new(payload, stream_offset);
    while output.len() < output_end {
        let chunk_size = (output_end - output.len()).min(CHUNK_SIZE);
        let header = cursor.peek_be24()?;
        if header & 0x80_0000 == 0 {
            let decoded = decode_array(&mut cursor, Some(chunk_size), 0)?;
            output.extend_from_slice(&decoded);
            continue;
        }

        cursor.advance(3)?;
        let payload_size =
            usize::try_from(header & 0x7_ffff).map_err(|_| KrakenError::InvalidQuantum {
                offset: cursor.absolute_offset(),
            })?;
        let mode = (header >> 19) & 0xf;
        if payload_size > chunk_size || (payload_size < chunk_size && mode > 1) {
            return Err(KrakenError::InvalidQuantum {
                offset: cursor.absolute_offset() - 3,
            });
        }
        if payload_size == chunk_size {
            if mode != 0 {
                return Err(KrakenError::InvalidQuantum {
                    offset: cursor.absolute_offset() - 3,
                });
            }
            output.extend_from_slice(cursor.take(payload_size)?);
            continue;
        }
        let lz_offset = cursor.absolute_offset();
        let lz_payload = cursor.take(payload_size)?;
        decode_lz_payload(lz_payload, chunk_size, output, mode, lz_offset)?;
    }
    if !cursor.is_empty() {
        return Err(KrakenError::InvalidQuantum {
            offset: cursor.absolute_offset(),
        });
    }
    Ok(())
}

fn decode_lz_payload(
    payload: &[u8],
    chunk_size: usize,
    output: &mut Vec<u8>,
    mode: u32,
    stream_offset: usize,
) -> Result<(), KrakenError> {
    let chunk_end = output
        .len()
        .checked_add(chunk_size)
        .ok_or(KrakenError::InvalidQuantum {
            offset: stream_offset,
        })?;
    let mut cursor = Cursor::new(payload, stream_offset);
    if output.is_empty() {
        output.extend_from_slice(cursor.take(8)?);
    }
    if cursor.peek_byte()? & 0x80 != 0 {
        return Err(KrakenError::UnsupportedQuantum {
            offset: cursor.absolute_offset(),
        });
    }

    let literals = decode_array(&mut cursor, None, 0)?;
    let commands = decode_array(&mut cursor, None, 0)?;
    if commands.len() > chunk_size {
        return Err(KrakenError::InvalidQuantum {
            offset: cursor.absolute_offset(),
        });
    }
    let offset_scale = if cursor.peek_byte()? & 0x80 != 0 {
        usize::from(cursor.read_byte()? - 127)
    } else {
        0
    };
    let packed_offsets = decode_array(&mut cursor, None, 0)?;
    let low_digits = if offset_scale > 1 {
        decode_array(&mut cursor, Some(packed_offsets.len()), 0)?
    } else {
        Vec::new()
    };
    let packed_lengths = decode_array(&mut cursor, None, 0)?;
    if packed_offsets.len() > commands.len() || packed_lengths.len() > chunk_size / 4 {
        return Err(KrakenError::InvalidQuantum {
            offset: cursor.absolute_offset(),
        });
    }
    let suffix_offset = cursor.absolute_offset();
    let suffix = cursor.remaining();
    if suffix.is_empty() {
        return Err(KrakenError::InvalidQuantum {
            offset: suffix_offset,
        });
    }
    let mut bits = PairedBits::new(suffix, suffix_offset);
    let extended_count = bits.read_back_gamma_minus_one()?;
    if extended_count > 512 {
        return Err(KrakenError::InvalidQuantum {
            offset: suffix_offset,
        });
    }
    let explicit_offsets = decode_explicit_offsets(
        &mut bits,
        &packed_offsets,
        &low_digits,
        offset_scale,
        suffix_offset,
    )?;
    let mut extended = Vec::with_capacity(extended_count);
    for index in 0..extended_count {
        extended.push(if index & 1 == 0 {
            bits.read_front_extended_length()?
        } else {
            bits.read_back_extended_length()?
        });
    }
    let long_lengths = expand_long_lengths(&packed_lengths, &extended, suffix_offset)?;
    execute_lz_commands(
        output,
        chunk_end,
        &literals,
        &commands,
        &explicit_offsets,
        &long_lengths,
        mode,
        stream_offset,
    )
}

fn decode_explicit_offsets(
    bits: &mut PairedBits<'_>,
    packed_offsets: &[u8],
    low_digits: &[u8],
    offset_scale: usize,
    suffix_offset: usize,
) -> Result<Vec<i32>, KrakenError> {
    let mut output = Vec::with_capacity(packed_offsets.len());
    for (index, &packed) in packed_offsets.iter().enumerate() {
        let stored_offset = if offset_scale == 0 {
            let distance = if index & 1 == 0 {
                bits.read_front_distance(packed)?
            } else {
                bits.read_back_distance(packed)?
            };
            let distance = i32::try_from(distance).map_err(|_| KrakenError::InvalidQuantum {
                offset: suffix_offset,
            })?;
            -distance
        } else {
            let raw_offset = if index & 1 == 0 {
                bits.read_front_scaled_offset(packed)?
            } else {
                bits.read_back_scaled_offset(packed)?
            };
            let low = low_digits.get(index).copied().unwrap_or(0);
            raw_offset
                .checked_mul(i32::try_from(offset_scale).map_err(|_| {
                    KrakenError::InvalidQuantum {
                        offset: suffix_offset,
                    }
                })?)
                .and_then(|value| value.checked_sub(i32::from(low)))
                .ok_or(KrakenError::InvalidQuantum {
                    offset: suffix_offset,
                })?
        };
        if stored_offset >= 0 {
            return Err(KrakenError::InvalidQuantum {
                offset: suffix_offset,
            });
        }
        output.push(stored_offset);
    }
    Ok(output)
}

fn expand_long_lengths(
    packed: &[u8],
    extended: &[usize],
    offset: usize,
) -> Result<Vec<usize>, KrakenError> {
    let mut extended_cursor = 0_usize;
    let mut output = Vec::with_capacity(packed.len());
    for &value in packed {
        let base = if value == 255 {
            let value = extended
                .get(extended_cursor)
                .copied()
                .ok_or(KrakenError::InvalidQuantum { offset })?;
            extended_cursor += 1;
            value
                .checked_add(255)
                .ok_or(KrakenError::InvalidQuantum { offset })?
        } else {
            usize::from(value)
        };
        output.push(
            base.checked_add(3)
                .ok_or(KrakenError::InvalidQuantum { offset })?,
        );
    }
    if extended_cursor != extended.len() {
        return Err(KrakenError::InvalidQuantum { offset });
    }
    Ok(output)
}

fn decode_array(
    cursor: &mut Cursor<'_>,
    required_size: Option<usize>,
    depth: usize,
) -> Result<Vec<u8>, KrakenError> {
    if depth >= MAX_ARRAY_RECURSION {
        return Err(KrakenError::InvalidArray {
            offset: cursor.absolute_offset(),
        });
    }
    let start = cursor.absolute_offset();
    let first = cursor.peek_byte()?;
    let array_type = (first >> 4) & 7;
    if array_type > 5 {
        return Err(KrakenError::InvalidArray { offset: start });
    }

    if array_type == 0 {
        let stored_size = if first >= 0x80 {
            usize::from(cursor.read_be16()? & 0x0fff)
        } else {
            let value = cursor.read_be24()?;
            if value > 0x3_ffff {
                return Err(KrakenError::InvalidArray { offset: start });
            }
            usize::try_from(value).map_err(|_| KrakenError::InvalidArray { offset: start })?
        };
        require_array_size(required_size, stored_size, start)?;
        return Ok(cursor.take(stored_size)?.to_vec());
    }

    let (compressed_size, decoded_size) = if first >= 0x80 {
        let value = cursor.read_be24()?;
        let compressed = value & 0x3ff;
        let decoded = compressed + ((value >> 10) & 0x3ff) + 1;
        (
            usize::try_from(compressed).map_err(|_| KrakenError::InvalidArray { offset: start })?,
            usize::try_from(decoded).map_err(|_| KrakenError::InvalidArray { offset: start })?,
        )
    } else {
        let type_byte = cursor.read_byte()?;
        let value = cursor.read_be32()?;
        let compressed = value & 0x3_ffff;
        let decoded = (((value >> 18) | (u32::from(type_byte) << 14)) & 0x3_ffff) + 1;
        if compressed >= decoded {
            return Err(KrakenError::InvalidArray { offset: start });
        }
        (
            usize::try_from(compressed).map_err(|_| KrakenError::InvalidArray { offset: start })?,
            usize::try_from(decoded).map_err(|_| KrakenError::InvalidArray { offset: start })?,
        )
    };
    require_array_size(required_size, decoded_size, start)?;
    let payload_offset = cursor.absolute_offset();
    let payload = cursor.take(compressed_size)?;
    match array_type {
        2 => decode_huffman_one_partition(payload, decoded_size, payload_offset),
        3 => decode_rle(payload, decoded_size, payload_offset, depth + 1),
        5 => decode_recursive_arrays(payload, decoded_size, payload_offset, depth + 1),
        _ => Err(KrakenError::UnsupportedQuantum { offset: start }),
    }
}

fn decode_huffman_one_partition(
    payload: &[u8],
    decoded_size: usize,
    offset: usize,
) -> Result<Vec<u8>, KrakenError> {
    let (table, table_size) = decode_huffman_table(payload, offset)?;
    let split_bytes = payload
        .get(table_size..table_size + 2)
        .ok_or(KrakenError::Truncated {
            offset: offset + table_size,
        })?;
    let first_len = usize::from(u16::from_le_bytes([split_bytes[0], split_bytes[1]]));
    let streams = payload
        .get(table_size + 2..)
        .ok_or(KrakenError::Truncated {
            offset: offset + table_size + 2,
        })?;
    if first_len > streams.len() {
        return Err(KrakenError::InvalidArray { offset });
    }

    let first = &streams[..first_len];
    let opposing = &streams[first_len..];
    let mut output = Vec::with_capacity(decoded_size);
    let mut first_bits = HuffBits::new(first, false);
    let mut second_bits = HuffBits::new(opposing, false);
    let mut backward_bits = HuffBits::new(opposing, true);
    while output.len() < decoded_size {
        output.push(table.decode(&mut first_bits, offset)?);
        if output.len() == decoded_size {
            break;
        }
        output.push(table.decode(&mut backward_bits, offset)?);
        if output.len() == decoded_size {
            break;
        }
        output.push(table.decode(&mut second_bits, offset)?);
    }
    if first_bits.consumed_bytes() != first.len()
        || second_bits
            .consumed_bytes()
            .checked_add(backward_bits.consumed_bytes())
            != Some(opposing.len())
    {
        return Err(KrakenError::InvalidArray { offset });
    }
    Ok(output)
}

struct OldHuffmanTable {
    entries: Vec<(u16, u8, u8)>,
}

impl OldHuffmanTable {
    fn decode(&self, bits: &mut HuffBits<'_>, offset: usize) -> Result<u8, KrakenError> {
        let mut code = 0_u16;
        for length in 1..=11_u8 {
            code |= u16::from(bits.read(offset)?) << (length - 1);
            if let Some(&(_, _, symbol)) = self
                .entries
                .iter()
                .find(|&&(entry_code, entry_len, _)| entry_len == length && entry_code == code)
            {
                return Ok(symbol);
            }
        }
        Err(KrakenError::InvalidArray { offset })
    }
}

struct HuffBits<'a> {
    bytes: &'a [u8],
    bit: usize,
    reverse_bytes: bool,
}

impl<'a> HuffBits<'a> {
    fn new(bytes: &'a [u8], reverse_bytes: bool) -> Self {
        Self {
            bytes,
            bit: 0,
            reverse_bytes,
        }
    }

    fn read(&mut self, offset: usize) -> Result<u8, KrakenError> {
        let byte_index = self.bit / 8;
        let byte_index = if self.reverse_bytes {
            self.bytes
                .len()
                .checked_sub(byte_index + 1)
                .ok_or(KrakenError::Truncated { offset })?
        } else {
            byte_index
        };
        let byte = *self
            .bytes
            .get(byte_index)
            .ok_or(KrakenError::Truncated { offset })?;
        let value = byte >> (self.bit & 7) & 1;
        self.bit += 1;
        Ok(value)
    }

    fn consumed_bytes(&self) -> usize {
        self.bit.div_ceil(8)
    }
}

fn decode_huffman_table(
    payload: &[u8],
    offset: usize,
) -> Result<(OldHuffmanTable, usize), KrakenError> {
    if let Some(header) = payload.get(..4) {
        let value = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let fields = (0xff_u32 << 11) | (0xff_u32 << 3);
        if value & !fields == 0x0080_0000 {
            let symbols = [((value >> 11) & 0xff) as u8, ((value >> 3) & 0xff) as u8];
            if symbols[0] < symbols[1] {
                return Ok((
                    OldHuffmanTable {
                        entries: vec![(0, 1, symbols[0]), (1, 1, symbols[1])],
                    },
                    4,
                ));
            }
        }
    }

    if let Some(header) = payload.get(..5) {
        let value = header.iter().fold(0_u64, |accumulator, &byte| {
            accumulator << 8 | u64::from(byte)
        });
        let fields = (0xff_u64 << 19) | (0xff_u64 << 10) | (0xff_u64 << 1);
        if value & !fields == 0x0000_c804_0001 {
            let symbols = [
                ((value >> 19) & 0xff) as u8,
                ((value >> 10) & 0xff) as u8,
                ((value >> 1) & 0xff) as u8,
            ];
            if symbols.windows(2).all(|pair| pair[0] < pair[1]) {
                return Ok((
                    OldHuffmanTable {
                        entries: vec![
                            (0b01, 2, symbols[0]),
                            (0, 1, symbols[1]),
                            (0b11, 2, symbols[2]),
                        ],
                    },
                    5,
                ));
            }
        }
    }

    if let Some(header) = payload.get(..7) {
        let value = header.iter().fold(0_u64, |accumulator, &byte| {
            accumulator << 8 | u64::from(byte)
        });
        let fields = (0xff_u64 << 35) | (0xff_u64 << 26) | (0xff_u64 << 17) | (0xff_u64 << 8);
        if value & !fields == 0x01_0804_0201_0080 {
            let symbols = [
                ((value >> 35) & 0xff) as u8,
                ((value >> 26) & 0xff) as u8,
                ((value >> 17) & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
            ];
            if symbols.windows(2).all(|pair| pair[0] < pair[1]) {
                return Ok((
                    OldHuffmanTable {
                        entries: vec![
                            (0b00, 2, symbols[0]),
                            (0b10, 2, symbols[1]),
                            (0b01, 2, symbols[2]),
                            (0b11, 2, symbols[3]),
                        ],
                    },
                    7,
                ));
            }
        }
    }
    for &(alphabet_size, max_start) in &[(8_u8, 248_u8), (16, 240)] {
        for start in 0..=max_start {
            let header = encode_contiguous_new_huffman_header(alphabet_size, start);
            if payload.starts_with(&header) {
                let bit_length = u8::try_from(alphabet_size.ilog2()).unwrap();
                let entries = (0..alphabet_size)
                    .map(|index| {
                        (
                            reverse_low_bits(u16::from(index), bit_length),
                            bit_length,
                            start + index,
                        )
                    })
                    .collect();
                return Ok((OldHuffmanTable { entries }, header.len()));
            }
        }
    }
    Err(KrakenError::UnsupportedQuantum { offset })
}

fn reverse_low_bits(mut value: u16, bit_count: u8) -> u16 {
    let mut reversed = 0_u16;
    for _ in 0..bit_count {
        reversed = reversed << 1 | (value & 1);
        value >>= 1;
    }
    reversed
}

fn encode_contiguous_new_huffman_header(alphabet_size: u8, start: u8) -> Vec<u8> {
    match (alphabet_size, start) {
        (8, 0) => vec![0x90, 0x70, 0x08, 0x95, 0xff, 0xe0],
        (16, 0) => vec![0x80, 0xf0, 0x00, 0x82, 0x22, 0xab, 0xfe],
        (8, _) => {
            let mut output = vec![0x90, 0x71, 0x08, 0x95];
            append_new_huffman_start_code(&mut output, start, 3, 9);
            output
        }
        (16, _) => {
            let mut output = vec![0x80, 0xf0, 0x80, 0x82, 0x22, 0xab];
            append_new_huffman_start_code(&mut output, start, 7, 1);
            output
        }
        _ => Vec::new(),
    }
}

fn append_new_huffman_start_code(
    output: &mut Vec<u8>,
    start: u8,
    leading_ones: usize,
    delimiter_ones: usize,
) {
    debug_assert!(start > 0);
    let tier = usize::try_from((u16::from(start) + 1).ilog2()).unwrap();
    let base = (1_usize << tier) - 1;
    let delta = usize::from(start) - base;
    let mut bits = Vec::with_capacity(leading_ones + tier + delimiter_ones + tier);
    bits.extend(std::iter::repeat_n(true, leading_ones));
    bits.extend(std::iter::repeat_n(false, tier - 1));
    bits.extend(std::iter::repeat_n(true, delimiter_ones));
    for shift in (0..tier).rev() {
        bits.push(delta >> shift & 1 != 0);
    }
    let byte_count = bits.len().div_ceil(8);
    bits.resize(byte_count * 8, false);
    output.extend(bits.chunks_exact(8).map(|byte_bits| {
        byte_bits
            .iter()
            .fold(0_u8, |byte, &bit| byte << 1 | u8::from(bit))
    }));
}

fn require_array_size(
    required_size: Option<usize>,
    actual: usize,
    offset: usize,
) -> Result<(), KrakenError> {
    if required_size.is_some_and(|required| required != actual) {
        return Err(KrakenError::InvalidArray { offset });
    }
    Ok(())
}

fn decode_rle(
    payload: &[u8],
    decoded_size: usize,
    offset: usize,
    depth: usize,
) -> Result<Vec<u8>, KrakenError> {
    if payload.len() == 1 {
        return Ok(vec![payload[0]; decoded_size]);
    }
    if payload.is_empty() {
        return Err(KrakenError::InvalidArray { offset });
    }

    let commands = if payload[0] == 0 {
        payload[1..].to_vec()
    } else {
        let mut cursor = Cursor::new(payload, offset);
        let mut decoded = decode_array(&mut cursor, None, depth)?;
        decoded.extend_from_slice(cursor.remaining());
        decoded
    };
    let mut front = 0_usize;
    let mut back = commands.len();
    let mut output = Vec::with_capacity(decoded_size);
    let mut rle_byte = 0_u8;
    while front < back {
        let command = commands[back - 1];
        let (literal_count, run_count) = if command == 1 {
            if front >= back - 1 {
                return Err(KrakenError::InvalidArray { offset });
            }
            rle_byte = commands[front];
            front += 1;
            back -= 1;
            continue;
        } else if command >= 0x30 {
            back -= 1;
            (
                usize::from(command.wrapping_neg().wrapping_sub(1) & 0xf),
                usize::from(command >> 4),
            )
        } else {
            if back.saturating_sub(front) < 2 {
                return Err(KrakenError::InvalidArray { offset });
            }
            back -= 2;
            let word = u16::from_le_bytes([commands[back], commands[back + 1]]);
            if (0x10..=0x2f).contains(&command) {
                let value = word
                    .checked_sub(4096)
                    .ok_or(KrakenError::InvalidArray { offset })?;
                (usize::from(value & 0x3f), usize::from(value >> 6))
            } else if (9..=15).contains(&command) {
                let value = word
                    .checked_sub(0x08ff)
                    .ok_or(KrakenError::InvalidArray { offset })?;
                (
                    0,
                    usize::from(value)
                        .checked_mul(128)
                        .ok_or(KrakenError::InvalidArray { offset })?,
                )
            } else {
                let value = word
                    .checked_sub(511)
                    .ok_or(KrakenError::InvalidArray { offset })?;
                (
                    usize::from(value)
                        .checked_mul(64)
                        .ok_or(KrakenError::InvalidArray { offset })?,
                    0,
                )
            }
        };

        let literal_end = front
            .checked_add(literal_count)
            .filter(|end| *end <= back)
            .ok_or(KrakenError::InvalidArray { offset })?;
        let new_output_size = output
            .len()
            .checked_add(literal_count)
            .and_then(|size| size.checked_add(run_count))
            .filter(|size| *size <= decoded_size)
            .ok_or(KrakenError::InvalidArray { offset })?;
        output.extend_from_slice(&commands[front..literal_end]);
        output.resize(new_output_size, rle_byte);
        front = literal_end;
    }
    if output.len() != decoded_size {
        return Err(KrakenError::InvalidArray { offset });
    }
    Ok(output)
}

fn decode_recursive_arrays(
    payload: &[u8],
    decoded_size: usize,
    offset: usize,
    depth: usize,
) -> Result<Vec<u8>, KrakenError> {
    let mut cursor = Cursor::new(payload, offset);
    let count_byte = cursor.read_byte()?;
    let count = usize::from(count_byte & 0x7f);
    if count < 2 || count_byte & 0x80 != 0 {
        return Err(KrakenError::UnsupportedQuantum { offset });
    }
    let mut output = Vec::with_capacity(decoded_size);
    for _ in 0..count {
        let part = decode_array(&mut cursor, None, depth)?;
        if output.len().saturating_add(part.len()) > decoded_size {
            return Err(KrakenError::InvalidArray { offset });
        }
        output.extend_from_slice(&part);
    }
    if !cursor.is_empty() || output.len() != decoded_size {
        return Err(KrakenError::InvalidArray {
            offset: cursor.absolute_offset(),
        });
    }
    Ok(output)
}

#[allow(
    dead_code,
    reason = "wired into quantum decoding once the paired-bit distance parser is implemented"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the side streams are explicit to make exact consumption auditable"
)]
fn execute_lz_commands(
    output: &mut Vec<u8>,
    chunk_end: usize,
    literals: &[u8],
    commands: &[u8],
    explicit_offsets: &[i32],
    long_lengths: &[usize],
    mode: u32,
    stream_offset: usize,
) -> Result<(), KrakenError> {
    if mode > 1 || chunk_end < output.len() {
        return Err(KrakenError::InvalidQuantum {
            offset: stream_offset,
        });
    }
    let output_start = 0_usize;
    let mut literal_cursor = 0_usize;
    let mut offset_cursor = 0_usize;
    let mut length_cursor = 0_usize;
    let mut recent = [-8_i32; 3];
    let mut last_offset = -8_i32;

    for &command in commands {
        let literal_code = usize::from(command & 3);
        let literal_length = if literal_code < 3 {
            literal_code
        } else {
            take_length(long_lengths, &mut length_cursor, stream_offset)?
        };
        emit_literals(
            output,
            chunk_end,
            literals,
            &mut literal_cursor,
            literal_length,
            last_offset,
            mode,
            output_start,
            stream_offset,
        )?;

        let offset_index = usize::from(command >> 6);
        let selected_offset = if offset_index < 3 {
            recent[offset_index]
        } else {
            let value =
                *explicit_offsets
                    .get(offset_cursor)
                    .ok_or(KrakenError::InvalidQuantum {
                        offset: stream_offset,
                    })?;
            offset_cursor += 1;
            value
        };
        match offset_index {
            0 => {}
            1 => recent.swap(0, 1),
            2 => {
                recent = [recent[2], recent[0], recent[1]];
            }
            3 => {
                recent = [selected_offset, recent[0], recent[1]];
            }
            _ => {
                return Err(KrakenError::InvalidQuantum {
                    offset: stream_offset,
                });
            }
        }
        last_offset = selected_offset;

        let match_code = usize::from((command >> 2) & 0xf);
        let match_length = if match_code < 15 {
            match_code + 2
        } else {
            take_length(long_lengths, &mut length_cursor, stream_offset)?
                .checked_add(14)
                .ok_or(KrakenError::InvalidQuantum {
                    offset: stream_offset,
                })?
        };
        copy_match(
            output,
            chunk_end,
            selected_offset,
            match_length,
            output_start,
            stream_offset,
        )?;
    }

    let final_literal_count = literals.len().saturating_sub(literal_cursor);
    emit_literals(
        output,
        chunk_end,
        literals,
        &mut literal_cursor,
        final_literal_count,
        last_offset,
        mode,
        output_start,
        stream_offset,
    )?;
    if output.len() != chunk_end
        || literal_cursor != literals.len()
        || offset_cursor != explicit_offsets.len()
        || length_cursor != long_lengths.len()
    {
        return Err(KrakenError::InvalidQuantum {
            offset: stream_offset,
        });
    }
    Ok(())
}

#[allow(dead_code, reason = "used by the staged LZ command executor")]
fn take_length(lengths: &[usize], cursor: &mut usize, offset: usize) -> Result<usize, KrakenError> {
    let value = lengths
        .get(*cursor)
        .copied()
        .ok_or(KrakenError::InvalidQuantum { offset })?;
    *cursor += 1;
    Ok(value)
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit cursors keep LZ side-stream consumption auditable"
)]
#[allow(dead_code, reason = "used by the staged LZ command executor")]
fn emit_literals(
    output: &mut Vec<u8>,
    chunk_end: usize,
    literals: &[u8],
    literal_cursor: &mut usize,
    count: usize,
    last_offset: i32,
    mode: u32,
    output_start: usize,
    stream_offset: usize,
) -> Result<(), KrakenError> {
    let literal_end = literal_cursor
        .checked_add(count)
        .ok_or(KrakenError::InvalidQuantum {
            offset: stream_offset,
        })?;
    let source = literals
        .get(*literal_cursor..literal_end)
        .ok_or(KrakenError::InvalidQuantum {
            offset: stream_offset,
        })?;
    if output.len().saturating_add(count) > chunk_end {
        return Err(KrakenError::InvalidQuantum {
            offset: stream_offset,
        });
    }
    for &literal in source {
        let value = if mode == 0 {
            let predictor = history_index(output.len(), last_offset, output_start, stream_offset)?;
            literal.wrapping_add(output[predictor])
        } else {
            literal
        };
        output.push(value);
    }
    *literal_cursor = literal_end;
    Ok(())
}

#[allow(dead_code, reason = "used by the staged LZ command executor")]
fn copy_match(
    output: &mut Vec<u8>,
    chunk_end: usize,
    offset: i32,
    count: usize,
    output_start: usize,
    stream_offset: usize,
) -> Result<(), KrakenError> {
    if output.len().saturating_add(count) > chunk_end {
        return Err(KrakenError::InvalidQuantum {
            offset: stream_offset,
        });
    }
    for _ in 0..count {
        let source = history_index(output.len(), offset, output_start, stream_offset)?;
        let value = output[source];
        output.push(value);
    }
    Ok(())
}

#[allow(dead_code, reason = "used by the staged LZ command executor")]
fn history_index(
    output_position: usize,
    offset: i32,
    output_start: usize,
    stream_offset: usize,
) -> Result<usize, KrakenError> {
    if offset >= 0 {
        return Err(KrakenError::InvalidQuantum {
            offset: stream_offset,
        });
    }
    let distance =
        usize::try_from(offset.unsigned_abs()).map_err(|_| KrakenError::InvalidQuantum {
            offset: stream_offset,
        })?;
    output_position
        .checked_sub(distance)
        .filter(|source| *source >= output_start)
        .ok_or(KrakenError::InvalidQuantum {
            offset: stream_offset,
        })
}

#[allow(
    dead_code,
    reason = "staged paired-bit suffix decoder awaiting distance and length value grammars"
)]
struct PairedBits<'a> {
    bytes: &'a [u8],
    front_bits: usize,
    back_bits: usize,
    stream_offset: usize,
}

#[allow(
    dead_code,
    reason = "staged paired-bit suffix decoder awaiting distance and length value grammars"
)]
impl<'a> PairedBits<'a> {
    const fn new(bytes: &'a [u8], stream_offset: usize) -> Self {
        Self {
            bytes,
            front_bits: 0,
            back_bits: 0,
            stream_offset,
        }
    }

    fn read_front(&mut self, count: u32) -> Result<u32, KrakenError> {
        let mut value = 0_u32;
        for _ in 0..count {
            value = value << 1 | u32::from(self.front_bit()?);
        }
        Ok(value)
    }

    fn read_back(&mut self, count: u32) -> Result<u32, KrakenError> {
        let mut value = 0_u32;
        for _ in 0..count {
            value = value << 1 | u32::from(self.back_bit()?);
        }
        Ok(value)
    }

    fn read_back_gamma_minus_one(&mut self) -> Result<usize, KrakenError> {
        let mut leading_zeroes = 0_u32;
        while self.back_bit()? == 0 {
            leading_zeroes += 1;
            if leading_zeroes > 31 {
                return Err(KrakenError::InvalidQuantum {
                    offset: self.stream_offset,
                });
            }
        }
        let tail = self.read_back(leading_zeroes)?;
        let value = (1_u32 << leading_zeroes) | tail;
        usize::try_from(value - 1).map_err(|_| KrakenError::InvalidQuantum {
            offset: self.stream_offset,
        })
    }

    fn read_front_extended_length(&mut self) -> Result<usize, KrakenError> {
        let mut tier = 0_u32;
        while self.front_bit()? == 0 {
            tier += 1;
            if tier > 25 {
                return Err(KrakenError::InvalidQuantum {
                    offset: self.stream_offset,
                });
            }
        }
        let payload_bits = tier + 6;
        let payload = self.read_front(payload_bits)?;
        let base = ((1_u64 << tier) - 1) << 6;
        usize::try_from(base + u64::from(payload)).map_err(|_| KrakenError::InvalidQuantum {
            offset: self.stream_offset,
        })
    }

    fn read_back_extended_length(&mut self) -> Result<usize, KrakenError> {
        let mut tier = 0_u32;
        while self.back_bit()? == 0 {
            tier += 1;
            if tier > 25 {
                return Err(KrakenError::InvalidQuantum {
                    offset: self.stream_offset,
                });
            }
        }
        let payload_bits = tier + 6;
        let payload = self.read_back(payload_bits)?;
        let base = ((1_u64 << tier) - 1) << 6;
        usize::try_from(base + u64::from(payload)).map_err(|_| KrakenError::InvalidQuantum {
            offset: self.stream_offset,
        })
    }

    fn read_front_distance(&mut self, packed: u8) -> Result<usize, KrakenError> {
        let tier = u32::from(packed >> 4);
        let extra = self.read_front(tier + 4)?;
        decode_distance_value(packed, tier, extra, self.stream_offset)
    }

    fn read_back_distance(&mut self, packed: u8) -> Result<usize, KrakenError> {
        let tier = u32::from(packed >> 4);
        let extra = self.read_back(tier + 4)?;
        decode_distance_value(packed, tier, extra, self.stream_offset)
    }

    fn read_front_scaled_offset(&mut self, command: u8) -> Result<i32, KrakenError> {
        let bit_count = u32::from(command >> 3);
        let extra = self.read_front(bit_count)?;
        decode_scaled_offset_value(command, bit_count, extra, self.stream_offset)
    }

    fn read_back_scaled_offset(&mut self, command: u8) -> Result<i32, KrakenError> {
        let bit_count = u32::from(command >> 3);
        let extra = self.read_back(bit_count)?;
        decode_scaled_offset_value(command, bit_count, extra, self.stream_offset)
    }

    fn front_bit(&mut self) -> Result<u8, KrakenError> {
        self.ensure_available()?;
        let byte_index = self.front_bits / 8;
        let bit_index = self.front_bits % 8;
        self.front_bits += 1;
        Ok((self.bytes[byte_index] >> (7 - bit_index)) & 1)
    }

    fn back_bit(&mut self) -> Result<u8, KrakenError> {
        self.ensure_available()?;
        let byte_from_end = self.back_bits / 8;
        let bit_index = self.back_bits % 8;
        let byte_index = self.bytes.len() - 1 - byte_from_end;
        self.back_bits += 1;
        Ok((self.bytes[byte_index] >> (7 - bit_index)) & 1)
    }

    fn ensure_available(&self) -> Result<(), KrakenError> {
        let total_bits = self
            .bytes
            .len()
            .checked_mul(8)
            .ok_or(KrakenError::InvalidQuantum {
                offset: self.stream_offset,
            })?;
        if self.front_bits.saturating_add(self.back_bits) >= total_bits {
            return Err(KrakenError::InvalidQuantum {
                offset: self.stream_offset,
            });
        }
        Ok(())
    }
}

fn decode_distance_value(
    packed: u8,
    tier: u32,
    extra: u32,
    offset: usize,
) -> Result<usize, KrakenError> {
    let base = 8_u64 + (((1_u64 << tier) - 1) << 8);
    let distance = base + u64::from(packed & 0xf) + (u64::from(extra) << 4);
    usize::try_from(distance).map_err(|_| KrakenError::InvalidQuantum { offset })
}

fn decode_scaled_offset_value(
    command: u8,
    bit_count: u32,
    extra: u32,
    offset: usize,
) -> Result<i32, KrakenError> {
    if bit_count > 26 {
        return Err(KrakenError::InvalidQuantum { offset });
    }
    let base = 8_u32 + u32::from(command & 7);
    let value = base
        .checked_shl(bit_count)
        .and_then(|value| value.checked_add(extra))
        .ok_or(KrakenError::InvalidQuantum { offset })?;
    8_i32
        .checked_sub(i32::try_from(value).map_err(|_| KrakenError::InvalidQuantum { offset })?)
        .ok_or(KrakenError::InvalidQuantum { offset })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
    stream_offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8], stream_offset: usize) -> Self {
        Self {
            bytes,
            position: 0,
            stream_offset,
        }
    }

    fn absolute_offset(&self) -> usize {
        self.stream_offset.saturating_add(self.position)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn peek_byte(&self) -> Result<u8, KrakenError> {
        self.bytes
            .get(self.position)
            .copied()
            .ok_or(KrakenError::Truncated {
                offset: self.absolute_offset(),
            })
    }

    fn read_byte(&mut self) -> Result<u8, KrakenError> {
        let value = self.peek_byte()?;
        self.position += 1;
        Ok(value)
    }

    fn peek_be24(&self) -> Result<u32, KrakenError> {
        let bytes = self
            .bytes
            .get(self.position..self.position.saturating_add(3))
            .ok_or(KrakenError::Truncated {
                offset: self.absolute_offset(),
            })?;
        Ok(u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]))
    }

    fn read_be16(&mut self) -> Result<u16, KrakenError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_be24(&mut self) -> Result<u32, KrakenError> {
        let value = self.peek_be24()?;
        self.position += 3;
        Ok(value)
    }

    fn read_be32(&mut self) -> Result<u32, KrakenError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn advance(&mut self, count: usize) -> Result<(), KrakenError> {
        self.take(count).map(|_| ())
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], KrakenError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(KrakenError::Truncated {
                offset: self.absolute_offset(),
            })?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(KrakenError::Truncated {
                offset: self.absolute_offset(),
            })?;
        self.position = end;
        Ok(value)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BLOCK_SIZE, CHUNK_SIZE, Cursor, KrakenError, PairedBits, decode, decode_array,
        decode_lz_payload, decode_quantum, decode_scaled_offset_value, encode,
        encode_contiguous_new_huffman_header, encode_extended_length, execute_lz_commands,
    };

    #[test]
    fn round_trips_raw_and_constant_blocks() {
        for size in [
            0,
            1,
            255,
            256,
            BLOCK_SIZE - 1,
            BLOCK_SIZE,
            BLOCK_SIZE + 1,
            BLOCK_SIZE * 2,
        ] {
            let patterned: Vec<u8> = (0..size)
                .map(|index| index.wrapping_mul(73).to_le_bytes()[0])
                .collect();
            assert_eq!(decode(&encode(&patterned), size), Ok(patterned));
            let constant = vec![0xa5; size];
            assert_eq!(decode(&encode(&constant), size), Ok(constant));
        }
    }

    #[test]
    fn constant_blocks_use_compact_quantums() {
        assert_eq!(
            encode(&vec![0x5a; BLOCK_SIZE]),
            [0x8c, 0x06, 0x07, 0xff, 0xff, 0x5a]
        );
    }

    #[test]
    fn period_eight_inputs_use_lz_encoding() {
        let seed = [0x00, 0x49, 0x92, 0xdb, 0x24, 0x6d, 0xb6, 0x00];
        for size in [288_usize, 512, CHUNK_SIZE, BLOCK_SIZE, BLOCK_SIZE + 512] {
            let payload: Vec<u8> = seed.iter().copied().cycle().take(size).collect();
            let encoded = encode(&payload);
            assert!(encoded.len() < payload.len(), "encoded size {size}");
            assert_eq!(decode(&encoded, size), Ok(payload));
        }
    }

    #[test]
    fn encodes_extended_length_tiers() {
        for (value, expected) in [
            (0_usize, &[0x80][..]),
            (12, &[0x98]),
            (63, &[0xfe]),
            (64, &[0x40, 0x00]),
            (112, &[0x58, 0x00]),
            (224, &[0x24, 0x00]),
            (480, &[0x11, 0x00]),
            (3_808, &[0x07, 0x90, 0x00]),
            (130_784, &[0x00, 0x3f, 0xe4, 0x00]),
        ] {
            assert_eq!(encode_extended_length(value), expected);
        }
    }

    #[test]
    fn decodes_stored_quantums_and_non_restart_headers() {
        let payload: Vec<u8> = (0..65_536_usize)
            .map(|index| index.wrapping_mul(73).to_le_bytes()[0])
            .collect();
        let mut stored = vec![0x0c, 0x06, 0x00, 0xff, 0xff];
        stored.extend_from_slice(&payload);
        assert_eq!(decode(&stored, payload.len()), Ok(payload));

        assert_eq!(
            decode(&[0x0c, 0x06, 0x07, 0xff, 0xff, 0x5a], 16),
            Ok(vec![0x5a; 16])
        );
    }

    #[test]
    fn rejects_truncated_and_unknown_streams() {
        assert_eq!(
            decode(&[0xcc, 0x06, 1], 2),
            Err(KrakenError::Truncated { offset: 2 })
        );
        assert_eq!(
            decode(&[0x8c, 0x06, 0x10, 0, 0], 1),
            Err(KrakenError::UnsupportedQuantum { offset: 2 })
        );
        assert_eq!(
            decode(&[0, 0], 1),
            Err(KrakenError::InvalidHeader { offset: 0 })
        );
    }

    #[test]
    fn decodes_entropy_only_rle_quantum() {
        let stream = [
            0x8c, 0x06, // compressed Kraken block
            0x00, 0x00, 0x05, // six payload bytes
            0x30, 0x00, 0x3c, 0x00, 0x01, // long RLE envelope: 1 -> 16
            0xa5,
        ];
        assert_eq!(decode(&stream, 16), Ok(vec![0xa5; 16]));
    }

    #[test]
    fn decodes_stored_entropy_arrays() {
        let bytes = [0x00, 0x00, 0x04, 1, 2, 3, 4];
        let mut cursor = Cursor::new(&bytes, 100);
        assert_eq!(decode_array(&mut cursor, Some(4), 0), Ok(vec![1, 2, 3, 4]));
        assert!(cursor.is_empty());
    }

    #[test]
    fn decodes_old_table_binary_huffman_array() {
        let bytes = [
            0x20, 0x01, 0xfc, 0x00, 0x18, // type 2: 24 -> 128
            0x00, 0x80, 0x00, 0x08, // old-table symbols 0 and 1
            0x06, 0x00, // first forward stream is six bytes
            0x73, 0xe8, 0x8f, 0xc9, 0xf7, 0x06, // forward stream 0
            0x46, 0x24, 0xa4, 0x07, 0xef, 0x02, // forward stream 1
            0x07, 0xb0, 0xef, 0x2a, 0xab, 0x46, // backward stream
        ];
        let mut state = 0x9e37_79b9_u32;
        let expected: Vec<u8> = (0..128)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[0] & 1
            })
            .collect();
        let mut cursor = Cursor::new(&bytes, 0);
        assert_eq!(decode_array(&mut cursor, Some(128), 0), Ok(expected));
        assert!(cursor.is_empty());
    }

    #[test]
    fn decodes_old_table_three_and_four_symbol_huffman_arrays() {
        let triple = [
            0x20, 0x01, 0xfc, 0x00, 0x23, // type 2: 35 -> 128
            0x00, 0xc8, 0x04, 0x04, 0x05, // old three-symbol table
            0x09, 0x00, // first forward stream is nine bytes
            0xfd, 0xf5, 0xb4, 0x37, 0xa9, 0x86, 0x36, 0xcf, 0x06, 0x73, 0xe7, 0xae, 0xeb, 0x28,
            0x6b, 0x7c, 0x15, 0xf7, 0x01, 0xef, 0x52, 0xc0, 0xe9, 0x55, 0xae, 0xbe, 0xab, 0xd2,
        ];
        let mut expected_triple: Vec<u8> = (0..128_usize)
            .map(|index| u8::try_from(index % 3).unwrap())
            .collect();
        deterministic_shuffle(&mut expected_triple, 0x243f_6a88);
        let mut cursor = Cursor::new(&triple, 0);
        assert_eq!(decode_array(&mut cursor, Some(128), 0), Ok(expected_triple));
        assert!(cursor.is_empty());

        let quad = [
            0x20, 0x01, 0xfc, 0x00, 0x2a, // type 2: 42 -> 128
            0x01, 0x08, 0x04, 0x06, 0x05, 0x03, 0x80, // old four-symbol table
            0x0b, 0x00, // first forward stream is eleven bytes
            0x9d, 0x30, 0xe3, 0x21, 0xf6, 0x13, 0x22, 0x94, 0xb2, 0x9b, 0x2a, 0xd8, 0x0d, 0xe5,
            0x9e, 0xf7, 0x74, 0xe6, 0xaf, 0x93, 0xd1, 0x04, 0x24, 0x3c, 0x94, 0xb1, 0xf5, 0x9a,
            0x07, 0x94, 0xfe, 0xb1, 0x00,
        ];
        let mut expected_quad: Vec<u8> = (0..128_usize)
            .map(|index| u8::try_from(index % 4).unwrap())
            .collect();
        deterministic_shuffle(&mut expected_quad, 0xb7e1_5163);
        let mut cursor = Cursor::new(&quad, 0);
        assert_eq!(decode_array(&mut cursor, Some(128), 0), Ok(expected_quad));
        assert!(cursor.is_empty());
    }

    #[test]
    fn decodes_contiguous_new_table_eight_symbol_huffman_array() {
        let bytes = [
            0x20, 0x01, 0xfc, 0x00, 0x3a, // type 2: 58 -> 128
            0x90, 0x70, 0x08, 0x95, 0xff, 0xe0, // new eight-symbol table
            0x11, 0x00, // first forward stream is seventeen bytes
            0xb9, 0x83, 0xc4, 0x2b, 0xb7, 0x3d, 0x80, 0x75, 0x94, 0xd1, 0x08, 0xe1, 0xe2, 0x60,
            0x7d, 0xdd, 0x00, 0x61, 0xac, 0x8a, 0x36, 0xe8, 0x67, 0xee, 0x03, 0x9e, 0x59, 0x75,
            0x46, 0x2c, 0xdb, 0xf6, 0x28, 0x00, 0xb2, 0xc5, 0xf5, 0x52, 0x74, 0xed, 0xd4, 0x60,
            0x3b, 0x82, 0x93, 0xce, 0x6e, 0xe1, 0x90, 0x3e,
        ];
        let mut expected: Vec<u8> = (0..128_usize)
            .map(|index| u8::try_from(index % 8).unwrap())
            .collect();
        deterministic_shuffle(&mut expected, 0x299f_31d0);
        let mut cursor = Cursor::new(&bytes, 0);
        assert_eq!(decode_array(&mut cursor, Some(128), 0), Ok(expected));
        assert!(cursor.is_empty());
    }

    #[test]
    fn reproduces_contiguous_new_table_headers() {
        for (alphabet, start, expected) in [
            (8, 0, "90700895ffe0"),
            (8, 1, "90710895fff0"),
            (8, 7, "90710895e7fc00"),
            (8, 127, "90710895e07fc000"),
            (8, 247, "90710895e07ffc00"),
            (16, 0, "80f0008222abfe"),
            (16, 1, "80f0808222abff00"),
            (16, 15, "80f0808222abfe20"),
            (16, 127, "80f0808222abfe0400"),
            (16, 239, "80f0808222abfe0780"),
        ] {
            assert_eq!(
                encode_contiguous_new_huffman_header(alphabet, start),
                decode_hex(expected)
            );
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }

    fn deterministic_shuffle(values: &mut [u8], mut state: u32) {
        for index in (1..values.len()).rev() {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            values.swap(index, usize::try_from(state).unwrap() % (index + 1));
        }
    }

    #[test]
    fn rejects_malformed_binary_huffman_stream_boundaries() {
        let bytes = [
            0x20, 0x00, 0x3c, 0x00, 0x0f, // type 2: 15 -> 16
            0x00, 0x80, 0x00, 0x08, // old-table symbols 0 and 1
            0x03, 0x00, // invalid: first stream should contain one byte
            0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut cursor = Cursor::new(&bytes, 20);
        assert!(matches!(
            decode_array(&mut cursor, Some(16), 0),
            Err(KrakenError::InvalidArray { .. })
        ));
    }

    #[test]
    fn decodes_bidirectional_rle_commands() {
        let bytes = [
            0x30, 0x00, 0x10, 0x00, 0x04, // type 3: 4 -> 5
            0x00, 0x00, b'A', 0x3d, // marker, two literals, then three zero bytes
        ];
        let mut cursor = Cursor::new(&bytes, 0);
        assert_eq!(
            decode_array(&mut cursor, Some(5), 0),
            Ok(vec![0, b'A', 0, 0, 0])
        );
        assert!(cursor.is_empty());
    }

    #[test]
    fn decodes_simple_recursive_array_composition() {
        let bytes = [
            0x50, 0x00, 0x3c, 0x00, 0x0d, // type 5: 13 -> 16
            0x02, // two arrays
            0x30, 0x00, 0x1c, 0x00, 0x01, b'a', // RLE: 1 -> 8
            0x30, 0x00, 0x1c, 0x00, 0x01, b'b', // RLE: 1 -> 8
        ];
        let mut cursor = Cursor::new(&bytes, 0);
        assert_eq!(
            decode_array(&mut cursor, Some(16), 0),
            Ok([vec![b'a'; 8], vec![b'b'; 8]].concat())
        );
        assert!(cursor.is_empty());
    }

    #[test]
    fn decodes_stored_lz_chunk() {
        let payload = [0x80, 0x00, 0x04, 9, 8, 7, 6];
        let mut output = Vec::new();
        assert_eq!(decode_quantum(&payload, 4, &mut output, 0), Ok(()));
        assert_eq!(output, [9, 8, 7, 6]);
    }

    #[test]
    fn executes_mode_one_lz_commands() {
        let mut output = b"abcdefgh".to_vec();
        assert_eq!(
            execute_lz_commands(&mut output, 14, b"XY", &[0x0a], &[], &[], 1, 0),
            Ok(())
        );
        assert_eq!(output, b"abcdefghXYcdef");
    }

    #[test]
    fn executes_mode_zero_delta_literals() {
        let mut output = b"abcdefgh".to_vec();
        assert_eq!(
            execute_lz_commands(&mut output, 14, &[1, 1], &[0x0a], &[], &[], 0, 0),
            Ok(())
        );
        assert_eq!(output, b"abcdefghbccdef");
    }

    #[test]
    fn rejects_lz_matches_before_output_history() {
        let mut output = b"abcdefgh".to_vec();
        assert_eq!(
            execute_lz_commands(&mut output, 12, &[], &[0xc8], &[-9], &[], 1, 42),
            Err(KrakenError::InvalidQuantum { offset: 42 })
        );
    }

    #[test]
    fn decodes_backward_gamma_extended_length_counts() {
        let mut none = PairedBits::new(&[0x80], 0);
        assert_eq!(none.read_back_gamma_minus_one(), Ok(0));

        let mut one = PairedBits::new(&[0x40], 0);
        assert_eq!(one.read_back_gamma_minus_one(), Ok(1));

        let mut truncated = PairedBits::new(&[0], 7);
        assert_eq!(
            truncated.read_back_gamma_minus_one(),
            Err(KrakenError::InvalidQuantum { offset: 7 })
        );
    }

    #[test]
    fn decodes_forward_extended_lengths() {
        for (bytes, expected) in [
            (&[0x80, 0x40][..], 0_usize),
            (&[0x98, 0x40], 12),
            (&[0xfe, 0x40], 63),
            (&[0x40, 0x00, 0x40], 64),
            (&[0x58, 0x00, 0x40], 112),
            (&[0x24, 0x00, 0x40], 224),
            (&[0x11, 0x00, 0x40], 480),
            (&[0x07, 0x90, 0x00, 0x40], 3_808),
            (&[0x00, 0x3f, 0xe4, 0x00, 0x40], 130_784),
        ] {
            let mut bits = PairedBits::new(bytes, 0);
            assert_eq!(bits.read_back_gamma_minus_one(), Ok(1));
            assert_eq!(bits.read_front_extended_length(), Ok(expected));
        }
    }

    #[test]
    fn decodes_legacy_distance_tiers() {
        for (bytes, packed, count, expected) in [
            (&[0x00, 0x80][..], 0x01, 0_usize, 9_usize),
            (&[0x10, 0x80], 0x00, 0, 24),
            (&[0xf0, 0x80], 0x08, 0, 256),
            (&[0x3a, 0xd8, 0x80, 0x6a], 0x18, 2, 384),
            (&[0x3c, 0x66, 0xc0, 0x28, 0x63], 0x28, 2, 1024),
        ] {
            let mut bits = PairedBits::new(bytes, 0);
            assert_eq!(bits.read_back_gamma_minus_one(), Ok(count));
            assert_eq!(bits.read_front_distance(packed), Ok(expected));
        }
    }

    #[test]
    fn decodes_scaled_offset_values() {
        assert_eq!(decode_scaled_offset_value(0x08, 1, 0, 0), Ok(-8));
        assert_eq!(decode_scaled_offset_value(0x08, 1, 1, 0), Ok(-9));
        assert_eq!(decode_scaled_offset_value(0x10, 2, 0, 0), Ok(-24));
        assert_eq!(
            decode_scaled_offset_value(0xd8, 27, 0, 9),
            Err(KrakenError::InvalidQuantum { offset: 9 })
        );
    }

    #[test]
    fn decodes_scaled_offset_lz_payload() {
        let payload = [
            b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', // initial history
            0x00, 0x00, 0x00, // no literals
            0x00, 0x00, 0x01, 0xc8, // one explicit-offset, four-byte match
            0x81, // scaled offsets, scale 2
            0x00, 0x00, 0x01, 0x04, // raw scaled offset -4
            0x00, 0x00, 0x01, 0x00, // low digit 0: -4 * 2 = -8
            0x00, 0x00, 0x00, // no long lengths
            0x80, // no extended lengths or offset bits
        ];
        let mut output = Vec::new();
        assert_eq!(decode_lz_payload(&payload, 12, &mut output, 1, 0), Ok(()));
        assert_eq!(output, b"abcdefghabcd");
    }

    #[test]
    fn decodes_native_period_eight_lz_vector() {
        let stream = [
            0x8c, 0x06, 0x00, 0x00, 0x25, // outer quantum: 38 bytes
            0x88, 0x00, 0x23, // mode 1 LZ chunk: 35 bytes
            0x00, 0x49, 0x92, 0xdb, 0x24, 0x6d, 0xb6, 0x00, // initial history
            0x00, 0x00, 0x08, // eight stored literals
            0x00, 0x49, 0x92, 0xdb, 0x24, 0x6d, 0xb6, 0x00, 0x00, 0x00, 0x01,
            0x7c, // one command
            0x00, 0x00, 0x00, // no explicit offsets
            0x00, 0x00, 0x01, 0xff, // one extended packed length
            0x00, 0x3f, 0xe4, 0x00, 0x40, // extended value and count
        ];
        let seed = [0x00, 0x49, 0x92, 0xdb, 0x24, 0x6d, 0xb6, 0x00];
        let expected: Vec<u8> = seed.iter().copied().cycle().take(131_072).collect();
        assert_eq!(decode(&stream, expected.len()), Ok(expected));
    }

    #[test]
    fn rejects_recursive_array_depth_bombs() {
        let mut cursor = Cursor::new(&[0x00, 0x00, 0x00], 0);
        assert_eq!(
            decode_array(&mut cursor, None, super::MAX_ARRAY_RECURSION),
            Err(KrakenError::InvalidArray { offset: 0 })
        );
    }
}
