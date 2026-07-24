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
        3 => decode_rle(payload, decoded_size, payload_offset, depth + 1),
        5 => decode_recursive_arrays(payload, decoded_size, payload_offset, depth + 1),
        _ => Err(KrakenError::UnsupportedQuantum { offset: start }),
    }
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
        BLOCK_SIZE, Cursor, KrakenError, PairedBits, decode, decode_array, decode_lz_payload,
        decode_quantum, decode_scaled_offset_value, encode, execute_lz_commands,
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
