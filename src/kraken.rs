//! Implements the DLL-free subset of the Oodle Kraken byte stream.
//!
//! Streams are divided into independent 256 KiB blocks. This module emits
//! standards-compatible raw blocks and compact constant-byte blocks. The
//! decoder accepts those block forms plus stored compressed-block quantums and
//! rejects entropy-coded quantums until their bounded decoder is implemented.

use thiserror::Error;

const BLOCK_SIZE: usize = 256 * 1024;
const RAW_BLOCK_HEADER: [u8; 2] = [0xcc, 0x06];
const COMPRESSED_BLOCK_HEADER: [u8; 2] = [0x8c, 0x06];
const MEMSET_QUANTUM: [u8; 3] = [0x07, 0xff, 0xff];

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
        if header[1] != 0x06 {
            return Err(KrakenError::InvalidHeader {
                offset: input_offset - 2,
            });
        }
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
        if !matches!(header[0], 0x0c | 0x8c) {
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
            if quantum_header <= 0x3_ffff && stored_size == block_size {
                input_offset += 3;
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
            return Err(KrakenError::UnsupportedQuantum {
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

#[cfg(test)]
mod tests {
    use super::{BLOCK_SIZE, KrakenError, decode, encode};

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
            decode(&[0x8c, 0x06, 4, 0, 0], 1),
            Err(KrakenError::UnsupportedQuantum { offset: 2 })
        );
        assert_eq!(
            decode(&[0, 0], 1),
            Err(KrakenError::InvalidHeader { offset: 0 })
        );
    }
}
