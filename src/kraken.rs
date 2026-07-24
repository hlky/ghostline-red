//! Implements a DLL-free interoperable Oodle Kraken byte stream.
//!
//! Streams are divided into independent 256 KiB blocks. This module emits
//! compatible raw, constant-byte, general Huffman, compact tANS, and
//! deterministic LZ blocks. The decoder also accepts general old/new Huffman,
//! tANS, RLE, recursive/indexed array composition, both LZ modes, and their
//! paired offset and extended-length metadata.

use std::{cmp::Reverse, collections::BinaryHeap};
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
/// The encoder chooses the smallest compatible candidate among compact memset,
/// canonical Huffman, compact tANS, greedy LZ, and uncompressed blocks.
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
    let greedy = encode_greedy_lz_stream(input);
    if let Some(encoded) = greedy.as_ref()
        && encoded.len().saturating_mul(8) < input.len()
        && input.windows(2).any(|pair| pair[0] != pair[1])
    {
        return encoded.clone();
    }
    let huffman = encode_huffman_stream(input);
    if let Some(encoded) = [huffman, greedy].into_iter().flatten().min_by_key(Vec::len) {
        return encoded;
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

fn encode_greedy_lz_stream(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut absolute_offset = 0_usize;
    for block in input.chunks(BLOCK_SIZE) {
        let encoded = encode_greedy_lz_block(block, absolute_offset)?;
        if encoded.len() >= block.len() + RAW_BLOCK_HEADER.len() {
            return None;
        }
        output.extend_from_slice(&encoded);
        absolute_offset += block.len();
    }
    Some(output)
}

fn encode_greedy_lz_block(block: &[u8], absolute_offset: usize) -> Option<Vec<u8>> {
    let mut quantum = Vec::new();
    let mut chunk_offset = 0_usize;
    for chunk in block.chunks(CHUNK_SIZE) {
        let has_initial_history = absolute_offset + chunk_offset == 0;
        let lz = encode_stable_distance_lz_chunk(chunk, has_initial_history)
            .or_else(|| encode_greedy_lz_chunk(chunk, has_initial_history));
        if let Some(lz) = lz {
            write_be24(&mut quantum, 0x88_0000 | u32::try_from(lz.len()).ok()?);
            quantum.extend_from_slice(&lz);
        } else {
            write_be24(&mut quantum, 0x80_0000 | u32::try_from(chunk.len()).ok()?);
            quantum.extend_from_slice(chunk);
        }
        chunk_offset += chunk.len();
    }
    if quantum.len() >= block.len() {
        return None;
    }
    let mut output = Vec::with_capacity(quantum.len() + 5);
    output.extend_from_slice(&COMPRESSED_BLOCK_HEADER);
    write_be24(
        &mut output,
        u32::try_from(quantum.len().checked_sub(1)?).ok()?,
    );
    output.extend_from_slice(&quantum);
    Some(output)
}

fn encode_stable_distance_lz_chunk(chunk: &[u8], has_initial_history: bool) -> Option<Vec<u8>> {
    let start = usize::from(has_initial_history) * 8;
    if chunk.len() < start + 8 {
        return None;
    }
    let mut latest = vec![u32::MAX; 1 << 16];
    let mut selected = None;
    for position in 0..chunk.len().saturating_sub(3) {
        let key = hash_four_bytes(chunk.get(position..position + 4)?);
        let previous = latest[key];
        latest[key] = u32::try_from(position).ok()?;
        if position < start || previous == u32::MAX {
            continue;
        }
        let previous = usize::try_from(previous).ok()?;
        let distance = position - previous;
        if (8..=0x3fff).contains(&distance)
            && common_prefix_length(
                &chunk[previous..],
                &chunk[position..],
                chunk.len() - position,
            ) == chunk.len() - position
        {
            selected = Some(distance);
            break;
        }
    }
    let distance = selected?;
    let offset = encode_scaled_offset(distance)?;
    let mut literals = Vec::new();
    let mut commands = Vec::new();
    let mut packed_lengths = Vec::new();
    let mut extended_lengths = Vec::new();
    let mut position = start;
    let mut literal_start = start;
    let mut first_match = true;
    while position + 4 <= chunk.len() {
        if position < distance {
            position += 1;
            continue;
        }
        let match_length = common_prefix_length(
            &chunk[position - distance..],
            &chunk[position..],
            chunk.len() - position,
        );
        if match_length < 4 {
            position += 1;
            continue;
        }
        let literal_length = position - literal_start;
        literals.extend_from_slice(&chunk[literal_start..position]);
        let literal_code = if literal_length < 3 {
            u8::try_from(literal_length).ok()?
        } else if literal_length <= 257 {
            packed_lengths.push(u8::try_from(literal_length - 3).ok()?);
            3
        } else {
            packed_lengths.push(255);
            extended_lengths.push(literal_length - 258);
            3
        };
        let match_code = if match_length <= 16 {
            u8::try_from(match_length - 2).ok()?
        } else if match_length <= 271 {
            packed_lengths.push(u8::try_from(match_length - 17).ok()?);
            15
        } else {
            packed_lengths.push(255);
            extended_lengths.push(match_length - 272);
            15
        };
        let offset_index = if first_match { 3 } else { 0 };
        commands.push(offset_index << 6 | match_code << 2 | literal_code);
        first_match = false;
        position += match_length;
        literal_start = position;
    }
    if commands.is_empty() {
        return None;
    }
    literals.extend_from_slice(&chunk[literal_start..]);
    let mut lz = Vec::new();
    if has_initial_history {
        lz.extend_from_slice(&chunk[..8]);
    }
    encode_stored_array(&mut lz, &literals);
    encode_stored_array(&mut lz, &commands);
    lz.push(128);
    encode_stored_array(&mut lz, &[offset.0]);
    encode_stored_array(&mut lz, &packed_lengths);
    append_lz_suffix(&mut lz, &[(offset.1, offset.2)], &extended_lengths);
    (lz.len() < chunk.len()).then_some(lz)
}

fn encode_greedy_lz_chunk(chunk: &[u8], has_initial_history: bool) -> Option<Vec<u8>> {
    let start = usize::from(has_initial_history) * 8;
    if chunk.len() < start + 8 {
        return None;
    }
    let previous = build_previous_matches(chunk)?;
    let mut literals = Vec::new();
    let mut commands = Vec::new();
    let mut packed_offsets = Vec::new();
    let mut offset_suffixes = Vec::new();
    let mut packed_lengths = Vec::new();
    let mut extended_lengths = Vec::new();
    let mut recent = [8_usize; 3];
    let mut position = start;
    let mut literal_start = start;
    while position + 4 <= chunk.len() {
        let (best_distance, best_length) = find_best_match(chunk, &previous, position, &recent)?;
        if best_length < 4 {
            position += 1;
            continue;
        }
        let literal_length = position - literal_start;
        literals.extend_from_slice(&chunk[literal_start..position]);
        let literal_code = if literal_length < 3 {
            u8::try_from(literal_length).ok()?
        } else if literal_length <= 257 {
            packed_lengths.push(u8::try_from(literal_length - 3).ok()?);
            3
        } else {
            packed_lengths.push(255);
            extended_lengths.push(literal_length - 258);
            3
        };
        let match_code = if best_length <= 16 {
            u8::try_from(best_length - 2).ok()?
        } else if best_length <= 271 {
            packed_lengths.push(u8::try_from(best_length - 17).ok()?);
            15
        } else {
            packed_lengths.push(255);
            extended_lengths.push(best_length - 272);
            15
        };
        let offset_index = if let Some(index) = recent
            .iter()
            .position(|&distance| distance == best_distance)
        {
            match index {
                0 => {}
                1 => recent.swap(0, 1),
                2 => recent = [recent[2], recent[0], recent[1]],
                _ => unreachable!("recent-offset table has exactly three entries"),
            }
            u8::try_from(index).ok()?
        } else {
            let (packed, extra, bits) = encode_scaled_offset(best_distance)?;
            packed_offsets.push(packed);
            offset_suffixes.push((extra, bits));
            recent = [best_distance, recent[0], recent[1]];
            3
        };
        commands.push(offset_index << 6 | match_code << 2 | literal_code);
        position += best_length;
        literal_start = position;
    }
    if commands.is_empty() {
        return None;
    }
    literals.extend_from_slice(&chunk[literal_start..]);

    let mut lz = Vec::new();
    if has_initial_history {
        lz.extend_from_slice(&chunk[..8]);
    }
    encode_stored_array(&mut lz, &literals);
    encode_stored_array(&mut lz, &commands);
    lz.push(128);
    encode_stored_array(&mut lz, &packed_offsets);
    encode_stored_array(&mut lz, &packed_lengths);
    append_lz_suffix(&mut lz, &offset_suffixes, &extended_lengths);
    (lz.len() < chunk.len()).then_some(lz)
}

fn build_previous_matches(chunk: &[u8]) -> Option<Vec<u32>> {
    let mut latest = vec![u32::MAX; 1 << 16];
    let mut previous = vec![u32::MAX; chunk.len()];
    let count = chunk.len().saturating_sub(3);
    for (position, prior) in previous.iter_mut().enumerate().take(count) {
        let key = hash_four_bytes(chunk.get(position..position + 4)?);
        *prior = latest[key];
        latest[key] = u32::try_from(position).ok()?;
    }
    Some(previous)
}

fn find_best_match(
    chunk: &[u8],
    previous: &[u32],
    position: usize,
    recent: &[usize; 3],
) -> Option<(usize, usize)> {
    let mut best = (0_usize, 0_usize);
    for &distance in recent {
        if position >= distance {
            let length = common_prefix_length(
                &chunk[position - distance..],
                &chunk[position..],
                chunk.len() - position,
            );
            if length > best.1 {
                best = (distance, length);
            }
        }
    }
    let prior = *previous.get(position)?;
    if prior != u32::MAX {
        let prior = usize::try_from(prior).ok()?;
        let distance = position - prior;
        if (8..=0x3fff).contains(&distance) {
            let length =
                common_prefix_length(&chunk[prior..], &chunk[position..], chunk.len() - position);
            if length > best.1 {
                best = (distance, length);
            }
        }
    }
    Some(best)
}

fn hash_four_bytes(bytes: &[u8]) -> usize {
    let value = u32::from_le_bytes(bytes.try_into().expect("caller supplies four bytes"));
    usize::from(((value.wrapping_mul(0x9e37_79b1)) >> 16) as u16)
}

fn common_prefix_length(left: &[u8], right: &[u8], maximum: usize) -> usize {
    let limit = left.len().min(right.len()).min(maximum);
    let mut offset = 0_usize;
    while offset + 16 <= limit {
        if left[offset..offset + 16] != right[offset..offset + 16] {
            return offset
                + left[offset..offset + 16]
                    .iter()
                    .zip(&right[offset..offset + 16])
                    .position(|(left, right)| left != right)
                    .unwrap_or(16);
        }
        offset += 16;
    }
    offset
        + left[offset..limit]
            .iter()
            .zip(&right[offset..limit])
            .position(|(left, right)| left != right)
            .unwrap_or(limit - offset)
}

fn encode_scaled_offset(distance: usize) -> Option<(u8, u32, u8)> {
    if distance < 8 {
        return None;
    }
    let value = u32::try_from(distance.checked_add(8)?).ok()?;
    let bit_count = value.ilog2().checked_sub(3)?;
    if bit_count > 26 {
        return None;
    }
    let base = value >> bit_count;
    if !(8..=15).contains(&base) {
        return None;
    }
    let extra = value & ((1_u32 << bit_count) - 1);
    let command = u8::try_from((bit_count << 3) | (base - 8)).ok()?;
    Some((command, extra, u8::try_from(bit_count).ok()?))
}

fn append_lz_suffix(output: &mut Vec<u8>, offsets: &[(u32, u8)], extended_lengths: &[usize]) {
    let mut front = MsbBits::new();
    let mut back = MsbBits::new();
    back.push_gamma(extended_lengths.len() + 1);
    for (index, &(extra, bit_count)) in offsets.iter().enumerate() {
        if index & 1 == 0 {
            front.push_value(extra, u32::from(bit_count));
        } else {
            back.push_value(extra, u32::from(bit_count));
        }
    }
    for (index, &value) in extended_lengths.iter().enumerate() {
        if index & 1 == 0 {
            front.push_extended_length(value);
        } else {
            back.push_extended_length(value);
        }
    }
    output.extend(front.finish());
    let mut back = back.finish();
    back.reverse();
    output.extend(back);
}

struct MsbBits {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl MsbBits {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_len: 0,
        }
    }

    fn push_bit(&mut self, bit: bool) {
        if self.bit_len.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit {
            let byte = self.bytes.last_mut().expect("a byte was just appended");
            *byte |= 1 << (7 - self.bit_len % 8);
        }
        self.bit_len += 1;
    }

    fn push_value(&mut self, value: u32, count: u32) {
        for shift in (0..count).rev() {
            self.push_bit(value >> shift & 1 != 0);
        }
    }

    fn push_gamma(&mut self, value: usize) {
        let bits = value.ilog2();
        for _ in 0..bits {
            self.push_bit(false);
        }
        self.push_value(u32::try_from(value).unwrap_or(u32::MAX), bits + 1);
    }

    fn push_extended_length(&mut self, value: usize) {
        let mut tier = 0_u32;
        let mut base = 0_usize;
        while value >= base + (1_usize << (tier + 6)) {
            base += 1_usize << (tier + 6);
            tier += 1;
        }
        for _ in 0..tier {
            self.push_bit(false);
        }
        self.push_bit(true);
        self.push_value(u32::try_from(value - base).unwrap_or(u32::MAX), tier + 6);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn encode_huffman_stream(input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    for block in input.chunks(BLOCK_SIZE) {
        if let Some(&value) = block.first()
            && block.iter().all(|byte| *byte == value)
        {
            output.extend_from_slice(&COMPRESSED_BLOCK_HEADER);
            output.extend_from_slice(&MEMSET_QUANTUM);
            output.push(value);
            continue;
        }
        let encoded = encode_huffman_block(block)?;
        if encoded.len() >= block.len() + RAW_BLOCK_HEADER.len() {
            return None;
        }
        output.extend_from_slice(&encoded);
    }
    Some(output)
}

fn encode_huffman_block(block: &[u8]) -> Option<Vec<u8>> {
    let mut quantum = Vec::new();
    for chunk in block.chunks(CHUNK_SIZE) {
        quantum.extend_from_slice(&encode_entropy_array(chunk)?);
    }
    if quantum.is_empty() || quantum.len() >= block.len() || quantum.len() > 0x3_ffff {
        return None;
    }
    let mut output = Vec::with_capacity(quantum.len() + 5);
    output.extend_from_slice(&COMPRESSED_BLOCK_HEADER);
    write_be24(&mut output, u32::try_from(quantum.len() - 1).ok()?);
    output.extend_from_slice(&quantum);
    Some(output)
}

fn encode_entropy_array(input: &[u8]) -> Option<Vec<u8>> {
    let huffman = encode_huffman_array(input);
    let tans = encode_tans_array(input);
    match (huffman, tans) {
        (Some(huffman), Some(tans)) if tans.len() < huffman.len() => Some(tans),
        (Some(huffman), _) => Some(huffman),
        (None, tans) => tans,
    }
}

fn encode_tans_array(input: &[u8]) -> Option<Vec<u8>> {
    const TABLE_BITS: usize = 8;
    const TABLE_SIZE: usize = 1 << TABLE_BITS;
    if input.len() < 5 {
        return None;
    }
    let mut frequencies = [0_usize; 256];
    for &symbol in input {
        frequencies[usize::from(symbol)] = frequencies[usize::from(symbol)].checked_add(1)?;
    }
    let symbols: Vec<u8> = frequencies
        .iter()
        .enumerate()
        .filter_map(|(symbol, &frequency)| {
            (frequency != 0)
                .then(|| u8::try_from(symbol).ok())
                .flatten()
        })
        .collect();
    if !(2..=9).contains(&symbols.len()) {
        return None;
    }
    let weights = normalize_tans_weights(&symbols, &frequencies, TABLE_SIZE)?;
    let mut table_weights = weights.clone();
    table_weights.sort_unstable();
    let table = build_tans_table(&table_weights, TABLE_BITS)?;
    let mut symbol_rows = [None; 256];
    for (row, &(symbol, _)) in table_weights.iter().enumerate() {
        symbol_rows[usize::from(symbol)] = Some(row);
    }
    let mut inverse = vec![[None; TABLE_SIZE]; table_weights.len()];
    for (previous, entry) in table.iter().enumerate() {
        for current in entry.base..=entry.base.checked_add(entry.mask)? {
            let slot = inverse
                .get_mut(symbol_rows[usize::from(entry.symbol)]?)?
                .get_mut(current)?;
            if slot.is_none() {
                *slot = Some((previous, current - entry.base, entry.bits));
            }
        }
    }

    let body_size = input.len() - 5;
    let mut events = Vec::with_capacity(body_size);
    let mut position = 0_usize;
    while position < body_size {
        for side in [false, true] {
            for state in 0..5 {
                if position == body_size {
                    break;
                }
                events.push((state, side, input[position]));
                position += 1;
            }
        }
    }
    let mut states: [usize; 5] = std::array::from_fn(|index| usize::from(input[body_size + index]));
    let mut encoded_events = vec![(false, 0_u16, 0_u8); body_size];
    for (index, &(state, side, symbol)) in events.iter().enumerate().rev() {
        let (previous, value, bit_count) = inverse[symbol_rows[usize::from(symbol)]?]
            .get(states[state])?
            .as_ref()
            .copied()?;
        encoded_events[index] = (
            side,
            u16::try_from(value).ok()?,
            u8::try_from(bit_count).ok()?,
        );
        states[state] = previous;
    }

    let mut front = LsbWriter::with_capacity(input.len());
    let mut back = LsbWriter::with_capacity(input.len());
    let table_bits = u8::try_from(TABLE_BITS).ok()?;
    front.push(u16::try_from(states[0]).ok()?, table_bits);
    back.push(u16::try_from(states[1]).ok()?, table_bits);
    front.push(u16::try_from(states[2]).ok()?, table_bits);
    back.push(u16::try_from(states[3]).ok()?, table_bits);
    front.push(u16::try_from(states[4]).ok()?, table_bits);
    for (side, value, bit_count) in encoded_events {
        if side {
            back.push(value, bit_count);
        } else {
            front.push(value, bit_count);
        }
    }
    let mut payload = encode_tans_header(&weights, TABLE_BITS)?;
    payload.extend(front.finish());
    let mut back = back.finish();
    back.reverse();
    payload.extend(back);
    encode_array_envelope(1, &payload, input.len())
}

fn normalize_tans_weights(
    symbols: &[u8],
    frequencies: &[usize; 256],
    table_size: usize,
) -> Option<Vec<(u8, usize)>> {
    let remaining = table_size.checked_sub(symbols.len())?;
    let total = symbols.iter().try_fold(0_usize, |total, &symbol| {
        total.checked_add(frequencies[usize::from(symbol)])
    })?;
    let mut allocated = 0_usize;
    let mut weights = Vec::with_capacity(symbols.len());
    let mut remainders = Vec::with_capacity(symbols.len());
    for &symbol in symbols {
        let scaled = frequencies[usize::from(symbol)].checked_mul(remaining)?;
        let extra = scaled / total;
        allocated = allocated.checked_add(extra)?;
        weights.push((symbol, extra + 1));
        remainders.push((scaled % total, symbol));
    }
    remainders.sort_unstable_by_key(|&(remainder, symbol)| (std::cmp::Reverse(remainder), symbol));
    for &(_, symbol) in remainders.iter().take(remaining.checked_sub(allocated)?) {
        weights[symbols.binary_search(&symbol).ok()?].1 += 1;
    }
    weights.sort_unstable_by_key(|&(symbol, weight)| (weight, symbol));
    Some(weights)
}

fn encode_tans_header(weights: &[(u8, usize)], table_bits: usize) -> Option<Vec<u8>> {
    if !(2..=9).contains(&weights.len()) || !(8..=11).contains(&table_bits) {
        return None;
    }
    let mut previous = 0_usize;
    let maximum_delta = weights
        .iter()
        .take(weights.len() - 1)
        .map(|&(_, weight)| {
            let delta = weight.checked_sub(previous)?;
            previous = weight;
            Some(delta)
        })
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .max()?;
    let delta_bits = usize::try_from(maximum_delta.ilog2())
        .ok()?
        .checked_add(1)?;
    if delta_bits > table_bits {
        return None;
    }
    let mut bits = MsbBits::new();
    bits.push_bit(false);
    bits.push_value(u32::try_from(table_bits - 8).ok()?, 2);
    bits.push_bit(false);
    bits.push_value(u32::try_from(weights.len() - 2).ok()?, 3);
    bits.push_value(u32::try_from(delta_bits).ok()?, 4);
    previous = 0;
    for &(symbol, weight) in weights.iter().take(weights.len() - 1) {
        bits.push_value(u32::from(symbol), 8);
        bits.push_value(
            u32::try_from(weight.checked_sub(previous)?).ok()?,
            u32::try_from(delta_bits).ok()?,
        );
        previous = weight;
    }
    bits.push_value(u32::from(weights.last()?.0), 8);
    Some(bits.finish())
}

fn encode_huffman_array(input: &[u8]) -> Option<Vec<u8>> {
    let mut frequencies = [0_usize; 256];
    for &byte in input {
        frequencies[usize::from(byte)] = frequencies[usize::from(byte)].checked_add(1)?;
    }
    let symbols: Vec<u8> = frequencies
        .into_iter()
        .enumerate()
        .filter(|&(_, frequency)| frequency != 0)
        .map(|(symbol, _)| u8::try_from(symbol).expect("symbol index fits in a byte"))
        .collect();
    if symbols.len() == 1 {
        return encode_array_envelope(3, &[symbols[0]], input.len());
    }
    let lengths = huffman_code_lengths(&symbols, &frequencies)?;
    let canonical = canonical_huffman_table(&symbols, &lengths)?;
    let mut codes = [None; 256];
    for &(code, bit_count, symbol) in &canonical.entries {
        codes[usize::from(symbol)] = Some((code, bit_count));
    }
    let mut table = encode_sparse_huffman_table(&symbols, &lengths)?;
    let encoded_cost = huffman_payload_cost(input, &codes)?.checked_add(table.len())?;

    let minimum = *symbols.first()?;
    let maximum = *symbols.last()?;
    let span = usize::from(maximum) - usize::from(minimum) + 1;
    if let Some(alphabet_size) = [5_u8, 8, 16, 32, 64, 128]
        .into_iter()
        .find(|&size| span <= usize::from(size))
    {
        let start = minimum.min(u8::MAX - alphabet_size + 1);
        if usize::from(maximum) < usize::from(start) + usize::from(alphabet_size) {
            let compact_table = encode_contiguous_new_huffman_header(alphabet_size, start);
            let mut compact_codes = [None; 256];
            for symbol_index in 0..alphabet_size {
                compact_codes[usize::from(start + symbol_index)] =
                    huffman_encoder_code(alphabet_size, symbol_index);
            }
            if !compact_table.is_empty() {
                let compact_cost = huffman_payload_cost(input, &compact_codes)?
                    .checked_add(compact_table.len())?;
                if compact_cost < encoded_cost {
                    table = compact_table;
                    codes = compact_codes;
                }
            }
        }
    }
    let mut first_bits = LsbWriter::with_capacity(input.len().div_ceil(3));
    let mut second_bits = LsbWriter::with_capacity(input.len() / 3);
    let mut backward_bits = LsbWriter::with_capacity(input.len().saturating_add(1) / 3);
    for (index, &symbol) in input.iter().enumerate() {
        let (code, bit_count) = codes[usize::from(symbol)]?;
        match index % 3 {
            0 => first_bits.push(code, bit_count),
            1 => backward_bits.push(code, bit_count),
            _ => second_bits.push(code, bit_count),
        }
    }
    let first = first_bits.finish();
    let second = second_bits.finish();
    let mut backward = backward_bits.finish();
    backward.reverse();
    let mut payload =
        Vec::with_capacity(table.len() + 2 + first.len() + second.len() + backward.len());
    payload.extend_from_slice(&table);
    payload.extend_from_slice(&u16::try_from(first.len()).ok()?.to_le_bytes());
    payload.extend_from_slice(&first);
    payload.extend_from_slice(&second);
    payload.extend_from_slice(&backward);
    if payload.len() >= input.len() || payload.len() > 0x3_ffff || input.len() > 0x3_ffff {
        return None;
    }
    encode_array_envelope(2, &payload, input.len())
}

fn huffman_payload_cost(input: &[u8], codes: &[Option<(u16, u8)>; 256]) -> Option<usize> {
    let mut partition_bits = [0_usize; 3];
    for (index, &symbol) in input.iter().enumerate() {
        partition_bits[index % 3] =
            partition_bits[index % 3].checked_add(usize::from(codes[usize::from(symbol)]?.1))?;
    }
    partition_bits
        .into_iter()
        .try_fold(2_usize, |total, bits| total.checked_add(bits.div_ceil(8)))
}

fn huffman_encoder_code(alphabet_size: u8, symbol_index: u8) -> Option<(u16, u8)> {
    match alphabet_size {
        5 => [(0b00, 2), (0b10, 2), (0b01, 2), (0b011, 3), (0b111, 3)]
            .get(usize::from(symbol_index))
            .copied(),
        8 | 16 | 32 | 64 | 128 if symbol_index < alphabet_size => {
            let bits = u8::try_from(alphabet_size.ilog2()).ok()?;
            Some((reverse_low_bits(u16::from(symbol_index), bits), bits))
        }
        _ => None,
    }
}

fn huffman_code_lengths(symbols: &[u8], frequencies: &[usize; 256]) -> Option<Vec<u8>> {
    if !(2..=255).contains(&symbols.len()) {
        return None;
    }
    let leaf_count = symbols.len();
    let mut weights: Vec<usize> = symbols
        .iter()
        .map(|&symbol| frequencies[usize::from(symbol)])
        .collect();
    let mut parents = vec![usize::MAX; leaf_count * 2 - 1];
    let mut active: BinaryHeap<Reverse<(usize, usize)>> = weights
        .iter()
        .copied()
        .enumerate()
        .map(|(node, weight)| Reverse((weight, node)))
        .collect();
    while active.len() > 1 {
        let Reverse((_, first)) = active.pop()?;
        let Reverse((_, second)) = active.pop()?;
        let parent = weights.len();
        weights.push(weights[first].checked_add(weights[second])?);
        parents[first] = parent;
        parents[second] = parent;
        active.push(Reverse((weights[parent], parent)));
    }
    let mut lengths = Vec::with_capacity(leaf_count);
    for leaf in 0..leaf_count {
        let mut length = 0_u8;
        let mut node = leaf;
        while parents[node] != usize::MAX {
            length = length.checked_add(1)?;
            node = parents[node];
        }
        lengths.push(length);
    }
    if lengths.iter().all(|&length| length <= 11) {
        return Some(lengths);
    }

    // A complete, length-limited tree is a safe fallback for extremely skewed
    // distributions. Give the shorter leaves to the most frequent symbols.
    let long_length = u8::try_from(leaf_count.next_power_of_two().ilog2()).ok()?;
    let short_count = (1_usize << long_length).checked_sub(leaf_count)?;
    let mut ranked: Vec<usize> = (0..leaf_count).collect();
    ranked.sort_unstable_by_key(|&index| {
        (
            std::cmp::Reverse(frequencies[usize::from(symbols[index])]),
            symbols[index],
        )
    });
    lengths.fill(long_length);
    for &index in ranked.iter().take(short_count) {
        lengths[index] = long_length.checked_sub(1)?;
    }
    Some(lengths)
}

fn encode_sparse_huffman_table(symbols: &[u8], lengths: &[u8]) -> Option<Vec<u8>> {
    if symbols.len() != lengths.len() || !(2..=255).contains(&symbols.len()) {
        return None;
    }
    let maximum = lengths.iter().copied().max()?;
    if !(1..=11).contains(&maximum) {
        return None;
    }
    let length_bits = if maximum == 1 {
        0
    } else {
        u32::from(maximum - 1).ilog2() + 1
    };
    if length_bits > 4 {
        return None;
    }
    let mut bits = MsbBits::new();
    bits.push_bit(false);
    bits.push_bit(false);
    bits.push_value(u32::try_from(symbols.len()).ok()?, 8);
    bits.push_value(length_bits, 3);
    for (&symbol, &length) in symbols.iter().zip(lengths) {
        bits.push_value(u32::from(symbol), 8);
        bits.push_value(u32::from(length - 1), length_bits);
    }
    Some(bits.finish())
}

fn encode_array_envelope(array_type: u8, payload: &[u8], decoded_size: usize) -> Option<Vec<u8>> {
    if payload.len() >= decoded_size || payload.len() > 0x3_ffff || decoded_size > 0x3_ffff {
        return None;
    }
    let decoded_minus_one = u32::try_from(decoded_size.checked_sub(1)?).ok()?;
    let compressed = u32::try_from(payload.len()).ok()?;
    let mut output = Vec::with_capacity(payload.len() + 5);
    output.push(array_type << 4 | u8::try_from(decoded_minus_one >> 14).ok()?);
    output.extend_from_slice(&((decoded_minus_one & 0x3fff) << 18 | compressed).to_be_bytes());
    output.extend_from_slice(payload);
    Some(output)
}

struct LsbWriter {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl LsbWriter {
    fn with_capacity(symbol_count: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(symbol_count.div_ceil(2)),
            bit_len: 0,
        }
    }

    fn push(&mut self, code: u16, bit_count: u8) {
        for shift in 0..bit_count {
            if self.bit_len.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if code >> shift & 1 != 0 {
                let byte = self.bytes.last_mut().expect("a byte was just appended");
                *byte |= 1 << (self.bit_len & 7);
            }
            self.bit_len += 1;
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
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
    bits.require_no_unread_bytes()?;
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
        1 => decode_tans(payload, decoded_size, payload_offset),
        2 => decode_huffman_one_partition(payload, decoded_size, payload_offset),
        4 => decode_huffman_two_partitions(payload, decoded_size, payload_offset),
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
    decode_huffman_group(
        &table,
        &payload[table_size..],
        decoded_size,
        offset + table_size,
    )
}

fn decode_huffman_two_partitions(
    payload: &[u8],
    decoded_size: usize,
    offset: usize,
) -> Result<Vec<u8>, KrakenError> {
    let (table, table_size) = decode_huffman_table(payload, offset)?;
    let partition_bytes =
        payload
            .get(table_size..table_size + 3)
            .ok_or(KrakenError::Truncated {
                offset: offset + table_size,
            })?;
    let first_size = usize::from(partition_bytes[0])
        | usize::from(partition_bytes[1]) << 8
        | usize::from(partition_bytes[2]) << 16;
    let groups = payload
        .get(table_size + 3..)
        .ok_or(KrakenError::Truncated {
            offset: offset + table_size + 3,
        })?;
    if first_size > groups.len() {
        return Err(KrakenError::InvalidArray { offset });
    }
    let first_decoded = decoded_size.div_ceil(2);
    let mut output = decode_huffman_group(
        &table,
        &groups[..first_size],
        first_decoded,
        offset + table_size + 3,
    )?;
    output.extend(decode_huffman_group(
        &table,
        &groups[first_size..],
        decoded_size - first_decoded,
        offset + table_size + 3 + first_size,
    )?);
    Ok(output)
}

fn decode_huffman_group(
    table: &OldHuffmanTable,
    payload: &[u8],
    decoded_size: usize,
    offset: usize,
) -> Result<Vec<u8>, KrakenError> {
    let split_bytes = payload.get(..2).ok_or(KrakenError::Truncated { offset })?;
    let first_len = usize::from(u16::from_le_bytes([split_bytes[0], split_bytes[1]]));
    let streams = payload
        .get(2..)
        .ok_or(KrakenError::Truncated { offset: offset + 2 })?;
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
    if let Some(table) = decode_old_huffman_table(payload) {
        return Ok(table);
    }
    if let Some(table) = decode_new_huffman_table(payload) {
        return Ok(table);
    }
    Err(KrakenError::UnsupportedQuantum { offset })
}

fn decode_old_huffman_table(payload: &[u8]) -> Option<(OldHuffmanTable, usize)> {
    let mut bits = MsbReader::new(payload);
    if bits.read(1)? != 0 {
        return None;
    }
    let mut symbols = Vec::new();
    let mut lengths = Vec::new();
    if bits.read(1)? == 0 {
        let symbol_count = bits.read(8)?;
        if symbol_count == 0 {
            return None;
        }
        if symbol_count == 1 {
            symbols.push(u8::try_from(bits.read(8)?).ok()?);
            lengths.push(1);
        } else {
            let length_bits = bits.read(3)?;
            if length_bits > 4 {
                return None;
            }
            for _ in 0..symbol_count {
                symbols.push(u8::try_from(bits.read(8)?).ok()?);
                lengths.push(u8::try_from(bits.read(length_bits)?.checked_add(1)?).ok()?);
            }
        }
    } else {
        let forced_bits = bits.read(2)?;
        let mut symbol = 0_usize;
        let mut average_quarters = 32_i32;
        let mut skip_zero_run = bits.read(1)? != 0;
        loop {
            if !skip_zero_run {
                symbol = symbol.checked_add(bits.read_gamma_run()?)?;
                if symbol >= 256 {
                    break;
                }
            }
            skip_zero_run = false;
            let run = bits.read_gamma_run()?;
            if symbol.checked_add(run)? > 256 {
                return None;
            }
            for _ in 0..run {
                let encoded = i32::try_from(bits.read_gamma_x(forced_bits)?).ok()?;
                let delta = -(encoded & 1) ^ (encoded >> 1);
                let length = delta.checked_add((average_quarters + 2) >> 2)?;
                if !(1..=11).contains(&length) {
                    return None;
                }
                symbols.push(u8::try_from(symbol).ok()?);
                lengths.push(u8::try_from(length).ok()?);
                average_quarters = length.checked_add((3 * average_quarters + 2) >> 2)?;
                symbol += 1;
            }
            if symbol == 256 {
                break;
            }
        }
        if symbols.len() < 2 {
            return None;
        }
    }
    let table = canonical_huffman_table(&symbols, &lengths)?;
    Some((table, bits.consumed_bytes()))
}

#[cfg(test)]
const STREAMINGWORLD_LITERAL_HEADER: &[u8] = &[
    0x8c, 0xdd, 0x80, 0x0b, 0x24, 0xcf, 0xf3, 0xf9, 0x42, 0x4a, 0x49, 0x49, 0x17, 0x35, 0x4e, 0x3e,
    0x4b, 0x29, 0x4c, 0x6c, 0xd0, 0x94, 0xb0, 0xa2, 0x59, 0xe6, 0x91, 0x24, 0x10, 0x82, 0xb1, 0xe2,
    0x12, 0xc5, 0x81, 0x1a, 0x48, 0x4c, 0x84, 0x21, 0x99, 0x91, 0x49, 0x29, 0xa6, 0x26, 0x53, 0x79,
    0xa7, 0xee, 0x52, 0xb5, 0x49, 0x69, 0x24, 0xf3, 0x1e, 0xa4, 0xa4, 0xa4, 0xa9, 0xf0, 0x6d, 0x83,
    0x6d, 0xfe, 0xfd, 0xbd, 0x4f, 0x3d, 0xb6, 0xcd, 0xe6, 0xfc, 0xdb, 0x3f, 0xd9, 0xd4, 0x7e, 0x02,
    0x07, 0x21, 0x11, 0xa0, 0x09, 0x00, 0x80, 0x18,
];
#[cfg(test)]
const MAINMENU_RLE_COMMAND_HEADER: &[u8] = &[
    0x97, 0x46, 0xc0, 0x8b, 0x92, 0x88, 0x86, 0x74, 0x4c, 0xb5, 0x95, 0x2f, 0x96, 0xe2, 0x6d, 0x5a,
    0x12, 0xd7, 0xab, 0x91, 0x4a, 0xa5, 0x5a, 0xba, 0x89, 0xa6, 0x7a, 0xeb, 0x7d, 0xeb, 0x4f, 0x18,
    0xdb, 0xce, 0xda, 0xd4, 0x76, 0x69, 0xcb, 0xbb, 0x16, 0x6b, 0x8d, 0xfc, 0xeb, 0x3b, 0x72, 0xbf,
    0xaf, 0x82, 0x0c, 0x17, 0x09, 0x22, 0x02, 0x80, 0x57, 0x00, 0x23, 0x4a, 0x41, 0x10, 0x55, 0x64,
    0x07, 0x20, 0x09, 0xda, 0x83, 0x86, 0x4f, 0xc4, 0x23, 0x08, 0x61, 0x04,
];
fn decode_new_huffman_table(payload: &[u8]) -> Option<(OldHuffmanTable, usize)> {
    let mut bits = MsbReader::new(payload);
    if bits.read(2)? != 0b10 {
        return None;
    }
    let forced_bits = bits.read(2)?;
    let symbol_count = bits.read(8)?.checked_add(1)?;
    let fluff = if symbol_count == 256 {
        0
    } else {
        let range = symbol_count.min(257_usize.checked_sub(symbol_count)?);
        bits.read_truncated(range.checked_mul(2)?)?
    };
    let rice_count = symbol_count.checked_add(fluff)?;
    let mut rice = Vec::with_capacity(rice_count);
    for _ in 0..rice_count {
        rice.push(bits.read_unary()?);
    }
    for value in rice.iter_mut().take(symbol_count) {
        *value = value
            .checked_shl(u32::try_from(forced_bits).ok()?)?
            .checked_add(bits.read(forced_bits)?)?;
    }

    let mut lengths = Vec::with_capacity(symbol_count);
    let mut running_sum = 0x1e_i32;
    for &encoded in rice.iter().take(symbol_count) {
        let encoded = i32::try_from(encoded).ok()?;
        let delta = -(encoded & 1) ^ (encoded >> 1);
        let length = delta.checked_add(running_sum >> 2)?.checked_add(1)?;
        if !(1..=11).contains(&length) {
            return None;
        }
        lengths.push(u8::try_from(length).ok()?);
        running_sum = running_sum.checked_add(delta)?;
    }

    let mut symbols = Vec::with_capacity(symbol_count);
    let range_codes = &rice[symbol_count..];
    let range_count = fluff >> 1;
    let mut range_code = 0_usize;
    let mut symbol = 0_usize;
    if fluff & 1 != 0 {
        let width = *range_codes.get(range_code)?;
        range_code += 1;
        if width >= 8 {
            return None;
        }
        symbol = bits.read(width.checked_add(1)?)? + (1_usize << (width + 1)) - 1;
    }
    for _ in 0..range_count {
        let count_width = *range_codes.get(range_code)?;
        let space_width = *range_codes.get(range_code.checked_add(1)?)?;
        range_code += 2;
        if count_width >= 9 || space_width >= 8 {
            return None;
        }
        let count = bits.read(count_width)? + (1_usize << count_width);
        let space = bits.read(space_width.checked_add(1)?)? + (1_usize << (space_width + 1)) - 1;
        let end = symbol.checked_add(count)?.min(256);
        if end - symbol != count {
            return None;
        }
        symbols.extend(
            (symbol..end)
                .map(|value| u8::try_from(value).ok())
                .collect::<Option<Vec<_>>>()?,
        );
        symbol = end.checked_add(space)?;
    }
    let remaining = symbol_count.checked_sub(symbols.len())?;
    let end = symbol.checked_add(remaining)?;
    if remaining == 0 || symbol >= 256 || end > 256 || range_code != range_codes.len() {
        return None;
    }
    symbols.extend(
        (symbol..end)
            .map(|value| u8::try_from(value).ok())
            .collect::<Option<Vec<_>>>()?,
    );
    let table = canonical_huffman_table(&symbols, &lengths)?;
    Some((table, bits.consumed_bytes()))
}

struct MsbReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> MsbReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, count: usize) -> Option<usize> {
        if count > usize::BITS as usize
            || self.position.checked_add(count)? > self.bytes.len().checked_mul(8)?
        {
            return None;
        }
        let mut value = 0_usize;
        for _ in 0..count {
            let byte = self.bytes[self.position / 8];
            value = value << 1 | usize::from(byte >> (7 - self.position % 8) & 1);
            self.position += 1;
        }
        Some(value)
    }

    fn read_unary(&mut self) -> Option<usize> {
        let mut value = 0_usize;
        while self.read(1)? == 0 {
            value = value.checked_add(1)?;
            if value > 255 {
                return None;
            }
        }
        Some(value)
    }

    fn read_gamma_run(&mut self) -> Option<usize> {
        let zeroes = self.peek_zeroes()?;
        let width = zeroes.checked_add(1)?.checked_mul(2)?;
        self.read(width)?.checked_sub(1)
    }

    fn read_gamma_x(&mut self, forced_bits: usize) -> Option<usize> {
        let zeroes = self.peek_zeroes()?;
        let width = zeroes.checked_add(forced_bits)?.checked_add(1)?;
        let prefix = self.read(width)?;
        let tier = zeroes
            .checked_sub(1)?
            .checked_shl(u32::try_from(forced_bits).ok()?)?;
        prefix.checked_add(tier)
    }

    fn peek_zeroes(&self) -> Option<usize> {
        let total = self.bytes.len().checked_mul(8)?;
        let mut position = self.position;
        while position < total {
            let byte = self.bytes[position / 8];
            if byte >> (7 - position % 8) & 1 != 0 {
                return Some(position - self.position);
            }
            position += 1;
            if position - self.position > 23 {
                return None;
            }
        }
        None
    }

    fn read_truncated(&mut self, range: usize) -> Option<usize> {
        if range <= 1 {
            return Some(0);
        }
        let width = usize::try_from((range - 1).ilog2()).ok()?.checked_add(1)?;
        let value = self.read(width)?;
        let cutoff = (1_usize << width).checked_sub(range)?;
        if value >> 1 >= cutoff {
            value.checked_sub(cutoff)
        } else {
            self.position = self.position.checked_sub(1)?;
            Some(value >> 1)
        }
    }

    fn consumed_bytes(&self) -> usize {
        self.position.div_ceil(8)
    }
}

#[derive(Clone, Copy, Default)]
struct TansEntry {
    mask: usize,
    bits: usize,
    symbol: u8,
    base: usize,
}

fn decode_tans(payload: &[u8], decoded_size: usize, offset: usize) -> Result<Vec<u8>, KrakenError> {
    if payload.len() < 8 || decoded_size < 5 {
        return Err(KrakenError::InvalidArray { offset });
    }
    let mut header = MsbReader::new(payload);
    if header.read(1) != Some(0) {
        return Err(KrakenError::InvalidArray { offset });
    }
    let table_bits = header
        .read(2)
        .and_then(|value| value.checked_add(8))
        .ok_or(KrakenError::InvalidArray { offset })?;
    let weights =
        decode_tans_weights(&mut header, table_bits).ok_or(KrakenError::InvalidArray { offset })?;
    let table =
        build_tans_table(&weights, table_bits).ok_or(KrakenError::InvalidArray { offset })?;
    let stream = payload
        .get(header.consumed_bytes()..)
        .ok_or(KrakenError::InvalidArray { offset })?;
    let mut bits = TansPairedBits::new(stream);
    let states = [
        bits.read_front(table_bits),
        bits.read_back(table_bits),
        bits.read_front(table_bits),
        bits.read_back(table_bits),
        bits.read_front(table_bits),
    ];
    if states.iter().any(Option::is_none) {
        return Err(KrakenError::InvalidArray { offset });
    }
    let mut states = states.map(Option::unwrap);
    let body_size = decoded_size - 5;
    let mut output = Vec::with_capacity(decoded_size);
    while output.len() < body_size {
        for side in [false, true] {
            for state in &mut states {
                if output.len() == body_size {
                    break;
                }
                let entry = table
                    .get(*state)
                    .copied()
                    .ok_or(KrakenError::InvalidArray { offset })?;
                output.push(entry.symbol);
                let value = if side {
                    bits.read_back(entry.bits)
                } else {
                    bits.read_front(entry.bits)
                }
                .ok_or(KrakenError::InvalidArray { offset })?;
                *state = entry
                    .base
                    .checked_add(value & entry.mask)
                    .ok_or(KrakenError::InvalidArray { offset })?;
            }
        }
    }
    if !bits.consumed_exactly() || states.iter().any(|&state| state > 0xff) {
        return Err(KrakenError::InvalidArray { offset });
    }
    output.extend(states.map(|state| u8::try_from(state).unwrap()));
    Ok(output)
}

fn decode_tans_weights(bits: &mut MsbReader<'_>, table_bits: usize) -> Option<Vec<(u8, usize)>> {
    let table_size = 1_usize.checked_shl(u32::try_from(table_bits).ok()?)?;
    if bits.read(1)? == 0 {
        let count = bits.read(3)?.checked_add(1)?;
        let delta_bits = bits.read(4)?;
        if delta_bits == 0 || delta_bits > table_bits {
            return None;
        }
        let mut seen = [false; 256];
        let mut weights = Vec::with_capacity(count + 1);
        let mut weight = 0_usize;
        let mut total = 0_usize;
        for _ in 0..count {
            let symbol = u8::try_from(bits.read(8)?).ok()?;
            if seen[usize::from(symbol)] {
                return None;
            }
            weight = weight.checked_add(bits.read(delta_bits)?)?;
            if weight == 0 {
                return None;
            }
            total = total.checked_add(weight)?;
            if total >= table_size {
                return None;
            }
            seen[usize::from(symbol)] = true;
            weights.push((symbol, weight));
        }
        let symbol = u8::try_from(bits.read(8)?).ok()?;
        let remaining = table_size.checked_sub(total)?;
        if seen[usize::from(symbol)] || remaining <= 1 || remaining < weight {
            return None;
        }
        weights.push((symbol, remaining));
        weights.sort_unstable();
        return Some(weights);
    }

    let base_bits = bits.read(3)?;
    let symbol_count = bits.read(8)?.checked_add(1)?;
    if symbol_count < 2 {
        return None;
    }
    let fluff = tans_fluff(bits, symbol_count)?;
    let mut rice = Vec::with_capacity(symbol_count.checked_add(fluff)?);
    for _ in 0..symbol_count.checked_add(fluff)? {
        rice.push(bits.read_unary()?);
    }
    let ranges = decode_symbol_ranges(bits, symbol_count, &rice[symbol_count..])?;
    let mut weights = Vec::with_capacity(symbol_count);
    let mut average = 6_i32;
    let mut total = 0_usize;
    let mut rice_index = 0_usize;
    for (start, count) in ranges {
        for symbol in start..start.checked_add(count)? {
            let extra_bits = base_bits.checked_add(*rice.get(rice_index)?)?;
            rice_index += 1;
            if extra_bits > 15 {
                return None;
            }
            let mut value = i32::try_from(bits.read(extra_bits)?).ok()? + (1_i32 << extra_bits)
                - (1_i32 << base_bits);
            let average_quarter = average >> 2;
            let mut limit = 2 * average_quarter;
            if value <= limit {
                value = average_quarter + (-(value & 1) ^ (value >> 1));
            }
            limit = limit.min(value);
            let weight = usize::try_from(value.checked_add(1)?).ok()?;
            average = average.checked_add(limit - average_quarter)?;
            total = total.checked_add(weight)?;
            weights.push((u8::try_from(symbol).ok()?, weight));
        }
    }
    if rice_index != symbol_count || total != table_size {
        return None;
    }
    Some(weights)
}

fn tans_fluff(bits: &mut MsbReader<'_>, symbol_count: usize) -> Option<usize> {
    if symbol_count == 256 {
        Some(0)
    } else {
        let range = symbol_count.min(257_usize.checked_sub(symbol_count)?);
        bits.read_truncated(range.checked_mul(2)?)
    }
}

fn decode_symbol_ranges(
    bits: &mut MsbReader<'_>,
    symbol_count: usize,
    codes: &[usize],
) -> Option<Vec<(usize, usize)>> {
    let mut ranges = Vec::with_capacity((codes.len() >> 1) + 1);
    let mut code = 0_usize;
    let mut symbol = 0_usize;
    let mut used = 0_usize;
    if codes.len() & 1 != 0 {
        let width = *codes.get(code)?;
        code += 1;
        if width >= 8 {
            return None;
        }
        symbol = bits.read(width + 1)? + (1_usize << (width + 1)) - 1;
    }
    for _ in 0..(codes.len() >> 1) {
        let count_width = *codes.get(code)?;
        let space_width = *codes.get(code + 1)?;
        code += 2;
        if count_width >= 9 || space_width >= 8 {
            return None;
        }
        let count = bits.read(count_width)? + (1_usize << count_width);
        let space = bits.read(space_width + 1)? + (1_usize << (space_width + 1)) - 1;
        if symbol.checked_add(count)? > 256 {
            return None;
        }
        ranges.push((symbol, count));
        used = used.checked_add(count)?;
        symbol = symbol.checked_add(count)?.checked_add(space)?;
    }
    let remaining = symbol_count.checked_sub(used)?;
    if remaining == 0 || symbol.checked_add(remaining)? > 256 || code != codes.len() {
        return None;
    }
    ranges.push((symbol, remaining));
    Some(ranges)
}

fn build_tans_table(weights: &[(u8, usize)], table_bits: usize) -> Option<Vec<TansEntry>> {
    let table_size = 1_usize.checked_shl(u32::try_from(table_bits).ok()?)?;
    let singles: Vec<u8> = weights
        .iter()
        .filter_map(|&(symbol, weight)| (weight == 1).then_some(symbol))
        .collect();
    let allocated = table_size.checked_sub(singles.len())?;
    let quarter = allocated >> 2;
    let mut pointers = [
        0,
        quarter + usize::from(allocated & 3 > 0),
        quarter * 2 + usize::from(allocated & 3 > 0) + usize::from(allocated & 3 > 1),
        quarter * 3
            + usize::from(allocated & 3 > 0)
            + usize::from(allocated & 3 > 1)
            + usize::from(allocated & 3 > 2),
    ];
    let mut table = vec![TansEntry::default(); table_size];
    for (index, symbol) in singles.into_iter().enumerate() {
        table[allocated + index] = TansEntry {
            mask: table_size - 1,
            bits: table_bits,
            symbol,
            base: 0,
        };
    }

    let mut weight_sum = 0_usize;
    for &(symbol, weight) in weights.iter().filter(|(_, weight)| *weight >= 2) {
        if weight > 4 {
            let symbol_bits = usize::try_from(weight.ilog2()).ok()?;
            let mut shift = table_bits.checked_sub(symbol_bits)?;
            let mut entry = TansEntry {
                mask: (1_usize << shift) - 1,
                bits: shift,
                symbol,
                base: (table_size - 1) & (weight << shift),
            };
            let mut increment = 1_usize << shift;
            let mut short_count = (1_usize << (symbol_bits + 1)).checked_sub(weight)?;
            for (partition, pointer) in pointers.iter_mut().enumerate() {
                let count = (weight + weight_sum.wrapping_sub(partition + 1) % 4).checked_div(4)?;
                let first = short_count.min(count);
                for _ in 0..first {
                    *table.get_mut(*pointer)? = entry;
                    *pointer += 1;
                    entry.base = entry.base.checked_add(increment)?;
                }
                short_count -= first;
                if first != count {
                    shift = shift.checked_sub(1)?;
                    increment >>= 1;
                    entry.bits = shift;
                    entry.mask >>= 1;
                    entry.base = 0;
                    for _ in first..count {
                        *table.get_mut(*pointer)? = entry;
                        *pointer += 1;
                        entry.base = entry.base.checked_add(increment)?;
                    }
                    short_count = weight;
                }
            }
        } else {
            let mut partitions = ((1_u32 << weight) - 1) << (weight_sum & 3);
            partitions |= partitions >> 4;
            for sequence in weight..weight.checked_mul(2)? {
                let partition = usize::try_from(partitions.trailing_zeros()).ok()?;
                partitions &= partitions - 1;
                let pointer = pointers.get_mut(partition)?;
                let symbol_bits = usize::try_from(sequence.ilog2()).ok()?;
                let shift = table_bits.checked_sub(symbol_bits)?;
                *table.get_mut(*pointer)? = TansEntry {
                    mask: (1_usize << shift) - 1,
                    bits: shift,
                    symbol,
                    base: (table_size - 1) & (sequence << shift),
                };
                *pointer += 1;
            }
        }
        weight_sum = weight_sum.checked_add(weight)?;
    }
    if pointers
        != [
            quarter + usize::from(allocated & 3 > 0),
            quarter * 2 + usize::from(allocated & 3 > 0) + usize::from(allocated & 3 > 1),
            quarter * 3
                + usize::from(allocated & 3 > 0)
                + usize::from(allocated & 3 > 1)
                + usize::from(allocated & 3 > 2),
            allocated,
        ]
    {
        return None;
    }
    Some(table)
}

struct TansPairedBits<'a> {
    bytes: &'a [u8],
    front: usize,
    back: usize,
}

impl<'a> TansPairedBits<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            front: 0,
            back: 0,
        }
    }

    fn read_front(&mut self, count: usize) -> Option<usize> {
        let mut value = 0_usize;
        for shift in 0..count {
            if self.front.checked_add(self.back)? >= self.bytes.len().checked_mul(8)? {
                return None;
            }
            let bit = self.bytes[self.front / 8] >> (self.front & 7) & 1;
            value |= usize::from(bit) << shift;
            self.front += 1;
        }
        Some(value)
    }

    fn read_back(&mut self, count: usize) -> Option<usize> {
        let mut value = 0_usize;
        for shift in 0..count {
            if self.front.checked_add(self.back)? >= self.bytes.len().checked_mul(8)? {
                return None;
            }
            let byte = self.bytes.len().checked_sub(self.back / 8 + 1)?;
            let bit = self.bytes[byte] >> (self.back & 7) & 1;
            value |= usize::from(bit) << shift;
            self.back += 1;
        }
        Some(value)
    }

    fn consumed_exactly(&self) -> bool {
        self.front.div_ceil(8) + self.back.div_ceil(8) == self.bytes.len()
    }
}

fn canonical_huffman_table(symbols: &[u8], lengths: &[u8]) -> Option<OldHuffmanTable> {
    if symbols.len() != lengths.len() || symbols.is_empty() {
        return None;
    }
    let kraft_slots = lengths.iter().try_fold(0_u32, |slots, &length| {
        if !(1..=11).contains(&length) {
            return None;
        }
        slots.checked_add(1_u32 << (11 - length))
    })?;
    if kraft_slots != 1 << 11 {
        return None;
    }
    let mut ordered: Vec<(u8, u8)> = symbols
        .iter()
        .copied()
        .zip(lengths.iter().copied())
        .collect();
    ordered.sort_unstable_by_key(|&(symbol, length)| (length, symbol));
    let mut code = 0_u16;
    let mut previous_length = 0_u8;
    let mut entries = Vec::with_capacity(ordered.len());
    for (symbol, length) in ordered {
        code = code.checked_shl(u32::from(length - previous_length))?;
        entries.push((reverse_low_bits(code, length), length, symbol));
        code = code.checked_add(1)?;
        previous_length = length;
    }
    Some(OldHuffmanTable { entries })
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
        (5, 0) => vec![0xa0, 0x40, 0x4b, 0xeb, 0xa0],
        (8, 0) => vec![0x90, 0x70, 0x08, 0x95, 0xff, 0xe0],
        (16, 0) => vec![0x80, 0xf0, 0x00, 0x82, 0x22, 0xab, 0xfe],
        (32, 0) => vec![0x81, 0xf0, 0x01, 0x11, 0x55, 0xff, 0xff, 0xff, 0x80],
        (64, 0) => vec![
            0x83, 0xf0, 0x02, 0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0,
        ],
        (128, 0) => vec![
            0x87, 0xf0, 0x05, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xfe,
        ],
        (5, _) => {
            let mut output = vec![0xa0, 0x42, 0x4b];
            append_new_huffman_start_code(
                &mut output,
                start,
                &[true],
                &[
                    true, true, true, false, true, false, true, true, true, false, true,
                ],
            );
            output
        }
        (8, _) => {
            let mut output = vec![0x90, 0x71, 0x08, 0x95];
            append_new_huffman_start_code(&mut output, start, &[true, true, true], &[true; 9]);
            output
        }
        (16, _) => {
            let mut output = vec![0x80, 0xf0, 0x80, 0x82, 0x22, 0xab];
            append_new_huffman_start_code(&mut output, start, &[true; 7], &[true]);
            output
        }
        _ => Vec::new(),
    }
}

fn append_new_huffman_start_code(
    output: &mut Vec<u8>,
    start: u8,
    leading_bits: &[bool],
    delimiter_bits: &[bool],
) {
    debug_assert!(start > 0);
    let tier = usize::try_from((u16::from(start) + 1).ilog2()).unwrap();
    let base = (1_usize << tier) - 1;
    let delta = usize::from(start) - base;
    let mut bits = Vec::with_capacity(leading_bits.len() + tier + delimiter_bits.len() + tier);
    bits.extend_from_slice(leading_bits);
    bits.extend(std::iter::repeat_n(false, tier - 1));
    bits.extend_from_slice(delimiter_bits);
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
        // Zero shares the compact command shape: it emits fifteen literals
        // and no run. Native streams use it even though early interoperability
        // notes only documented the >= 0x30 range.
        } else if command == 0 || command >= 0x30 {
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
    if count_byte & 0x80 != 0 {
        let source_count = usize::from(count_byte & 0x3f);
        return decode_multi_array(&mut cursor, source_count, 1, decoded_size, offset, depth);
    }
    if count < 2 {
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

#[expect(
    clippy::too_many_lines,
    reason = "the indexed-array state machine stays linear so exact side-stream consumption is auditable"
)]
fn decode_multi_array(
    cursor: &mut Cursor<'_>,
    source_count: usize,
    destination_count: usize,
    decoded_size: usize,
    offset: usize,
    depth: usize,
) -> Result<Vec<u8>, KrakenError> {
    if source_count == 0 {
        let output = decode_array(cursor, Some(decoded_size), depth)?;
        if !cursor.is_empty() {
            return Err(KrakenError::InvalidArray {
                offset: cursor.absolute_offset(),
            });
        }
        return Ok(output);
    }
    let mut sources = Vec::with_capacity(source_count);
    for _ in 0..source_count {
        sources.push(decode_array(cursor, None, depth)?);
    }
    let control = cursor.read_le16()?;
    let combined = control & 0x8000 != 0;
    let indexes = decode_array(cursor, None, depth)?;
    if indexes.len() < destination_count {
        return Err(KrakenError::InvalidArray { offset });
    }
    let (indexes, length_logs) = if combined {
        let mut unpacked_indexes = Vec::with_capacity(indexes.len());
        let mut logs = Vec::with_capacity(indexes.len());
        for value in indexes {
            unpacked_indexes.push(value & 0xf);
            logs.push(value >> 4);
        }
        (unpacked_indexes, logs)
    } else {
        let length_count = indexes
            .len()
            .checked_sub(destination_count)
            .ok_or(KrakenError::InvalidArray { offset })?;
        let logs = decode_array(cursor, Some(length_count), depth)?;
        if logs.iter().any(|&value| value > 16) {
            return Err(KrakenError::InvalidArray { offset });
        }
        (indexes, logs)
    };
    if indexes.last() != Some(&0) {
        return Err(KrakenError::InvalidArray { offset });
    }
    let bit_count = usize::from(control & 0x3fff);
    let bit_offset = cursor.absolute_offset();
    let bit_region = cursor.take(bit_count)?;
    if !cursor.is_empty() {
        return Err(KrakenError::InvalidArray {
            offset: cursor.absolute_offset(),
        });
    }
    let mut bits = PairedBits::new(bit_region, bit_offset);
    let mut lengths = Vec::with_capacity(length_logs.len());
    for (index, &log) in length_logs.iter().enumerate() {
        let value = if index & 1 == 0 {
            bits.read_front(u32::from(log))
        } else {
            bits.read_back(u32::from(log))
        }?;
        lengths.push(usize::try_from(value).map_err(|_| KrakenError::InvalidArray { offset })?);
    }
    bits.require_no_unread_bytes()
        .map_err(|_| KrakenError::InvalidArray { offset })?;

    let mut source_positions = vec![0_usize; source_count];
    let mut output = Vec::with_capacity(decoded_size);
    let mut index_cursor = 0_usize;
    let mut length_cursor = 0_usize;
    for _ in 0..destination_count {
        loop {
            let source = *indexes
                .get(index_cursor)
                .ok_or(KrakenError::InvalidArray { offset })?;
            index_cursor += 1;
            if source == 0 {
                if combined {
                    length_cursor = length_cursor
                        .checked_add(1)
                        .ok_or(KrakenError::InvalidArray { offset })?;
                }
                break;
            }
            let source_index = usize::from(source)
                .checked_sub(1)
                .filter(|&value| value < sources.len())
                .ok_or(KrakenError::InvalidArray { offset })?;
            let length = *lengths
                .get(length_cursor)
                .ok_or(KrakenError::InvalidArray { offset })?;
            length_cursor += 1;
            let start = source_positions[source_index];
            let end = start
                .checked_add(length)
                .filter(|&value| value <= sources[source_index].len())
                .ok_or(KrakenError::InvalidArray { offset })?;
            if output.len().saturating_add(length) > decoded_size {
                return Err(KrakenError::InvalidArray { offset });
            }
            output.extend_from_slice(&sources[source_index][start..end]);
            source_positions[source_index] = end;
        }
    }
    if index_cursor != indexes.len()
        || length_cursor != lengths.len()
        || output.len() != decoded_size
        || source_positions
            .iter()
            .zip(&sources)
            .any(|(&position, source)| position != source.len())
    {
        return Err(KrakenError::InvalidArray { offset });
    }
    Ok(output)
}

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
    let source = history_index(output.len(), offset, output_start, stream_offset)?;
    let mut remaining = count;
    while remaining != 0 {
        let available = output.len() - source;
        let amount = remaining.min(available);
        let end = source
            .checked_add(amount)
            .ok_or(KrakenError::InvalidQuantum {
                offset: stream_offset,
            })?;
        output.extend_from_within(source..end);
        remaining -= amount;
    }
    Ok(())
}

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

struct PairedBits<'a> {
    bytes: &'a [u8],
    front_bits: usize,
    back_bits: usize,
    stream_offset: usize,
}

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

    fn require_no_unread_bytes(&self) -> Result<(), KrakenError> {
        let touched = self
            .front_bits
            .div_ceil(8)
            .checked_add(self.back_bits.div_ceil(8))
            .ok_or(KrakenError::InvalidQuantum {
                offset: self.stream_offset,
            })?;
        if touched < self.bytes.len() || touched > self.bytes.len().saturating_add(1) {
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

    fn read_le16(&mut self) -> Result<u16, KrakenError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
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
        BLOCK_SIZE, CHUNK_SIZE, COMPRESSED_BLOCK_HEADER, Cursor, KrakenError, LsbWriter,
        MAINMENU_RLE_COMMAND_HEADER, PairedBits, STREAMINGWORLD_LITERAL_HEADER,
        canonical_huffman_table, decode, decode_array, decode_lz_payload, decode_quantum,
        decode_rle, decode_scaled_offset_value, encode, encode_array_envelope,
        encode_contiguous_new_huffman_header, encode_extended_length, encode_greedy_lz_chunk,
        execute_lz_commands,
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
    fn generic_repetitions_use_lz_encoding() {
        let seed: Vec<u8> = (0..97_u8)
            .map(|value| value.wrapping_mul(73).wrapping_add(19))
            .collect();
        let payload: Vec<u8> = seed.iter().copied().cycle().take(32 * 1024).collect();
        let encoded = encode(&payload);

        assert_eq!(encoded.get(..2), Some(COMPRESSED_BLOCK_HEADER.as_slice()));
        assert!(encoded.len() < payload.len() / 8);
        assert_eq!(decode(&encoded, payload.len()), Ok(payload));

        let mut state = 0x243f_6a88_u32;
        let large_seed: Vec<u8> = (0..4_093)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[0]
            })
            .collect();
        let payload: Vec<u8> = large_seed.iter().copied().cycle().take(32 * 1024).collect();
        let encoded = encode(&payload);
        assert!(encoded.len() < payload.len() / 2);
        assert_eq!(decode(&encoded, payload.len()), Ok(payload));
    }

    #[test]
    fn greedy_lz_uses_multiple_explicit_offsets() {
        fn bytes(seed: u32, count: usize) -> Vec<u8> {
            let mut state = seed;
            (0..count)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state.to_le_bytes()[0]
                })
                .collect()
        }

        let initial = bytes(0x243f_6a88, 8);
        let first = bytes(0x85a3_08d3, 64);
        let second = bytes(0x1319_8a2e, 80);
        let third = bytes(0x0370_7344, 96);
        let mut payload = initial;
        payload.extend_from_slice(&first);
        payload.extend_from_slice(&second);
        payload.extend_from_slice(&first);
        payload.extend_from_slice(&third);
        payload.extend_from_slice(&second);
        payload.extend_from_slice(&third);

        let lz = encode_greedy_lz_chunk(&payload, true).unwrap();
        let mut cursor = Cursor::new(&lz, 0);
        cursor.advance(8).unwrap();
        decode_array(&mut cursor, None, 0).unwrap();
        decode_array(&mut cursor, None, 0).unwrap();
        assert_eq!(cursor.read_byte(), Ok(128));
        let packed_offsets = decode_array(&mut cursor, None, 0).unwrap();

        assert!(packed_offsets.len() >= 2);
        let mut output = Vec::new();
        assert_eq!(
            decode_lz_payload(&lz, payload.len(), &mut output, 1, 0),
            Ok(())
        );
        assert_eq!(output, payload);
    }

    #[test]
    fn rejects_unread_lz_suffix_bytes() {
        let seed: Vec<u8> = (0..17_u8).map(|value| value.wrapping_mul(31)).collect();
        let payload: Vec<u8> = seed.iter().copied().cycle().take(1_024).collect();
        let lz = encode_greedy_lz_chunk(&payload, true).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            decode_lz_payload(&lz, payload.len(), &mut output, 1, 0),
            Ok(())
        );
        assert_eq!(output, payload);

        let mut malformed = lz;
        malformed.push(0);
        let mut output = Vec::new();
        assert!(decode_lz_payload(&malformed, 1_024, &mut output, 1, 0).is_err());
    }

    #[test]
    fn contiguous_alphabets_use_huffman_encoding() {
        for &alphabet in &[2_u8, 3, 4, 5, 8, 16, 32, 64, 128] {
            for size in [128_usize, CHUNK_SIZE, BLOCK_SIZE + 1_024] {
                let mut state = 0x510e_527f_u32 ^ u32::from(alphabet);
                let payload: Vec<u8> = (0..size)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 17;
                        state ^= state << 5;
                        let base = if alphabet <= 16 { 100 } else { 0 };
                        base + state.to_le_bytes()[0] % alphabet
                    })
                    .collect();
                let encoded = encode(&payload);
                if size >= CHUNK_SIZE {
                    assert!(encoded.len() < payload.len(), "alphabet {alphabet}, {size}");
                }
                assert_eq!(
                    decode(&encoded, payload.len()),
                    Ok(payload),
                    "alphabet {alphabet}, {size}"
                );
            }
        }
    }

    #[test]
    fn sparse_small_alphabets_use_old_huffman_tables() {
        for symbols in [&[1_u8, 200][..], &[0_u8, 7, 255], &[0_u8, 5, 100, 255]] {
            let mut state = 0x1f83_d9ab_u32;
            let payload: Vec<u8> = (0..CHUNK_SIZE)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    symbols[usize::try_from(state).unwrap() % symbols.len()]
                })
                .collect();
            let encoded = encode(&payload);
            assert!(encoded.len() < payload.len());
            assert_eq!(decode(&encoded, payload.len()), Ok(payload));
        }
    }

    #[test]
    fn general_sparse_alphabets_use_frequency_huffman_tables() {
        for symbols in [
            &[0_u8, 17, 63, 129, 200, 255][..],
            &[1_u8, 9, 31, 65, 127, 191, 223, 254],
            &[
                0_u8, 3, 7, 12, 18, 25, 33, 42, 52, 63, 75, 88, 102, 117, 133, 150, 168, 187, 207,
                228, 250,
            ],
        ] {
            let mut payload = Vec::with_capacity(CHUNK_SIZE);
            for index in 0..CHUNK_SIZE {
                let rank = index.trailing_zeros() as usize % symbols.len();
                payload.push(symbols[rank]);
            }
            let encoded = encode(&payload);
            assert!(encoded.len() < payload.len());
            assert_eq!(decode(&encoded, payload.len()), Ok(payload));
        }
    }

    #[test]
    fn encodes_compact_tans_arrays() {
        let mut encoded_cases = 0;
        let mut selected_cases = 0;
        for alphabet in [2_u8, 3, 5, 9] {
            let mut state = 0x6a09_e667_u32 ^ u32::from(alphabet);
            let payload: Vec<u8> = (0..CHUNK_SIZE)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state.to_le_bytes()[0] % alphabet
                })
                .collect();
            if let Some(encoded) = super::encode_tans_array(&payload) {
                encoded_cases += 1;
                let mut cursor = super::Cursor::new(&encoded, 0);
                assert_eq!(
                    super::decode_array(&mut cursor, Some(payload.len()), 0),
                    Ok(payload.clone())
                );
                assert!(cursor.is_empty());
            }
            if super::encode_entropy_array(&payload).is_some_and(|encoded| encoded[0] >> 4 & 7 == 1)
            {
                selected_cases += 1;
            }
        }
        assert!(encoded_cases >= 3);
        assert!(selected_cases >= 1);
    }

    #[test]
    fn length_limited_huffman_fallback_is_complete() {
        let symbols: Vec<u8> = (0..64).collect();
        let mut frequencies = [0_usize; 256];
        let mut first = 1_usize;
        let mut second = 1_usize;
        for &symbol in &symbols {
            frequencies[usize::from(symbol)] = first;
            (first, second) = (second, first.saturating_add(second));
        }
        let lengths = super::huffman_code_lengths(&symbols, &frequencies).unwrap();
        assert!(lengths.iter().all(|&length| length <= 11));
        assert!(super::canonical_huffman_table(&symbols, &lengths).is_some());
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
    fn arbitrary_malformed_streams_fail_without_panicking() {
        let mut state = 0x9e37_79b9_u32;
        for case in 0..2_000_usize {
            let length = case % 129;
            let mut bytes = Vec::with_capacity(length);
            for _ in 0..length {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                bytes.push(state.to_le_bytes()[0]);
            }
            let decoded_size = state as usize % 4_097;
            let _ = decode(&bytes, decoded_size);
        }
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
    fn decodes_real_dense_tans_array() {
        let encoded = decode_hex(
            "1001c4004e142ae484c46b9afe3293fc10141fbb0673488602b35ea00959305bd2\
             aeb37592c9893f8b958a4b65b3a27af652b1f577881104061aae6ae674d141dad1\
             c0b4ab18feea703da9a0212c9c071fd7d8",
        );
        let expected = decode_hex(
            "02030303070102030114241d04030513110c030b020100020201050505050505050502030005050505040c000106020202020202a201020b0a020200010602020506060605050506060600070201020206110611061d020902090215061106110611051f0221020912120215021502210310",
        );
        let mut cursor = Cursor::new(&encoded, 911);

        assert_eq!(decode_array(&mut cursor, Some(114), 0), Ok(expected));
        assert!(cursor.is_empty());

        let mut reserved = encoded.clone();
        reserved[5] |= 0x80;
        assert!(decode_array(&mut Cursor::new(&reserved, 0), Some(114), 0).is_err());
        assert!(decode_array(&mut Cursor::new(&encoded[..20], 0), Some(114), 0).is_err());
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
    fn decodes_contiguous_new_table_five_and_eight_symbol_huffman_arrays() {
        let five = [
            0x20, 0x01, 0xfc, 0x00, 0x2e, // type 2: 46 -> 128
            0xa0, 0x40, 0x4b, 0xeb, 0xa0, // new five-symbol table
            0x0d, 0x00, // first forward stream is thirteen bytes
            0xd4, 0xbd, 0x6c, 0xba, 0xfe, 0x94, 0x2b, 0x84, 0xcb, 0xf6, 0xc6, 0x73, 0x08, 0x3b,
            0x7f, 0x8d, 0x8d, 0x6f, 0xd0, 0xff, 0x69, 0x25, 0xfd, 0x30, 0x1b, 0x0a, 0xae, 0x2f,
            0x58, 0xc2, 0xf3, 0xbb, 0x0f, 0x7c, 0x7f, 0xcb, 0x43, 0xad, 0xcd,
        ];
        let mut expected_five: Vec<u8> = (0..128_usize)
            .map(|index| u8::try_from(index % 5).unwrap())
            .collect();
        deterministic_shuffle(&mut expected_five, 0xa409_3822);
        let mut cursor = Cursor::new(&five, 0);
        assert_eq!(decode_array(&mut cursor, Some(128), 0), Ok(expected_five));
        assert!(cursor.is_empty());

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
    fn decodes_nonuniform_new_five_symbol_huffman_table() {
        let input: Vec<u8> = (0..128)
            .map(|index| u8::try_from(index % 5).unwrap())
            .collect();
        let table = canonical_huffman_table(&[0, 1, 2, 3, 4], &[1, 2, 3, 4, 4]).unwrap();
        let mut forward_zero = LsbWriter::with_capacity(32);
        let mut forward_one = LsbWriter::with_capacity(32);
        let mut backward = LsbWriter::with_capacity(32);
        for (index, &symbol) in input.iter().enumerate() {
            let &(code, length, _) = table
                .entries
                .iter()
                .find(|&&(_, _, entry_symbol)| entry_symbol == symbol)
                .unwrap();
            match index % 3 {
                0 => forward_zero.push(code, length),
                1 => backward.push(code, length),
                _ => forward_one.push(code, length),
            }
        }
        let forward_zero = forward_zero.finish();
        let forward_one = forward_one.finish();
        let mut backward = backward.finish();
        backward.reverse();
        let mut payload = vec![0xa0, 0x40, 0x2f, 0x7d, 0x40];
        payload.extend_from_slice(&u16::try_from(forward_zero.len()).unwrap().to_le_bytes());
        payload.extend_from_slice(&forward_zero);
        payload.extend_from_slice(&forward_one);
        payload.extend_from_slice(&backward);
        let encoded = encode_array_envelope(2, &payload, input.len()).unwrap();
        let mut cursor = Cursor::new(&encoded, 0);

        assert_eq!(decode_array(&mut cursor, Some(input.len()), 0), Ok(input));
        assert!(cursor.is_empty());
    }

    #[test]
    fn recognizes_stock_streamingworld_huffman_table() {
        let (table, consumed) =
            super::decode_huffman_table(STREAMINGWORLD_LITERAL_HEADER, 21).unwrap();
        assert_eq!(consumed, STREAMINGWORLD_LITERAL_HEADER.len());
        assert_eq!(table.entries.len(), 206);
    }

    #[test]
    fn recognizes_stock_mainmenu_rle_command_huffman_table() {
        let (table, consumed) =
            super::decode_huffman_table(MAINMENU_RLE_COMMAND_HEADER, 24).unwrap();
        assert_eq!(consumed, MAINMENU_RLE_COMMAND_HEADER.len());
        assert_eq!(table.entries.len(), 117);
    }

    #[test]
    fn general_new_huffman_grammar_decodes_stock_tables() {
        for (header, expected_symbols) in [
            (STREAMINGWORLD_LITERAL_HEADER, 206),
            (MAINMENU_RLE_COMMAND_HEADER, 117),
        ] {
            let (table, consumed) = super::decode_new_huffman_table(header).unwrap();
            assert_eq!(consumed, header.len());
            assert_eq!(table.entries.len(), expected_symbols);
        }
    }

    #[test]
    fn reproduces_contiguous_new_table_headers() {
        for (alphabet, start, expected) in [
            (5, 0, "a0404beba0"),
            (5, 1, "a0424bf5d0"),
            (5, 7, "a0424b9d7400"),
            (5, 127, "a0424b81d74000"),
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
            (32, 0, "81f0011155ffffff80"),
            (64, 0, "83f0022afffffffffffffff0"),
            (128, 0, "87f0057ffffffffffffffffffffffffffffffe"),
        ] {
            assert_eq!(
                encode_contiguous_new_huffman_header(alphabet, start),
                decode_hex(expected)
            );
        }
    }

    #[test]
    fn decodes_two_partition_huffman_array() {
        let group = [
            0x11, 0x00, // first forward stream is seventeen bytes
            0xb9, 0x83, 0xc4, 0x2b, 0xb7, 0x3d, 0x80, 0x75, 0x94, 0xd1, 0x08, 0xe1, 0xe2, 0x60,
            0x7d, 0xdd, 0x00, 0x61, 0xac, 0x8a, 0x36, 0xe8, 0x67, 0xee, 0x03, 0x9e, 0x59, 0x75,
            0x46, 0x2c, 0xdb, 0xf6, 0x28, 0x00, 0xb2, 0xc5, 0xf5, 0x52, 0x74, 0xed, 0xd4, 0x60,
            0x3b, 0x82, 0x93, 0xce, 0x6e, 0xe1, 0x90, 0x3e,
        ];
        let mut bytes = vec![
            0x40, 0x03, 0xfc, 0x00, 0x71, // type 4: 113 -> 256
            0x90, 0x70, 0x08, 0x95, 0xff, 0xe0, // new eight-symbol table
            0x34, 0x00, 0x00, // first partition is 52 bytes
        ];
        bytes.extend_from_slice(&group);
        bytes.extend_from_slice(&group);
        let mut half: Vec<u8> = (0..128_usize)
            .map(|index| u8::try_from(index % 8).unwrap())
            .collect();
        deterministic_shuffle(&mut half, 0x299f_31d0);
        let expected = [half.as_slice(), half.as_slice()].concat();
        let mut cursor = Cursor::new(&bytes, 0);
        assert_eq!(decode_array(&mut cursor, Some(256), 0), Ok(expected));
        assert!(cursor.is_empty());
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
    fn decodes_zero_byte_compact_rle_literal_command() {
        let mut payload = vec![0];
        payload.extend(1_u8..=15);
        payload.push(0);

        assert_eq!(decode_rle(&payload, 15, 0, 0), Ok((1_u8..=15).collect()));
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
    fn decodes_zero_source_multi_array_passthrough() {
        let bytes = [
            0x50, 0x00, 0x3c, 0x00, 0x07, // type 5: 7 -> 16
            0x80, // multi-array form with zero temporary source arrays
            0x30, 0x00, 0x3c, 0x00, 0x01, b'x', // one requested destination array
        ];
        let mut cursor = Cursor::new(&bytes, 0);
        assert_eq!(decode_array(&mut cursor, Some(16), 0), Ok(vec![b'x'; 16]));
        assert!(cursor.is_empty());
    }

    #[test]
    fn decodes_indexed_multi_array_composition() {
        let prefix = [
            0x82, // indexed composition with two temporary source arrays
            0x00, 0x00, 0x03, b'a', b'b', b'c', // source 1
            0x00, 0x00, 0x03, b'X', b'Y', b'Z', // source 2
        ];
        for (control, indexes, logs) in [
            (
                [0x02, 0x00],
                &[0x00, 0x00, 0x03, 0x01, 0x02, 0x00][..],
                &[0x00, 0x00, 0x02, 0x02, 0x02][..],
            ),
            (
                [0x02, 0x80],
                &[0x00, 0x00, 0x03, 0x21, 0x22, 0x00][..],
                &[][..],
            ),
        ] {
            let mut payload = prefix.to_vec();
            payload.extend_from_slice(&control);
            payload.extend_from_slice(indexes);
            payload.extend_from_slice(logs);
            payload.extend_from_slice(&[0xc0, 0xc0]);

            assert_eq!(
                super::decode_recursive_arrays(&payload, 6, 0, 1),
                Ok(b"abcXYZ".to_vec())
            );
        }
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
