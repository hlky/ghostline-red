//! Reader for the index of a Cyberpunk 2077 `.archive` file.

use crate::{
    binary::ReadLeExt,
    compression::{CompressionError, Kraken},
    cr2w, kraken,
};
use rayon::prelude::*;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};
use thiserror::Error;

/// Little-endian integer representation of `RDAR`.
pub const ARCHIVE_MAGIC: u32 = 1_380_009_042;
const FNV1A64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;
const HEADER_SIZE: u64 = 40;
const FILE_ENTRY_SIZE: u64 = 56;
const FILE_SEGMENT_SIZE: u64 = 16;
const DEPENDENCY_SIZE: u64 = 8;
const EXTENDED_HEADER_SIZE: usize = 0xac;
const LXRS_MAGIC: u32 = 0x4c58_5253;
const COMPRESSION_BATCH_SIZE: usize = 2;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("could not read archive: {0}")]
    Io(#[from] io::Error),
    #[error("not a Cyberpunk archive (magic {actual:#010x})")]
    InvalidMagic { actual: u32 },
    #[error("archive index is outside the file")]
    InvalidIndex,
    #[error("entry {entry} references invalid segment range {start}..{end}")]
    InvalidSegmentRange { entry: usize, start: u32, end: u32 },
    #[error("archive table counts overflow addressable memory")]
    CountOverflow,
    #[error("archive compression failed: {0}")]
    Compression(#[from] CompressionError),
    #[error("archive entry {hash:016x} has no resolvable depot path")]
    UnresolvedPath { hash: u64 },
    #[error("invalid path beneath archive root: {0}")]
    InvalidDepotPath(PathBuf),
    #[error("duplicate depot-path hash {hash:016x}")]
    DuplicateHash { hash: u64 },
    #[error("unsupported or malformed CR2W payload: {0}")]
    Cr2w(#[from] cr2w::Cr2wError),
    #[error("compressed archive segment requires a Kraken library")]
    KrakenRequired,
    #[error("crash-isolated Kraken decompression worker failed")]
    DecompressionWorker,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveHeader {
    pub version: u32,
    pub index_position: u64,
    pub index_size: u32,
    pub debug_position: u64,
    pub debug_size: u32,
    pub file_size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveEntry {
    pub name_hash: u64,
    pub timestamp_filetime: i64,
    pub inline_buffer_segments: u32,
    pub segments_start: u32,
    pub segments_end: u32,
    pub dependencies_start: u32,
    pub dependencies_end: u32,
    pub sha1: String,
    pub compressed_size: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveIndex {
    pub header: ArchiveHeader,
    pub file_table_offset: u32,
    pub file_table_size: u32,
    pub crc: u64,
    pub entries: Vec<ArchiveEntry>,
    pub segments: Vec<ArchiveSegment>,
    pub segment_count: u32,
    pub dependency_count: u32,
    pub custom_paths: Vec<String>,
}

/// Calculates `REDengine`'s normalized depot-path hash.
#[must_use]
pub fn depot_path_hash(path: &str) -> u64 {
    let normalized = path
        .trim_matches(['\'', '"', '/', '\\', ' ', '\n', '\r'])
        .replace('/', "\\")
        .to_lowercase();
    let mut hash = FNV1A64_OFFSET;
    let mut previous_was_separator = false;
    for byte in normalized.bytes() {
        let is_separator = byte == b'\\';
        if is_separator && previous_was_separator {
            continue;
        }
        hash = (hash ^ u64::from(byte)).wrapping_mul(FNV1A64_PRIME);
        previous_was_separator = is_separator;
    }
    hash
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ArchiveSegment {
    pub offset: u64,
    pub compressed_size: u32,
    pub size: u32,
}

#[derive(Debug)]
struct RawEntry {
    name_hash: u64,
    timestamp_filetime: i64,
    inline_buffer_segments: u32,
    segments_start: u32,
    segments_end: u32,
    dependencies_start: u32,
    dependencies_end: u32,
    sha1: [u8; 20],
}

/// Reads and validates the header and index tables without loading payloads.
///
/// # Errors
///
/// Returns [`ArchiveError`] when the file cannot be read or its header, table
/// sizes, or segment ranges are invalid.
#[expect(
    clippy::too_many_lines,
    reason = "keeping the sequential on-disk layout visible makes format auditing safer"
)]
pub fn read_archive(path: &Path) -> Result<ArchiveIndex, ArchiveError> {
    let file = File::open(path)?;
    let actual_len = file.metadata()?.len();
    let mut reader = BufReader::new(file);

    let magic = reader.read_u32_le()?;
    if magic != ARCHIVE_MAGIC {
        return Err(ArchiveError::InvalidMagic { actual: magic });
    }

    let header = ArchiveHeader {
        version: reader.read_u32_le()?,
        index_position: reader.read_u64_le()?,
        index_size: reader.read_u32_le()?,
        debug_position: reader.read_u64_le()?,
        debug_size: reader.read_u32_le()?,
        file_size: reader.read_u64_le()?,
    };
    let custom_data_length = reader.read_u32_le()?;

    let index_end = header
        .index_position
        .checked_add(u64::from(header.index_size))
        .ok_or(ArchiveError::InvalidIndex)?;
    if header.index_position < HEADER_SIZE || index_end > actual_len {
        return Err(ArchiveError::InvalidIndex);
    }
    reader.seek(SeekFrom::Start(header.index_position))?;

    let file_table_offset = reader.read_u32_le()?;
    let file_table_size = reader.read_u32_le()?;
    let crc = reader.read_u64_le()?;
    let entry_count = reader.read_u32_le()?;
    let segment_count = reader.read_u32_le()?;
    let dependency_count = reader.read_u32_le()?;

    validate_table_size(
        entry_count,
        segment_count,
        dependency_count,
        header.index_size,
    )?;

    let mut raw_entries =
        Vec::with_capacity(usize::try_from(entry_count).map_err(|_| ArchiveError::CountOverflow)?);
    for _ in 0..entry_count {
        let name_hash = reader.read_u64_le()?;
        let timestamp_filetime = reader.read_i64_le()?;
        let inline_buffer_segments = reader.read_u32_le()?;
        let segments_start = reader.read_u32_le()?;
        let segments_end = reader.read_u32_le()?;
        let dependencies_start = reader.read_u32_le()?;
        let dependencies_end = reader.read_u32_le()?;
        let mut sha1 = [0_u8; 20];
        reader.read_exact(&mut sha1)?;
        raw_entries.push(RawEntry {
            name_hash,
            timestamp_filetime,
            inline_buffer_segments,
            segments_start,
            segments_end,
            dependencies_start,
            dependencies_end,
            sha1,
        });
    }

    let mut segments = Vec::with_capacity(
        usize::try_from(segment_count).map_err(|_| ArchiveError::CountOverflow)?,
    );
    for _ in 0..segment_count {
        segments.push(ArchiveSegment {
            offset: reader.read_u64_le()?,
            compressed_size: reader.read_u32_le()?,
            size: reader.read_u32_le()?,
        });
    }

    let mut entries = Vec::with_capacity(raw_entries.len());
    for (entry_index, raw) in raw_entries.into_iter().enumerate() {
        let start = usize::try_from(raw.segments_start).map_err(|_| ArchiveError::CountOverflow)?;
        let end = usize::try_from(raw.segments_end).map_err(|_| ArchiveError::CountOverflow)?;
        let selected = segments
            .get(start..end)
            .ok_or(ArchiveError::InvalidSegmentRange {
                entry: entry_index,
                start: raw.segments_start,
                end: raw.segments_end,
            })?;
        let compressed_size = selected
            .iter()
            .map(|segment| u64::from(segment.compressed_size))
            .sum();
        let size = selected.iter().map(|segment| u64::from(segment.size)).sum();
        let _first_offset = selected.first().map(|segment| segment.offset);

        entries.push(ArchiveEntry {
            name_hash: raw.name_hash,
            timestamp_filetime: raw.timestamp_filetime,
            inline_buffer_segments: raw.inline_buffer_segments,
            segments_start: raw.segments_start,
            segments_end: raw.segments_end,
            dependencies_start: raw.dependencies_start,
            dependencies_end: raw.dependencies_end,
            sha1: encode_hex(&raw.sha1),
            compressed_size,
            size,
        });
    }

    Ok(ArchiveIndex {
        header,
        file_table_offset,
        file_table_size,
        crc,
        entries,
        segments,
        segment_count,
        dependency_count,
        custom_paths: read_custom_paths(path, custom_data_length)?,
    })
}

/// Packs a loose depot tree into a Cyberpunk archive.
///
/// # Errors
///
/// Returns [`ArchiveError`] for invalid paths, duplicate hashes, malformed
/// CR2W files, compression failures, or output I/O failures.
pub fn pack(source: &Path, output: &Path, kraken_path: &OsStr) -> Result<(), ArchiveError> {
    let mut files = collect_files(source)?;
    files.sort_by_key(|(hash, _, _)| *hash);
    for pair in files.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(ArchiveError::DuplicateHash { hash: pair[0].0 });
        }
    }
    let compressed_chunks: Result<Vec<Vec<Option<Vec<u8>>>>, ArchiveError> = files
        .par_chunks(COMPRESSION_BATCH_SIZE)
        .map(|chunk| {
            let mut positions = Vec::new();
            let mut payloads = Vec::new();
            for (position, (_, depot_path, path)) in chunk.iter().enumerate() {
                let bytes = fs::read(path)?;
                let payload = main_payload(&bytes)?;
                if !should_store_uncompressed(depot_path) && payload.len() >= 256 {
                    positions.push(position);
                    payloads.push(payload.to_vec());
                }
            }
            let compressed = compress_batch_isolated(&payloads, kraken_path);
            let mut result: Vec<Option<Vec<u8>>> = (0..chunk.len()).map(|_| None).collect();
            for (position, payload) in positions.into_iter().zip(compressed) {
                result[position] = payload;
            }
            Ok(result)
        })
        .collect();
    let compressed_payloads = compressed_chunks?.into_iter().flatten();

    let mut writer = BufWriter::new(File::create(output)?);
    writer.write_all(&[0_u8; EXTENDED_HEADER_SIZE])?;
    let custom_paths: Vec<String> = files.iter().map(|(_, path, _)| path.clone()).collect();
    let custom_data_length = write_lxrs(&mut writer, &custom_paths)?;

    let mut entries = Vec::with_capacity(files.len());
    let mut segments = Vec::new();
    for ((hash, depot_path, path), compressed) in files.into_iter().zip(compressed_payloads) {
        let bytes = fs::read(path)?;
        let segment_start =
            u32::try_from(segments.len()).map_err(|_| ArchiveError::CountOverflow)?;
        let inline_buffers = if bytes.starts_with(b"CR2W") {
            write_cr2w_segments(&mut writer, &bytes, compressed, &mut segments)?
        } else {
            align_if_needed(&mut writer, &depot_path)?;
            write_payload_segment(&mut writer, &bytes, compressed, &mut segments)?;
            0
        };
        let segment_end = u32::try_from(segments.len()).map_err(|_| ArchiveError::CountOverflow)?;
        entries.push(RawEntry {
            name_hash: hash,
            timestamp_filetime: 0,
            inline_buffer_segments: inline_buffers,
            segments_start: segment_start,
            segments_end: segment_end,
            dependencies_start: 0,
            dependencies_end: 0,
            sha1: Sha1::digest(&bytes).into(),
        });
    }

    pad_to_page(&mut writer)?;
    let index_position = writer.stream_position()?;
    let index = build_index_bytes(&entries, &segments)?;
    writer.write_all(&index)?;
    let index_size = u32::try_from(index.len()).map_err(|_| ArchiveError::CountOverflow)?;
    pad_to_page(&mut writer)?;
    let file_size = writer.stream_position()?;
    writer.seek(SeekFrom::Start(0))?;
    write_archive_header(
        &mut writer,
        index_position,
        index_size,
        file_size,
        custom_data_length,
    )?;
    writer.flush()?;
    Ok(())
}

/// Extracts an archive using its embedded LXRS depot paths.
///
/// # Errors
///
/// Returns [`ArchiveError`] for unresolved or unsafe paths, malformed
/// segments, decompression failures, or output I/O failures.
pub fn extract(
    archive_path: &Path,
    output: &Path,
    kraken_path: &OsStr,
    paths_root: Option<&Path>,
) -> Result<(), ArchiveError> {
    let index = read_archive(archive_path)?;
    let mut custom_paths = if index.custom_paths.is_empty() {
        read_compressed_custom_paths(archive_path, kraken_path)?
    } else {
        index.custom_paths.clone()
    };
    if let Some(root) = paths_root {
        custom_paths.extend(
            collect_files(root)?
                .into_iter()
                .map(|(_, depot_path, _)| depot_path),
        );
    }
    let paths: HashMap<u64, &str> = custom_paths
        .iter()
        .map(|path| (depot_path_hash(path), path.as_str()))
        .collect();
    let mut archive = BufReader::new(File::open(archive_path)?);

    for (entry_index, entry) in index.entries.iter().enumerate() {
        let depot_path = paths
            .get(&entry.name_hash)
            .ok_or(ArchiveError::UnresolvedPath {
                hash: entry.name_hash,
            })?;
        let target = output.join(safe_depot_path(depot_path)?);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut target_file = BufWriter::new(File::create(target)?);
        let start =
            usize::try_from(entry.segments_start).map_err(|_| ArchiveError::CountOverflow)?;
        let end = usize::try_from(entry.segments_end).map_err(|_| ArchiveError::CountOverflow)?;
        let selected = index
            .segments
            .get(start..end)
            .ok_or(ArchiveError::InvalidSegmentRange {
                entry: entry_index,
                start: entry.segments_start,
                end: entry.segments_end,
            })?;
        for (segment_index, segment) in selected.iter().enumerate() {
            target_file.write_all(&read_segment(
                &mut archive,
                *segment,
                kraken_path,
                segment_index == 0,
            )?)?;
        }
        target_file.flush()?;
    }
    Ok(())
}

fn collect_files(source: &Path) -> Result<Vec<(u64, String, PathBuf)>, ArchiveError> {
    let mut result = Vec::new();
    let mut pending = vec![source.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for item in fs::read_dir(&directory)? {
            let path = item?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let Some(extension) = path.extension().and_then(OsStr::to_str) else {
                continue;
            };
            if matches!(
                extension.to_ascii_lowercase().as_str(),
                "tmp" | "md" | "txt"
            ) {
                continue;
            }
            let relative = path
                .strip_prefix(source)
                .map_err(|_| ArchiveError::InvalidDepotPath(path.clone()))?;
            let depot_path = relative.to_string_lossy().replace('/', "\\");
            result.push((depot_path_hash(&depot_path), depot_path, path));
        }
    }
    Ok(result)
}

fn write_cr2w_segments(
    writer: &mut (impl Write + Seek),
    bytes: &[u8],
    compressed: Option<Vec<u8>>,
    segments: &mut Vec<ArchiveSegment>,
) -> Result<u32, ArchiveError> {
    let objects_end =
        usize::try_from(read_u32_at(bytes, 24)?).map_err(|_| ArchiveError::CountOverflow)?;
    let table_offset = 40 + 5 * 12;
    let buffer_table_offset = usize::try_from(read_u32_at(bytes, table_offset)?)
        .map_err(|_| ArchiveError::CountOverflow)?;
    let buffer_count = read_u32_at(bytes, table_offset + 4)?;
    let main = bytes.get(..objects_end).ok_or(ArchiveError::InvalidIndex)?;
    write_payload_segment(writer, main, compressed, segments)?;
    for index in 0..buffer_count {
        let info = buffer_table_offset
            .checked_add(usize::try_from(index).map_err(|_| ArchiveError::CountOverflow)? * 24)
            .ok_or(ArchiveError::CountOverflow)?;
        let offset = usize::try_from(read_u32_at(bytes, info + 8)?)
            .map_err(|_| ArchiveError::CountOverflow)?;
        let disk_size = read_u32_at(bytes, info + 12)?;
        let memory_size = read_u32_at(bytes, info + 16)?;
        let end = offset
            .checked_add(usize::try_from(disk_size).map_err(|_| ArchiveError::CountOverflow)?)
            .ok_or(ArchiveError::CountOverflow)?;
        let buffer = bytes.get(offset..end).ok_or(ArchiveError::InvalidIndex)?;
        let archive_offset = writer.stream_position()?;
        writer.write_all(buffer)?;
        segments.push(ArchiveSegment {
            offset: archive_offset,
            compressed_size: disk_size,
            size: memory_size,
        });
    }
    Ok(buffer_count.saturating_sub(1))
}

fn write_payload_segment(
    writer: &mut (impl Write + Seek),
    bytes: &[u8],
    compressed: Option<Vec<u8>>,
    segments: &mut Vec<ArchiveSegment>,
) -> Result<(), ArchiveError> {
    let offset = writer.stream_position()?;
    let size = u32::try_from(bytes.len()).map_err(|_| ArchiveError::CountOverflow)?;
    let payload = if let Some(compressed) = compressed.filter(|data| data.len() + 8 < bytes.len()) {
        let mut kark = Vec::with_capacity(compressed.len() + 8);
        kark.extend_from_slice(b"KARK");
        kark.extend_from_slice(&size.to_le_bytes());
        kark.extend_from_slice(&compressed);
        kark
    } else {
        bytes.to_vec()
    };
    writer.write_all(&payload)?;
    segments.push(ArchiveSegment {
        offset,
        compressed_size: u32::try_from(payload.len()).map_err(|_| ArchiveError::CountOverflow)?,
        size,
    });
    Ok(())
}

fn main_payload(bytes: &[u8]) -> Result<&[u8], ArchiveError> {
    if !bytes.starts_with(b"CR2W") {
        return Ok(bytes);
    }
    let objects_end =
        usize::try_from(read_u32_at(bytes, 24)?).map_err(|_| ArchiveError::CountOverflow)?;
    bytes.get(..objects_end).ok_or(ArchiveError::InvalidIndex)
}

fn should_store_uncompressed(depot_path: &str) -> bool {
    let lower = depot_path.to_ascii_lowercase();
    [
        ".bk2",
        ".bnk",
        ".opusinfo",
        ".wem",
        ".bin",
        ".dat",
        ".opuspak",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
        || lower.ends_with("soundbanks.json")
}

/// Compresses a framed batch inside the current process.
///
/// This exists for the hidden crash-isolated worker command. Normal packing
/// must use the worker rather than calling this function directly.
///
/// # Errors
///
/// Returns [`ArchiveError`] when the frame is invalid or Kraken cannot load,
/// compress, or validate every payload.
pub fn compress_worker_batch(
    wire_input: &[u8],
    kraken_path: &OsStr,
) -> Result<Vec<u8>, ArchiveError> {
    let mut cursor = 0_usize;
    let count = usize::try_from(read_wire_u32(wire_input, &mut cursor)?)
        .map_err(|_| ArchiveError::CountOverflow)?;
    if count > COMPRESSION_BATCH_SIZE {
        return Err(ArchiveError::InvalidIndex);
    }
    let mut inputs = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::try_from(read_wire_u64(wire_input, &mut cursor)?)
            .map_err(|_| ArchiveError::CountOverflow)?;
        let end = cursor
            .checked_add(length)
            .ok_or(ArchiveError::CountOverflow)?;
        inputs.push(
            wire_input
                .get(cursor..end)
                .ok_or(ArchiveError::InvalidIndex)?,
        );
        cursor = end;
    }
    if cursor != wire_input.len() {
        return Err(ArchiveError::InvalidIndex);
    }
    let kraken = Kraken::load(kraken_path)?;
    let mut output = Vec::new();
    write_u32(
        &mut output,
        u32::try_from(count).map_err(|_| ArchiveError::CountOverflow)?,
    )?;
    for input in inputs {
        let compressed = kraken.compress_validated(input)?;
        write_u64(
            &mut output,
            u64::try_from(compressed.len()).map_err(|_| ArchiveError::CountOverflow)?,
        )?;
        output.extend_from_slice(&compressed);
    }
    Ok(output)
}

/// Decompresses one framed payload inside the current process.
///
/// This is only called by the hidden worker command so a faulty native codec
/// cannot corrupt the long-lived CLI process.
///
/// # Errors
///
/// Returns [`ArchiveError`] for malformed framing, codec loading failures, or
/// invalid decompression output.
pub fn decompress_worker(wire_input: &[u8], kraken_path: &OsStr) -> Result<Vec<u8>, ArchiveError> {
    let mut cursor = 0_usize;
    let expected_size = usize::try_from(read_wire_u64(wire_input, &mut cursor)?)
        .map_err(|_| ArchiveError::CountOverflow)?;
    let compressed_size = usize::try_from(read_wire_u64(wire_input, &mut cursor)?)
        .map_err(|_| ArchiveError::CountOverflow)?;
    let end = cursor
        .checked_add(compressed_size)
        .ok_or(ArchiveError::CountOverflow)?;
    let compressed = wire_input
        .get(cursor..end)
        .filter(|_| end == wire_input.len())
        .ok_or(ArchiveError::InvalidIndex)?;
    Kraken::load(kraken_path)?
        .decompress(compressed, expected_size)
        .map_err(ArchiveError::from)
}

/// Decompresses a raw Kraken stream in a crash-isolated worker.
///
/// # Errors
///
/// Returns [`ArchiveError`] if the worker cannot start, crashes, rejects the
/// stream, or produces a size other than `expected_size`.
pub fn decompress_payload_isolated(
    input: &[u8],
    expected_size: usize,
    kraken_path: &OsStr,
) -> Result<Vec<u8>, ArchiveError> {
    if let Ok(output) = kraken::decode(input, expected_size) {
        return Ok(output);
    }
    let executable = std::env::current_exe()?;
    let mut child = Command::new(executable)
        .arg("--kraken")
        .arg(kraken_path)
        .arg("kraken-decompress-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut wire = Vec::with_capacity(input.len().saturating_add(16));
    write_u64(
        &mut wire,
        u64::try_from(expected_size).map_err(|_| ArchiveError::CountOverflow)?,
    )?;
    write_u64(
        &mut wire,
        u64::try_from(input.len()).map_err(|_| ArchiveError::CountOverflow)?,
    )?;
    wire.extend_from_slice(input);
    child
        .stdin
        .take()
        .ok_or(ArchiveError::DecompressionWorker)?
        .write_all(&wire)?;
    let output = child.wait_with_output()?;
    if !output.status.success() || output.stdout.len() != expected_size {
        return Err(ArchiveError::DecompressionWorker);
    }
    Ok(output.stdout)
}

fn compress_batch_isolated(inputs: &[Vec<u8>], kraken_path: &OsStr) -> Vec<Option<Vec<u8>>> {
    if inputs.is_empty() {
        return Vec::new();
    }
    let fallback = || {
        inputs
            .iter()
            .map(|input| {
                let encoded = kraken::encode(input);
                (encoded.len() < input.len()).then_some(encoded)
            })
            .collect()
    };
    let Ok(executable) = std::env::current_exe() else {
        return fallback();
    };
    let child = Command::new(executable)
        .arg("--kraken")
        .arg(kraken_path)
        .arg("kraken-compress-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return fallback();
    };
    let mut wire = Vec::new();
    if write_u32(&mut wire, u32::try_from(inputs.len()).unwrap_or(u32::MAX)).is_err() {
        return fallback();
    }
    for input in inputs {
        if write_u64(&mut wire, u64::try_from(input.len()).unwrap_or(u64::MAX)).is_err() {
            return fallback();
        }
        wire.extend_from_slice(input);
    }
    let Some(mut stdin) = child.stdin.take() else {
        return fallback();
    };
    if stdin.write_all(&wire).is_err() {
        return fallback();
    }
    drop(stdin);
    let Ok(output) = child.wait_with_output() else {
        return fallback();
    };
    if !output.status.success() {
        return fallback();
    }
    parse_compression_batch(&output.stdout, inputs.len()).unwrap_or_else(fallback)
}

fn parse_compression_batch(bytes: &[u8], expected: usize) -> Option<Vec<Option<Vec<u8>>>> {
    let mut cursor = 0_usize;
    let count = usize::try_from(read_wire_u32(bytes, &mut cursor).ok()?).ok()?;
    if count != expected {
        return None;
    }
    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        let length = usize::try_from(read_wire_u64(bytes, &mut cursor).ok()?).ok()?;
        let end = cursor.checked_add(length)?;
        result.push(Some(bytes.get(cursor..end)?.to_vec()));
        cursor = end;
    }
    (cursor == bytes.len()).then_some(result)
}

fn read_wire_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, ArchiveError> {
    let value = read_u32_at(bytes, *cursor)?;
    *cursor += 4;
    Ok(value)
}

fn read_wire_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, ArchiveError> {
    let data: [u8; 8] = bytes
        .get(*cursor..*cursor + 8)
        .ok_or(ArchiveError::InvalidIndex)?
        .try_into()
        .map_err(|_| ArchiveError::InvalidIndex)?;
    *cursor += 8;
    Ok(u64::from_le_bytes(data))
}

fn read_segment(
    reader: &mut (impl Read + Seek),
    segment: ArchiveSegment,
    kraken_path: &OsStr,
    decompress: bool,
) -> Result<Vec<u8>, ArchiveError> {
    reader.seek(SeekFrom::Start(segment.offset))?;
    let mut payload = vec![
        0_u8;
        usize::try_from(segment.compressed_size)
            .map_err(|_| ArchiveError::CountOverflow)?
    ];
    reader.read_exact(&mut payload)?;
    if !decompress || segment.compressed_size == segment.size {
        return Ok(payload);
    }
    if payload.get(..4) != Some(b"KARK") {
        return Ok(payload);
    }
    let declared = read_u32_at(&payload, 4)?;
    decompress_payload_isolated(
        &payload[8..],
        usize::try_from(declared).map_err(|_| ArchiveError::CountOverflow)?,
        kraken_path,
    )
}

fn write_lxrs(writer: &mut impl Write, custom_paths: &[String]) -> Result<u32, ArchiveError> {
    let mut encoded = Vec::new();
    for path in custom_paths {
        encoded.extend_from_slice(path.as_bytes());
        encoded.push(0);
    }
    write_u32(writer, LXRS_MAGIC)?;
    write_u32(writer, 1)?;
    write_u32(
        writer,
        u32::try_from(encoded.len()).map_err(|_| ArchiveError::CountOverflow)?,
    )?;
    write_u32(
        writer,
        u32::try_from(encoded.len()).map_err(|_| ArchiveError::CountOverflow)?,
    )?;
    write_u32(
        writer,
        u32::try_from(custom_paths.len()).map_err(|_| ArchiveError::CountOverflow)?,
    )?;
    writer.write_all(&encoded)?;
    u32::try_from(encoded.len() + 20).map_err(|_| ArchiveError::CountOverflow)
}

fn read_custom_paths(path: &Path, length: u32) -> Result<Vec<String>, ArchiveError> {
    if length == 0 {
        return Ok(Vec::new());
    }
    let mut reader = BufReader::new(File::open(path)?);
    reader.seek(SeekFrom::Start(
        u64::try_from(EXTENDED_HEADER_SIZE).map_err(|_| ArchiveError::CountOverflow)?,
    ))?;
    if reader.read_u32_le()? != LXRS_MAGIC || reader.read_u32_le()? != 1 {
        return Err(ArchiveError::InvalidIndex);
    }
    let size = reader.read_u32_le()?;
    let compressed_size = reader.read_u32_le()?;
    let count = reader.read_u32_le()?;
    if size != compressed_size {
        // WolvenKit normally compresses LXRS. Extraction of those archives is
        // enabled later alongside global hash-database support; archives
        // produced by this tool deliberately store this tiny table verbatim.
        return Ok(Vec::new());
    }
    let mut bytes = vec![0_u8; usize::try_from(size).map_err(|_| ArchiveError::CountOverflow)?];
    reader.read_exact(&mut bytes)?;
    let mut result =
        Vec::with_capacity(usize::try_from(count).map_err(|_| ArchiveError::CountOverflow)?);
    let mut start = 0;
    for _ in 0..count {
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| start + offset)
            .ok_or(ArchiveError::InvalidIndex)?;
        result.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        start = end + 1;
    }
    Ok(result)
}

fn read_compressed_custom_paths(
    path: &Path,
    kraken_path: &OsStr,
) -> Result<Vec<String>, ArchiveError> {
    let mut reader = BufReader::new(File::open(path)?);
    reader.seek(SeekFrom::Start(
        u64::try_from(EXTENDED_HEADER_SIZE).map_err(|_| ArchiveError::CountOverflow)?,
    ))?;
    if reader.read_u32_le()? != LXRS_MAGIC || reader.read_u32_le()? != 1 {
        return Err(ArchiveError::InvalidIndex);
    }
    let size = reader.read_u32_le()?;
    let compressed_size = reader.read_u32_le()?;
    let count = reader.read_u32_le()?;
    if size == compressed_size {
        return read_custom_paths(path, size.saturating_add(20));
    }
    let mut compressed =
        vec![0_u8; usize::try_from(compressed_size).map_err(|_| ArchiveError::CountOverflow)?];
    reader.read_exact(&mut compressed)?;
    let bytes = decompress_payload_isolated(
        &compressed,
        usize::try_from(size).map_err(|_| ArchiveError::CountOverflow)?,
        kraken_path,
    )?;
    decode_custom_paths(&bytes, count)
}

/// Reads embedded LXRS depot paths, including `WolvenKit`'s Kraken-compressed form.
///
/// # Errors
///
/// Returns [`ArchiveError`] for malformed metadata, I/O failures, or native
/// decompression worker failure.
pub fn read_archive_paths(path: &Path, kraken_path: &OsStr) -> Result<Vec<String>, ArchiveError> {
    let index = read_archive(path)?;
    if index.custom_paths.is_empty() {
        read_compressed_custom_paths(path, kraken_path)
    } else {
        Ok(index.custom_paths)
    }
}

fn decode_custom_paths(bytes: &[u8], count: u32) -> Result<Vec<String>, ArchiveError> {
    let mut result =
        Vec::with_capacity(usize::try_from(count).map_err(|_| ArchiveError::CountOverflow)?);
    let mut start = 0;
    for _ in 0..count {
        let end = bytes
            .get(start..)
            .and_then(|remaining| remaining.iter().position(|byte| *byte == 0))
            .map(|offset| start + offset)
            .ok_or(ArchiveError::InvalidIndex)?;
        result.push(String::from_utf8_lossy(&bytes[start..end]).into_owned());
        start = end + 1;
    }
    Ok(result)
}

fn build_index_bytes(
    entries: &[RawEntry],
    segments: &[ArchiveSegment],
) -> Result<Vec<u8>, ArchiveError> {
    let mut body = Vec::new();
    write_u32(
        &mut body,
        u32::try_from(entries.len()).map_err(|_| ArchiveError::CountOverflow)?,
    )?;
    write_u32(
        &mut body,
        u32::try_from(segments.len()).map_err(|_| ArchiveError::CountOverflow)?,
    )?;
    write_u32(&mut body, 0)?;
    for entry in entries {
        write_u64(&mut body, entry.name_hash)?;
        write_i64(&mut body, entry.timestamp_filetime)?;
        write_u32(&mut body, entry.inline_buffer_segments)?;
        write_u32(&mut body, entry.segments_start)?;
        write_u32(&mut body, entry.segments_end)?;
        write_u32(&mut body, entry.dependencies_start)?;
        write_u32(&mut body, entry.dependencies_end)?;
        body.write_all(&entry.sha1)?;
    }
    for segment in segments {
        write_u64(&mut body, segment.offset)?;
        write_u32(&mut body, segment.compressed_size)?;
        write_u32(&mut body, segment.size)?;
    }
    let mut result = Vec::new();
    write_u32(&mut result, 8)?;
    write_u32(
        &mut result,
        u32::try_from(body.len() + 8).map_err(|_| ArchiveError::CountOverflow)?,
    )?;
    write_u64(&mut result, crc64(&body))?;
    result.extend_from_slice(&body);
    Ok(result)
}

fn crc64(bytes: &[u8]) -> u64 {
    const POLYNOMIAL: u64 = 0xc96c_5795_d787_0f42;
    let mut table = [0_u64; 256];
    for (index, slot) in table.iter_mut().enumerate() {
        let mut value = index as u64;
        for _ in 0..8 {
            value = if value & 1 == 1 {
                (value >> 1) ^ POLYNOMIAL
            } else {
                value >> 1
            };
        }
        *slot = value;
    }
    let mut crc = u64::MAX;
    for byte in bytes {
        let low = u8::try_from(crc & 0xff).expect("masked CRC byte always fits");
        crc = (crc >> 8) ^ table[usize::from(low ^ byte)];
    }
    !crc
}

fn write_archive_header(
    writer: &mut impl Write,
    index_position: u64,
    index_size: u32,
    file_size: u64,
    custom_data_length: u32,
) -> Result<(), ArchiveError> {
    write_u32(writer, ARCHIVE_MAGIC)?;
    write_u32(writer, 12)?;
    write_u64(writer, index_position)?;
    write_u32(writer, index_size)?;
    write_u64(writer, 0)?;
    write_u32(writer, 0)?;
    write_u64(writer, file_size)?;
    write_u32(writer, custom_data_length)?;
    Ok(())
}

fn align_if_needed(writer: &mut (impl Write + Seek), depot_path: &str) -> Result<(), ArchiveError> {
    let lower = depot_path.to_ascii_lowercase();
    if [".bk2", ".bnk", ".opusinfo", ".wem", ".bin"]
        .iter()
        .any(|extension| lower.ends_with(extension))
        || lower.ends_with("soundbanks.json")
    {
        pad_to_page(writer)?;
    }
    Ok(())
}

fn pad_to_page(writer: &mut (impl Write + Seek)) -> Result<(), ArchiveError> {
    let position = writer.stream_position()?;
    let padding = (4096 - position % 4096) % 4096;
    let padding = usize::try_from(padding).map_err(|_| ArchiveError::CountOverflow)?;
    writer.write_all(&vec![0_u8; padding])?;
    Ok(())
}

fn safe_depot_path(path: &str) -> Result<PathBuf, ArchiveError> {
    let candidate = PathBuf::from(path.replace('\\', "/"));
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ArchiveError::InvalidDepotPath(candidate));
    }
    Ok(candidate)
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, ArchiveError> {
    let data: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(ArchiveError::InvalidIndex)?
        .try_into()
        .map_err(|_| ArchiveError::InvalidIndex)?;
    Ok(u32::from_le_bytes(data))
}

fn write_u32(writer: &mut impl Write, value: u32) -> Result<(), ArchiveError> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn write_u64(writer: &mut impl Write, value: u64) -> Result<(), ArchiveError> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn write_i64(writer: &mut impl Write, value: i64) -> Result<(), ArchiveError> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn validate_table_size(
    entries: u32,
    segments: u32,
    dependencies: u32,
    index_size: u32,
) -> Result<(), ArchiveError> {
    let required = 28_u64
        .checked_add(u64::from(entries) * FILE_ENTRY_SIZE)
        .and_then(|value| value.checked_add(u64::from(segments) * FILE_SEGMENT_SIZE))
        .and_then(|value| value.checked_add(u64::from(dependencies) * DEPENDENCY_SIZE))
        .ok_or(ArchiveError::CountOverflow)?;
    if required > u64::from(index_size) {
        return Err(ArchiveError::InvalidIndex);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    #[test]
    fn invalid_magic_should_be_rejected() {
        let mut path = tempfile::NamedTempFile::new().unwrap();
        path.write_all(b"NOPE").unwrap();
        let error = read_archive(path.path()).unwrap_err();
        assert!(matches!(error, ArchiveError::InvalidMagic { .. }));
    }

    #[test]
    fn little_endian_reader_should_decode_values() {
        let mut input = Cursor::new([0x78, 0x56, 0x34, 0x12]);
        assert_eq!(input.read_u32_le().unwrap(), 0x1234_5678);
    }

    #[test]
    fn depot_hash_should_normalize_case_and_slashes() {
        let windows = depot_path_hash(r"mod\ghostline\test.ent");
        let portable = depot_path_hash("/MOD/Ghostline//test.ent/");
        assert_eq!(windows, portable);
    }
}
