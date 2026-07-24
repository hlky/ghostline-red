//! Structural inspection for CR2W files.

use crate::binary::ReadLeExt;
use serde::Serialize;
use std::{
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
    path::Path,
};
use thiserror::Error;

pub const CR2W_MAGIC: [u8; 4] = *b"CR2W";
pub const TABLE_COUNT: usize = 10;

#[derive(Debug, Error)]
pub enum Cr2wError {
    #[error("could not read CR2W file: {0}")]
    Io(#[from] io::Error),
    #[error("not a CR2W file (magic {actual:?})")]
    InvalidMagic { actual: [u8; 4] },
    #[error("CR2W table {table} is outside the file")]
    InvalidTable { table: usize },
    #[error("CR2W string table contains invalid UTF-8 at offset {offset}")]
    InvalidString { offset: u32 },
    #[error("CR2W name {name} references missing string offset {offset}")]
    MissingNameString { name: usize, offset: u32 },
    #[error("CR2W import {import} references missing string or name")]
    InvalidImport { import: usize },
}

#[derive(Debug, Clone, Serialize)]
pub struct Cr2wInspection {
    pub header: Cr2wHeader,
    pub strings: Vec<Cr2wString>,
    pub names: Vec<Cr2wName>,
    pub imports: Vec<Cr2wImport>,
    pub exports: Vec<Cr2wExport>,
    pub buffers: Vec<Cr2wBuffer>,
    pub embedded: Vec<Cr2wEmbedded>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cr2wHeader {
    pub version: u32,
    pub flags: u32,
    pub timestamp: u64,
    pub build_version: u32,
    pub objects_end: u32,
    pub buffers_end: u32,
    pub crc32: u32,
    pub chunk_count: u32,
    pub tables: Vec<Cr2wTable>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cr2wTable {
    pub offset: u32,
    pub item_count: u32,
    pub crc32: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cr2wString {
    pub offset: u32,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cr2wName {
    pub value: String,
    pub hash: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cr2wImport {
    pub depot_path: String,
    pub class_name: String,
    pub flags: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cr2wExport {
    pub class_name: String,
    pub object_flags: u16,
    pub parent_id: u32,
    pub data_size: u32,
    pub data_offset: u32,
    pub template: u32,
    pub crc32: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cr2wBuffer {
    pub flags: u32,
    pub index: u32,
    pub offset: u32,
    pub disk_size: u32,
    pub memory_size: u32,
    pub crc32: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Cr2wEmbedded {
    pub import_index: u32,
    pub chunk_index: u32,
    pub path_hash: u64,
    pub depot_path: String,
}

/// Reads a CR2W header and its ten table descriptors.
///
/// # Errors
///
/// Returns [`Cr2wError`] when the file cannot be read or does not begin with
/// the CR2W magic bytes.
pub fn inspect(path: &Path) -> Result<Cr2wInspection, Cr2wError> {
    let mut reader = BufReader::new(File::open(path)?);
    let file_len = reader.get_ref().metadata()?.len();
    let mut magic = [0_u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != CR2W_MAGIC {
        return Err(Cr2wError::InvalidMagic { actual: magic });
    }

    let version = reader.read_u32_le()?;
    let flags = reader.read_u32_le()?;
    let timestamp = reader.read_u64_le()?;
    let build_version = reader.read_u32_le()?;
    let objects_end = reader.read_u32_le()?;
    let buffers_end = reader.read_u32_le()?;
    let crc32 = reader.read_u32_le()?;
    let chunk_count = reader.read_u32_le()?;
    let mut tables = Vec::with_capacity(TABLE_COUNT);
    for _ in 0..TABLE_COUNT {
        tables.push(Cr2wTable {
            offset: reader.read_u32_le()?,
            item_count: reader.read_u32_le()?,
            crc32: reader.read_u32_le()?,
        });
    }

    let header = Cr2wHeader {
        version,
        flags,
        timestamp,
        build_version,
        objects_end,
        buffers_end,
        crc32,
        chunk_count,
        tables,
    };
    validate_tables(&header.tables, file_len)?;
    let strings = read_strings(&mut reader, &header.tables[0])?;
    let names = read_names(&mut reader, &header.tables[1], &strings)?;
    let imports = read_imports(&mut reader, &header.tables[2], &strings, &names)?;
    let exports = read_exports(&mut reader, &header.tables[4], &names)?;
    let buffers = read_buffers(&mut reader, &header.tables[5])?;
    let embedded = read_embedded(&mut reader, &header.tables[6], &imports)?;

    Ok(Cr2wInspection {
        header,
        strings,
        names,
        imports,
        exports,
        buffers,
        embedded,
    })
}

fn read_embedded(
    reader: &mut (impl Read + Seek),
    table: &Cr2wTable,
    imports: &[Cr2wImport],
) -> Result<Vec<Cr2wEmbedded>, Cr2wError> {
    reader.seek(SeekFrom::Start(u64::from(table.offset)))?;
    let mut result = Vec::with_capacity(table.item_count as usize);
    for embedded_index in 0..table.item_count {
        let import_index = reader.read_u32_le()?;
        let chunk_index = reader.read_u32_le()?;
        let path_hash = reader.read_u64_le()?;
        let depot_path = usize::try_from(import_index)
            .ok()
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| imports.get(index))
            .map(|import| import.depot_path.clone())
            .ok_or(Cr2wError::InvalidImport {
                import: embedded_index as usize,
            })?;
        result.push(Cr2wEmbedded {
            import_index,
            chunk_index,
            path_hash,
            depot_path,
        });
    }
    Ok(result)
}

fn validate_tables(tables: &[Cr2wTable], file_len: u64) -> Result<(), Cr2wError> {
    for (index, table) in tables.iter().enumerate() {
        if u64::from(table.offset) > file_len {
            return Err(Cr2wError::InvalidTable { table: index });
        }
    }
    Ok(())
}

fn read_strings(
    reader: &mut (impl Read + Seek),
    table: &Cr2wTable,
) -> Result<Vec<Cr2wString>, Cr2wError> {
    reader.seek(SeekFrom::Start(u64::from(table.offset)))?;
    let mut bytes = vec![
        0_u8;
        usize::try_from(table.item_count)
            .map_err(|_| { Cr2wError::InvalidTable { table: 0 } })?
    ];
    reader.read_exact(&mut bytes)?;
    let mut strings = Vec::new();
    let mut start = 0_usize;
    while start < bytes.len() {
        let relative_end = bytes[start..]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len() - start);
        let end = start + relative_end;
        let value = std::str::from_utf8(&bytes[start..end])
            .map_err(|_| Cr2wError::InvalidString {
                offset: u32::try_from(start).unwrap_or(u32::MAX),
            })?
            .to_owned();
        strings.push(Cr2wString {
            offset: u32::try_from(start).map_err(|_| Cr2wError::InvalidTable { table: 0 })?,
            value: if value.is_empty() {
                "None".to_owned()
            } else {
                value
            },
        });
        start = end.saturating_add(1);
    }
    Ok(strings)
}

fn read_names(
    reader: &mut (impl Read + Seek),
    table: &Cr2wTable,
    strings: &[Cr2wString],
) -> Result<Vec<Cr2wName>, Cr2wError> {
    reader.seek(SeekFrom::Start(u64::from(table.offset)))?;
    let mut result = Vec::with_capacity(table.item_count as usize);
    for name_index in 0..table.item_count as usize {
        let offset = reader.read_u32_le()?;
        let hash = reader.read_u32_le()?;
        let value = strings
            .iter()
            .find(|item| item.offset == offset)
            .ok_or(Cr2wError::MissingNameString {
                name: name_index,
                offset,
            })?
            .value
            .clone();
        result.push(Cr2wName { value, hash });
    }
    Ok(result)
}

fn read_imports(
    reader: &mut (impl Read + Seek),
    table: &Cr2wTable,
    strings: &[Cr2wString],
    names: &[Cr2wName],
) -> Result<Vec<Cr2wImport>, Cr2wError> {
    reader.seek(SeekFrom::Start(u64::from(table.offset)))?;
    let mut result = Vec::with_capacity(table.item_count as usize);
    for import_index in 0..table.item_count as usize {
        let offset = reader.read_u32_le()?;
        let class_index = usize::from(reader.read_u16_le()?);
        let flags = reader.read_u16_le()?;
        let depot_path = strings
            .iter()
            .find(|item| item.offset == offset)
            .map(|item| item.value.clone());
        let class_name = names.get(class_index).map(|item| item.value.clone());
        result.push(Cr2wImport {
            depot_path: depot_path.ok_or(Cr2wError::InvalidImport {
                import: import_index,
            })?,
            class_name: class_name.ok_or(Cr2wError::InvalidImport {
                import: import_index,
            })?,
            flags,
        });
    }
    Ok(result)
}

fn read_exports(
    reader: &mut (impl Read + Seek),
    table: &Cr2wTable,
    names: &[Cr2wName],
) -> Result<Vec<Cr2wExport>, Cr2wError> {
    reader.seek(SeekFrom::Start(u64::from(table.offset)))?;
    let mut result = Vec::with_capacity(table.item_count as usize);
    for export_index in 0..table.item_count as usize {
        let class_index = usize::from(reader.read_u16_le()?);
        let object_flags = reader.read_u16_le()?;
        result.push(Cr2wExport {
            class_name: names
                .get(class_index)
                .ok_or(Cr2wError::InvalidImport {
                    import: export_index,
                })?
                .value
                .clone(),
            object_flags,
            parent_id: reader.read_u32_le()?,
            data_size: reader.read_u32_le()?,
            data_offset: reader.read_u32_le()?,
            template: reader.read_u32_le()?,
            crc32: reader.read_u32_le()?,
        });
    }
    Ok(result)
}

fn read_buffers(
    reader: &mut (impl Read + Seek),
    table: &Cr2wTable,
) -> Result<Vec<Cr2wBuffer>, Cr2wError> {
    reader.seek(SeekFrom::Start(u64::from(table.offset)))?;
    let mut result = Vec::with_capacity(table.item_count as usize);
    for _ in 0..table.item_count {
        result.push(Cr2wBuffer {
            flags: reader.read_u32_le()?,
            index: reader.read_u32_le()?,
            offset: reader.read_u32_le()?,
            disk_size: reader.read_u32_le()?,
            memory_size: reader.read_u32_le()?,
            crc32: reader.read_u32_le()?,
        });
    }
    Ok(result)
}
