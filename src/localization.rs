//! Typed CR2W codec for `localizationPersistenceOnScreenEntries`.

use crate::cr2w::{self, Cr2wError};
use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};
use thiserror::Error;

const MAGIC_AND_HEADER_SIZE: usize = 40;
const TABLES_OFFSET: usize = 40;
const TABLE_SIZE: usize = 12;
const EXPORT_SIZE: usize = 24;
const DEAD_BEEF: u32 = 0xdead_beef;
type PropertySlice<'a> = (&'a str, &'a str, &'a [u8]);

#[derive(Debug, Error)]
pub enum LocalizationError {
    #[error("could not access localization resource: {0}")]
    Io(#[from] io::Error),
    #[error("invalid CR2W localization resource: {0}")]
    Cr2w(#[from] Cr2wError),
    #[error("invalid localization JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported localization CR2W layout: {0}")]
    Unsupported(&'static str),
    #[error("localization data exceeds CR2W's 32-bit offsets")]
    TooLarge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnScreenEntry {
    #[serde(rename = "$type", default = "entry_type")]
    pub red_type: String,
    #[serde(rename = "femaleVariant")]
    pub female_variant: String,
    #[serde(rename = "maleVariant")]
    pub male_variant: String,
    #[serde(rename = "primaryKey")]
    pub primary_key: String,
    #[serde(rename = "secondaryKey")]
    pub secondary_key: String,
}

fn entry_type() -> String {
    "localizationPersistenceOnScreenEntry".to_owned()
}

/// Reads the supported localization entries from a CR2W file.
///
/// # Errors
///
/// Returns [`LocalizationError`] for I/O, malformed CR2W metadata, or an
/// unexpected class/property layout.
pub fn read_entries(path: &Path) -> Result<Vec<OnScreenEntry>, LocalizationError> {
    let inspection = cr2w::inspect(path)?;
    if inspection.exports.len() != 2
        || inspection.exports[0].class_name != "JsonResource"
        || inspection.exports[1].class_name != "localizationPersistenceOnScreenEntries"
    {
        return Err(LocalizationError::Unsupported("unexpected exports"));
    }
    let bytes = fs::read(path)?;
    let names: Vec<&str> = inspection
        .names
        .iter()
        .map(|name| name.value.as_str())
        .collect();
    let export = &inspection.exports[1];
    let mut cursor =
        usize::try_from(export.data_offset).map_err(|_| LocalizationError::TooLarge)?;
    expect_byte(&bytes, &mut cursor, 0)?;
    let (property, red_type, payload) = read_property(&bytes, &mut cursor, &names)?
        .ok_or(LocalizationError::Unsupported("missing entries property"))?;
    if property != "entries" || red_type != "array:localizationPersistenceOnScreenEntry" {
        return Err(LocalizationError::Unsupported("unexpected root property"));
    }
    parse_entry_array(payload, &names)
}

/// Writes supported localization JSON using an existing localization CR2W as
/// the type-table template.
///
/// # Errors
///
/// Returns [`LocalizationError`] if JSON is malformed, the template layout is
/// unsupported, or the output cannot be written.
pub fn write_from_json(
    json_path: &Path,
    template_path: &Path,
    output_path: &Path,
) -> Result<(), LocalizationError> {
    let document: serde_json::Value = serde_json::from_slice(&fs::read(json_path)?)?;
    let entries: Vec<OnScreenEntry> = serde_json::from_value(
        document
            .pointer("/Data/RootChunk/root/Data/entries")
            .cloned()
            .ok_or(LocalizationError::Unsupported("missing JSON entries"))?,
    )?;
    let inspection = cr2w::inspect(template_path)?;
    if inspection.exports.len() != 2 {
        return Err(LocalizationError::Unsupported("template export count"));
    }
    let mut bytes = fs::read(template_path)?;
    let names: Vec<&str> = inspection
        .names
        .iter()
        .map(|name| name.value.as_str())
        .collect();
    let name_index = |value: &str| {
        names
            .iter()
            .position(|name| *name == value)
            .and_then(|index| u16::try_from(index).ok())
            .ok_or(LocalizationError::Unsupported("template name missing"))
    };

    let export0 = &inspection.exports[0];
    let export0_start =
        usize::try_from(export0.data_offset).map_err(|_| LocalizationError::TooLarge)?;
    let export0_end = export0_start
        .checked_add(usize::try_from(export0.data_size).map_err(|_| LocalizationError::TooLarge)?)
        .ok_or(LocalizationError::TooLarge)?;
    let mut chunk1 = vec![0_u8];
    let mut array = Vec::new();
    push_u32(
        &mut array,
        u32::try_from(entries.len()).map_err(|_| LocalizationError::TooLarge)?,
    );
    for entry in &entries {
        array.push(0);
        if !entry.secondary_key.is_empty() {
            write_string_property(
                &mut array,
                name_index("secondaryKey")?,
                name_index("String")?,
                &entry.secondary_key,
            )?;
        }
        if !entry.female_variant.is_empty() {
            write_string_property(
                &mut array,
                name_index("femaleVariant")?,
                name_index("String")?,
                &entry.female_variant,
            )?;
        }
        if !entry.male_variant.is_empty() {
            write_string_property(
                &mut array,
                name_index("maleVariant")?,
                name_index("String")?,
                &entry.male_variant,
            )?;
        }
        if entry.primary_key != "0" {
            return Err(LocalizationError::Unsupported("nonzero primaryKey"));
        }
        push_u16(&mut array, 0);
    }
    write_property(
        &mut chunk1,
        name_index("entries")?,
        name_index("array:localizationPersistenceOnScreenEntry")?,
        &array,
    )?;
    push_u16(&mut chunk1, 0);

    bytes.truncate(export0_end);
    bytes.extend_from_slice(&chunk1);
    let chunk1_size = u32::try_from(chunk1.len()).map_err(|_| LocalizationError::TooLarge)?;
    let file_end = u32::try_from(bytes.len()).map_err(|_| LocalizationError::TooLarge)?;

    let export_table = &inspection.header.tables[4];
    let export_table_offset =
        usize::try_from(export_table.offset).map_err(|_| LocalizationError::TooLarge)?;
    write_u32_at(
        &mut bytes,
        export_table_offset + EXPORT_SIZE + 8,
        chunk1_size,
    )?;
    write_u32_at(
        &mut bytes,
        export_table_offset + EXPORT_SIZE + 12,
        u32::try_from(export0_end).map_err(|_| LocalizationError::TooLarge)?,
    )?;
    write_u32_at(&mut bytes, 24, file_end)?;
    write_u32_at(&mut bytes, 28, file_end)?;

    let table_bytes_end = export_table_offset + 2 * EXPORT_SIZE;
    let table_crc = crc32fast::hash(&bytes[export_table_offset..table_bytes_end]);
    write_u32_at(&mut bytes, TABLES_OFFSET + 4 * TABLE_SIZE + 8, table_crc)?;
    let header_crc = calculate_header_crc(&bytes)?;
    write_u32_at(&mut bytes, 32, header_crc)?;
    fs::write(output_path, bytes)?;
    Ok(())
}

/// Creates WolvenKit-shaped JSON for the supported localization resource.
///
/// # Errors
///
/// Returns [`LocalizationError`] when the CR2W cannot be decoded or the JSON
/// output cannot be written.
pub fn write_json(input: &Path, output: &Path) -> Result<(), LocalizationError> {
    let entries = read_entries(input)?;
    let document = serde_json::json!({
        "Header": {
            "WolvenKitVersion": "ghostline-red 0.1.0",
            "WKitJsonVersion": "0.0.9",
            "GameVersion": 2310,
            "ExportedDateTime": "1970-01-01T00:00:00Z",
            "DataType": "CR2W",
            "ArchiveFileName": input.to_string_lossy()
        },
        "Data": {
            "Version": 195,
            "BuildVersion": 0,
            "RootChunk": {
                "$type": "JsonResource",
                "cookingPlatform": "PLATFORM_PC",
                "root": {
                    "HandleId": "0",
                    "Data": {
                        "$type": "localizationPersistenceOnScreenEntries",
                        "entries": entries
                    }
                }
            }
        }
    });
    fs::write(output, serde_json::to_vec_pretty(&document)?)?;
    Ok(())
}

fn parse_entry_array(
    payload: &[u8],
    names: &[&str],
) -> Result<Vec<OnScreenEntry>, LocalizationError> {
    let mut cursor = 0_usize;
    let count = read_u32(payload, &mut cursor)?;
    let mut result = Vec::with_capacity(count as usize);
    for _ in 0..count {
        expect_byte(payload, &mut cursor, 0)?;
        let mut entry = OnScreenEntry {
            red_type: entry_type(),
            female_variant: String::new(),
            male_variant: String::new(),
            primary_key: "0".to_owned(),
            secondary_key: String::new(),
        };
        while let Some((property, red_type, data)) = read_property(payload, &mut cursor, names)? {
            if red_type != "String" {
                return Err(LocalizationError::Unsupported("entry property type"));
            }
            let value = read_prefixed_string(data)?;
            match property {
                "femaleVariant" => entry.female_variant = value,
                "maleVariant" => entry.male_variant = value,
                "secondaryKey" => entry.secondary_key = value,
                _ => return Err(LocalizationError::Unsupported("entry property")),
            }
        }
        result.push(entry);
    }
    Ok(result)
}

fn read_property<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    names: &[&'a str],
) -> Result<Option<PropertySlice<'a>>, LocalizationError> {
    let name_index = usize::from(read_u16(bytes, cursor)?);
    if name_index == 0 {
        return Ok(None);
    }
    let type_index = usize::from(read_u16(bytes, cursor)?);
    let total_size = read_u32(bytes, cursor)?;
    let payload_size = total_size
        .checked_sub(4)
        .ok_or(LocalizationError::Unsupported("property size"))?;
    let end = cursor
        .checked_add(usize::try_from(payload_size).map_err(|_| LocalizationError::TooLarge)?)
        .ok_or(LocalizationError::TooLarge)?;
    let data = bytes
        .get(*cursor..end)
        .ok_or(LocalizationError::Unsupported("truncated property"))?;
    *cursor = end;
    Ok(Some((
        *names
            .get(name_index)
            .ok_or(LocalizationError::Unsupported("property name index"))?,
        *names
            .get(type_index)
            .ok_or(LocalizationError::Unsupported("property type index"))?,
        data,
    )))
}

fn read_prefixed_string(bytes: &[u8]) -> Result<String, LocalizationError> {
    let (negative, length, prefix_size) = read_vlq(bytes)?;
    if !negative {
        return Err(LocalizationError::Unsupported("UTF-16 string"));
    }
    let value = bytes
        .get(prefix_size..prefix_size + length)
        .ok_or(LocalizationError::Unsupported("truncated string"))?;
    String::from_utf8(value.to_vec())
        .map_err(|_| LocalizationError::Unsupported("invalid UTF-8 string"))
}

fn read_vlq(bytes: &[u8]) -> Result<(bool, usize, usize), LocalizationError> {
    let first = *bytes
        .first()
        .ok_or(LocalizationError::Unsupported("missing string length"))?;
    let negative = first & 0x80 != 0;
    let mut value = usize::from(first & 0x3f);
    let mut shift = 6;
    let mut cursor = 1;
    if first & 0x40 != 0 {
        loop {
            let byte = *bytes
                .get(cursor)
                .ok_or(LocalizationError::Unsupported("truncated VLQ"))?;
            cursor += 1;
            value |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
    }
    Ok((negative, value, cursor))
}

fn write_string_property(
    output: &mut Vec<u8>,
    name: u16,
    red_type: u16,
    value: &str,
) -> Result<(), LocalizationError> {
    if value.is_empty() {
        return Ok(());
    }
    let mut payload = Vec::new();
    write_negative_vlq(
        &mut payload,
        u32::try_from(value.len()).map_err(|_| LocalizationError::TooLarge)?,
    );
    payload.extend_from_slice(value.as_bytes());
    write_property(output, name, red_type, &payload)
}

fn write_property(
    output: &mut Vec<u8>,
    name: u16,
    red_type: u16,
    payload: &[u8],
) -> Result<(), LocalizationError> {
    push_u16(output, name);
    push_u16(output, red_type);
    push_u32(
        output,
        u32::try_from(payload.len() + 4).map_err(|_| LocalizationError::TooLarge)?,
    );
    output.extend_from_slice(payload);
    Ok(())
}

fn write_negative_vlq(output: &mut Vec<u8>, value: u32) {
    let mut remaining = value >> 6;
    let mut first = (value & 0x3f) as u8 | 0x80;
    if remaining > 0 {
        first |= 0x40;
    }
    output.push(first);
    while remaining > 0 {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining > 0 {
            byte |= 0x80;
        }
        output.push(byte);
    }
}

fn calculate_header_crc(bytes: &[u8]) -> Result<u32, LocalizationError> {
    if bytes.len() < MAGIC_AND_HEADER_SIZE + 10 * TABLE_SIZE {
        return Err(LocalizationError::Unsupported("truncated header"));
    }
    let mut header = bytes[..MAGIC_AND_HEADER_SIZE + 10 * TABLE_SIZE].to_vec();
    header[32..36].copy_from_slice(&DEAD_BEEF.to_le_bytes());
    let mut hasher = Hasher::new();
    hasher.update(&header);
    Ok(hasher.finalize())
}

fn expect_byte(bytes: &[u8], cursor: &mut usize, expected: u8) -> Result<(), LocalizationError> {
    if bytes.get(*cursor) != Some(&expected) {
        return Err(LocalizationError::Unsupported("class marker"));
    }
    *cursor += 1;
    Ok(())
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, LocalizationError> {
    let data: [u8; 2] = bytes
        .get(*cursor..*cursor + 2)
        .ok_or(LocalizationError::Unsupported("truncated u16"))?
        .try_into()
        .map_err(|_| LocalizationError::Unsupported("truncated u16"))?;
    *cursor += 2;
    Ok(u16::from_le_bytes(data))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, LocalizationError> {
    let data: [u8; 4] = bytes
        .get(*cursor..*cursor + 4)
        .ok_or(LocalizationError::Unsupported("truncated u32"))?
        .try_into()
        .map_err(|_| LocalizationError::Unsupported("truncated u32"))?;
    *cursor += 4;
    Ok(u32::from_le_bytes(data))
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), LocalizationError> {
    bytes
        .get_mut(offset..offset + 4)
        .ok_or(LocalizationError::Unsupported("write outside template"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
