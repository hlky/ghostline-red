//! Template-backed generic CR2W writer.

use crate::{
    archive::{self, ArchiveError},
    cr2w::{self, Cr2wError, Cr2wInspection},
    redpackage::{self, PackageError, PackageSettings},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crc32fast::Hasher;
use serde_json::Value;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeSet, HashMap, HashSet},
    ffi::OsStr,
    fs, io,
    path::Path,
};
use thiserror::Error;

const TABLES_OFFSET: usize = 40;
const TABLE_SIZE: usize = 12;
const EXPORT_SIZE: usize = 24;
const BUFFER_SIZE: usize = 24;
const DEAD_BEEF: u32 = 0xdead_beef;

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("could not access CR2W input or output: {0}")]
    Io(#[from] io::Error),
    #[error("invalid CR2W template: {0}")]
    Cr2w(#[from] Cr2wError),
    #[error("invalid WKit JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported template-backed write: {0}")]
    Unsupported(String),
    #[error("CR2W output exceeds 32-bit offsets")]
    TooLarge,
    #[error("could not decode base64 buffer data: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("could not decompress a template buffer: {0}")]
    Archive(#[from] ArchiveError),
    #[error("could not rebuild a RedPackage buffer: {0}")]
    Package(#[from] PackageError),
}

#[derive(Debug)]
struct BufferOverride {
    bytes: Vec<u8>,
    stored: bool,
    memory_size: u32,
}

#[derive(Debug)]
struct BufferLayout {
    offset: u32,
    disk_size: u32,
    memory_size: u32,
    crc32: u32,
}

#[derive(Debug)]
struct PrefixLayout {
    offsets: [usize; 10],
    counts: [u32; 10],
}

#[derive(Debug, Clone)]
struct NewImport {
    depot_path: String,
    flags: u16,
}

struct NewExport<'a> {
    handle_id: String,
    value: &'a Value,
    class_name: String,
    template_index: usize,
}

struct Encoder<'a> {
    template: &'a [u8],
    file: &'a Cr2wInspection,
    names: RefCell<HashMap<String, u16>>,
    new_names: RefCell<Vec<String>>,
    imports: RefCell<HashMap<String, u16>>,
    new_imports: RefCell<Vec<NewImport>>,
    handle_exports: RefCell<HashMap<String, usize>>,
    candidate_handles: RefCell<HashSet<String>>,
    discovering_handles: Cell<bool>,
    classes: &'a BTreeSet<String>,
}

/// Writes WKit-shaped JSON using an existing CR2W resource as its audited
/// table, chunk-layout, and buffer template.
///
/// Reflected values and strings are rebuilt. Chunks absent from the JSON handle
/// graph, custom appendices, and buffer payloads are retained byte-for-byte.
///
/// # Errors
///
/// Returns [`WriterError`] for malformed JSON/templates, values not present in
/// the template name/import tables, unsupported structural changes, or I/O.
#[expect(
    clippy::too_many_lines,
    reason = "the sequential container rebuild keeps offset and CRC patching auditable"
)]
pub fn write_with_template(
    json_path: &Path,
    template_path: &Path,
    output_path: &Path,
    classes: &BTreeSet<String>,
    kraken_path: &OsStr,
) -> Result<(), WriterError> {
    let document: Value = serde_json::from_slice(&fs::read(json_path)?)?;
    let root = document
        .pointer("/Data/RootChunk")
        .ok_or_else(|| unsupported("missing Data.RootChunk"))?;
    let mut chunks = HashMap::new();
    chunks.insert(0_usize, root);

    let file = cr2w::inspect(template_path)?;
    let mut buffer_overrides = HashMap::new();
    if let Some(embedded) = document
        .pointer("/Data/EmbeddedFiles")
        .and_then(Value::as_array)
    {
        if embedded.len() != file.embedded.len() {
            return Err(unsupported("embedded file count change"));
        }
        for (json, template) in embedded.iter().zip(&file.embedded) {
            let content = json
                .get("Content")
                .ok_or_else(|| unsupported("embedded Content missing"))?;
            chunks.insert(
                usize::try_from(template.chunk_index).map_err(|_| WriterError::TooLarge)?,
                content,
            );
        }
    }
    let template = fs::read(template_path)?;
    collect_buffer_overrides(&document, &mut buffer_overrides)?;
    collect_redpackage_overrides(
        &document,
        &file,
        &template,
        classes,
        kraken_path,
        &mut buffer_overrides,
    )?;
    let names = file
        .names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            Ok((
                name.value.clone(),
                u16::try_from(index).map_err(|_| WriterError::TooLarge)?,
            ))
        })
        .collect::<Result<HashMap<_, _>, WriterError>>()?;
    let encoder = Encoder {
        template: &template,
        file: &file,
        names: RefCell::new(names),
        new_names: RefCell::new(Vec::new()),
        imports: RefCell::new(
            file.imports
                .iter()
                .enumerate()
                .map(|(index, import)| {
                    Ok((
                        import.depot_path.clone(),
                        u16::try_from(index + 1).map_err(|_| WriterError::TooLarge)?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, WriterError>>()?,
        ),
        new_imports: RefCell::new(Vec::new()),
        handle_exports: RefCell::new(HashMap::new()),
        candidate_handles: RefCell::new(HashSet::new()),
        discovering_handles: Cell::new(true),
        classes,
    };
    // Discover the mapping from WKit handle identities to CR2W export indices
    // from the authoritative pointers in the template itself.
    for index in 0..file.exports.len() {
        let Some(value) = chunks.get(&index).copied() else {
            continue;
        };
        let export = &file.exports[index];
        let class_name = export.class_name.as_str();
        let start = usize::try_from(export.data_offset).map_err(|_| WriterError::TooLarge)?;
        let size = usize::try_from(export.data_size).map_err(|_| WriterError::TooLarge)?;
        let _ = encoder.encode_class(value, start, size, class_name, &mut chunks)?;
    }
    encoder.discovering_handles.set(false);
    let new_exports = collect_new_exports(&document, &file, &encoder.candidate_handles)?;
    for (offset, export) in new_exports.iter().enumerate() {
        let export_index = file.exports.len() + offset;
        chunks.insert(export_index, export.value);
        encoder
            .handle_exports
            .borrow_mut()
            .insert(export.handle_id.clone(), export_index);
        let _ = encoder.name_index(&export.class_name)?;
    }

    let new_names = encoder.new_names.borrow().clone();
    let mut name_values: Vec<String> = file.names.iter().map(|name| name.value.clone()).collect();
    name_values.extend(new_names.iter().cloned());
    let new_imports = encoder.new_imports.borrow().clone();
    let (mut output, prefix_layout) =
        build_prefix(&template, &file, &name_values, &new_imports, &new_exports)?;
    let mut export_layout = Vec::with_capacity(file.exports.len() + new_exports.len());
    for index in 0..file.exports.len() + new_exports.len() {
        let (export, class_name) = if let Some(export) = file.exports.get(index) {
            (export, export.class_name.as_str())
        } else {
            let new_export = &new_exports[index - file.exports.len()];
            (
                &file.exports[new_export.template_index],
                new_export.class_name.as_str(),
            )
        };
        let template_start =
            usize::try_from(export.data_offset).map_err(|_| WriterError::TooLarge)?;
        let template_size = usize::try_from(export.data_size).map_err(|_| WriterError::TooLarge)?;
        let offset = u32::try_from(output.len()).map_err(|_| WriterError::TooLarge)?;
        if let Some(value) = chunks.get(&index) {
            let (chunk_bytes, _) = encoder.encode_class(
                value,
                template_start,
                template_size,
                class_name,
                &mut chunks,
            )?;
            output.extend_from_slice(&chunk_bytes);
        } else {
            let end = template_start
                .checked_add(template_size)
                .ok_or(WriterError::TooLarge)?;
            output.extend_from_slice(
                template
                    .get(template_start..end)
                    .ok_or_else(|| unsupported("template chunk bounds"))?,
            );
        }
        let size = u32::try_from(output.len())
            .map_err(|_| WriterError::TooLarge)?
            .checked_sub(offset)
            .ok_or(WriterError::TooLarge)?;
        export_layout.push((offset, size));
    }
    let objects_end = u32::try_from(output.len()).map_err(|_| WriterError::TooLarge)?;

    let mut buffer_layout = Vec::with_capacity(file.buffers.len());
    for (index, buffer) in file.buffers.iter().enumerate() {
        let start = usize::try_from(buffer.offset).map_err(|_| WriterError::TooLarge)?;
        let size = usize::try_from(buffer.disk_size).map_err(|_| WriterError::TooLarge)?;
        let end = start.checked_add(size).ok_or(WriterError::TooLarge)?;
        let offset = u32::try_from(output.len()).map_err(|_| WriterError::TooLarge)?;
        let stored = template
            .get(start..end)
            .ok_or_else(|| unsupported("template buffer bounds"))?;
        let (bytes, memory_size) = if let Some(replacement) = buffer_overrides.get(&index) {
            if replacement.stored {
                (replacement.bytes.clone(), replacement.memory_size)
            } else if buffer_matches(stored, buffer.memory_size, &replacement.bytes, kraken_path)? {
                (stored.to_vec(), buffer.memory_size)
            } else {
                (
                    replacement.bytes.clone(),
                    u32::try_from(replacement.bytes.len()).map_err(|_| WriterError::TooLarge)?,
                )
            }
        } else {
            (stored.to_vec(), buffer.memory_size)
        };
        output.extend_from_slice(&bytes);
        buffer_layout.push(BufferLayout {
            offset,
            disk_size: u32::try_from(bytes.len()).map_err(|_| WriterError::TooLarge)?,
            memory_size,
            crc32: crc32fast::hash(&bytes),
        });
    }
    let buffers_end = u32::try_from(output.len()).map_err(|_| WriterError::TooLarge)?;

    patch_layout(
        &mut output,
        &prefix_layout,
        &export_layout,
        &buffer_layout,
        objects_end,
        buffers_end,
    )?;
    fs::write(output_path, output)?;
    Ok(())
}

impl Encoder<'_> {
    fn encode_class<'v>(
        &self,
        value: &'v Value,
        template_start: usize,
        template_size: usize,
        red_type: &str,
        chunks: &mut HashMap<usize, &'v Value>,
    ) -> Result<(Vec<u8>, usize), WriterError> {
        let template_end = template_start
            .checked_add(template_size)
            .filter(|end| *end <= self.template.len())
            .ok_or_else(|| unsupported("class template bounds"))?;
        if red_type == "AreaShapeOutline" {
            return Ok((
                self.template[template_start..template_end].to_vec(),
                template_end,
            ));
        }
        let object = value
            .as_object()
            .ok_or_else(|| unsupported(format!("{red_type} is not an object")))?;
        let mut cursor = template_start;
        if self.byte(cursor)? != 0 {
            return Err(unsupported(format!("{red_type} custom-data chunk")));
        }
        cursor += 1;
        let mut output = vec![0];
        loop {
            let name_index = self.u16(cursor)?;
            cursor += 2;
            if name_index == 0 {
                output.extend_from_slice(&0_u16.to_le_bytes());
                break;
            }
            let type_index = self.u16(cursor)?;
            cursor += 2;
            let total_size =
                usize::try_from(self.u32(cursor)?).map_err(|_| WriterError::TooLarge)?;
            cursor += 4;
            let payload_size = total_size
                .checked_sub(4)
                .ok_or_else(|| unsupported("property size"))?;
            let payload_end = cursor
                .checked_add(payload_size)
                .filter(|end| *end <= template_end)
                .ok_or_else(|| unsupported("property bounds"))?;
            let property = self.name(name_index)?;
            let property_type = self.name(type_index)?;
            let property_value = object
                .get(property)
                .ok_or_else(|| unsupported(format!("{red_type}.{property} missing")))?;
            let (payload, consumed) =
                self.encode_value(property_value, property_type, cursor, payload_size, chunks)?;
            if consumed != payload_end {
                return Err(unsupported(format!(
                    "{red_type}.{property} template was not consumed"
                )));
            }
            output.extend_from_slice(&name_index.to_le_bytes());
            output.extend_from_slice(&type_index.to_le_bytes());
            let encoded_size = u32::try_from(payload.len())
                .map_err(|_| WriterError::TooLarge)?
                .checked_add(4)
                .ok_or(WriterError::TooLarge)?;
            output.extend_from_slice(&encoded_size.to_le_bytes());
            output.extend_from_slice(&payload);
            cursor = payload_end;
        }
        if matches!(
            red_type,
            "worldStreamingSector"
                | "worldStreamingWorld"
                | "gameDeviceResourceData"
                | "CMaterialInstance"
        ) {
            // Typed reverse appendix codecs are connected separately; until
            // then the audited template bytes remain authoritative.
            output.extend_from_slice(&self.template[cursor..template_end]);
            return Ok((output, template_end));
        }
        Ok((output, cursor))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the match is the auditable RED binary write dispatch table"
    )]
    fn encode_value<'v>(
        &self,
        value: &'v Value,
        red_type: &str,
        template_start: usize,
        template_size: usize,
        chunks: &mut HashMap<usize, &'v Value>,
    ) -> Result<(Vec<u8>, usize), WriterError> {
        let template_end = template_start + template_size;
        let exact = |bytes| Ok((bytes, template_end));
        match red_type {
            "Bool" => exact(vec![u8::from(json_bool(value)?)]),
            "Int8" => exact(
                i8::try_from(json_i64(value)?)
                    .map_err(|_| unsupported("Int8 range"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "Uint8" => exact(vec![
                u8::try_from(json_u64(value)?).map_err(|_| unsupported("Uint8 range"))?,
            ]),
            "Int16" => exact(
                i16::try_from(json_i64(value)?)
                    .map_err(|_| unsupported("Int16 range"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "Uint16" => exact(
                u16::try_from(json_u64(value)?)
                    .map_err(|_| unsupported("Uint16 range"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "Int32" => exact(
                i32::try_from(json_i64(value)?)
                    .map_err(|_| unsupported("Int32 range"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "Uint32" => exact(
                u32::try_from(json_u64(value)?)
                    .map_err(|_| unsupported("Uint32 range"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "Int64" => exact(json_string_i64(value)?.to_le_bytes().to_vec()),
            "Uint64" | "CRUID" | "CDateTime" => {
                exact(json_string_u64(value)?.to_le_bytes().to_vec())
            }
            "Float" => exact(json_f32(value)?.to_le_bytes().to_vec()),
            "Double" => exact(json_f64(value)?.to_le_bytes().to_vec()),
            "CName" => exact(
                self.name_index(storage_value(value)?)?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "String" => exact(encode_string(
                value.as_str().ok_or_else(|| unsupported("String value"))?,
            )?),
            "NodeRef" => exact(encode_string(storage_value(value)?)?),
            "TweakDBID" => exact(
                tweak_db_id(storage_or_string(value)?)?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "gamedataLocKeyWrapper" => exact(
                value
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| unsupported("LocKey value"))?
                    .parse::<u64>()
                    .map_err(|_| unsupported("LocKey value"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "LocalizationString" => {
                let mut output = value
                    .get("unk1")
                    .and_then(Value::as_str)
                    .ok_or_else(|| unsupported("LocalizationString.unk1"))?
                    .parse::<u64>()
                    .map_err(|_| unsupported("LocalizationString.unk1"))?
                    .to_le_bytes()
                    .to_vec();
                output.extend_from_slice(&encode_string(
                    value
                        .get("value")
                        .and_then(Value::as_str)
                        .ok_or_else(|| unsupported("LocalizationString.value"))?,
                )?);
                exact(output)
            }
            "DataBuffer" | "serializationDeferredDataBuffer" => {
                exact(self.template[template_start..template_end].to_vec())
            }
            _ if red_type.starts_with("array:") => {
                self.encode_array(value, &red_type[6..], template_start, template_size, chunks)
            }
            _ if red_type.starts_with("handle:") || red_type.starts_with("whandle:") => {
                if value.is_null() {
                    return exact(0_u32.to_le_bytes().to_vec());
                }
                let template_stored = self.u32(template_start)?;
                let template_export_index = usize::try_from(
                    template_stored
                        .checked_sub(1)
                        .ok_or_else(|| unsupported("non-null handle has null template"))?,
                )
                .map_err(|_| WriterError::TooLarge)?;
                let identity = value
                    .get("HandleId")
                    .or_else(|| value.get("HandleRefId"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| unsupported("handle identity"))?;
                if self.discovering_handles.get() {
                    if let Some(data) = value.get("Data") {
                        self.handle_exports
                            .borrow_mut()
                            .insert(identity.to_owned(), template_export_index);
                        chunks.insert(template_export_index, data);
                    }
                    return exact(template_stored.to_le_bytes().to_vec());
                }
                let mapped_export_index = self
                    .handle_exports
                    .borrow()
                    .get(identity)
                    .copied()
                    .unwrap_or(template_export_index);
                let export_index = if mapped_export_index >= self.file.exports.len() {
                    mapped_export_index
                } else {
                    template_export_index
                };
                let stored =
                    u32::try_from(export_index.checked_add(1).ok_or(WriterError::TooLarge)?)
                        .map_err(|_| WriterError::TooLarge)?;
                if let Some(data) = value.get("Data") {
                    if let Some(existing) = chunks.insert(export_index, data)
                        && !std::ptr::eq(existing, data)
                        && existing != data
                    {
                        return Err(unsupported("conflicting handle data"));
                    }
                } else if value.get("HandleRefId").is_none() {
                    return Err(unsupported("handle value"));
                }
                exact(stored.to_le_bytes().to_vec())
            }
            _ if red_type.starts_with("rRef:") || red_type.starts_with("raRef:") => {
                let path = value
                    .pointer("/DepotPath/$value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| unsupported("resource path"))?;
                let index = if path == "0" {
                    0
                } else if let Some(index) = self.imports.borrow().get(path).copied() {
                    index
                } else {
                    let flags = match value.get("Flags").and_then(Value::as_str) {
                        Some("Soft") => 4,
                        Some("Default") | None => 0,
                        Some(other) => {
                            return Err(unsupported(format!("resource reference flags {other}")));
                        }
                    };
                    let mut new_imports = self.new_imports.borrow_mut();
                    let index = u16::try_from(self.file.imports.len() + new_imports.len() + 1)
                        .map_err(|_| WriterError::TooLarge)?;
                    new_imports.push(NewImport {
                        depot_path: path.to_owned(),
                        flags,
                    });
                    self.imports.borrow_mut().insert(path.to_owned(), index);
                    index
                };
                exact(index.to_le_bytes().to_vec())
            }
            _ if value.is_string() && template_size >= 4 && template_size.is_multiple_of(2) => {
                let mut output = Vec::new();
                for item in value
                    .as_str()
                    .ok_or_else(|| unsupported("bitfield value"))?
                    .split(", ")
                    .filter(|item| !item.is_empty())
                {
                    output.extend_from_slice(&self.name_index(item)?.to_le_bytes());
                }
                output.extend_from_slice(&0_u16.to_le_bytes());
                exact(output)
            }
            _ if self.classes.contains(red_type) && template_size != 2 => {
                self.encode_class(value, template_start, template_size, red_type, chunks)
            }
            _ if template_size == 2 => exact(
                self.name_index(
                    value
                        .as_str()
                        .ok_or_else(|| unsupported(format!("{red_type} enum")))?,
                )?
                .to_le_bytes()
                .to_vec(),
            ),
            _ => exact(self.template[template_start..template_end].to_vec()),
        }
    }

    fn encode_array<'v>(
        &self,
        value: &'v Value,
        inner: &str,
        template_start: usize,
        template_size: usize,
        chunks: &mut HashMap<usize, &'v Value>,
    ) -> Result<(Vec<u8>, usize), WriterError> {
        let values = value.as_array().ok_or_else(|| unsupported("array value"))?;
        let template_count =
            usize::try_from(self.u32(template_start)?).map_err(|_| WriterError::TooLarge)?;
        let template_end = template_start + template_size;
        let mut cursor = template_start + 4;
        let mut element_templates = Vec::with_capacity(template_count);
        for _ in 0..template_count {
            let element_end = self.skip_value(inner, cursor, template_end)?;
            element_templates.push((cursor, element_end - cursor));
            cursor = element_end;
        }
        if cursor != template_end {
            return Err(unsupported("array template trailing bytes"));
        }
        if !values.is_empty() && element_templates.is_empty() {
            return Err(unsupported("cannot grow an empty template array"));
        }
        if values.len() > element_templates.len()
            && !(inner.starts_with("handle:") || inner.starts_with("whandle:"))
        {
            return Err(unsupported("cannot grow a template handle array"));
        }
        let mut output = u32::try_from(values.len())
            .map_err(|_| WriterError::TooLarge)?
            .to_le_bytes()
            .to_vec();
        let encoded_values = if self.discovering_handles.get() {
            for value in values.iter().skip(element_templates.len()) {
                collect_handle_ids(value, &mut self.candidate_handles.borrow_mut());
            }
            &values[..values.len().min(element_templates.len())]
        } else {
            values
        };
        for (index, value) in encoded_values.iter().enumerate() {
            let (element_start, element_size) = element_templates
                .get(index)
                .or_else(|| element_templates.last())
                .copied()
                .ok_or_else(|| unsupported("array element template"))?;
            let (encoded, consumed) =
                self.encode_value(value, inner, element_start, element_size, chunks)?;
            if consumed != element_start + element_size {
                return Err(unsupported("array element template was not consumed"));
            }
            output.extend_from_slice(&encoded);
        }
        Ok((output, template_end))
    }

    fn skip_value(&self, red_type: &str, start: usize, limit: usize) -> Result<usize, WriterError> {
        if let Some(size) = fixed_size(red_type) {
            return start
                .checked_add(size)
                .filter(|end| *end <= limit)
                .ok_or_else(|| unsupported("fixed value bounds"));
        }
        if red_type == "String" || red_type == "NodeRef" {
            return self.skip_string(start, limit);
        }
        if red_type == "LocalizationString" {
            return self.skip_string(start + 8, limit);
        }
        if let Some(inner) = red_type.strip_prefix("array:") {
            let count = usize::try_from(self.u32(start)?).map_err(|_| WriterError::TooLarge)?;
            let mut cursor = start + 4;
            for _ in 0..count {
                cursor = self.skip_value(inner, cursor, limit)?;
            }
            return Ok(cursor);
        }
        if self.classes.contains(red_type) {
            let mut cursor = start;
            if self.byte(cursor)? != 0 {
                return Err(unsupported(format!("{red_type} class marker")));
            }
            cursor += 1;
            loop {
                let name = self.u16(cursor)?;
                cursor += 2;
                if name == 0 {
                    return Ok(cursor);
                }
                cursor += 2;
                let total =
                    usize::try_from(self.u32(cursor)?).map_err(|_| WriterError::TooLarge)?;
                cursor = cursor
                    .checked_add(total)
                    .filter(|end| *end <= limit)
                    .ok_or_else(|| unsupported("class property bounds"))?;
            }
        }
        start
            .checked_add(2)
            .filter(|end| *end <= limit)
            .ok_or_else(|| unsupported(format!("{red_type} array element")))
    }

    fn skip_string(&self, start: usize, limit: usize) -> Result<usize, WriterError> {
        let first = self.byte(start)?;
        let mut length = usize::from(first & 0x3f);
        let mut cursor = start + 1;
        if first & 0x40 != 0 {
            let mut shift = 6;
            loop {
                let byte = self.byte(cursor)?;
                cursor += 1;
                length |= usize::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
        }
        let width = if first & 0x80 != 0 { 1 } else { 2 };
        cursor
            .checked_add(length.checked_mul(width).ok_or(WriterError::TooLarge)?)
            .filter(|end| *end <= limit)
            .ok_or_else(|| unsupported("string bounds"))
    }

    fn name(&self, index: u16) -> Result<&str, WriterError> {
        self.file
            .names
            .get(usize::from(index))
            .map(|name| name.value.as_str())
            .ok_or_else(|| unsupported("name index"))
    }

    fn name_index(&self, value: &str) -> Result<u16, WriterError> {
        if let Some(index) = self.names.borrow().get(value).copied() {
            return Ok(index);
        }
        let index = u16::try_from(self.file.names.len() + self.new_names.borrow().len())
            .map_err(|_| WriterError::TooLarge)?;
        self.new_names.borrow_mut().push(value.to_owned());
        self.names.borrow_mut().insert(value.to_owned(), index);
        Ok(index)
    }

    fn byte(&self, offset: usize) -> Result<u8, WriterError> {
        self.template
            .get(offset)
            .copied()
            .ok_or_else(|| unsupported("template byte"))
    }

    fn u16(&self, offset: usize) -> Result<u16, WriterError> {
        Ok(u16::from_le_bytes(self.slice(offset)?))
    }

    fn u32(&self, offset: usize) -> Result<u32, WriterError> {
        Ok(u32::from_le_bytes(self.slice(offset)?))
    }

    fn slice<const N: usize>(&self, offset: usize) -> Result<[u8; N], WriterError> {
        self.template
            .get(offset..offset + N)
            .ok_or_else(|| unsupported("template integer"))?
            .try_into()
            .map_err(|_| unsupported("template integer"))
    }
}

fn patch_layout(
    output: &mut [u8],
    prefix: &PrefixLayout,
    exports: &[(u32, u32)],
    buffers: &[BufferLayout],
    objects_end: u32,
    buffers_end: u32,
) -> Result<(), WriterError> {
    write_u32_at(output, 24, objects_end)?;
    write_u32_at(output, 28, buffers_end)?;
    let export_table = prefix.offsets[4];
    for (index, (offset, size)) in exports.iter().enumerate() {
        let entry = export_table + index * EXPORT_SIZE;
        write_u32_at(output, entry + 8, *size)?;
        write_u32_at(output, entry + 12, *offset)?;
    }
    patch_table_crc(output, prefix, 4, EXPORT_SIZE)?;
    let buffer_table = prefix.offsets[5];
    for (index, buffer) in buffers.iter().enumerate() {
        let entry = buffer_table + index * BUFFER_SIZE;
        write_u32_at(output, entry + 8, buffer.offset)?;
        write_u32_at(output, entry + 12, buffer.disk_size)?;
        write_u32_at(output, entry + 16, buffer.memory_size)?;
        write_u32_at(output, entry + 20, buffer.crc32)?;
    }
    patch_table_crc(output, prefix, 5, BUFFER_SIZE)?;
    let header_crc = calculate_header_crc(output)?;
    write_u32_at(output, 32, header_crc)?;
    Ok(())
}

fn collect_handle_ids(value: &Value, identities: &mut HashSet<String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_handle_ids(value, identities);
            }
        }
        Value::Object(object) => {
            if let Some(identity) = object.get("HandleId").and_then(Value::as_str) {
                identities.insert(identity.to_owned());
            } else {
                for value in object.values() {
                    collect_handle_ids(value, identities);
                }
            }
        }
        _ => {}
    }
}

fn collect_new_exports<'a>(
    document: &'a Value,
    file: &Cr2wInspection,
    candidate_handles: &RefCell<HashSet<String>>,
) -> Result<Vec<NewExport<'a>>, WriterError> {
    fn visit<'a>(
        value: &'a Value,
        definitions: &mut Vec<(String, &'a Value)>,
    ) -> Result<(), WriterError> {
        match value {
            Value::Array(values) => {
                for value in values {
                    visit(value, definitions)?;
                }
            }
            Value::Object(object) => {
                if object
                    .get("Type")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.contains("RedPackage"))
                {
                    return Ok(());
                }
                if let (Some(handle_id), Some(data)) = (
                    object.get("HandleId").and_then(Value::as_str),
                    object.get("Data"),
                ) {
                    definitions.push((handle_id.to_owned(), data));
                }
                for value in object.values() {
                    visit(value, definitions)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    let mut definitions = Vec::new();
    visit(document, &mut definitions)?;
    let candidate_handles = candidate_handles.borrow();
    let mut new_exports = Vec::new();
    let mut seen = HashMap::<String, &Value>::new();
    for (handle_id, value) in definitions {
        if !candidate_handles.contains(&handle_id) {
            continue;
        }
        if let Some(existing) = seen.insert(handle_id.clone(), value)
            && existing != value
        {
            return Err(unsupported("conflicting HandleId definitions"));
        }
        if new_exports
            .iter()
            .any(|export: &NewExport<'_>| export.handle_id == handle_id)
        {
            continue;
        }
        let class_name = value
            .get("$type")
            .and_then(Value::as_str)
            .ok_or_else(|| unsupported("new export class"))?
            .to_owned();
        let template_index = file
            .exports
            .iter()
            .position(|export| export.class_name == class_name)
            .ok_or_else(|| {
                unsupported(format!(
                    "new export class {class_name} has no template instance"
                ))
            })?;
        new_exports.push(NewExport {
            handle_id,
            value,
            class_name,
            template_index,
        });
    }
    Ok(new_exports)
}

#[expect(
    clippy::too_many_lines,
    reason = "table reconstruction stays linear so offsets and CRC inputs are auditable"
)]
fn build_prefix(
    template: &[u8],
    file: &Cr2wInspection,
    names: &[String],
    new_imports: &[NewImport],
    new_exports: &[NewExport<'_>],
) -> Result<(Vec<u8>, PrefixLayout), WriterError> {
    const ITEM_SIZES: [usize; 10] = [1, 8, 8, 16, 24, 24, 16, 0, 0, 0];
    let mut output = template
        .get(..160)
        .ok_or_else(|| unsupported("template header"))?
        .to_vec();
    let mut offsets = [0_usize; 10];
    let mut counts = [0_u32; 10];

    for table_index in 0..10 {
        let descriptor = &file.header.tables[table_index];
        let old_count =
            usize::try_from(descriptor.item_count).map_err(|_| WriterError::TooLarge)?;
        let item_size = ITEM_SIZES[table_index];
        let old_size = old_count
            .checked_mul(item_size)
            .ok_or(WriterError::TooLarge)?;
        let old_start = usize::try_from(descriptor.offset).map_err(|_| WriterError::TooLarge)?;
        let old_end = old_start
            .checked_add(old_size)
            .ok_or(WriterError::TooLarge)?;
        let mut table_data = if old_count == 0 {
            Vec::new()
        } else {
            template
                .get(old_start..old_end)
                .ok_or_else(|| unsupported("template table bounds"))?
                .to_vec()
        };

        if table_index == 0 {
            for name in names.iter().skip(file.names.len()) {
                table_data.extend_from_slice(name.as_bytes());
                table_data.push(0);
            }
            for import in new_imports {
                table_data.extend_from_slice(import.depot_path.as_bytes());
                table_data.push(0);
            }
        } else if table_index == 1 {
            let mut string_offset = usize::try_from(file.header.tables[0].item_count)
                .map_err(|_| WriterError::TooLarge)?;
            for name in names.iter().skip(file.names.len()) {
                table_data.extend_from_slice(
                    &u32::try_from(string_offset)
                        .map_err(|_| WriterError::TooLarge)?
                        .to_le_bytes(),
                );
                table_data.extend_from_slice(&short_cname_hash(name).to_le_bytes());
                string_offset = string_offset
                    .checked_add(name.len() + 1)
                    .ok_or(WriterError::TooLarge)?;
            }
        } else if table_index == 2 {
            let added_name_bytes =
                names
                    .iter()
                    .skip(file.names.len())
                    .try_fold(0_usize, |total, name| {
                        total
                            .checked_add(name.len() + 1)
                            .ok_or(WriterError::TooLarge)
                    })?;
            let mut string_offset = usize::try_from(file.header.tables[0].item_count)
                .map_err(|_| WriterError::TooLarge)?
                .checked_add(added_name_bytes)
                .ok_or(WriterError::TooLarge)?;
            let none_index = names
                .iter()
                .position(|name| name == "None")
                .and_then(|index| u16::try_from(index).ok())
                .ok_or_else(|| unsupported("CName table has no None entry"))?;
            for import in new_imports {
                table_data.extend_from_slice(
                    &u32::try_from(string_offset)
                        .map_err(|_| WriterError::TooLarge)?
                        .to_le_bytes(),
                );
                table_data.extend_from_slice(&none_index.to_le_bytes());
                table_data.extend_from_slice(&import.flags.to_le_bytes());
                string_offset = string_offset
                    .checked_add(import.depot_path.len() + 1)
                    .ok_or(WriterError::TooLarge)?;
            }
        } else if table_index == 4 {
            for export in new_exports {
                let class_index = names
                    .iter()
                    .position(|name| name == &export.class_name)
                    .and_then(|index| u16::try_from(index).ok())
                    .ok_or_else(|| unsupported("new export class name index"))?;
                table_data.extend_from_slice(&class_index.to_le_bytes());
                table_data.extend_from_slice(&0_u16.to_le_bytes());
                table_data.extend_from_slice(&0_u32.to_le_bytes());
                table_data.extend_from_slice(&0_u32.to_le_bytes());
                table_data.extend_from_slice(&0_u32.to_le_bytes());
                table_data.extend_from_slice(&0_u32.to_le_bytes());
                table_data.extend_from_slice(&0_u32.to_le_bytes());
            }
        }

        let count = if table_index == 0 {
            u32::try_from(table_data.len()).map_err(|_| WriterError::TooLarge)?
        } else {
            u32::try_from(table_data.len().checked_div(item_size).unwrap_or_default())
                .map_err(|_| WriterError::TooLarge)?
        };
        counts[table_index] = count;
        if count == 0 {
            write_u32_at(&mut output, TABLES_OFFSET + table_index * TABLE_SIZE, 0)?;
            write_u32_at(&mut output, TABLES_OFFSET + table_index * TABLE_SIZE + 4, 0)?;
            write_u32_at(&mut output, TABLES_OFFSET + table_index * TABLE_SIZE + 8, 0)?;
            continue;
        }
        offsets[table_index] = output.len();
        let table_offset = u32::try_from(output.len()).map_err(|_| WriterError::TooLarge)?;
        write_u32_at(
            &mut output,
            TABLES_OFFSET + table_index * TABLE_SIZE,
            table_offset,
        )?;
        write_u32_at(
            &mut output,
            TABLES_OFFSET + table_index * TABLE_SIZE + 4,
            count,
        )?;
        write_u32_at(
            &mut output,
            TABLES_OFFSET + table_index * TABLE_SIZE + 8,
            crc32fast::hash(&table_data),
        )?;
        output.extend_from_slice(&table_data);
    }
    Ok((output, PrefixLayout { offsets, counts }))
}

fn short_cname_hash(value: &str) -> u32 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    if value == "None" || value.is_empty() {
        return 0;
    }
    let hash = value.bytes().fold(OFFSET, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(PRIME)
    });
    let upper = u32::try_from(hash >> 32).expect("upper half of a u64 always fits in u32");
    let lower =
        u32::try_from(hash & u64::from(u32::MAX)).expect("masked lower half always fits in u32");
    upper ^ lower
}

fn collect_buffer_overrides(
    value: &Value,
    result: &mut HashMap<usize, BufferOverride>,
) -> Result<(), WriterError> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_buffer_overrides(value, result)?;
            }
        }
        Value::Object(object) => {
            if let Some(index) = object
                .get("BufferId")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<isize>().ok())
                .filter(|value| *value >= 0)
                .and_then(|value| usize::try_from(value).ok())
            {
                let replacement = if object
                    .get("Type")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.contains("worldNodeDataBuffer"))
                {
                    Some(BufferOverride {
                        bytes: encode_world_node_buffer(
                            object
                                .get("Data")
                                .and_then(Value::as_array)
                                .ok_or_else(|| unsupported("worldNodeDataBuffer.Data"))?,
                        )?,
                        stored: false,
                        memory_size: 0,
                    })
                } else if let Some(bytes) = object.get("Bytes").and_then(Value::as_str) {
                    Some(BufferOverride {
                        bytes: STANDARD.decode(bytes)?,
                        stored: false,
                        memory_size: 0,
                    })
                } else if let Some(bytes) = object.get("StoredBytes").and_then(Value::as_str) {
                    Some(BufferOverride {
                        bytes: STANDARD.decode(bytes)?,
                        stored: true,
                        memory_size: object
                            .get("MemorySize")
                            .and_then(Value::as_u64)
                            .and_then(|value| u32::try_from(value).ok())
                            .ok_or_else(|| unsupported("stored buffer MemorySize"))?,
                    })
                } else {
                    None
                };
                if let Some(replacement) = replacement {
                    result.insert(index, replacement);
                }
            }
            for child in object.values() {
                collect_buffer_overrides(child, result)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_redpackage_overrides(
    value: &Value,
    file: &Cr2wInspection,
    template: &[u8],
    classes: &BTreeSet<String>,
    kraken_path: &OsStr,
    result: &mut HashMap<usize, BufferOverride>,
) -> Result<(), WriterError> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_redpackage_overrides(value, file, template, classes, kraken_path, result)?;
            }
        }
        Value::Object(object) => {
            let is_package = object
                .get("Type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.contains("RedPackage"));
            if is_package {
                let index = object
                    .get("BufferId")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or_else(|| unsupported("RedPackage BufferId"))?;
                let data = object
                    .get("Data")
                    .ok_or_else(|| unsupported("RedPackage Data"))?;
                let template_package =
                    uncompressed_template_buffer(file, template, index, kraken_path)?;
                let imports_as_hash = redpackage::imports_are_hashed(&template_package)?;
                let bytes = redpackage::encode_with_template(
                    &template_package,
                    data,
                    classes,
                    PackageSettings {
                        imports_as_hash,
                        handle_id_base: 0,
                    },
                )?;
                result.insert(
                    index,
                    BufferOverride {
                        bytes,
                        stored: false,
                        memory_size: 0,
                    },
                );
                return Ok(());
            }
            for child in object.values() {
                collect_redpackage_overrides(child, file, template, classes, kraken_path, result)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn uncompressed_template_buffer(
    file: &Cr2wInspection,
    template: &[u8],
    index: usize,
    kraken_path: &OsStr,
) -> Result<Vec<u8>, WriterError> {
    let buffer = file
        .buffers
        .get(index)
        .ok_or_else(|| unsupported("RedPackage buffer index"))?;
    let start = usize::try_from(buffer.offset).map_err(|_| WriterError::TooLarge)?;
    let end = start
        .checked_add(usize::try_from(buffer.disk_size).map_err(|_| WriterError::TooLarge)?)
        .ok_or(WriterError::TooLarge)?;
    let stored = template
        .get(start..end)
        .ok_or_else(|| unsupported("RedPackage buffer bounds"))?;
    if stored.get(..4) != Some(b"KARK") {
        return Ok(stored.to_vec());
    }
    let declared = u32::from_le_bytes(
        stored
            .get(4..8)
            .ok_or_else(|| unsupported("RedPackage KARK header"))?
            .try_into()
            .map_err(|_| unsupported("RedPackage KARK header"))?,
    );
    if declared != buffer.memory_size {
        return Err(unsupported("RedPackage KARK memory size"));
    }
    Ok(archive::decompress_payload_isolated(
        stored
            .get(8..)
            .ok_or_else(|| unsupported("RedPackage KARK payload"))?,
        usize::try_from(declared).map_err(|_| WriterError::TooLarge)?,
        kraken_path,
    )?)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "world node vectors are explicitly stored as IEEE-754 binary32"
)]
fn encode_world_node_buffer(entries: &[Value]) -> Result<Vec<u8>, WriterError> {
    let mut output = Vec::with_capacity(entries.len() * 144);
    for entry in entries {
        let vector = |name: &str, component: &str| {
            entry
                .get(name)
                .and_then(|value| value.get(component))
                .and_then(Value::as_f64)
                .map(|value| value as f32)
                .ok_or_else(|| unsupported(format!("world node {name}.{component}")))
        };
        let nested_vector = |name: &str, side: &str, component: &str| {
            entry
                .get(name)
                .and_then(|value| value.get(side))
                .and_then(|value| value.get(component))
                .and_then(Value::as_f64)
                .map(|value| value as f32)
                .ok_or_else(|| unsupported(format!("world node {name}.{side}.{component}")))
        };
        for component in ["X", "Y", "Z", "W"] {
            output.extend_from_slice(&vector("Position", component)?.to_le_bytes());
        }
        for component in ["i", "j", "k", "r"] {
            output.extend_from_slice(&vector("Orientation", component)?.to_le_bytes());
        }
        for component in ["X", "Y", "Z"] {
            output.extend_from_slice(&vector("Scale", component)?.to_le_bytes());
        }
        for component in ["X", "Y", "Z"] {
            output.extend_from_slice(&vector("Pivot", component)?.to_le_bytes());
        }
        for component in ["X", "Y", "Z"] {
            output.extend_from_slice(&nested_vector("Bounds", "Min", component)?.to_le_bytes());
        }
        for component in ["X", "Y", "Z"] {
            output.extend_from_slice(&nested_vector("Bounds", "Max", component)?.to_le_bytes());
        }
        output.extend_from_slice(&json_field_u64(entry, "Id")?.to_le_bytes());
        output.extend_from_slice(&storage_field_u64(entry, "QuestPrefabRefHash")?.to_le_bytes());
        output.extend_from_slice(&storage_field_u64(entry, "UkHash1")?.to_le_bytes());
        output.extend_from_slice(
            &entry
                .pointer("/CookedPrefabData/DepotPath/$value")
                .and_then(Value::as_str)
                .ok_or_else(|| unsupported("world node CookedPrefabData"))?
                .parse::<u64>()
                .unwrap_or_else(|_| {
                    crate::archive::depot_path_hash(
                        entry
                            .pointer("/CookedPrefabData/DepotPath/$value")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    )
                })
                .to_le_bytes(),
        );
        for field in ["MaxStreamingDistance", "UkFloat1"] {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "world node storage is explicitly binary32"
            )]
            let value = entry
                .get(field)
                .and_then(Value::as_f64)
                .ok_or_else(|| unsupported(format!("world node {field}")))?
                as f32;
            output.extend_from_slice(&value.to_le_bytes());
        }
        for field in ["NodeIndex", "Uk10", "Uk11", "Uk12"] {
            let value = entry
                .get(field)
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| unsupported(format!("world node {field}")))?;
            output.extend_from_slice(&value.to_le_bytes());
        }
        for field in ["Uk13", "Uk14"] {
            output.extend_from_slice(&json_field_u64(entry, field)?.to_le_bytes());
        }
    }
    Ok(output)
}

fn json_field_u64(value: &Value, field: &str) -> Result<u64, WriterError> {
    value
        .get(field)
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .or_else(|| value.as_u64().map(|v| v.to_string()))
        })
        .ok_or_else(|| unsupported(format!("world node {field}")))?
        .parse()
        .map_err(|_| unsupported(format!("world node {field}")))
}

fn storage_field_u64(value: &Value, field: &str) -> Result<u64, WriterError> {
    let stored = value
        .get(field)
        .and_then(|value| value.get("$value"))
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported(format!("world node {field}")))?;
    Ok(stored
        .parse()
        .unwrap_or_else(|_| node_ref_hash_without_aliases(stored)))
}

fn node_ref_hash_without_aliases(value: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    if value.is_empty() {
        return 0;
    }
    let characters: Vec<char> = value.chars().collect();
    let mut hash = OFFSET;
    let mut index = 0;
    while index < characters.len() {
        if characters[index] == '#' {
            index += 1;
            if characters.get(index) == Some(&';') {
                index = characters[index..]
                    .iter()
                    .position(|character| *character == '/')
                    .map_or(characters.len(), |offset| index + offset);
            }
        }
        let Some(character) = characters.get(index) else {
            break;
        };
        hash = (hash ^ u64::from(u32::from(*character))).wrapping_mul(PRIME);
        index += 1;
    }
    hash
}

fn buffer_matches(
    stored: &[u8],
    memory_size: u32,
    replacement: &[u8],
    kraken_path: &OsStr,
) -> Result<bool, WriterError> {
    if stored.get(..4) != Some(b"KARK") {
        return Ok(stored == replacement);
    }
    let declared = u32::from_le_bytes(
        stored
            .get(4..8)
            .ok_or_else(|| unsupported("KARK header"))?
            .try_into()
            .map_err(|_| unsupported("KARK header"))?,
    );
    if declared != memory_size {
        return Err(unsupported("KARK memory size"));
    }
    match archive::decompress_payload_isolated(
        &stored[8..],
        usize::try_from(declared).map_err(|_| WriterError::TooLarge)?,
        kraken_path,
    ) {
        Ok(bytes) => Ok(bytes == replacement),
        // Some base-game buffers require Oodle rather than the fallback
        // Kraken DLL. Preserve them when no compatible decoder is available.
        Err(_) => Ok(false),
    }
}

fn patch_table_crc(
    output: &mut [u8],
    prefix: &PrefixLayout,
    table: usize,
    item_size: usize,
) -> Result<(), WriterError> {
    let count = prefix.counts[table];
    if count == 0 {
        return Ok(());
    }
    let start = prefix.offsets[table];
    let count = usize::try_from(count).map_err(|_| WriterError::TooLarge)?;
    let end = start
        .checked_add(count.checked_mul(item_size).ok_or(WriterError::TooLarge)?)
        .ok_or(WriterError::TooLarge)?;
    let crc = crc32fast::hash(
        output
            .get(start..end)
            .ok_or_else(|| unsupported("table CRC bounds"))?,
    );
    write_u32_at(output, TABLES_OFFSET + table * TABLE_SIZE + 8, crc)
}

fn calculate_header_crc(bytes: &[u8]) -> Result<u32, WriterError> {
    let mut header = bytes
        .get(..160)
        .ok_or_else(|| unsupported("CR2W header"))?
        .to_vec();
    header[32..36].copy_from_slice(&DEAD_BEEF.to_le_bytes());
    let mut hasher = Hasher::new();
    hasher.update(&header);
    Ok(hasher.finalize())
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), WriterError> {
    bytes
        .get_mut(offset..offset + 4)
        .ok_or_else(|| unsupported("patch bounds"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn encode_string(value: &str) -> Result<Vec<u8>, WriterError> {
    let length = u32::try_from(value.len()).map_err(|_| WriterError::TooLarge)?;
    let mut output = Vec::new();
    write_negative_vlq(&mut output, length);
    output.extend_from_slice(value.as_bytes());
    Ok(output)
}

fn write_negative_vlq(output: &mut Vec<u8>, value: u32) {
    let mut remaining = value;
    let low = u8::try_from(remaining & 0x3f).expect("masked to six bits");
    remaining >>= 6;
    output.push(0x80 | low | if remaining > 0 { 0x40 } else { 0 });
    while remaining > 0 {
        let byte = u8::try_from(remaining & 0x7f).expect("masked to seven bits");
        remaining >>= 7;
        output.push(byte | if remaining > 0 { 0x80 } else { 0 });
    }
}

fn fixed_size(red_type: &str) -> Option<usize> {
    match red_type {
        "Bool" | "Int8" | "Uint8" => Some(1),
        "Int16" | "Uint16" | "CName" => Some(2),
        "Int32" | "Uint32" | "Float" => Some(4),
        "Int64"
        | "Uint64"
        | "Double"
        | "CRUID"
        | "CDateTime"
        | "TweakDBID"
        | "gamedataLocKeyWrapper" => Some(8),
        value if value.starts_with("handle:") || value.starts_with("whandle:") => Some(4),
        value if value.starts_with("rRef:") || value.starts_with("raRef:") => Some(2),
        _ => None,
    }
}

fn storage_value(value: &Value) -> Result<&str, WriterError> {
    value
        .get("$value")
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported("storage value"))
}

fn storage_or_string(value: &Value) -> Result<&str, WriterError> {
    value
        .as_str()
        .or_else(|| value.get("$value").and_then(Value::as_str))
        .ok_or_else(|| unsupported("storage/string value"))
}

fn tweak_db_id(value: &str) -> Result<u64, WriterError> {
    if let Ok(number) = value.parse() {
        return Ok(number);
    }
    let length = u64::try_from(value.len()).map_err(|_| WriterError::TooLarge)?;
    Ok(u64::from(crc32fast::hash(value.as_bytes())) | (length << 32))
}

fn json_bool(value: &Value) -> Result<bool, WriterError> {
    value
        .as_bool()
        .or_else(|| value.as_u64().map(|number| number != 0))
        .ok_or_else(|| unsupported("Bool value"))
}

fn json_i64(value: &Value) -> Result<i64, WriterError> {
    value.as_i64().ok_or_else(|| unsupported("integer value"))
}

fn json_u64(value: &Value) -> Result<u64, WriterError> {
    value.as_u64().ok_or_else(|| unsupported("integer value"))
}

fn json_f64(value: &Value) -> Result<f64, WriterError> {
    value.as_f64().ok_or_else(|| unsupported("float value"))
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "RED Float is explicitly IEEE-754 binary32; JSON numbers are binary64"
)]
fn json_f32(value: &Value) -> Result<f32, WriterError> {
    Ok(json_f64(value)? as f32)
}

fn json_string_i64(value: &Value) -> Result<i64, WriterError> {
    value
        .as_str()
        .ok_or_else(|| unsupported("Int64 string"))?
        .parse()
        .map_err(|_| unsupported("Int64 string"))
}

fn json_string_u64(value: &Value) -> Result<u64, WriterError> {
    value
        .as_str()
        .ok_or_else(|| unsupported("Uint64 string"))?
        .parse()
        .map_err(|_| unsupported("Uint64 string"))
}

fn unsupported(message: impl Into<String>) -> WriterError {
    WriterError::Unsupported(message.into())
}

#[cfg(test)]
mod tests {
    use super::write_with_template;
    use crate::{codec, schema};
    use std::{
        collections::{BTreeSet, HashMap},
        env,
        ffi::OsStr,
        fs,
        path::PathBuf,
    };

    #[test]
    #[ignore = "real CR2W round-trip test; requires CR2W_FIXTURE and RED_SCHEMA"]
    fn serialized_cr2w_fixture_round_trips_and_applies_edits() {
        let fixture = env::var_os("CR2W_FIXTURE").map(PathBuf::from).unwrap();
        let schema_path = env::var_os("RED_SCHEMA").map(PathBuf::from).unwrap();
        let classes: HashMap<String, schema::RedClass> =
            serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
        let class_names: BTreeSet<String> = classes.into_keys().collect();
        let missing_dll = OsStr::new("missing-kraken.dll");
        let mut document = codec::decode_wkit(&fixture, &class_names, missing_dll).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let json_path = workspace.path().join("fixture.json");
        let output_path = workspace.path().join("roundtrip.cr2w");
        fs::write(&json_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();

        write_with_template(
            &json_path,
            &fixture,
            &output_path,
            &class_names,
            missing_dll,
        )
        .unwrap();

        assert_eq!(fs::read(&output_path).unwrap(), fs::read(&fixture).unwrap());

        let replacement = document
            .pointer("/Data/RootChunk/autoFoliageMapping/DepotPath/$value")
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_owned();
        let target = document
            .pointer_mut("/Data/RootChunk/areaResource/DepotPath/$value")
            .unwrap();
        *target = serde_json::Value::String(replacement.clone());
        fs::write(&json_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
        write_with_template(
            &json_path,
            &fixture,
            &output_path,
            &class_names,
            missing_dll,
        )
        .unwrap();
        let decoded = codec::decode_wkit(&output_path, &class_names, missing_dll).unwrap();

        assert_ne!(fs::read(&output_path).unwrap(), fs::read(&fixture).unwrap());
        assert_eq!(
            decoded
                .pointer("/Data/RootChunk/areaResource/DepotPath/$value")
                .and_then(serde_json::Value::as_str),
            Some(replacement.as_str())
        );
    }
}
