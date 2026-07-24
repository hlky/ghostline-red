//! Dynamic CR2W value decoding driven by on-disk RED type names.

use crate::{
    archive::{self, ArchiveError},
    cr2w::{self, Cr2wError, Cr2wInspection},
    redpackage::{self, PackageError, PackageSettings},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeSet, HashSet},
    ffi::OsStr,
    fmt::Write as _,
    fs, io,
    path::Path,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("could not access CR2W input: {0}")]
    Io(#[from] io::Error),
    #[error("invalid CR2W input: {0}")]
    Cr2w(#[from] Cr2wError),
    #[error("malformed RED value at byte {offset}: {reason}")]
    Malformed { offset: usize, reason: &'static str },
    #[error("unsupported RED type {red_type}")]
    Unsupported { red_type: String },
    #[error("could not decompress CR2W buffer: {0}")]
    Archive(#[from] ArchiveError),
    #[error("could not decode RedPackage buffer: {0}")]
    Package(#[from] PackageError),
}

struct Decoder<'a> {
    bytes: &'a [u8],
    file: &'a Cr2wInspection,
    classes: &'a BTreeSet<String>,
    kraken_path: &'a OsStr,
}

/// Decodes all reflected CR2W exports to a dynamic JSON representation.
///
/// # Errors
///
/// Returns [`CodecError`] for malformed metadata, bounds violations, custom
/// appendices, or RED value encodings not yet implemented.
pub fn decode_exports(
    path: &Path,
    classes: &BTreeSet<String>,
    kraken_path: &OsStr,
) -> Result<Value, CodecError> {
    let file = cr2w::inspect(path)?;
    let bytes = fs::read(path)?;
    let decoder = Decoder {
        bytes: &bytes,
        file: &file,
        classes,
        kraken_path,
    };
    let exports = file
        .exports
        .iter()
        .enumerate()
        .map(|(index, export)| {
            let start = usize::try_from(export.data_offset).map_err(|_| malformed(0, "offset"))?;
            let size = usize::try_from(export.data_size).map_err(|_| malformed(start, "size"))?;
            let (value, consumed) = decoder.read_class(&export.class_name, start, size)?;
            if consumed != start + size {
                return Err(malformed(consumed, "export trailing bytes"));
            }
            Ok(json!({"index": index, "$type": export.class_name, "value": value}))
        })
        .collect::<Result<Vec<_>, CodecError>>()?;
    Ok(json!({ "exports": exports }))
}

/// Decodes a CR2W file into the recursive handle shape used by `WKit` JSON.
///
/// # Errors
///
/// Returns [`CodecError`] under the same conditions as [`decode_exports`], or
/// when an encoded handle points outside the export table.
pub fn decode_wkit(
    path: &Path,
    classes: &BTreeSet<String>,
    kraken_path: &OsStr,
) -> Result<Value, CodecError> {
    let flat = decode_exports(path, classes, kraken_path)?;
    let exports = flat
        .get("exports")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(0, "exports"))?
        .iter()
        .map(|export| {
            export
                .get("value")
                .cloned()
                .ok_or_else(|| malformed(0, "export value"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let root = exports
        .first()
        .cloned()
        .ok_or_else(|| malformed(0, "root export"))?;
    let mut visited = HashSet::new();
    let root = expand_handles(root, &exports, &mut visited)?;
    let inspection = cr2w::inspect(path)?;
    let embedded = inspection
        .embedded
        .iter()
        .map(|item| {
            let chunk = usize::try_from(item.chunk_index)
                .ok()
                .and_then(|index| exports.get(index))
                .cloned()
                .ok_or_else(|| malformed(0, "embedded chunk"))?;
            Ok(json!({
                "FileName": {
                    "$type": "ResourcePath",
                    "$storage": "string",
                    "$value": item.depot_path
                },
                "Content": expand_handles(chunk, &exports, &mut visited)?
            }))
        })
        .collect::<Result<Vec<_>, CodecError>>()?;
    let mut data = json!({
        "Version": inspection.header.version,
        "BuildVersion": inspection.header.build_version,
        "RootChunk": root
    });
    if !embedded.is_empty() {
        let object = data
            .as_object_mut()
            .ok_or_else(|| malformed(0, "document data"))?;
        object.insert("EmbeddedFiles".to_owned(), Value::Array(embedded));
    }
    Ok(json!({
        "Header": {
            "WolvenKitVersion": "ghostline-red 0.1.0",
            "WKitJsonVersion": "0.0.9",
            "GameVersion": 2310,
            "ExportedDateTime": "1970-01-01T00:00:00Z",
            "DataType": "CR2W",
            "ArchiveFileName": path.to_string_lossy()
        },
        "Data": data
    }))
}

fn expand_handles(
    value: Value,
    exports: &[Value],
    visited: &mut HashSet<usize>,
) -> Result<Value, CodecError> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(|value| expand_handles(value, exports, visited))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(mut object) if object.len() == 1 && object.contains_key("$handle") => {
            let index = object
                .remove("$handle")
                .and_then(|value| value.as_u64())
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| malformed(0, "handle index"))?;
            if !visited.insert(index) {
                let handle_id = index
                    .checked_sub(1)
                    .ok_or_else(|| malformed(0, "root handle reference"))?;
                return Ok(json!({"HandleRefId": handle_id.to_string()}));
            }
            let data = exports
                .get(index)
                .cloned()
                .ok_or_else(|| malformed(0, "handle export"))?;
            let handle_id = index
                .checked_sub(1)
                .ok_or_else(|| malformed(0, "root handle"))?;
            Ok(json!({
                "HandleId": handle_id.to_string(),
                "Data": expand_handles(data, exports, visited)?
            }))
        }
        Value::Object(object) => object
            .into_iter()
            .map(|(key, value)| Ok((key, expand_handles(value, exports, visited)?)))
            .collect::<Result<Map<_, _>, CodecError>>()
            .map(Value::Object),
        scalar => Ok(scalar),
    }
}

impl Decoder<'_> {
    fn read_class(
        &self,
        red_type: &str,
        start: usize,
        size: usize,
    ) -> Result<(Value, usize), CodecError> {
        let end = start
            .checked_add(size)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed(start, "class bounds"))?;
        if red_type == "AreaShapeOutline" {
            return Ok((
                json!({
                    "$type": red_type,
                    "buffer": STANDARD.encode(&self.bytes[start..end])
                }),
                end,
            ));
        }
        let mut cursor = start;
        if self.byte(cursor)? != 0 {
            return Err(malformed(cursor, "class marker"));
        }
        cursor += 1;
        let mut object = Map::new();
        object.insert("$type".to_owned(), Value::String(red_type.to_owned()));
        loop {
            let name_index = usize::from(self.u16(cursor)?);
            cursor += 2;
            if name_index == 0 {
                break;
            }
            let type_index = usize::from(self.u16(cursor)?);
            cursor += 2;
            let total_size = usize::try_from(self.u32(cursor)?)
                .map_err(|_| malformed(cursor, "property size"))?;
            cursor += 4;
            let payload_size = total_size
                .checked_sub(4)
                .ok_or_else(|| malformed(cursor, "property size"))?;
            let payload_end = cursor
                .checked_add(payload_size)
                .filter(|value| *value <= end)
                .ok_or_else(|| malformed(cursor, "property bounds"))?;
            let property = self.name(name_index, cursor)?.to_owned();
            let property_type = self.name(type_index, cursor)?.to_owned();
            let (value, consumed) = if matches!(
                property_type.as_str(),
                "DataBuffer" | "serializationDeferredDataBuffer"
            ) && is_redpackage_property(red_type, &property)
            {
                let index = if property_type == "DataBuffer" {
                    let encoded = self.u32(cursor)?;
                    usize::try_from(
                        encoded
                            .checked_sub(0x8000_0001)
                            .ok_or_else(|| malformed(cursor, "RedPackage buffer pointer"))?,
                    )
                    .map_err(|_| malformed(cursor, "RedPackage buffer index"))?
                } else {
                    usize::from(
                        self.u16(cursor)?
                            .checked_sub(1)
                            .ok_or_else(|| malformed(cursor, "RedPackage deferred pointer"))?,
                    )
                };
                (
                    self.package_buffer(
                        index,
                        cursor,
                        red_type == "appearanceAppearanceDefinition"
                            || (red_type == "entEntityTemplate"
                                && self.file.exports.first().is_some_and(|export| {
                                    export.class_name == "appearanceAppearanceResource"
                                })),
                    )?,
                    payload_end,
                )
            } else {
                self.read_value(&property_type, cursor, payload_size)?
            };
            if consumed != payload_end {
                return Err(malformed(consumed, "property trailing bytes"));
            }
            object.insert(property, value);
            cursor = payload_end;
        }
        cursor = match red_type {
            "worldStreamingSector" => {
                self.read_streaming_sector_appendix(cursor, end, &mut object)?
            }
            "gameDeviceResourceData" => self.read_device_data_appendix(cursor, end, &mut object)?,
            "CMaterialInstance" => {
                self.read_material_instance_appendix(cursor, end, &mut object)?
            }
            "worldStreamingWorld" => end,
            _ => cursor,
        };
        Ok((Value::Object(object), cursor))
    }

    fn read_streaming_sector_appendix(
        &self,
        mut cursor: usize,
        end: usize,
        object: &mut Map<String, Value>,
    ) -> Result<usize, CodecError> {
        object.insert("version".to_owned(), json!(self.u32(cursor)?.cast_signed()));
        cursor += 4;
        let _inner_size = self.u32(cursor)?;
        cursor += 4;
        object.insert(
            "nodeData".to_owned(),
            self.world_node_buffer(self.u32(cursor)?, cursor)?,
        );
        cursor += 4;

        let (node_count, next) = self.vlq(cursor)?;
        cursor = next;
        let mut nodes = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            nodes.push(json!({"$handle": self.u32(cursor)?.wrapping_sub(1)}));
            cursor += 4;
        }
        object.insert("nodes".to_owned(), Value::Array(nodes));

        let (reference_count, next) = self.vlq(cursor)?;
        cursor = next;
        let mut references = Vec::with_capacity(reference_count);
        for _ in 0..reference_count {
            let (reference, next) = self.string(cursor)?;
            references.push(storage_string("NodeRef", &reference));
            cursor = next;
        }
        object.insert("nodeRefs".to_owned(), Value::Array(references));

        let (variant_count, next) = self.vlq(cursor)?;
        cursor = next;
        let mut variants = Vec::with_capacity(variant_count);
        for _ in 0..variant_count {
            variants.push(json!(self.u32(cursor)?.cast_signed()));
            cursor += 4;
        }
        object.insert("variantIndices".to_owned(), Value::Array(variants));
        object.insert(
            "persistentNodeIndex".to_owned(),
            json!(self.u32(cursor)?.cast_signed()),
        );
        cursor += 4;
        if cursor > end {
            return Err(malformed(cursor, "streaming sector appendix"));
        }
        Ok(cursor)
    }

    fn read_device_data_appendix(
        &self,
        mut cursor: usize,
        end: usize,
        object: &mut Map<String, Value>,
    ) -> Result<usize, CodecError> {
        let _inner_size = self.u32(cursor)?;
        cursor += 4;
        let count =
            usize::try_from(self.u32(cursor)?).map_err(|_| malformed(cursor, "device count"))?;
        cursor += 4;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let hash = self.u64(cursor)?;
            cursor += 8;
            let class_name = self.name(usize::from(self.u16(cursor)?), cursor)?;
            cursor += 2;
            let (child_count, next) = self.vlq(cursor)?;
            cursor = next;
            let (parent_count, next) = self.vlq(cursor)?;
            cursor = next;
            let mut children = Vec::with_capacity(child_count);
            for _ in 0..child_count {
                children.push(Value::String(self.u64(cursor)?.to_string()));
                cursor += 8;
            }
            let mut parents = Vec::with_capacity(parent_count);
            for _ in 0..parent_count {
                parents.push(Value::String(self.u64(cursor)?.to_string()));
                cursor += 8;
            }
            let x = f32::from_bits(self.u32(cursor)?);
            let y = f32::from_bits(self.u32(cursor + 4)?);
            let z = f32::from_bits(self.u32(cursor + 8)?);
            cursor += 12;
            entries.push(json!({
                "$type": "gameDeviceResourceData_Cls1",
                "hash": hash.to_string(),
                "className": storage_string("CName", class_name),
                "children": children,
                "parents": parents,
                "nodePosition": {"$type": "Vector3", "X": x, "Y": y, "Z": z}
            }));
        }
        object.insert("unk1".to_owned(), Value::Array(entries));
        if cursor > end {
            return Err(malformed(cursor, "device data appendix"));
        }
        Ok(cursor)
    }

    fn read_material_instance_appendix(
        &self,
        mut cursor: usize,
        end: usize,
        object: &mut Map<String, Value>,
    ) -> Result<usize, CodecError> {
        let count =
            usize::try_from(self.u32(cursor)?).map_err(|_| malformed(cursor, "material count"))?;
        cursor += 4;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let total_size = usize::try_from(self.u32(cursor)?)
                .map_err(|_| malformed(cursor, "material value size"))?;
            let entry_end = cursor
                .checked_add(total_size)
                .filter(|value| *value <= end)
                .ok_or_else(|| malformed(cursor, "material value bounds"))?;
            cursor += 4;
            let name = self
                .name(usize::from(self.u16(cursor)?), cursor)?
                .to_owned();
            cursor += 2;
            let red_type = self
                .name(usize::from(self.u16(cursor)?), cursor)?
                .to_owned();
            cursor += 2;
            let (value, consumed) =
                self.read_value(&red_type, cursor, entry_end.saturating_sub(cursor))?;
            if consumed != entry_end {
                return Err(malformed(consumed, "material value trailing bytes"));
            }
            values.push(json!({"$type": red_type, name: value}));
            cursor = entry_end;
        }
        object.insert("values".to_owned(), Value::Array(values));
        Ok(cursor)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the contiguous match is an auditable RED binary type dispatch table"
    )]
    fn read_value(
        &self,
        red_type: &str,
        start: usize,
        size: usize,
    ) -> Result<(Value, usize), CodecError> {
        let end = start
            .checked_add(size)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed(start, "value bounds"))?;
        let exact = |value| Ok((value, end));
        match red_type {
            "Bool" => exact(json!(self.byte(start)? != 0)),
            "Int8" => exact(json!(self.byte(start)?.cast_signed())),
            "Uint8" => exact(json!(self.byte(start)?)),
            "Int16" => exact(json!(self.u16(start)?.cast_signed())),
            "Uint16" => exact(json!(self.u16(start)?)),
            "Int32" => exact(json!(self.u32(start)?.cast_signed())),
            "Uint32" => exact(json!(self.u32(start)?)),
            "Int64" => exact(Value::String(self.u64(start)?.cast_signed().to_string())),
            "Uint64" | "CRUID" | "CDateTime" => exact(Value::String(self.u64(start)?.to_string())),
            "Float" => exact(json!(f32::from_bits(self.u32(start)?))),
            "Double" => exact(json!(f64::from_bits(self.u64(start)?))),
            "CName" => exact(storage_string(
                "CName",
                self.name(usize::from(self.u16(start)?), start)?,
            )),
            "String" => {
                let (value, consumed) = self.string(start)?;
                Ok((Value::String(value), consumed))
            }
            "NodeRef" => {
                let (value, consumed) = self.string(start)?;
                Ok((storage_string("NodeRef", &value), consumed))
            }
            "TweakDBID" => exact(storage_u64("TweakDBID", self.u64(start)?)),
            "gamedataLocKeyWrapper" => exact(json!({
                "unk1": "0", "value": self.u64(start)?.to_string()
            })),
            "LocalizationString" => {
                let unknown = self.u64(start)?;
                let (value, consumed) = self.string(start + 8)?;
                Ok((
                    json!({"unk1": unknown.to_string(), "value": value}),
                    consumed,
                ))
            }
            "DataBuffer" => exact(self.data_buffer(self.u32(start)?, start, end)?),
            "serializationDeferredDataBuffer" => {
                let encoded = self.u16(start)?;
                let pointer = encoded
                    .checked_sub(1)
                    .ok_or_else(|| malformed(start, "deferred buffer pointer"))?;
                exact(self.table_buffer(usize::from(pointer), start)?)
            }
            "CGUID" => exact(json!({"$type": "CGUID", "$bytes": hex(&self.bytes[start..end])})),
            _ if red_type.starts_with("array:") => {
                self.read_counted_array(&red_type[6..], start, size, None)
            }
            _ if red_type.starts_with("static:") => {
                let (count, inner) =
                    split_count_type(&red_type[7..]).ok_or_else(|| unsupported(red_type))?;
                self.read_counted_array(inner, start, size, Some(count))
            }
            _ if red_type.starts_with("handle:") || red_type.starts_with("whandle:") => {
                exact(json!({"$handle": self.u32(start)?.wrapping_sub(1)}))
            }
            _ if red_type.starts_with("rRef:") || red_type.starts_with("raRef:") => {
                let index = usize::from(self.u16(start)?);
                let (path, flags) = if index == 0 {
                    ("0".to_owned(), "Default".to_owned())
                } else {
                    let import = self
                        .file
                        .imports
                        .get(index - 1)
                        .ok_or_else(|| malformed(start, "import index"))?;
                    (import.depot_path.clone(), import_flags(import.flags))
                };
                exact(json!({
                    "DepotPath": {
                        "$type": "ResourcePath",
                        "$storage": if index == 0 { "uint64" } else { "string" },
                        "$value": path
                    },
                    "Flags": flags
                }))
            }
            _ if self.classes.contains(red_type) => self.read_class(red_type, start, size),
            _ if size == 2 => exact(Value::String(
                self.name(usize::from(self.u16(start)?), start)?.to_owned(),
            )),
            _ if size >= 4 && size.is_multiple_of(2) && self.u16(end - 2)? == 0 => {
                let mut cursor = start;
                let mut values = Vec::new();
                while cursor < end {
                    let index = usize::from(self.u16(cursor)?);
                    cursor += 2;
                    if index == 0 {
                        break;
                    }
                    values.push(self.name(index, cursor)?.to_owned());
                }
                exact(Value::String(values.join(", ")))
            }
            _ => Err(unsupported(red_type)),
        }
    }

    fn read_counted_array(
        &self,
        inner: &str,
        start: usize,
        size: usize,
        maximum: Option<usize>,
    ) -> Result<(Value, usize), CodecError> {
        let end = start + size;
        let count =
            usize::try_from(self.u32(start)?).map_err(|_| malformed(start, "array count"))?;
        if maximum.is_some_and(|limit| count > limit) {
            return Err(malformed(start, "static array count"));
        }
        let mut cursor = start + 4;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let element_size = fixed_size(inner).unwrap_or(end.saturating_sub(cursor));
            let (value, consumed) = self.read_value(inner, cursor, element_size)?;
            if consumed <= cursor || consumed > end {
                return Err(malformed(cursor, "array element bounds"));
            }
            values.push(value);
            cursor = consumed;
        }
        if cursor != end {
            return Err(malformed(cursor, "array trailing bytes"));
        }
        Ok((Value::Array(values), cursor))
    }

    fn string(&self, start: usize) -> Result<(String, usize), CodecError> {
        let first = self.byte(start)?;
        let utf8 = first & 0x80 != 0;
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
        let byte_length = if utf8 {
            length
        } else {
            length
                .checked_mul(2)
                .ok_or_else(|| malformed(start, "string length"))?
        };
        let end = cursor
            .checked_add(byte_length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed(cursor, "string bounds"))?;
        let value = if utf8 {
            std::str::from_utf8(&self.bytes[cursor..end])
                .map_err(|_| malformed(cursor, "UTF-8"))?
                .to_owned()
        } else {
            let words = self.bytes[cursor..end]
                .chunks_exact(2)
                .map(|word| u16::from_le_bytes([word[0], word[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&words).map_err(|_| malformed(cursor, "UTF-16"))?
        };
        Ok((value, end))
    }

    fn vlq(&self, start: usize) -> Result<(usize, usize), CodecError> {
        let first = self.byte(start)?;
        if first & 0x80 != 0 {
            return Err(malformed(start, "negative count"));
        }
        let mut value = usize::from(first & 0x3f);
        let mut cursor = start + 1;
        if first & 0x40 != 0 {
            let mut shift = 6;
            loop {
                let byte = self.byte(cursor)?;
                cursor += 1;
                value |= usize::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
                if shift > 27 {
                    return Err(malformed(start, "VLQ count"));
                }
            }
        }
        Ok((value, cursor))
    }

    fn name(&self, index: usize, offset: usize) -> Result<&str, CodecError> {
        self.file
            .names
            .get(index)
            .map(|name| name.value.as_str())
            .ok_or_else(|| malformed(offset, "name index"))
    }

    fn data_buffer(&self, encoded: u32, start: usize, end: usize) -> Result<Value, CodecError> {
        if encoded == 0x8000_0000 {
            return Ok(json!({"BufferId": "-1", "Flags": 0, "Bytes": ""}));
        }
        if encoded > 0x8000_0000 {
            let pointer = usize::try_from((encoded ^ 0x8000_0000) - 1)
                .map_err(|_| malformed(start, "buffer pointer"))?;
            return self.table_buffer(pointer, start);
        }
        let length =
            usize::try_from(encoded).map_err(|_| malformed(start, "inline buffer length"))?;
        let payload_end = start
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
            .filter(|value| *value <= end)
            .ok_or_else(|| malformed(start, "inline buffer bounds"))?;
        Ok(json!({
            "BufferId": "-1",
            "Flags": 0,
            "Bytes": STANDARD.encode(&self.bytes[start + 4..payload_end])
        }))
    }

    fn table_buffer(&self, index: usize, offset: usize) -> Result<Value, CodecError> {
        let (buffer, bytes, stored) = self.buffer(index, offset, true)?;
        if stored {
            return Ok(json!({
                "BufferId": index.to_string(),
                "Flags": buffer.flags,
                "Compression": "KARK",
                "DiskSize": buffer.disk_size,
                "MemorySize": buffer.memory_size,
                "StoredBytes": STANDARD.encode(&bytes)
            }));
        }
        Ok(json!({
            "BufferId": index.to_string(),
            "Flags": buffer.flags,
            "Bytes": STANDARD.encode(&bytes)
        }))
    }

    fn package_buffer(
        &self,
        index: usize,
        offset: usize,
        imports_as_hash: bool,
    ) -> Result<Value, CodecError> {
        let (buffer, bytes, _) = self.buffer(index, offset, false)?;
        let handle_id_base = self
            .file
            .exports
            .len()
            .checked_add(index.saturating_mul(65_536))
            .ok_or_else(|| malformed(offset, "RedPackage handle ID base"))?;
        let data = redpackage::decode(
            &bytes,
            self.classes,
            PackageSettings {
                imports_as_hash,
                handle_id_base,
            },
        )?;
        Ok(json!({
            "BufferId": index.to_string(),
            "Flags": buffer.flags,
            "Type": "WolvenKit.RED4.Archive.Buffer.RedPackage, WolvenKit.RED4, Version=8.17.4.0, Culture=neutral, PublicKeyToken=null",
            "Data": data
        }))
    }

    fn world_node_buffer(&self, encoded: u32, offset: usize) -> Result<Value, CodecError> {
        if encoded <= 0x8000_0000 {
            return Err(malformed(offset, "world node buffer pointer"));
        }
        let index = usize::try_from((encoded ^ 0x8000_0000) - 1)
            .map_err(|_| malformed(offset, "world node buffer index"))?;
        let (buffer, bytes, _) = self.buffer(index, offset, false)?;
        if !bytes.len().is_multiple_of(144) {
            return Err(malformed(offset, "world node buffer size"));
        }
        let mut entries = Vec::with_capacity(bytes.len() / 144);
        for entry in bytes.chunks_exact(144) {
            let f32_at =
                |at| f32::from_le_bytes([entry[at], entry[at + 1], entry[at + 2], entry[at + 3]]);
            let u16_at = |at| u16::from_le_bytes([entry[at], entry[at + 1]]);
            let u64_at = |at| {
                u64::from_le_bytes([
                    entry[at],
                    entry[at + 1],
                    entry[at + 2],
                    entry[at + 3],
                    entry[at + 4],
                    entry[at + 5],
                    entry[at + 6],
                    entry[at + 7],
                ])
            };
            entries.push(json!({
                "Id": u64_at(80).to_string(),
                "NodeIndex": u16_at(120),
                "Position": {"$type":"Vector4","W":f32_at(12),"X":f32_at(0),"Y":f32_at(4),"Z":f32_at(8)},
                "Orientation": {"$type":"Quaternion","i":f32_at(16),"j":f32_at(20),"k":f32_at(24),"r":f32_at(28)},
                "Scale": {"$type":"Vector3","X":f32_at(32),"Y":f32_at(36),"Z":f32_at(40)},
                "Pivot": {"$type":"Vector3","X":f32_at(44),"Y":f32_at(48),"Z":f32_at(52)},
                "Bounds": {
                    "$type":"Box",
                    "Min":{"$type":"Vector4","W":0.0,"X":f32_at(56),"Y":f32_at(60),"Z":f32_at(64)},
                    "Max":{"$type":"Vector4","W":0.0,"X":f32_at(68),"Y":f32_at(72),"Z":f32_at(76)}
                },
                "QuestPrefabRefHash": storage_u64("NodeRef",u64_at(88)),
                "UkHash1": storage_u64("NodeRef",u64_at(96)),
                "CookedPrefabData": {
                    "DepotPath": storage_u64("ResourcePath",u64_at(104)),
                    "Flags":"Default"
                },
                "MaxStreamingDistance":f32_at(112),
                "UkFloat1":f32_at(116),
                "Uk10":u16_at(122),
                "Uk11":u16_at(124),
                "Uk12":u16_at(126),
                "Uk13":u64_at(128).to_string(),
                "Uk14":u64_at(136).to_string()
            }));
        }
        Ok(json!({
            "BufferId": index.to_string(),
            "Flags": buffer.flags,
            "Type": "WolvenKit.RED4.Archive.Buffer.worldNodeDataBuffer, WolvenKit.RED4, Version=8.17.4.0, Culture=neutral, PublicKeyToken=null",
            "Data": entries
        }))
    }

    fn buffer(
        &self,
        index: usize,
        offset: usize,
        allow_stored_fallback: bool,
    ) -> Result<(&crate::cr2w::Cr2wBuffer, Vec<u8>, bool), CodecError> {
        let buffer = self
            .file
            .buffers
            .get(index)
            .ok_or_else(|| malformed(offset, "buffer index"))?;
        let start =
            usize::try_from(buffer.offset).map_err(|_| malformed(offset, "buffer offset"))?;
        let size =
            usize::try_from(buffer.disk_size).map_err(|_| malformed(offset, "buffer size"))?;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed(start, "buffer bounds"))?;
        let stored = &self.bytes[start..end];
        let (bytes, is_stored) =
            if buffer.disk_size != buffer.memory_size && stored.get(..4) == Some(b"KARK") {
                let declared = u32::from_le_bytes(
                    stored[4..8]
                        .try_into()
                        .map_err(|_| malformed(start, "KARK header"))?,
                );
                if declared != buffer.memory_size {
                    return Err(malformed(start, "KARK memory size"));
                }
                match archive::decompress_payload_isolated(
                    &stored[8..],
                    usize::try_from(declared).map_err(|_| malformed(start, "KARK size"))?,
                    self.kraken_path,
                ) {
                    Ok(bytes) => (bytes, false),
                    Err(_) if allow_stored_fallback => (stored.to_vec(), true),
                    Err(error) => return Err(error.into()),
                }
            } else {
                (stored.to_vec(), false)
            };
        Ok((buffer, bytes, is_stored))
    }

    fn byte(&self, offset: usize) -> Result<u8, CodecError> {
        self.bytes
            .get(offset)
            .copied()
            .ok_or_else(|| malformed(offset, "byte"))
    }

    fn u16(&self, offset: usize) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.slice(offset)?))
    }

    fn u32(&self, offset: usize) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.slice(offset)?))
    }

    fn u64(&self, offset: usize) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.slice(offset)?))
    }

    fn slice<const N: usize>(&self, offset: usize) -> Result<[u8; N], CodecError> {
        self.bytes
            .get(offset..offset + N)
            .ok_or_else(|| malformed(offset, "integer bounds"))?
            .try_into()
            .map_err(|_| malformed(offset, "integer"))
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
        "CGUID" => Some(16),
        value if value.starts_with("handle:") || value.starts_with("whandle:") => Some(4),
        value if value.starts_with("rRef:") || value.starts_with("raRef:") => Some(2),
        _ => None,
    }
}

fn is_redpackage_property(class_name: &str, property_name: &str) -> bool {
    matches!(
        (class_name, property_name),
        (
            "appearanceAppearanceDefinition" | "entEntityTemplate",
            "compiledData"
        ) | ("inkWidgetLibraryItem", "packageData")
            | (
                "entEntityInstanceData" | "gamePersistentStateDataResource",
                "buffer"
            )
    )
}

fn split_count_type(value: &str) -> Option<(usize, &str)> {
    let (count, inner) = value.split_once(',')?;
    Some((count.parse().ok()?, inner))
}

fn storage_string(red_type: &str, value: &str) -> Value {
    json!({"$type": red_type, "$storage": "string", "$value": value})
}

fn storage_u64(red_type: &str, value: u64) -> Value {
    json!({"$type": red_type, "$storage": "uint64", "$value": value.to_string()})
}

fn import_flags(flags: u16) -> String {
    match flags {
        1 => "Template",
        2 => "Soft",
        _ => "Default",
    }
    .to_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    )
}

fn malformed(offset: usize, reason: &'static str) -> CodecError {
    CodecError::Malformed { offset, reason }
}

fn unsupported(red_type: &str) -> CodecError {
    CodecError::Unsupported {
        red_type: red_type.to_owned(),
    }
}
