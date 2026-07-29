//! Dynamic CR2W value decoding driven by on-disk RED type names.

use crate::{
    archive::{self, ArchiveError},
    cr2w::{self, Cr2wError, Cr2wInspection},
    redpackage::{self, PackageError, PackageSettings},
    schema::{RedClass, RedSchema},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
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
    enums: Option<&'a BTreeSet<String>>,
    bitfields: Option<&'a BTreeSet<String>>,
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
    decode_exports_inner(path, classes, None, None, kraken_path)
}

/// Decodes reflected exports using official enum and bitfield categories.
///
/// # Errors
///
/// Returns [`CodecError`] under the same conditions as [`decode_exports`].
pub fn decode_exports_with_red_schema(
    path: &Path,
    schema: &RedSchema,
    kraken_path: &OsStr,
) -> Result<Value, CodecError> {
    let classes = schema.class_names();
    decode_exports_inner(
        path,
        &classes,
        Some(&schema.enums),
        Some(&schema.bitfields),
        kraken_path,
    )
}

fn decode_exports_inner(
    path: &Path,
    classes: &BTreeSet<String>,
    enums: Option<&BTreeSet<String>>,
    bitfields: Option<&BTreeSet<String>>,
    kraken_path: &OsStr,
) -> Result<Value, CodecError> {
    let file = cr2w::inspect(path)?;
    let bytes = fs::read(path)?;
    let decoder = Decoder {
        bytes: &bytes,
        file: &file,
        classes,
        enums,
        bitfields,
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
    decode_wkit_inner(path, classes, None, None, kraken_path, None)
}

/// Decodes a CR2W file using schema property order to reproduce `WolvenKit`
/// handle identity assignment.
///
/// # Errors
///
/// Returns [`CodecError`] under the same conditions as [`decode_wkit`].
pub fn decode_wkit_with_schema(
    path: &Path,
    classes: &BTreeMap<String, RedClass>,
    kraken_path: &OsStr,
) -> Result<Value, CodecError> {
    let class_names = classes.keys().cloned().collect();
    decode_wkit_inner(path, &class_names, None, None, kraken_path, Some(classes))
}

/// Decodes CR2W using official `REDmod` RTTI categories and property order.
///
/// # Errors
///
/// Returns [`CodecError`] under the same conditions as [`decode_wkit`].
pub fn decode_wkit_with_red_schema(
    path: &Path,
    schema: &RedSchema,
    kraken_path: &OsStr,
) -> Result<Value, CodecError> {
    let class_names = schema.class_names();
    decode_wkit_inner(
        path,
        &class_names,
        Some(&schema.enums),
        Some(&schema.bitfields),
        kraken_path,
        Some(&schema.classes),
    )
}

fn decode_wkit_inner(
    path: &Path,
    classes: &BTreeSet<String>,
    enums: Option<&BTreeSet<String>>,
    bitfields: Option<&BTreeSet<String>>,
    kraken_path: &OsStr,
    schema: Option<&BTreeMap<String, RedClass>>,
) -> Result<Value, CodecError> {
    let mut flat = decode_exports_inner(path, classes, enums, bitfields, kraken_path)?;
    let wrapped_exports = flat
        .get_mut("exports")
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .ok_or_else(|| malformed(0, "exports"))?
        .into_iter();
    let exports = wrapped_exports
        .map(|mut export| {
            export
                .as_object_mut()
                .and_then(|object| object.remove("value"))
                .ok_or_else(|| malformed(0, "export value"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let inspection = cr2w::inspect(path)?;
    let handle_ids = reachable_handle_ids(&exports, &inspection, schema)?;
    let root = exports.first().ok_or_else(|| malformed(0, "root export"))?;
    let mut visited = HashSet::new();
    let root = expand_handles(root, &exports, &handle_ids, &mut visited)?;
    let embedded = inspection
        .embedded
        .iter()
        .map(|item| {
            let chunk = usize::try_from(item.chunk_index)
                .ok()
                .and_then(|index| exports.get(index))
                .ok_or_else(|| malformed(0, "embedded chunk"))?;
            Ok(json!({
                "FileName": {
                    "$type": "ResourcePath",
                    "$storage": "string",
                    "$value": item.depot_path
                },
                "Content": expand_handles(chunk, &exports, &handle_ids, &mut visited)?
            }))
        })
        .collect::<Result<Vec<_>, CodecError>>()?;
    drop_values(exports);
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
            "WolvenKitVersion": concat!(
                "8.17-compatible (ghostline-red ",
                env!("CARGO_PKG_VERSION"),
                ")"
            ),
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
    value: &Value,
    exports: &[Value],
    handle_ids: &HashMap<usize, usize>,
    visited: &mut HashSet<usize>,
) -> Result<Value, CodecError> {
    enum Work<'a> {
        Visit(&'a Value),
        FinishArray(usize),
        FinishObject(Vec<String>),
        FinishHandle(usize),
    }

    let mut pending = vec![Work::Visit(value)];
    let mut completed = Vec::new();
    while let Some(work) = pending.pop() {
        match work {
            Work::Visit(Value::Array(values)) => {
                pending.push(Work::FinishArray(values.len()));
                pending.extend(values.iter().rev().map(Work::Visit));
            }
            Work::Visit(Value::Object(object))
                if object.len() == 1 && object.contains_key("$handle") =>
            {
                let index = object
                    .get("$handle")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(|| malformed(0, "handle index"))?;
                if index == usize::try_from(u32::MAX).expect("u32 always fits in usize") {
                    completed.push(Value::Null);
                    continue;
                }
                let handle_id = handle_ids
                    .get(&index)
                    .copied()
                    .ok_or_else(|| malformed(0, "unreachable handle"))?;
                if visited.insert(index) {
                    let data = exports
                        .get(index)
                        .ok_or_else(|| malformed(0, "handle export"))?;
                    pending.push(Work::FinishHandle(handle_id));
                    pending.push(Work::Visit(data));
                } else {
                    completed.push(json!({"HandleRefId": handle_id.to_string()}));
                }
            }
            Work::Visit(Value::Object(object)) => {
                pending.push(Work::FinishObject(object.keys().cloned().collect()));
                pending.extend(object.values().rev().map(Work::Visit));
            }
            Work::Visit(scalar) => completed.push(scalar.clone()),
            Work::FinishArray(length) => {
                let start = completed
                    .len()
                    .checked_sub(length)
                    .ok_or_else(|| malformed(0, "array expansion"))?;
                let values = completed.drain(start..).collect();
                completed.push(Value::Array(values));
            }
            Work::FinishObject(keys) => {
                let start = completed
                    .len()
                    .checked_sub(keys.len())
                    .ok_or_else(|| malformed(0, "object expansion"))?;
                let values = completed.drain(start..).collect::<Vec<_>>();
                completed.push(Value::Object(keys.into_iter().zip(values).collect()));
            }
            Work::FinishHandle(handle_id) => {
                let data = completed
                    .pop()
                    .ok_or_else(|| malformed(0, "handle expansion"))?;
                completed.push(json!({
                    "HandleId": handle_id.to_string(),
                    "Data": data
                }));
            }
        }
    }
    completed
        .pop()
        .filter(|_| completed.is_empty())
        .ok_or_else(|| malformed(0, "value expansion"))
}

fn drop_values(values: Vec<Value>) {
    let mut pending = values;
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => pending.extend(values.into_values()),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}

fn reachable_handle_ids(
    exports: &[Value],
    inspection: &Cr2wInspection,
    schema: Option<&BTreeMap<String, RedClass>>,
) -> Result<HashMap<usize, usize>, CodecError> {
    let root = exports.first().ok_or_else(|| malformed(0, "root export"))?;
    let mut pending = Vec::new();
    for embedded in inspection.embedded.iter().rev() {
        let index =
            usize::try_from(embedded.chunk_index).map_err(|_| malformed(0, "embedded chunk"))?;
        pending.push(
            exports
                .get(index)
                .ok_or_else(|| malformed(0, "embedded chunk"))?,
        );
    }
    pending.push(root);
    let mut handle_ids = HashMap::new();
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(values) => pending.extend(values.iter().rev()),
            Value::Object(object) if object.len() == 1 && object.contains_key("$handle") => {
                let index = object
                    .get("$handle")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(|| malformed(0, "handle index"))?;
                if index == usize::try_from(u32::MAX).expect("u32 always fits in usize") {
                    continue;
                }
                if !handle_ids.contains_key(&index) {
                    handle_ids.insert(index, handle_ids.len());
                    pending.push(
                        exports
                            .get(index)
                            .ok_or_else(|| malformed(0, "handle export"))?,
                    );
                }
            }
            Value::Object(object) => {
                pending.extend(ordered_object_values(object, schema).into_iter().rev());
            }
            _ => {}
        }
    }
    Ok(handle_ids)
}

fn ordered_object_values<'a>(
    object: &'a Map<String, Value>,
    schema: Option<&BTreeMap<String, RedClass>>,
) -> Vec<&'a Value> {
    let Some(schema) = schema else {
        return object.values().collect();
    };
    let Some(class_name) = object.get("$type").and_then(Value::as_str) else {
        return object.values().collect();
    };
    let mut properties = Vec::new();
    let mut pending = vec![class_name];
    let mut visited = HashSet::new();
    while let Some(class_name) = pending.pop() {
        if !visited.insert(class_name) {
            continue;
        }
        let Some(class) = schema.get(class_name) else {
            continue;
        };
        properties.extend(class.properties.keys().map(String::as_str));
        if let Some(base) = class.base.as_deref() {
            pending.push(base);
        }
    }
    properties.sort_unstable();
    let mut seen = HashSet::new();
    let mut values = Vec::with_capacity(object.len());
    for name in properties {
        if seen.insert(name)
            && let Some(value) = object.get(name)
        {
            values.push(value);
        }
    }
    values.extend(
        object
            .iter()
            .filter(|(name, _)| name.as_str() != "$type" && !seen.contains(name.as_str()))
            .map(|(_, value)| value),
    );
    values
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
        if is_opaque_custom_data(red_type) {
            return Ok(self.read_opaque_custom_data(red_type, start, end));
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
        cursor = self.read_opaque_appendix(red_type, cursor, end, &mut object);
        Ok((Value::Object(object), cursor))
    }

    fn read_opaque_appendix(
        &self,
        red_type: &str,
        cursor: usize,
        end: usize,
        object: &mut Map<String, Value>,
    ) -> usize {
        if cursor >= end || !is_opaque_appendix(red_type) {
            return cursor;
        }
        object.insert(
            "$rawTail".to_owned(),
            Value::String(STANDARD.encode(&self.bytes[cursor..end])),
        );
        end
    }

    fn read_opaque_custom_data(&self, red_type: &str, start: usize, end: usize) -> (Value, usize) {
        (
            json!({
                "$type": red_type,
                "$rawData": STANDARD.encode(&self.bytes[start..end])
            }),
            end,
        )
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
            "SharedDataBuffer" => {
                let length = usize::try_from(self.u32(start)?)
                    .map_err(|_| malformed(start, "shared buffer length"))?;
                let payload_end = start
                    .checked_add(4)
                    .and_then(|start| start.checked_add(length))
                    .filter(|payload_end| *payload_end <= end)
                    .ok_or_else(|| malformed(start, "shared buffer bounds"))?;
                Ok((
                    json!({
                        "Flags": 0,
                        "Bytes": STANDARD.encode(&self.bytes[start + 4..payload_end])
                    }),
                    payload_end,
                ))
            }
            "DataBuffer" => self.data_buffer(self.u32(start)?, start, end),
            "serializationDeferredDataBuffer" => {
                let encoded = self.u16(start)?;
                if encoded == 0 {
                    exact(json!({"BufferId": "-1", "Flags": 0, "Bytes": ""}))
                } else {
                    exact(self.table_buffer(usize::from(encoded - 1), start)?)
                }
            }
            "CGUID" => exact(json!({"$type": "CGUID", "$bytes": hex(&self.bytes[start..end])})),
            _ if is_opaque_custom_data(red_type) => {
                Ok(self.read_opaque_custom_data(red_type, start, end))
            }
            _ if red_type.starts_with("array:") => {
                self.read_counted_array(&red_type[6..], start, size, None)
            }
            _ if red_type.starts_with("static:") => {
                let (count, inner) =
                    split_count_type(&red_type[7..]).ok_or_else(|| unsupported(red_type))?;
                self.read_counted_array(inner, start, size, Some(count))
            }
            _ if red_type.starts_with('[') => {
                let (count, inner) =
                    split_fixed_array_type(red_type).ok_or_else(|| unsupported(red_type))?;
                let (elements, consumed) =
                    self.read_counted_array(inner, start, size, Some(count))?;
                Ok((json!({"Elements": elements}), consumed))
            }
            _ if red_type.starts_with("curveData:") => {
                self.read_legacy_curve(&red_type[10..], start, size)
            }
            _ if red_type.starts_with("multiChannelCurve:") => {
                self.read_multi_channel_curve(start, size)
            }
            _ if red_type.starts_with("handle:") || red_type.starts_with("whandle:") => {
                let stored = self.u32(start)?;
                exact(if stored == 0 {
                    Value::Null
                } else {
                    json!({"$handle": stored - 1})
                })
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
            _ if self.enums.is_some_and(|enums| enums.contains(red_type)) => {
                if size != 2 {
                    return Err(malformed(start, "enum size"));
                }
                exact(Value::String(
                    self.name(usize::from(self.u16(start)?), start)?.to_owned(),
                ))
            }
            _ if self
                .bitfields
                .is_some_and(|bitfields| bitfields.contains(red_type)) =>
            {
                self.read_bitfield(start, end)
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
            _ => Err(unsupported(&format!("{red_type} ({size} bytes)"))),
        }
    }

    fn read_bitfield(&self, start: usize, end: usize) -> Result<(Value, usize), CodecError> {
        if !(end - start).is_multiple_of(2) {
            return Err(malformed(start, "bitfield size"));
        }
        let mut cursor = start;
        let mut values = Vec::new();
        while cursor < end {
            let index = usize::from(self.u16(cursor)?);
            cursor += 2;
            if index == 0 {
                return (cursor == end)
                    .then(|| {
                        (
                            Value::String(if values.is_empty() {
                                "0".to_owned()
                            } else {
                                values.join(", ")
                            }),
                            end,
                        )
                    })
                    .ok_or_else(|| malformed(cursor, "bitfield trailing bytes"));
            }
            values.push(self.name(index, cursor)?.to_owned());
        }
        Err(malformed(cursor, "bitfield terminator"))
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
            let element_size = fixed_size(inner).unwrap_or_else(|| {
                if self.classes.contains(inner) || is_variable_size(inner) {
                    end.saturating_sub(cursor)
                } else {
                    2
                }
            });
            let (value, consumed) = self.read_value(inner, cursor, element_size)?;
            if consumed <= cursor || consumed > end {
                return Err(malformed(cursor, "array element bounds"));
            }
            values.push(value);
            cursor = consumed;
        }
        Ok((Value::Array(values), cursor))
    }

    fn read_legacy_curve(
        &self,
        inner: &str,
        start: usize,
        size: usize,
    ) -> Result<(Value, usize), CodecError> {
        let limit = start
            .checked_add(size)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed(start, "curve bounds"))?;
        let count =
            usize::try_from(self.u32(start)?).map_err(|_| malformed(start, "curve count"))?;
        let mut cursor = start + 4;
        let mut elements = Vec::with_capacity(count);
        for _ in 0..count {
            let point = f32::from_bits(self.u32(cursor)?);
            cursor += 4;
            let (value, consumed) = if fixed_curve_class_size(inner).is_some() {
                self.read_fixed_curve_class(inner, cursor, limit)?
                    .ok_or_else(|| malformed(cursor, "fixed curve class type"))?
            } else {
                let element_size = fixed_size(inner).unwrap_or(limit.saturating_sub(cursor));
                self.read_value(inner, cursor, element_size)?
            };
            if consumed <= cursor || consumed > limit {
                return Err(malformed(cursor, "curve element bounds"));
            }
            elements.push(json!({"Point": point, "Value": value}));
            cursor = consumed;
        }
        let end = cursor
            .checked_add(2)
            .filter(|end| *end <= limit)
            .ok_or_else(|| malformed(cursor, "curve trailing fields"))?;
        let interpolation = interpolation_type(self.byte(cursor)?)
            .ok_or_else(|| malformed(cursor, "curve interpolation type"))?;
        let link = segment_link_type(self.byte(cursor + 1)?)
            .ok_or_else(|| malformed(cursor + 1, "curve link type"))?;
        Ok((
            json!({
                "InterpolationType": interpolation,
                "LinkType": link,
                "Elements": elements
            }),
            end,
        ))
    }

    fn read_fixed_curve_class(
        &self,
        red_type: &str,
        start: usize,
        limit: usize,
    ) -> Result<Option<(Value, usize)>, CodecError> {
        let floats = |count: usize| -> Result<Vec<f32>, CodecError> {
            let end = start
                .checked_add(count * 4)
                .filter(|end| *end <= limit)
                .ok_or_else(|| malformed(start, "fixed curve class bounds"))?;
            (start..end)
                .step_by(4)
                .map(|offset| self.u32(offset).map(f32::from_bits))
                .collect()
        };
        match red_type {
            "Vector2" => {
                let values = floats(2)?;
                Ok(Some((
                    json!({
                        "$type": "Vector2",
                        "X": values[0],
                        "Y": values[1]
                    }),
                    start + 8,
                )))
            }
            "Vector3" => {
                let values = floats(3)?;
                Ok(Some((
                    json!({
                        "$type": "Vector3",
                        "X": values[0],
                        "Y": values[1],
                        "Z": values[2]
                    }),
                    start + 12,
                )))
            }
            "Vector4" => {
                let values = floats(4)?;
                Ok(Some((
                    json!({
                        "$type": "Vector4",
                        "W": values[3],
                        "X": values[0],
                        "Y": values[1],
                        "Z": values[2]
                    }),
                    start + 16,
                )))
            }
            "HDRColor" => {
                let values = floats(4)?;
                Ok(Some((
                    json!({
                        "$type": "HDRColor",
                        "Alpha": values[3],
                        "Blue": values[2],
                        "Green": values[1],
                        "Red": values[0]
                    }),
                    start + 16,
                )))
            }
            _ => Ok(None),
        }
    }

    fn read_multi_channel_curve(
        &self,
        start: usize,
        size: usize,
    ) -> Result<(Value, usize), CodecError> {
        let end = start
            .checked_add(size)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed(start, "multi-channel curve bounds"))?;
        let num_channels = self.u32(start)?;
        let interpolation = interpolation_type(self.byte(start + 4)?)
            .ok_or_else(|| malformed(start + 4, "curve interpolation type"))?;
        let link = channel_link_type(self.byte(start + 5)?)
            .ok_or_else(|| malformed(start + 5, "curve channel link type"))?;
        let alignment = self.u32(start + 6)?;
        let data_size = usize::try_from(self.u32(start + 10)?)
            .map_err(|_| malformed(start + 10, "multi-channel curve data size"))?;
        let data_start = start + 14;
        let data_end = data_start
            .checked_add(data_size)
            .filter(|data_end| *data_end == end)
            .ok_or_else(|| malformed(data_start, "multi-channel curve data bounds"))?;
        Ok((
            json!({
                "NumChannels": num_channels,
                "InterpolationType": interpolation,
                "LinkType": link,
                "Alignment": alignment,
                "Data": STANDARD.encode(&self.bytes[data_start..data_end])
            }),
            end,
        ))
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

    fn data_buffer(
        &self,
        encoded: u32,
        start: usize,
        end: usize,
    ) -> Result<(Value, usize), CodecError> {
        if encoded == 0x8000_0000 {
            return Ok((
                json!({"BufferId": "-1", "Flags": 0, "Bytes": ""}),
                start + 4,
            ));
        }
        if encoded > 0x8000_0000 {
            let pointer = usize::try_from((encoded ^ 0x8000_0000) - 1)
                .map_err(|_| malformed(start, "buffer pointer"))?;
            return Ok((self.table_buffer(pointer, start)?, start + 4));
        }
        let length =
            usize::try_from(encoded).map_err(|_| malformed(start, "inline buffer length"))?;
        let payload_end = start
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
            .filter(|value| *value <= end)
            .ok_or_else(|| malformed(start, "inline buffer bounds"))?;
        Ok((
            json!({
                "BufferId": "-1",
                "Flags": 0,
                "Bytes": STANDARD.encode(&self.bytes[start + 4..payload_end])
            }),
            payload_end,
        ))
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
        let Ok(data) = redpackage::decode(
            &bytes,
            self.classes,
            PackageSettings {
                imports_as_hash,
                handle_id_base,
            },
        ) else {
            return Ok(json!({
                "BufferId": index.to_string(),
                "Flags": buffer.flags,
                "Bytes": STANDARD.encode(&bytes)
            }));
        };
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
        let (bytes, is_stored) = if stored.get(..4) == Some(b"KARK") {
            let declared = u32::from_le_bytes(
                stored
                    .get(4..8)
                    .ok_or_else(|| malformed(start, "KARK header"))?
                    .try_into()
                    .map_err(|_| malformed(start, "KARK header"))?,
            );
            match archive::decompress_payload_isolated(
                stored
                    .get(8..)
                    .ok_or_else(|| malformed(start, "KARK payload"))?,
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
        "Int16" | "Uint16" | "CName" | "serializationDeferredDataBuffer" => Some(2),
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

fn is_variable_size(red_type: &str) -> bool {
    matches!(
        red_type,
        "String" | "NodeRef" | "LocalizationString" | "DataBuffer" | "SharedDataBuffer"
    ) || red_type.starts_with("array:")
        || red_type.starts_with("static:")
        || red_type.starts_with('[')
        || red_type.starts_with("curveData:")
        || red_type.starts_with("multiChannelCurve:")
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

fn is_opaque_custom_data(red_type: &str) -> bool {
    matches!(
        red_type,
        "Variant"
            | "AITrafficWorkspotCompiled"
            | "animAnimationBufferCompressed"
            | "gameCompiledSmartObjectData"
            | "gameSmartObjectAnimationDatabase"
            | "worldCompiledEffectInfo"
    )
}

fn is_opaque_appendix(red_type: &str) -> bool {
    matches!(
        red_type,
        "animRig"
            | "C2dArray"
            | "CMaterialTemplate"
            | "CPhysicsDecorationResource"
            | "gameLocationResource"
            | "gameLootResourceData"
            | "meshMeshParamSpeedTreeWind"
            | "physicsColliderMesh"
            | "physicsMaterialLibraryResource"
            | "scnAnimName"
            | "worldInstancedMeshNode"
            | "worldInstancedOccluderNode"
            | "worldTrafficCompiledNode"
            | "worldTrafficLanesSpotsResource"
            | "worldTrafficPersistentLaneConnectionsResource"
            | "worldTrafficPersistentLanePolygonResource"
            | "worldTrafficPersistentResource"
            | "worldTrafficPersistentSpatialResource"
    )
}

fn split_count_type(value: &str) -> Option<(usize, &str)> {
    let (count, inner) = value.split_once(',')?;
    Some((count.parse().ok()?, inner))
}

fn split_fixed_array_type(value: &str) -> Option<(usize, &str)> {
    let value = value.strip_prefix('[')?;
    let (count, inner) = value.split_once(']')?;
    (!inner.is_empty()).then_some((count.parse().ok()?, inner))
}

pub(crate) fn fixed_curve_class_size(red_type: &str) -> Option<usize> {
    match red_type {
        "Vector2" => Some(8),
        "Vector3" => Some(12),
        "Vector4" | "HDRColor" => Some(16),
        _ => None,
    }
}

fn interpolation_type(value: u8) -> Option<&'static str> {
    [
        "Constant",
        "Linear",
        "BezierQuadratic",
        "BezierCubic",
        "Hermite",
    ]
    .get(usize::from(value))
    .copied()
}

fn segment_link_type(value: u8) -> Option<&'static str> {
    ["ESLT_Normal", "ESLT_Smooth", "ESLT_SmoothSymmetric"]
        .get(usize::from(value))
        .copied()
}

fn channel_link_type(value: u8) -> Option<&'static str> {
    ["Normal", "Smooth", "SmoothSymmertric"]
        .get(usize::from(value))
        .copied()
}

fn storage_string(red_type: &str, value: &str) -> Value {
    json!({"$type": red_type, "$storage": "string", "$value": value})
}

fn storage_u64(red_type: &str, value: u64) -> Value {
    json!({"$type": red_type, "$storage": "uint64", "$value": value.to_string()})
}

fn import_flags(flags: u16) -> String {
    match flags {
        1 => "Obligatory",
        2 => "Template",
        4 => "Soft",
        8 => "Embedded",
        16 => "Inplace",
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

#[cfg(test)]
mod tests {
    use super::{
        channel_link_type, expand_handles, interpolation_type, segment_link_type,
        split_fixed_array_type,
    };
    use serde_json::json;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn handle_ids_follow_export_order() {
        let exports = vec![
            json!({"$type": "Root"}),
            json!({"$type": "Second"}),
            json!({"$type": "First"}),
        ];
        let value = json!([
            {"$handle": 2},
            {"$handle": 2},
            {"$handle": 1}
        ]);

        let handle_ids = HashMap::from([(1, 0), (2, 1)]);
        let actual = expand_handles(&value, &exports, &handle_ids, &mut HashSet::new()).unwrap();

        assert_eq!(
            actual,
            json!([
                {"HandleId": "1", "Data": {"$type": "First"}},
                {"HandleRefId": "1"},
                {"HandleId": "0", "Data": {"$type": "Second"}}
            ])
        );
    }

    #[test]
    fn expand_handles_decodes_zero_pointer_as_null() {
        let value = json!({"$handle": u32::MAX});
        let actual = expand_handles(&value, &[], &HashMap::new(), &mut HashSet::new()).unwrap();

        assert_eq!(actual, serde_json::Value::Null);
    }

    #[test]
    fn parses_fixed_array_type() {
        assert_eq!(split_fixed_array_type("[3]Int16"), Some((3, "Int16")));
        assert_eq!(split_fixed_array_type("[2][3]Float"), Some((2, "[3]Float")));
        assert_eq!(split_fixed_array_type("array:Int16"), None);
    }

    #[test]
    fn maps_legacy_curve_enums() {
        assert_eq!(interpolation_type(3), Some("BezierCubic"));
        assert_eq!(segment_link_type(1), Some("ESLT_Smooth"));
        assert_eq!(channel_link_type(2), Some("SmoothSymmertric"));
        assert_eq!(interpolation_type(5), None);
        assert_eq!(segment_link_type(3), None);
        assert_eq!(channel_link_type(3), None);
    }
}
