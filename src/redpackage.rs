//! Dynamic reader for RED package buffers embedded in CR2W resources.

use crate::archive;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeSet, HashMap, HashSet},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("malformed RedPackage at byte {offset}: {reason}")]
    Malformed { offset: usize, reason: &'static str },
    #[error("unsupported RedPackage type {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Copy)]
pub struct PackageSettings {
    pub imports_as_hash: bool,
    pub handle_id_base: usize,
}

#[derive(Debug, Clone)]
struct Import {
    path: PackagePath,
    soft: bool,
}

#[derive(Debug, Clone)]
enum PackagePath {
    Text(String),
    Hash(u64),
}

#[derive(Debug)]
struct Reader<'a> {
    bytes: &'a [u8],
    names: Vec<String>,
    imports: Vec<Import>,
    classes: &'a BTreeSet<String>,
    version: u8,
    unknown1: u8,
}

#[derive(Debug)]
struct PackageLayout {
    version: u8,
    unknown1: u8,
    sections: u16,
    header_size: usize,
    base: usize,
    names: Vec<String>,
    imports: Vec<Import>,
    chunks: Vec<(usize, usize)>,
}

struct Encoder<'a> {
    template: &'a [u8],
    reader: Reader<'a>,
    names: RefCell<HashMap<String, u16>>,
    new_names: RefCell<Vec<String>>,
    imports: RefCell<HashMap<(String, bool), i16>>,
    new_imports: RefCell<Vec<Import>>,
    chunks: RefCell<HashMap<usize, &'a Value>>,
    chunk_templates: RefCell<Vec<usize>>,
    class_templates: HashMap<String, usize>,
    handle_ids: RefCell<HashMap<String, usize>>,
    claimed_chunks: RefCell<HashSet<usize>>,
    discovering: Cell<bool>,
    imports_as_hash: bool,
}

/// Decodes a RED package buffer to the shape used by `WolvenKit` JSON.
///
/// # Errors
///
/// Returns [`PackageError`] when package metadata, offsets, or reflected values
/// are malformed, or when a RED value encoding is not implemented.
pub fn decode(
    bytes: &[u8],
    classes: &BTreeSet<String>,
    settings: PackageSettings,
) -> Result<Value, PackageError> {
    let version = byte(bytes, 0)?;
    let unknown1 = byte(bytes, 1)?;
    if !(2..=4).contains(&version) {
        return Err(malformed(0, "version"));
    }
    let sections = u16_at(bytes, 2)?;
    if !(6..=7).contains(&sections) {
        return Err(malformed(2, "section count"));
    }
    let _component_count =
        usize::try_from(u32_at(bytes, 4)?).map_err(|_| malformed(4, "component count"))?;
    let (ref_desc, ref_data, name_desc, name_data, chunk_desc, chunk_data, mut cursor) =
        if sections == 7 {
            (
                u32_at(bytes, 8)?,
                u32_at(bytes, 12)?,
                u32_at(bytes, 16)?,
                u32_at(bytes, 20)?,
                u32_at(bytes, 24)?,
                u32_at(bytes, 28)?,
                32_usize,
            )
        } else {
            (
                0,
                0,
                u32_at(bytes, 8)?,
                u32_at(bytes, 12)?,
                u32_at(bytes, 16)?,
                u32_at(bytes, 20)?,
                24_usize,
            )
        };

    let cruid_index = i16_at(bytes, cursor)?;
    cursor += 2;
    let cruid_count = usize::from(u16_at(bytes, cursor)?);
    cursor += 2;
    let mut cruids = Vec::with_capacity(cruid_count);
    for _ in 0..cruid_count {
        cruids.push(u64_at(bytes, cursor)?);
        cursor += 8;
    }
    let base = cursor;

    let imports = read_imports(bytes, base, ref_desc, ref_data, settings.imports_as_hash)?;
    let names = read_names(bytes, base, name_desc, name_data)?;
    let chunk_headers = read_chunk_headers(bytes, base, chunk_desc, chunk_data)?;
    let reader = Reader {
        bytes,
        names,
        imports,
        classes,
        version,
        unknown1,
    };
    let mut chunks = Vec::with_capacity(chunk_headers.len());
    for (index, (type_index, offset)) in chunk_headers.iter().copied().enumerate() {
        let end = chunk_headers
            .get(index + 1)
            .map_or(bytes.len(), |(_, next)| *next);
        let class_name = reader.name(type_index, offset)?;
        let (chunk, consumed) = reader
            .read_class(class_name, offset, end)
            .map_err(|error| {
                PackageError::Unsupported(format!("chunk {index} {class_name}: {error}"))
            })?;
        if consumed > end {
            return Err(malformed(consumed, "chunk overrun"));
        }
        chunks.push(chunk);
    }

    let mut pointed_to = HashSet::new();
    for chunk in &chunks {
        collect_handle_targets(chunk, &mut pointed_to);
    }
    let roots: Vec<usize> = (0..chunks.len())
        .filter(|index| !pointed_to.contains(index))
        .collect();
    let mut visited = HashSet::new();
    let expanded = roots
        .iter()
        .map(|index| expand_handles(chunks[*index].clone(), &chunks, &mut visited, settings))
        .collect::<Result<Vec<_>, _>>()?;
    let cruid_dict = expanded
        .iter()
        .enumerate()
        .filter_map(|(index, _)| {
            cruids
                .get(index)
                .map(|cruid| (index.to_string(), json!(cruid.to_string())))
        })
        .collect::<Map<_, _>>();
    Ok(json!({
        "Version": version,
        "Sections": sections,
        "CruidIndex": cruid_index,
        "CruidDict": cruid_dict,
        "Chunks": expanded
    }))
}

/// Rebuilds a RED package from WolvenKit-shaped JSON using an existing package
/// as the reflected field-layout template.
///
/// # Errors
///
/// Returns [`PackageError`] for malformed templates, unsupported structural
/// changes, invalid JSON values, or values exceeding package field limits.
#[expect(
    clippy::too_many_lines,
    reason = "the linear discovery and rebuild phases keep chunk-template mapping explicit"
)]
pub fn encode_with_template(
    template: &[u8],
    data: &Value,
    classes: &BTreeSet<String>,
    settings: PackageSettings,
) -> Result<Vec<u8>, PackageError> {
    let layout = parse_layout(template, classes, settings)?;
    let roots = data
        .get("Chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(0, "package Chunks"))?;
    let template_reader = &layout.reader;
    let mut flat_template = Vec::with_capacity(layout.layout.chunks.len());
    for (index, (type_index, start)) in layout.layout.chunks.iter().copied().enumerate() {
        let end = layout
            .layout
            .chunks
            .get(index + 1)
            .map_or(template.len(), |(_, next)| *next);
        let class_name = template_reader.name(type_index, start)?;
        flat_template.push(template_reader.read_class(class_name, start, end)?.0);
    }
    let mut pointed_to = HashSet::new();
    for chunk in &flat_template {
        collect_handle_targets(chunk, &mut pointed_to);
    }
    let root_indices: Vec<usize> = (0..flat_template.len())
        .filter(|index| !pointed_to.contains(index))
        .collect();
    if roots.len() != root_indices.len() {
        return Err(unsupported("package root chunk count change"));
    }

    let names = layout
        .layout
        .names
        .iter()
        .enumerate()
        .map(|(index, name)| {
            Ok((
                name.clone(),
                u16::try_from(index).map_err(|_| malformed(index, "name index"))?,
            ))
        })
        .collect::<Result<HashMap<_, _>, PackageError>>()?;
    let imports = layout
        .layout
        .imports
        .iter()
        .enumerate()
        .filter_map(|(index, import)| {
            let PackagePath::Text(path) = &import.path else {
                return None;
            };
            Some((
                (path.clone(), import.soft),
                i16::try_from(index).map_err(|_| malformed(index, "import index")),
            ))
        })
        .map(|(key, index)| Ok((key, index?)))
        .collect::<Result<HashMap<_, _>, PackageError>>()?;
    let encoder = Encoder {
        template,
        reader: Reader {
            bytes: template,
            names: layout.layout.names.clone(),
            imports: layout.layout.imports.clone(),
            classes,
            version: layout.layout.version,
            unknown1: layout.layout.unknown1,
        },
        names: RefCell::new(names),
        new_names: RefCell::new(Vec::new()),
        imports: RefCell::new(imports),
        new_imports: RefCell::new(Vec::new()),
        chunks: RefCell::new(
            root_indices
                .iter()
                .copied()
                .zip(roots)
                .collect::<HashMap<_, _>>(),
        ),
        chunk_templates: RefCell::new((0..layout.layout.chunks.len()).collect()),
        class_templates: layout
            .layout
            .chunks
            .iter()
            .enumerate()
            .map(|(index, &(type_index, start))| {
                Ok((template_reader.name(type_index, start)?.to_owned(), index))
            })
            .collect::<Result<HashMap<_, _>, PackageError>>()?,
        handle_ids: RefCell::new(HashMap::new()),
        claimed_chunks: RefCell::new(root_indices.iter().copied().collect()),
        discovering: Cell::new(true),
        imports_as_hash: settings.imports_as_hash,
    };

    // Discovery interns names/imports and follows template handle pointers.
    let mut index = 0;
    loop {
        let Some(template_index) = encoder.chunk_templates.borrow().get(index).copied() else {
            break;
        };
        let value = { encoder.chunks.borrow().get(&index).copied() };
        let Some(value) = value else {
            index += 1;
            continue;
        };
        let (type_index, start) = layout.layout.chunks[template_index];
        let end = layout
            .layout
            .chunks
            .get(template_index + 1)
            .map_or(template.len(), |(_, next)| *next);
        let class_name = encoder.reader.name(type_index, start)?;
        let _ = encoder.encode_class(value, class_name, start, end)?;
        index += 1;
    }
    encoder.discovering.set(false);

    let mut chunk_data = Vec::new();
    let chunk_templates = encoder.chunk_templates.borrow().clone();
    let mut chunk_offsets = Vec::with_capacity(chunk_templates.len());
    for (index, &template_index) in chunk_templates.iter().enumerate() {
        chunk_offsets.push(chunk_data.len());
        let (type_index, start) = layout.layout.chunks[template_index];
        let end = layout
            .layout
            .chunks
            .get(template_index + 1)
            .map_or(template.len(), |(_, next)| *next);
        let value = { encoder.chunks.borrow().get(&index).copied() };
        if let Some(value) = value {
            let class_name = encoder.reader.name(type_index, start)?;
            chunk_data.extend_from_slice(&encoder.encode_class(value, class_name, start, end)?);
        } else {
            chunk_data.extend_from_slice(
                template
                    .get(start..end)
                    .ok_or_else(|| malformed(start, "chunk template bounds"))?,
            );
        }
    }
    build_package(
        template,
        &layout.layout,
        &encoder,
        &chunk_templates,
        &chunk_offsets,
        &chunk_data,
        settings,
    )
}

/// Reports whether a package's import pool stores 64-bit depot hashes.
///
/// An empty import pool is reported as `false` because either representation
/// produces the same bytes until an import is added.
///
/// # Errors
///
/// Returns [`PackageError`] when the package header or import descriptor is
/// malformed.
pub fn imports_are_hashed(bytes: &[u8]) -> Result<bool, PackageError> {
    if u16_at(bytes, 2)? != 7 {
        return Ok(false);
    }
    let ref_desc = u32_at(bytes, 8)?;
    let ref_data = u32_at(bytes, 12)?;
    if ref_desc == ref_data {
        return Ok(false);
    }
    let header_size = 32;
    let cruid_count = usize::from(u16_at(bytes, header_size + 2)?);
    let base = header_size
        .checked_add(4)
        .and_then(|value| value.checked_add(cruid_count.checked_mul(8)?))
        .ok_or_else(|| malformed(header_size, "CRUID area"))?;
    let descriptor = u32_at(bytes, add(base, ref_desc)?)?;
    Ok(((descriptor >> 23) & 0xff) == 8)
}

struct ParsedLayout<'a> {
    layout: PackageLayout,
    reader: Reader<'a>,
}

fn parse_layout<'a>(
    bytes: &'a [u8],
    classes: &'a BTreeSet<String>,
    settings: PackageSettings,
) -> Result<ParsedLayout<'a>, PackageError> {
    let version = byte(bytes, 0)?;
    let unknown1 = byte(bytes, 1)?;
    let sections = u16_at(bytes, 2)?;
    let header_size = if sections == 7 { 32 } else { 24 };
    let (ref_desc, ref_data, name_desc, name_data, chunk_desc, chunk_data) = if sections == 7 {
        (
            u32_at(bytes, 8)?,
            u32_at(bytes, 12)?,
            u32_at(bytes, 16)?,
            u32_at(bytes, 20)?,
            u32_at(bytes, 24)?,
            u32_at(bytes, 28)?,
        )
    } else {
        (
            0,
            0,
            u32_at(bytes, 8)?,
            u32_at(bytes, 12)?,
            u32_at(bytes, 16)?,
            u32_at(bytes, 20)?,
        )
    };
    let cruid_count = usize::from(u16_at(bytes, header_size + 2)?);
    let base = header_size
        .checked_add(4)
        .and_then(|value| value.checked_add(cruid_count.checked_mul(8)?))
        .ok_or_else(|| malformed(header_size, "CRUID area"))?;
    let imports = read_imports(bytes, base, ref_desc, ref_data, settings.imports_as_hash)?;
    let names = read_names(bytes, base, name_desc, name_data)?;
    let chunks = read_chunk_headers(bytes, base, chunk_desc, chunk_data)?;
    Ok(ParsedLayout {
        reader: Reader {
            bytes,
            names: names.clone(),
            imports: imports.clone(),
            classes,
            version,
            unknown1,
        },
        layout: PackageLayout {
            version,
            unknown1,
            sections,
            header_size,
            base,
            names,
            imports,
            chunks,
        },
    })
}

fn read_imports(
    bytes: &[u8],
    base: usize,
    descriptor_offset: u32,
    data_offset: u32,
    hashes: bool,
) -> Result<Vec<Import>, PackageError> {
    let count = usize::try_from(
        data_offset
            .checked_sub(descriptor_offset)
            .ok_or_else(|| malformed(base, "import pool offsets"))?
            / 4,
    )
    .map_err(|_| malformed(base, "import count"))?;
    let descriptor_start = add(base, descriptor_offset)?;
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let bits = u32_at(bytes, descriptor_start + index * 4)?;
        let offset = bits & 0x007f_ffff;
        let size = usize::try_from((bits >> 23) & 0xff)
            .map_err(|_| malformed(descriptor_start, "import size"))?;
        let start = add(base, offset)?;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| malformed(start, "import bounds"))?;
        let path = if hashes {
            if size != 8 {
                return Err(malformed(start, "hashed import size"));
            }
            PackagePath::Hash(u64_at(bytes, start)?)
        } else {
            PackagePath::Text(
                std::str::from_utf8(&bytes[start..end])
                    .map_err(|_| malformed(start, "import UTF-8"))?
                    .to_owned(),
            )
        };
        result.push(Import {
            path,
            soft: bits >> 31 != 0,
        });
    }
    Ok(result)
}

fn read_names(
    bytes: &[u8],
    base: usize,
    descriptor_offset: u32,
    data_offset: u32,
) -> Result<Vec<String>, PackageError> {
    let count = usize::try_from(
        data_offset
            .checked_sub(descriptor_offset)
            .ok_or_else(|| malformed(base, "name pool offsets"))?
            / 4,
    )
    .map_err(|_| malformed(base, "name count"))?;
    let descriptor_start = add(base, descriptor_offset)?;
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let bits = u32_at(bytes, descriptor_start + index * 4)?;
        let start = add(base, bits & 0x00ff_ffff)?;
        let size = usize::try_from(bits >> 24).map_err(|_| malformed(start, "name size"))?;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| malformed(start, "name bounds"))?;
        let content_end = end
            .checked_sub(1)
            .filter(|end| bytes.get(*end) == Some(&0))
            .ok_or_else(|| malformed(start, "name terminator"))?;
        result.push(
            std::str::from_utf8(&bytes[start..content_end])
                .map_err(|_| malformed(start, "name UTF-8"))?
                .to_owned(),
        );
    }
    Ok(result)
}

fn read_chunk_headers(
    bytes: &[u8],
    base: usize,
    descriptor_offset: u32,
    data_offset: u32,
) -> Result<Vec<(usize, usize)>, PackageError> {
    let count = usize::try_from(
        data_offset
            .checked_sub(descriptor_offset)
            .ok_or_else(|| malformed(base, "chunk pool offsets"))?
            / 8,
    )
    .map_err(|_| malformed(base, "chunk count"))?;
    let start = add(base, descriptor_offset)?;
    (0..count)
        .map(|index| {
            let entry = start + index * 8;
            Ok((
                usize::try_from(u32_at(bytes, entry)?)
                    .map_err(|_| malformed(entry, "chunk type"))?,
                add(base, u32_at(bytes, entry + 4)?)?,
            ))
        })
        .collect()
}

impl Reader<'_> {
    fn read_class(
        &self,
        class_name: &str,
        start: usize,
        limit: usize,
    ) -> Result<(Value, usize), PackageError> {
        let field_count = usize::from(u16_at(self.bytes, start)?);
        let descriptors = start + 2;
        let mut fields = Vec::with_capacity(field_count);
        for index in 0..field_count {
            let descriptor = descriptors + index * 8;
            fields.push((
                usize::from(u16_at(self.bytes, descriptor)?),
                usize::from(u16_at(self.bytes, descriptor + 2)?),
                add(start, u32_at(self.bytes, descriptor + 4)?)?,
            ));
        }
        let mut object = Map::new();
        object.insert("$type".to_owned(), Value::String(class_name.to_owned()));
        let mut consumed = descriptors + field_count * 8;
        for (index, (name_index, type_index, field_start)) in fields.iter().copied().enumerate() {
            let field_limit = fields.get(index + 1).map_or(limit, |(_, _, next)| *next);
            if field_start > field_limit || field_limit > limit {
                return Err(malformed(field_start, "field bounds"));
            }
            let name = self.name(name_index, field_start)?;
            let red_type = self.name(type_index, field_start)?;
            let value_limit = fixed_size(red_type)
                .and_then(|size| field_start.checked_add(size))
                .unwrap_or(field_limit);
            let decoded = if class_name == "worldCompiledEffectInfo" && self.unknown1 == 2 {
                self.read_compiled_effect_property(name, field_start, field_limit)
            } else {
                None
            };
            let (value, end) = decoded
                .unwrap_or_else(|| self.read_value(red_type, field_start, value_limit))
                .map_err(|error| {
                    PackageError::Unsupported(format!(
                        "{class_name}.{name} ({red_type}) at {field_start}..{field_limit}: {error}"
                    ))
                })?;
            if end > field_limit {
                return Err(malformed(end, "field overrun"));
            }
            object.insert(name.to_owned(), value);
            consumed = end;
        }
        Ok((Value::Object(object), consumed))
    }

    fn read_compiled_effect_property(
        &self,
        name: &str,
        start: usize,
        limit: usize,
    ) -> Option<Result<(Value, usize), PackageError>> {
        let result = (|| {
            let count = usize::try_from(u32_at(self.bytes, start)?)
                .map_err(|_| malformed(start, "compiled effect count"))?;
            let mut cursor = start + 4;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let value = match name {
                    "placementTags" | "componentNames" => {
                        let value = storage_string(
                            "CName",
                            self.name(usize::from(u16_at(self.bytes, cursor)?), cursor)?,
                        );
                        cursor += 2;
                        value
                    }
                    "relativePositions" => {
                        let value = json!({
                            "$type": "Vector3",
                            "X": f32::from_bits(u32_at(self.bytes, cursor)?),
                            "Y": f32::from_bits(u32_at(self.bytes, cursor + 4)?),
                            "Z": f32::from_bits(u32_at(self.bytes, cursor + 8)?)
                        });
                        cursor += 12;
                        value
                    }
                    "relativeRotations" => {
                        let value = json!({
                            "$type": "Quaternion",
                            "i": f32::from_bits(u32_at(self.bytes, cursor)?),
                            "j": f32::from_bits(u32_at(self.bytes, cursor + 4)?),
                            "k": f32::from_bits(u32_at(self.bytes, cursor + 8)?),
                            "r": f32::from_bits(u32_at(self.bytes, cursor + 12)?)
                        });
                        cursor += 16;
                        value
                    }
                    "placementInfos" => {
                        let value = json!({
                            "$type": "worldCompiledEffectPlacementInfo",
                            "flags": byte(self.bytes, cursor + 3)?,
                            "placementTagIndex": byte(self.bytes, cursor)?,
                            "relativePositionIndex": byte(self.bytes, cursor + 1)?,
                            "relativeRotationIndex": byte(self.bytes, cursor + 2)?
                        });
                        cursor += 4;
                        value
                    }
                    "eventsSortedByRUID" => {
                        let value = json!({
                            "$type": "worldCompiledEffectEventInfo",
                            "componentIndexMask": u64_at(self.bytes, cursor + 16)?.to_string(),
                            "eventRUID": u64_at(self.bytes, cursor)?.to_string(),
                            "flags": byte(self.bytes, cursor + 24)?,
                            "placementIndexMask": u64_at(self.bytes, cursor + 8)?.to_string()
                        });
                        cursor += 32;
                        value
                    }
                    _ => return Err(unsupported(name)),
                };
                values.push(value);
            }
            if cursor > limit {
                return Err(malformed(cursor, "compiled effect bounds"));
            }
            Ok((Value::Array(values), cursor))
        })();
        matches!(
            name,
            "placementTags"
                | "componentNames"
                | "relativePositions"
                | "relativeRotations"
                | "placementInfos"
                | "eventsSortedByRUID"
        )
        .then_some(result)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the contiguous dispatch mirrors RED package primitive encodings"
    )]
    fn read_value(
        &self,
        red_type: &str,
        start: usize,
        limit: usize,
    ) -> Result<(Value, usize), PackageError> {
        let exact = |value| Ok((value, limit));
        match red_type {
            "Bool" | "Uint8" => exact(json!(byte(self.bytes, start)?)),
            "Int8" => exact(json!(byte(self.bytes, start)?.cast_signed())),
            "Int16" => exact(json!(i16_at(self.bytes, start)?)),
            "Uint16" => exact(json!(u16_at(self.bytes, start)?)),
            "Int32" => exact(json!(u32_at(self.bytes, start)?.cast_signed())),
            "Uint32" => exact(json!(u32_at(self.bytes, start)?)),
            "Int64" => exact(json!(u64_at(self.bytes, start)?.cast_signed().to_string())),
            "Uint64" | "CRUID" | "CDateTime" => {
                exact(json!(u64_at(self.bytes, start)?.to_string()))
            }
            "Float" => exact(json!(f32::from_bits(u32_at(self.bytes, start)?))),
            "Double" => exact(json!(f64::from_bits(u64_at(self.bytes, start)?))),
            "CName" => exact(storage_string(
                "CName",
                self.name(usize::from(u16_at(self.bytes, start)?), start)?,
            )),
            "String" | "CString" => {
                let (text, end) = length_prefixed_string(self.bytes, start)?;
                Ok((Value::String(text), end))
            }
            "NodeRef" => {
                let (text, end) = signed_length_string(self.bytes, start)?;
                Ok((storage_string("NodeRef", &text), end))
            }
            "TweakDBID" if self.version == 4 => {
                exact(storage_u64("TweakDBID", u64_at(self.bytes, start)?))
            }
            "TweakDBID" => {
                let (text, end) = signed_length_string(self.bytes, start)?;
                Ok((storage_string("TweakDBID", &text), end))
            }
            "LocalizationString" => {
                let unknown = u64_at(self.bytes, start)?;
                let (text, end) = length_prefixed_string(self.bytes, start + 8)?;
                Ok((json!({"unk1": unknown.to_string(), "value": text}), end))
            }
            "DataBuffer" => {
                let length = u32_at(self.bytes, start)?;
                if length == 0x8000_0000 {
                    return Ok((
                        json!({"BufferId": "-1", "Flags": 0, "Bytes": ""}),
                        start + 4,
                    ));
                }
                if length > 0x8000_0000 {
                    return Err(unsupported("package external DataBuffer"));
                }
                let length =
                    usize::try_from(length).map_err(|_| malformed(start, "buffer length"))?;
                let end = start
                    .checked_add(4)
                    .and_then(|value| value.checked_add(length))
                    .filter(|end| *end <= limit)
                    .ok_or_else(|| malformed(start, "buffer bounds"))?;
                Ok((
                    json!({
                        "BufferId": "-1",
                        "Flags": 0,
                        "Bytes": STANDARD.encode(&self.bytes[start + 4..end])
                    }),
                    end,
                ))
            }
            _ if red_type.starts_with("array:") => {
                let count = usize::try_from(u32_at(self.bytes, start)?)
                    .map_err(|_| malformed(start, "array count"))?;
                self.read_array(&red_type[6..], count, start + 4, limit)
            }
            _ if red_type.starts_with("static:") => {
                let (count, inner) =
                    split_count_type(&red_type[7..]).ok_or_else(|| unsupported(red_type))?;
                self.read_array(inner, count, start, limit)
            }
            _ if red_type.starts_with("handle:") || red_type.starts_with("whandle:") => {
                let (pointer, end) = if self.version == 2 {
                    (i32::from(i16_at(self.bytes, start)?), start + 2)
                } else {
                    (u32_at(self.bytes, start)?.cast_signed(), start + 4)
                };
                if pointer < 0 {
                    Ok((Value::Null, end))
                } else {
                    Ok((json!({"$package_handle": pointer}), end))
                }
            }
            _ if red_type.starts_with("rRef:") || red_type.starts_with("raRef:") => {
                let index = i16_at(self.bytes, start)?;
                let (path, storage, flags) = if index < 0 {
                    ("0".to_owned(), "uint64", "Default")
                } else {
                    let import = self
                        .imports
                        .get(usize::try_from(index).map_err(|_| malformed(start, "import index"))?)
                        .ok_or_else(|| malformed(start, "import index"))?;
                    match &import.path {
                        PackagePath::Text(path) => (
                            path.clone(),
                            "string",
                            if import.soft { "Soft" } else { "Default" },
                        ),
                        PackagePath::Hash(hash) => (
                            hash.to_string(),
                            "uint64",
                            if import.soft { "Soft" } else { "Default" },
                        ),
                    }
                };
                Ok((
                    json!({
                        "DepotPath": {
                            "$type": "ResourcePath",
                            "$storage": storage,
                            "$value": path
                        },
                        "Flags": flags
                    }),
                    start + 2,
                ))
            }
            _ if self.classes.contains(red_type) => self.read_class(red_type, start, limit),
            _ if limit == start + 2 => exact(Value::String(
                self.name(usize::from(u16_at(self.bytes, start)?), start)?
                    .to_owned(),
            )),
            _ => {
                let count = usize::from(byte(self.bytes, start)?);
                if start + 1 + count * 2 == limit {
                    let mut values = Vec::with_capacity(count);
                    for index in 0..count {
                        values.push(
                            self.name(
                                usize::from(u16_at(self.bytes, start + 1 + index * 2)?),
                                start,
                            )?
                            .to_owned(),
                        );
                    }
                    exact(Value::String(values.join(", ")))
                } else {
                    Err(unsupported(red_type))
                }
            }
        }
    }

    fn read_array(
        &self,
        inner: &str,
        count: usize,
        mut cursor: usize,
        limit: usize,
    ) -> Result<(Value, usize), PackageError> {
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let element_limit = fixed_size(inner).map_or(limit, |size| cursor + size);
            let (value, end) = self.read_value(inner, cursor, element_limit)?;
            if end <= cursor || end > limit {
                return Err(malformed(cursor, "array element bounds"));
            }
            values.push(value);
            cursor = end;
        }
        Ok((Value::Array(values), cursor))
    }

    fn name(&self, index: usize, offset: usize) -> Result<&str, PackageError> {
        self.names
            .get(index)
            .map(String::as_str)
            .ok_or_else(|| malformed(offset, "name index"))
    }
}

impl<'a> Encoder<'a> {
    fn encode_class(
        &self,
        value: &'a Value,
        class_name: &str,
        start: usize,
        limit: usize,
    ) -> Result<Vec<u8>, PackageError> {
        let object = value
            .as_object()
            .ok_or_else(|| malformed(start, "class JSON object"))?;
        let field_count = usize::from(u16_at(self.template, start)?);
        let descriptors = start + 2;
        let mut fields = Vec::with_capacity(field_count);
        for index in 0..field_count {
            let descriptor = descriptors + index * 8;
            fields.push((
                u16_at(self.template, descriptor)?,
                u16_at(self.template, descriptor + 2)?,
                add(start, u32_at(self.template, descriptor + 4)?)?,
            ));
        }
        let header_size = 2 + field_count * 8;
        let mut output = vec![0_u8; header_size];
        output[..2].copy_from_slice(
            &u16::try_from(field_count)
                .map_err(|_| malformed(start, "field count"))?
                .to_le_bytes(),
        );
        for (index, (name_index, type_index, field_start)) in fields.iter().copied().enumerate() {
            let field_limit = fields.get(index + 1).map_or(limit, |(_, _, next)| *next);
            let descriptor = 2 + index * 8;
            output[descriptor..descriptor + 2].copy_from_slice(&name_index.to_le_bytes());
            output[descriptor + 2..descriptor + 4].copy_from_slice(&type_index.to_le_bytes());
            let encoded_offset =
                u32::try_from(output.len()).map_err(|_| malformed(start, "field offset"))?;
            output[descriptor + 4..descriptor + 8].copy_from_slice(&encoded_offset.to_le_bytes());
            let name = self.reader.name(usize::from(name_index), field_start)?;
            let red_type = self.reader.name(usize::from(type_index), field_start)?;
            if let Some(json) = object.get(name) {
                let encoded = if class_name == "worldCompiledEffectInfo"
                    && self.reader.unknown1 == 2
                    && matches!(
                        name,
                        "placementTags"
                            | "componentNames"
                            | "relativePositions"
                            | "relativeRotations"
                            | "placementInfos"
                            | "eventsSortedByRUID"
                    ) {
                    self.encode_compiled_effect_property(json, name, field_start)?
                } else {
                    self.encode_value(json, class_name, name, red_type, field_start, field_limit)?
                };
                let (encoded, template_end) = encoded;
                output.extend_from_slice(&encoded);
                if template_end < field_limit {
                    output.extend_from_slice(
                        self.template
                            .get(template_end..field_limit)
                            .ok_or_else(|| malformed(template_end, "field padding"))?,
                    );
                }
            } else {
                output.extend_from_slice(
                    self.template
                        .get(field_start..field_limit)
                        .ok_or_else(|| malformed(field_start, "field template bounds"))?,
                );
            }
        }
        Ok(output)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the contiguous dispatch mirrors RED package primitive encodings"
    )]
    fn encode_value(
        &self,
        value: &'a Value,
        _class_name: &str,
        _property_name: &str,
        red_type: &str,
        start: usize,
        limit: usize,
    ) -> Result<(Vec<u8>, usize), PackageError> {
        let exact = |bytes| Ok((bytes, limit));
        match red_type {
            "Bool" | "Uint8" => exact(vec![
                json_u64(value, start)?
                    .try_into()
                    .map_err(|_| malformed(start, "Uint8 range"))?,
            ]),
            "Int8" => exact(vec![
                i8::try_from(json_i64(value, start)?)
                    .map_err(|_| malformed(start, "Int8 range"))?
                    .cast_unsigned(),
            ]),
            "Int16" => exact(
                i16::try_from(json_i64(value, start)?)
                    .map_err(|_| malformed(start, "Int16 range"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "Uint16" => exact(
                u16::try_from(json_u64(value, start)?)
                    .map_err(|_| malformed(start, "Uint16 range"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "Int32" => exact(
                i32::try_from(json_i64(value, start)?)
                    .map_err(|_| malformed(start, "Int32 range"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "Uint32" => exact(
                u32::try_from(json_u64(value, start)?)
                    .map_err(|_| malformed(start, "Uint32 range"))?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "Int64" => exact(json_string_i64(value, start)?.to_le_bytes().to_vec()),
            "Uint64" | "CRUID" | "CDateTime" => {
                exact(json_string_u64(value, start)?.to_le_bytes().to_vec())
            }
            "Float" => exact(json_f32(value, start)?.to_le_bytes().to_vec()),
            "Double" => exact(json_f64(value, start)?.to_le_bytes().to_vec()),
            "CName" => exact(
                self.name_index(storage_value(value, start)?)?
                    .to_le_bytes()
                    .to_vec(),
            ),
            "String" | "CString" => {
                let text = value
                    .as_str()
                    .ok_or_else(|| malformed(start, "string JSON"))?;
                let mut output = u16::try_from(text.len())
                    .map_err(|_| malformed(start, "string length"))?
                    .to_le_bytes()
                    .to_vec();
                output.extend_from_slice(text.as_bytes());
                let (_, template_end) = length_prefixed_string(self.template, start)?;
                Ok((output, template_end))
            }
            "NodeRef" => {
                let text = storage_value(value, start)?;
                let mut output = i16::try_from(text.len())
                    .map_err(|_| malformed(start, "NodeRef length"))?
                    .to_le_bytes()
                    .to_vec();
                output.extend_from_slice(text.as_bytes());
                let (_, template_end) = signed_length_string(self.template, start)?;
                Ok((output, template_end))
            }
            "TweakDBID" if self.reader.version == 4 => exact(
                tweak_db_id(storage_value(value, start)?)
                    .to_le_bytes()
                    .to_vec(),
            ),
            "TweakDBID" => {
                let text = storage_value(value, start)?;
                let mut output = i16::try_from(text.len())
                    .map_err(|_| malformed(start, "TweakDBID length"))?
                    .to_le_bytes()
                    .to_vec();
                output.extend_from_slice(text.as_bytes());
                let (_, template_end) = signed_length_string(self.template, start)?;
                Ok((output, template_end))
            }
            "LocalizationString" => {
                let mut output = value
                    .get("unk1")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed(start, "LocalizationString.unk1"))?
                    .parse::<u64>()
                    .map_err(|_| malformed(start, "LocalizationString.unk1"))?
                    .to_le_bytes()
                    .to_vec();
                let text = value
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed(start, "LocalizationString.value"))?;
                output.extend_from_slice(
                    &u16::try_from(text.len())
                        .map_err(|_| malformed(start, "LocalizationString length"))?
                        .to_le_bytes(),
                );
                output.extend_from_slice(text.as_bytes());
                let (_, template_end) = length_prefixed_string(self.template, start + 8)?;
                Ok((output, template_end))
            }
            "DataBuffer" => {
                let bytes = STANDARD
                    .decode(
                        value
                            .get("Bytes")
                            .and_then(Value::as_str)
                            .ok_or_else(|| malformed(start, "DataBuffer Bytes"))?,
                    )
                    .map_err(|_| malformed(start, "DataBuffer base64"))?;
                let mut output = u32::try_from(bytes.len())
                    .map_err(|_| malformed(start, "DataBuffer length"))?
                    .to_le_bytes()
                    .to_vec();
                output.extend_from_slice(&bytes);
                let template_length = usize::try_from(u32_at(self.template, start)?)
                    .map_err(|_| malformed(start, "DataBuffer template length"))?;
                Ok((output, start + 4 + template_length))
            }
            _ if red_type.starts_with("array:") => {
                self.encode_array(value, &red_type[6..], start, limit)
            }
            _ if red_type.starts_with("static:") => {
                let (count, inner) =
                    split_count_type(&red_type[7..]).ok_or_else(|| unsupported(red_type))?;
                let values = value
                    .as_array()
                    .ok_or_else(|| malformed(start, "static array JSON"))?;
                if values.len() != count {
                    return Err(unsupported("static array count change"));
                }
                self.encode_array_elements(values, inner, count, start, limit)
            }
            _ if red_type.starts_with("handle:") || red_type.starts_with("whandle:") => {
                let template_pointer = if self.reader.version == 2 {
                    i32::from(i16_at(self.template, start)?)
                } else {
                    u32_at(self.template, start)?.cast_signed()
                };
                let pointer = self.resolve_handle(value, template_pointer, start)?;
                let bytes = if self.reader.version == 2 {
                    i16::try_from(pointer)
                        .map_err(|_| malformed(start, "handle pointer"))?
                        .to_le_bytes()
                        .to_vec()
                } else {
                    pointer.to_le_bytes().to_vec()
                };
                Ok((bytes, start + if self.reader.version == 2 { 2 } else { 4 }))
            }
            _ if red_type.starts_with("rRef:") || red_type.starts_with("raRef:") => {
                let path = value
                    .pointer("/DepotPath/$value")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed(start, "resource path"))?;
                let soft = value.get("Flags").and_then(Value::as_str) == Some("Soft");
                let explicit_hash = value
                    .pointer("/DepotPath/$storage")
                    .and_then(Value::as_str)
                    .filter(|storage| *storage == "uint64")
                    .and_then(|_| path.parse::<u64>().ok());
                let index = if path == "0" {
                    -1
                } else {
                    self.import_index(path, explicit_hash, soft)?
                };
                Ok((index.to_le_bytes().to_vec(), start + 2))
            }
            _ if self.reader.classes.contains(red_type) => {
                let template_end = self.reader.read_class(red_type, start, limit)?.1;
                Ok((
                    self.encode_class(value, red_type, start, template_end)?,
                    template_end,
                ))
            }
            _ if limit == start + 2 => exact(
                self.name_index(
                    value
                        .as_str()
                        .ok_or_else(|| malformed(start, "enum JSON"))?,
                )?
                .to_le_bytes()
                .to_vec(),
            ),
            _ => {
                let names = value
                    .as_str()
                    .ok_or_else(|| unsupported(red_type))?
                    .split(", ")
                    .filter(|name| !name.is_empty())
                    .collect::<Vec<_>>();
                let mut output = vec![
                    u8::try_from(names.len()).map_err(|_| malformed(start, "bitfield count"))?,
                ];
                for name in names {
                    output.extend_from_slice(&self.name_index(name)?.to_le_bytes());
                }
                Ok((output, limit))
            }
        }
    }

    fn resolve_handle(
        &self,
        value: &'a Value,
        template_pointer: i32,
        start: usize,
    ) -> Result<i32, PackageError> {
        if value.is_null() {
            return Ok(-1);
        }
        if let Some(reference) = value.get("HandleRefId").and_then(Value::as_str) {
            let reference = reference
                .parse::<i64>()
                .map_err(|_| malformed(start, "handle reference"))?;
            if reference < 0 {
                return Ok(-1);
            }
            let index = self
                .handle_ids
                .borrow()
                .get(&reference.to_string())
                .copied()
                .ok_or_else(|| unsupported("unknown package handle reference"))?;
            return i32::try_from(index).map_err(|_| malformed(start, "handle pointer"));
        }
        let data = value
            .get("Data")
            .ok_or_else(|| malformed(start, "handle Data"))?;
        let handle_id = value.get("HandleId").and_then(Value::as_str);
        if let Some(handle_id) = handle_id
            && let Some(index) = self.handle_ids.borrow().get(handle_id).copied()
        {
            self.chunks.borrow_mut().insert(index, data);
            return i32::try_from(index).map_err(|_| malformed(start, "handle pointer"));
        }
        if let Some(index) = self
            .chunks
            .borrow()
            .iter()
            .find_map(|(&index, &existing)| std::ptr::eq(existing, data).then_some(index))
        {
            return i32::try_from(index).map_err(|_| malformed(start, "handle pointer"));
        }

        let template_index = if template_pointer >= 0 {
            usize::try_from(template_pointer).map_err(|_| malformed(start, "handle pointer"))?
        } else {
            let class_name = data
                .get("$type")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed(start, "handle class"))?;
            *self
                .class_templates
                .get(class_name)
                .ok_or_else(|| unsupported("new package handle class"))?
        };
        let index =
            if template_pointer >= 0 && self.claimed_chunks.borrow_mut().insert(template_index) {
                template_index
            } else {
                if !self.discovering.get() {
                    return Err(unsupported("late package handle discovery"));
                }
                let mut templates = self.chunk_templates.borrow_mut();
                let index = templates.len();
                templates.push(template_index);
                self.claimed_chunks.borrow_mut().insert(index);
                index
            };
        self.chunks.borrow_mut().insert(index, data);
        if let Some(handle_id) = handle_id {
            self.handle_ids
                .borrow_mut()
                .insert(handle_id.to_owned(), index);
        }
        i32::try_from(index).map_err(|_| malformed(start, "handle pointer"))
    }

    fn encode_array(
        &self,
        value: &'a Value,
        inner: &str,
        start: usize,
        limit: usize,
    ) -> Result<(Vec<u8>, usize), PackageError> {
        let values = value
            .as_array()
            .ok_or_else(|| malformed(start, "array JSON"))?;
        let mut output = u32::try_from(values.len())
            .map_err(|_| malformed(start, "array count"))?
            .to_le_bytes()
            .to_vec();
        let template_count = usize::try_from(u32_at(self.template, start)?)
            .map_err(|_| malformed(start, "template array count"))?;
        let (elements, template_end) =
            self.encode_array_elements(values, inner, template_count, start + 4, limit)?;
        output.extend_from_slice(&elements);
        Ok((output, template_end))
    }

    fn encode_array_elements(
        &self,
        values: &'a [Value],
        inner: &str,
        template_count: usize,
        start: usize,
        limit: usize,
    ) -> Result<(Vec<u8>, usize), PackageError> {
        let mut templates = Vec::with_capacity(template_count);
        let mut cursor = start;
        for _ in 0..template_count {
            let element_limit = fixed_size(inner).map_or(limit, |size| cursor + size);
            let (_, end) = self.reader.read_value(inner, cursor, element_limit)?;
            templates.push((cursor, element_limit, end));
            cursor = end;
        }
        if templates.is_empty() && !values.is_empty() {
            return Err(unsupported(
                "package array growth requires an existing element template",
            ));
        }
        let mut output = Vec::new();
        for (index, value) in values.iter().enumerate() {
            let (element_start, element_limit, _) = templates
                .get(index)
                .or_else(|| templates.last())
                .expect("non-empty values require an element template");
            let (encoded, _) =
                self.encode_value(value, "", "", inner, *element_start, *element_limit)?;
            output.extend_from_slice(&encoded);
        }
        Ok((output, cursor))
    }

    fn name_index(&self, value: &str) -> Result<u16, PackageError> {
        if let Some(index) = self.names.borrow().get(value).copied() {
            return Ok(index);
        }
        let index = u16::try_from(self.reader.names.len() + self.new_names.borrow().len())
            .map_err(|_| malformed(0, "name index"))?;
        self.new_names.borrow_mut().push(value.to_owned());
        self.names.borrow_mut().insert(value.to_owned(), index);
        Ok(index)
    }

    fn import_index(
        &self,
        path: &str,
        explicit_hash: Option<u64>,
        soft: bool,
    ) -> Result<i16, PackageError> {
        if let Some(index) = self.imports.borrow().get(&(path.to_owned(), soft)).copied() {
            return Ok(index);
        }
        let path_hash = explicit_hash.unwrap_or_else(|| archive::depot_path_hash(path));
        if let Some((index, _)) = self.reader.imports.iter().enumerate().find(|(_, import)| {
            import.soft == soft
                && match &import.path {
                    PackagePath::Text(existing) => existing == path,
                    PackagePath::Hash(hash) => *hash == path_hash,
                }
        }) {
            let index = i16::try_from(index).map_err(|_| malformed(index, "import index"))?;
            self.imports
                .borrow_mut()
                .insert((path.to_owned(), soft), index);
            return Ok(index);
        }
        let index = i16::try_from(self.reader.imports.len() + self.new_imports.borrow().len())
            .map_err(|_| malformed(0, "import index"))?;
        self.new_imports.borrow_mut().push(Import {
            path: if self.imports_as_hash {
                PackagePath::Hash(path_hash)
            } else {
                PackagePath::Text(path.to_owned())
            },
            soft,
        });
        self.imports
            .borrow_mut()
            .insert((path.to_owned(), soft), index);
        Ok(index)
    }

    fn encode_compiled_effect_property(
        &self,
        value: &'a Value,
        name: &str,
        start: usize,
    ) -> Result<(Vec<u8>, usize), PackageError> {
        let values = value
            .as_array()
            .ok_or_else(|| malformed(start, "compiled effect array"))?;
        let mut output = u32::try_from(values.len())
            .map_err(|_| malformed(start, "compiled effect count"))?
            .to_le_bytes()
            .to_vec();
        for value in values {
            match name {
                "placementTags" | "componentNames" => output.extend_from_slice(
                    &self.name_index(storage_value(value, start)?)?.to_le_bytes(),
                ),
                "relativePositions" => {
                    for key in ["X", "Y", "Z"] {
                        output.extend_from_slice(
                            &json_f32(
                                value.get(key).ok_or_else(|| malformed(start, "Vector3"))?,
                                start,
                            )?
                            .to_le_bytes(),
                        );
                    }
                }
                "relativeRotations" => {
                    for key in ["i", "j", "k", "r"] {
                        output.extend_from_slice(
                            &json_f32(
                                value
                                    .get(key)
                                    .ok_or_else(|| malformed(start, "Quaternion"))?,
                                start,
                            )?
                            .to_le_bytes(),
                        );
                    }
                }
                "placementInfos" => {
                    for key in [
                        "placementTagIndex",
                        "relativePositionIndex",
                        "relativeRotationIndex",
                        "flags",
                    ] {
                        output.push(
                            u8::try_from(json_u64(
                                value
                                    .get(key)
                                    .ok_or_else(|| malformed(start, "placement info"))?,
                                start,
                            )?)
                            .map_err(|_| malformed(start, "placement info"))?,
                        );
                    }
                }
                "eventsSortedByRUID" => {
                    for key in ["eventRUID", "placementIndexMask", "componentIndexMask"] {
                        output.extend_from_slice(
                            &json_string_u64(
                                value
                                    .get(key)
                                    .ok_or_else(|| malformed(start, "effect event"))?,
                                start,
                            )?
                            .to_le_bytes(),
                        );
                    }
                    output.push(
                        u8::try_from(json_u64(
                            value
                                .get("flags")
                                .ok_or_else(|| malformed(start, "effect event flags"))?,
                            start,
                        )?)
                        .map_err(|_| malformed(start, "effect event flags"))?,
                    );
                    output.extend_from_slice(&[0; 7]);
                }
                _ => return Err(unsupported(name)),
            }
        }
        let template_end = self
            .reader
            .read_compiled_effect_property(name, start, self.template.len())
            .ok_or_else(|| unsupported(name))??
            .1;
        Ok((output, template_end))
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the sequential package section rebuild keeps relative offsets auditable"
)]
fn build_package(
    template: &[u8],
    layout: &PackageLayout,
    encoder: &Encoder<'_>,
    chunk_templates: &[usize],
    chunk_offsets: &[usize],
    chunk_data: &[u8],
    settings: PackageSettings,
) -> Result<Vec<u8>, PackageError> {
    let mut names = layout.names.clone();
    names.extend(encoder.new_names.borrow().iter().cloned());
    let mut imports = layout.imports.clone();
    imports.extend(encoder.new_imports.borrow().iter().cloned());
    if layout.sections != 7 && !imports.is_empty() {
        return Err(unsupported("package section-count transition"));
    }

    let mut output = vec![0_u8; layout.header_size];
    output.extend_from_slice(
        template
            .get(layout.header_size..layout.base)
            .ok_or_else(|| malformed(layout.header_size, "CRUID template bounds"))?,
    );
    let base = output.len();

    let ref_desc_offset = if imports.is_empty() {
        0
    } else {
        relative_offset(output.len(), base)?
    };
    let ref_descriptor_start = output.len();
    output.resize(
        output
            .len()
            .checked_add(imports.len() * 4)
            .ok_or_else(|| malformed(base, "import descriptors"))?,
        0,
    );
    let ref_data_offset = if imports.is_empty() {
        0
    } else {
        relative_offset(output.len(), base)?
    };
    for (index, import) in imports.iter().enumerate() {
        let offset = relative_offset(output.len(), base)?;
        if offset >= 1 << 23 {
            return Err(malformed(output.len(), "import offset range"));
        }
        let import_bytes = match &import.path {
            PackagePath::Text(path) if !settings.imports_as_hash => path.as_bytes().to_vec(),
            PackagePath::Text(path) => archive::depot_path_hash(path).to_le_bytes().to_vec(),
            PackagePath::Hash(hash) => hash.to_le_bytes().to_vec(),
        };
        let size = u32::try_from(import_bytes.len())
            .map_err(|_| malformed(output.len(), "import size"))?;
        if size > u32::from(u8::MAX) {
            return Err(malformed(output.len(), "import size range"));
        }
        let bits = offset | (size << 23) | (u32::from(import.soft) << 31);
        write_u32(&mut output, ref_descriptor_start + index * 4, bits)?;
        output.extend_from_slice(&import_bytes);
    }

    let name_desc_offset = relative_offset(output.len(), base)?;
    let name_descriptor_start = output.len();
    output.resize(
        output
            .len()
            .checked_add(names.len() * 4)
            .ok_or_else(|| malformed(base, "name descriptors"))?,
        0,
    );
    let name_data_offset = relative_offset(output.len(), base)?;
    for (index, name) in names.iter().enumerate() {
        let offset = relative_offset(output.len(), base)?;
        if offset >= 1 << 24 {
            return Err(malformed(output.len(), "name offset range"));
        }
        let size =
            u32::try_from(name.len() + 1).map_err(|_| malformed(output.len(), "name size"))?;
        if size > u32::from(u8::MAX) {
            return Err(malformed(output.len(), "name size range"));
        }
        write_u32(
            &mut output,
            name_descriptor_start + index * 4,
            offset | (size << 24),
        )?;
        output.extend_from_slice(name.as_bytes());
        output.push(0);
    }

    let chunk_desc_offset = relative_offset(output.len(), base)?;
    let chunk_descriptor_start = output.len();
    output.resize(
        output
            .len()
            .checked_add(chunk_templates.len() * 8)
            .ok_or_else(|| malformed(base, "chunk descriptors"))?,
        0,
    );
    let chunk_data_offset = relative_offset(output.len(), base)?;
    for (index, (&template_index, chunk_offset)) in
        chunk_templates.iter().zip(chunk_offsets).enumerate()
    {
        let entry = chunk_descriptor_start + index * 8;
        let (type_index, _) = layout.chunks[template_index];
        write_u32(
            &mut output,
            entry,
            u32::try_from(type_index).map_err(|_| malformed(entry, "chunk type index"))?,
        )?;
        write_u32(
            &mut output,
            entry + 4,
            chunk_data_offset
                .checked_add(
                    u32::try_from(*chunk_offset).map_err(|_| malformed(entry, "chunk offset"))?,
                )
                .ok_or_else(|| malformed(entry, "chunk offset"))?,
        )?;
    }
    output.extend_from_slice(chunk_data);

    output[0] = layout.version;
    output[1] = layout.unknown1;
    write_u16(&mut output, 2, layout.sections)?;
    write_u32(&mut output, 4, u32_at(template, 4)?)?;
    if layout.sections == 7 {
        write_u32(&mut output, 8, ref_desc_offset)?;
        write_u32(&mut output, 12, ref_data_offset)?;
        write_u32(&mut output, 16, name_desc_offset)?;
        write_u32(&mut output, 20, name_data_offset)?;
        write_u32(&mut output, 24, chunk_desc_offset)?;
        write_u32(&mut output, 28, chunk_data_offset)?;
    } else {
        write_u32(&mut output, 8, name_desc_offset)?;
        write_u32(&mut output, 12, name_data_offset)?;
        write_u32(&mut output, 16, chunk_desc_offset)?;
        write_u32(&mut output, 20, chunk_data_offset)?;
    }
    Ok(output)
}

fn relative_offset(offset: usize, base: usize) -> Result<u32, PackageError> {
    u32::try_from(
        offset
            .checked_sub(base)
            .ok_or_else(|| malformed(offset, "relative offset"))?,
    )
    .map_err(|_| malformed(offset, "relative offset"))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), PackageError> {
    bytes
        .get_mut(offset..offset + 2)
        .ok_or_else(|| malformed(offset, "write bounds"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), PackageError> {
    bytes
        .get_mut(offset..offset + 4)
        .ok_or_else(|| malformed(offset, "write bounds"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn storage_value(value: &Value, offset: usize) -> Result<&str, PackageError> {
    value
        .get("$value")
        .and_then(Value::as_str)
        .or_else(|| value.as_str())
        .ok_or_else(|| malformed(offset, "stored string"))
}

fn json_i64(value: &Value, offset: usize) -> Result<i64, PackageError> {
    value
        .as_i64()
        .or_else(|| value.as_bool().map(i64::from))
        .ok_or_else(|| malformed(offset, "signed integer JSON"))
}

fn json_u64(value: &Value, offset: usize) -> Result<u64, PackageError> {
    value
        .as_u64()
        .or_else(|| value.as_bool().map(u64::from))
        .ok_or_else(|| malformed(offset, "unsigned integer JSON"))
}

fn json_string_i64(value: &Value, offset: usize) -> Result<i64, PackageError> {
    value
        .as_str()
        .ok_or_else(|| malformed(offset, "signed integer string"))?
        .parse()
        .map_err(|_| malformed(offset, "signed integer string"))
}

fn json_string_u64(value: &Value, offset: usize) -> Result<u64, PackageError> {
    value
        .as_str()
        .ok_or_else(|| malformed(offset, "unsigned integer string"))?
        .parse()
        .map_err(|_| malformed(offset, "unsigned integer string"))
}

fn json_f32(value: &Value, offset: usize) -> Result<f32, PackageError> {
    value
        .to_string()
        .parse()
        .map_err(|_| malformed(offset, "Float JSON"))
}

fn json_f64(value: &Value, offset: usize) -> Result<f64, PackageError> {
    value
        .as_f64()
        .ok_or_else(|| malformed(offset, "Double JSON"))
}

fn tweak_db_id(value: &str) -> u64 {
    value.parse::<u64>().unwrap_or_else(|_| {
        u64::from(crc32fast::hash(value.as_bytes()))
            | (u64::try_from(value.len()).unwrap_or(u64::MAX) << 32)
    })
}

fn collect_handle_targets(value: &Value, targets: &mut HashSet<usize>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_handle_targets(value, targets);
            }
        }
        Value::Object(object) => {
            if let Some(index) = object
                .get("$package_handle")
                .and_then(Value::as_i64)
                .and_then(|value| usize::try_from(value).ok())
            {
                targets.insert(index);
            }
            for value in object.values() {
                collect_handle_targets(value, targets);
            }
        }
        _ => {}
    }
}

fn expand_handles(
    value: Value,
    chunks: &[Value],
    visited: &mut HashSet<usize>,
    settings: PackageSettings,
) -> Result<Value, PackageError> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(|value| expand_handles(value, chunks, visited, settings))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(mut object)
            if object.len() == 1 && object.contains_key("$package_handle") =>
        {
            let index = object
                .remove("$package_handle")
                .and_then(|value| value.as_i64())
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| malformed(0, "handle index"))?;
            let handle_id = settings
                .handle_id_base
                .checked_add(index)
                .ok_or_else(|| malformed(0, "handle ID"))?;
            if !visited.insert(index) {
                return Ok(json!({"HandleRefId": handle_id.to_string()}));
            }
            let data = chunks
                .get(index)
                .cloned()
                .ok_or_else(|| malformed(0, "handle target"))?;
            Ok(json!({
                "HandleId": handle_id.to_string(),
                "Data": expand_handles(data, chunks, visited, settings)?
            }))
        }
        Value::Object(object) => object
            .into_iter()
            .map(|(key, value)| Ok((key, expand_handles(value, chunks, visited, settings)?)))
            .collect::<Result<Map<_, _>, PackageError>>()
            .map(Value::Object),
        scalar => Ok(scalar),
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
        _ if red_type.starts_with("handle:") || red_type.starts_with("whandle:") => Some(4),
        _ if red_type.starts_with("rRef:") || red_type.starts_with("raRef:") => Some(2),
        _ => None,
    }
}

fn split_count_type(value: &str) -> Option<(usize, &str)> {
    let (count, inner) = value.split_once(',')?;
    Some((count.parse().ok()?, inner))
}

fn length_prefixed_string(bytes: &[u8], start: usize) -> Result<(String, usize), PackageError> {
    let length = usize::from(u16_at(bytes, start)?);
    string_bytes(bytes, start + 2, length)
}

fn signed_length_string(bytes: &[u8], start: usize) -> Result<(String, usize), PackageError> {
    let length = usize::try_from(i16_at(bytes, start)?)
        .map_err(|_| malformed(start, "negative string length"))?;
    string_bytes(bytes, start + 2, length)
}

fn string_bytes(
    bytes: &[u8],
    start: usize,
    length: usize,
) -> Result<(String, usize), PackageError> {
    let end = start
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| malformed(start, "string bounds"))?;
    Ok((
        std::str::from_utf8(&bytes[start..end])
            .map_err(|_| malformed(start, "string UTF-8"))?
            .to_owned(),
        end,
    ))
}

fn storage_string(red_type: &str, value: &str) -> Value {
    json!({"$type": red_type, "$storage": "string", "$value": value})
}

fn storage_u64(red_type: &str, value: u64) -> Value {
    json!({"$type": red_type, "$storage": "uint64", "$value": value.to_string()})
}

fn byte(bytes: &[u8], offset: usize) -> Result<u8, PackageError> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| malformed(offset, "byte bounds"))
}

fn i16_at(bytes: &[u8], offset: usize) -> Result<i16, PackageError> {
    Ok(i16::from_le_bytes(slice(bytes, offset)?))
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, PackageError> {
    Ok(u16::from_le_bytes(slice(bytes, offset)?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, PackageError> {
    Ok(u32::from_le_bytes(slice(bytes, offset)?))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, PackageError> {
    Ok(u64::from_le_bytes(slice(bytes, offset)?))
}

fn slice<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], PackageError> {
    bytes
        .get(offset..offset + N)
        .ok_or_else(|| malformed(offset, "integer bounds"))?
        .try_into()
        .map_err(|_| malformed(offset, "integer"))
}

fn add(base: usize, relative: u32) -> Result<usize, PackageError> {
    base.checked_add(usize::try_from(relative).map_err(|_| malformed(base, "relative offset"))?)
        .ok_or_else(|| malformed(base, "relative offset"))
}

fn malformed(offset: usize, reason: &'static str) -> PackageError {
    PackageError::Malformed { offset, reason }
}

fn unsupported(red_type: &str) -> PackageError {
    PackageError::Unsupported(red_type.to_owned())
}
