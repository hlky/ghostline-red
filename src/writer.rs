//! Template-backed generic CR2W writer.

use crate::{
    archive::{self, ArchiveError},
    codec::{self, fixed_curve_class_size},
    cr2w::{self, Cr2wError, Cr2wInspection},
    redpackage::{self, PackageError, PackageSettings},
    schema::{self, RedSchema},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crc32fast::Hasher;
use serde::Deserialize;
use serde_json::Value;
use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
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

struct PrefixPlan<'a, 'v> {
    names: &'a [String],
    new_imports: &'a [NewImport],
    new_exports: &'a [NewExport<'v>],
    export_indices: &'a [usize],
    export_remap: &'a HashMap<usize, usize>,
    import_indices: &'a [usize],
    import_remap: &'a HashMap<usize, usize>,
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
    used_imports: RefCell<HashSet<String>>,
    handle_exports: RefCell<HashMap<String, usize>>,
    export_remap: RefCell<HashMap<usize, usize>>,
    claimed_exports: RefCell<HashSet<usize>>,
    candidate_handles: RefCell<HashSet<String>>,
    discovering_handles: Cell<bool>,
    classes: &'a BTreeSet<String>,
    schema: &'a BTreeMap<String, schema::RedClass>,
    enums: Option<&'a BTreeSet<String>>,
    bitfields: Option<&'a BTreeSet<String>>,
}

/// Writes WKit-shaped JSON using an existing CR2W resource as its audited
/// table, chunk-layout, and buffer template.
///
/// Reflected values and strings are rebuilt. Export chunks absent from the
/// authored JSON handle graph are pruned; custom appendices and buffer payloads
/// are retained byte-for-byte unless the JSON provides a supported override.
///
/// # Errors
///
/// Returns [`WriterError`] for malformed JSON/templates, values not present in
/// the template name/import tables, unsupported structural changes, or I/O.
pub fn write_with_template(
    json_path: &Path,
    template_path: &Path,
    output_path: &Path,
    classes: &BTreeSet<String>,
    schema: &BTreeMap<String, schema::RedClass>,
    kraken_path: &OsStr,
) -> Result<(), WriterError> {
    write_with_schema(
        json_path,
        template_path,
        output_path,
        classes,
        schema,
        None,
        None,
        None,
        kraken_path,
    )
}

/// Writes WKit-shaped JSON with explicit official enum and bitfield categories.
///
/// # Errors
///
/// Returns [`WriterError`] under the same conditions as
/// [`write_with_template`].
pub fn write_with_red_schema(
    json_path: &Path,
    template_path: &Path,
    output_path: &Path,
    schema: &RedSchema,
    kraken_path: &OsStr,
) -> Result<(), WriterError> {
    let classes = schema.class_names();
    write_with_schema(
        json_path,
        template_path,
        output_path,
        &classes,
        &schema.classes,
        Some(&schema.enums),
        Some(&schema.bitfields),
        Some(schema),
        kraken_path,
    )
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the sequential container rebuild keeps offset and CRC patching auditable"
)]
fn write_with_schema(
    json_path: &Path,
    template_path: &Path,
    output_path: &Path,
    classes: &BTreeSet<String>,
    schema: &BTreeMap<String, schema::RedClass>,
    enums: Option<&BTreeSet<String>>,
    bitfields: Option<&BTreeSet<String>>,
    red_schema: Option<&RedSchema>,
    kraken_path: &OsStr,
) -> Result<(), WriterError> {
    let document = read_json(json_path)?;
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
    remap_buffer_overrides(&mut buffer_overrides, &file, &template, kraken_path)?;
    let redpackage_ordinals = red_schema
        .and_then(|schema| {
            codec::decode_wkit_with_red_schema(template_path, schema, kraken_path).ok()
        })
        .map_or_else(HashMap::new, |template_document| {
            redpackage_ordinal_map(&document, &template_document)
        });
    let redpackage_context = RedPackageContext {
        file: &file,
        template: &template,
        classes,
        kraken_path,
        ordinals: &redpackage_ordinals,
    };
    let mut claimed_redpackages = HashSet::new();
    collect_redpackage_overrides(
        &document,
        &redpackage_context,
        &mut buffer_overrides,
        &mut claimed_redpackages,
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
        used_imports: RefCell::new(
            file.embedded
                .iter()
                .map(|embedded| embedded.depot_path.clone())
                .collect(),
        ),
        handle_exports: RefCell::new(HashMap::new()),
        export_remap: RefCell::new(HashMap::new()),
        claimed_exports: RefCell::new(HashSet::new()),
        candidate_handles: RefCell::new(HashSet::new()),
        discovering_handles: Cell::new(true),
        classes,
        schema,
        enums,
        bitfields,
    };
    // Seed discovery with every authored handle definition. Template-shaped
    // traversal can skip handles that only become reachable after array
    // growth or socket rewiring, but the second encoding pass must still have
    // a stable export mapping for those authored definitions.
    collect_handle_ids(&document, &mut encoder.candidate_handles.borrow_mut());
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
    let new_exports = collect_new_exports(
        &document,
        &file,
        &encoder.candidate_handles,
        &encoder.handle_exports,
    )?;
    for (offset, export) in new_exports.iter().enumerate() {
        let export_index = file.exports.len() + offset;
        chunks.insert(export_index, export.value);
        encoder
            .handle_exports
            .borrow_mut()
            .insert(export.handle_id.clone(), export_index);
        let _ = encoder.name_index(&export.class_name)?;
        let template = &file.exports[export.template_index];
        let start = usize::try_from(template.data_offset).map_err(|_| WriterError::TooLarge)?;
        let size = usize::try_from(template.data_size).map_err(|_| WriterError::TooLarge)?;
        let _ = encoder.encode_class(export.value, start, size, &export.class_name, &mut chunks)?;
    }
    encoder.discovering_handles.set(false);

    let (export_indices, export_remap) = compact_export_indices(&chunks);
    if export_indices.first() != Some(&0) {
        return Err(unsupported(
            "authored graph does not retain the root export",
        ));
    }
    {
        let mut handle_exports = encoder.handle_exports.borrow_mut();
        for export_index in handle_exports.values_mut() {
            *export_index = export_remap
                .get(export_index)
                .copied()
                .ok_or_else(|| unsupported("authored handle maps to a pruned export"))?;
        }
    }
    *encoder.export_remap.borrow_mut() = export_remap;
    let mut compact_chunks = HashMap::with_capacity(chunks.len());
    for (compact_index, source_index) in export_indices.iter().copied().enumerate() {
        let value = chunks
            .remove(&source_index)
            .ok_or_else(|| unsupported("missing authored export chunk"))?;
        compact_chunks.insert(compact_index, value);
    }
    chunks = compact_chunks;

    let new_imports = encoder.new_imports.borrow().clone();
    let (import_indices, import_remap) =
        compact_import_indices(&file, &new_imports, &encoder.used_imports.borrow());
    {
        let mut imports = encoder.imports.borrow_mut();
        imports.clear();
        for (compact_index, source_index) in import_indices.iter().copied().enumerate() {
            let path = if let Some(import) = file.imports.get(source_index) {
                &import.depot_path
            } else {
                &new_imports[source_index - file.imports.len()].depot_path
            };
            imports.insert(
                path.clone(),
                u16::try_from(compact_index + 1).map_err(|_| WriterError::TooLarge)?,
            );
        }
    }

    let new_names = encoder.new_names.borrow().clone();
    let mut name_values: Vec<String> = file.names.iter().map(|name| name.value.clone()).collect();
    name_values.extend(new_names.iter().cloned());
    let (mut output, prefix_layout) = build_prefix(
        &template,
        &file,
        &PrefixPlan {
            names: &name_values,
            new_imports: &new_imports,
            new_exports: &new_exports,
            export_indices: &export_indices,
            export_remap: &encoder.export_remap.borrow(),
            import_indices: &import_indices,
            import_remap: &import_remap,
        },
    )?;
    let mut export_layout = Vec::with_capacity(export_indices.len());
    for (index, source_index) in export_indices.iter().copied().enumerate() {
        let (export, class_name) = if let Some(export) = file.exports.get(source_index) {
            (export, export.class_name.as_str())
        } else {
            let new_export = &new_exports[source_index - file.exports.len()];
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
            } else if buffer_matches(stored, &replacement.bytes, kraken_path)? {
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

fn read_json(path: &Path) -> Result<Value, WriterError> {
    let bytes = fs::read(path)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
    Ok(Value::deserialize(deserializer)?)
}

impl Encoder<'_> {
    #[expect(
        clippy::too_many_lines,
        reason = "template properties and schema-inserted properties share one ordered class rebuild"
    )]
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
            return Ok((area_shape_outline_buffer(value)?, template_end));
        }
        if is_opaque_custom_data(red_type) {
            let bytes = value
                .get("$rawData")
                .and_then(Value::as_str)
                .map(|bytes| STANDARD.decode(bytes))
                .transpose()?
                .unwrap_or_else(|| self.template[template_start..template_end].to_vec());
            return Ok((bytes, template_end));
        }
        let object = value
            .as_object()
            .ok_or_else(|| unsupported(format!("{red_type} is not an object")))?;
        let mut cursor = template_start;
        if self.byte(cursor)? != 0 {
            return Err(unsupported(format!("{red_type} custom-data chunk")));
        }
        cursor += 1;
        let mut encoded_properties = Vec::new();
        let mut present_properties = HashSet::new();
        let mut property_order = 0_usize;
        loop {
            let name_index = self.u16(cursor)?;
            cursor += 2;
            if name_index == 0 {
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
            let (payload, consumed) = self
                .encode_value(property_value, property_type, cursor, payload_size, chunks)
                .map_err(|error| match error {
                    WriterError::Unsupported(reason) => {
                        unsupported(format!("{red_type}.{property}: {reason}"))
                    }
                    other => other,
                })?;
            if consumed != payload_end {
                return Err(unsupported(format!(
                    "{red_type}.{property} template was not consumed"
                )));
            }
            let ordinal = class_property(self.schema, red_type, property)
                .and_then(|property| property.ordinal);
            encoded_properties.push((
                ordinal,
                property_order,
                encode_property(name_index, type_index, &payload)?,
            ));
            present_properties.insert(property.to_owned());
            property_order += 1;
            cursor = payload_end;
        }
        for (property, property_value) in object {
            if property == "$type" || present_properties.contains(property) {
                continue;
            }
            let Some(schema_property) = class_property(self.schema, red_type, property) else {
                continue;
            };
            let Some(property_type) = red_type_from_cs(&schema_property.cs_type) else {
                continue;
            };
            if is_default_missing_value(property_value, &property_type) {
                continue;
            }
            let payload = self.encode_new_value(property_value, &property_type)?;
            let name_index = self.name_index(property)?;
            let type_index = self.name_index(&property_type)?;
            encoded_properties.push((
                schema_property.ordinal,
                property_order,
                encode_property(name_index, type_index, &payload)?,
            ));
            property_order += 1;
        }
        encoded_properties.sort_by_key(|(ordinal, order, _)| (ordinal.unwrap_or(u32::MAX), *order));
        let mut output = vec![0];
        for (_, _, property) in encoded_properties {
            output.extend_from_slice(&property);
        }
        output.extend_from_slice(&0_u16.to_le_bytes());
        if red_type == "worldStreamingSector" {
            output.extend_from_slice(&self.encode_streaming_sector_appendix(
                object,
                cursor,
                template_end,
                chunks,
            )?);
            return Ok((output, template_end));
        }
        if red_type == "gameDeviceResourceData" {
            output.extend_from_slice(&self.encode_device_data_appendix(object)?);
            return Ok((output, template_end));
        }
        if matches!(red_type, "worldStreamingWorld" | "CMaterialInstance") {
            // Typed reverse appendix codecs are connected separately; until
            // then the audited template bytes remain authoritative.
            output.extend_from_slice(&self.template[cursor..template_end]);
            return Ok((output, template_end));
        }
        if cursor < template_end && is_opaque_appendix(red_type) {
            let tail = object
                .get("$rawTail")
                .and_then(Value::as_str)
                .map(|bytes| STANDARD.decode(bytes))
                .transpose()?
                .unwrap_or_else(|| self.template[cursor..template_end].to_vec());
            output.extend_from_slice(&tail);
            return Ok((output, template_end));
        }
        Ok((output, cursor))
    }

    fn encode_new_value(&self, value: &Value, red_type: &str) -> Result<Vec<u8>, WriterError> {
        match red_type {
            "Bool" => Ok(vec![u8::from(json_bool(value)?)]),
            "Int8" => Ok(i8::try_from(json_i64(value)?)
                .map_err(|_| unsupported("Int8 range"))?
                .to_le_bytes()
                .to_vec()),
            "Uint8" => Ok(vec![
                u8::try_from(json_u64(value)?).map_err(|_| unsupported("Uint8 range"))?,
            ]),
            "Int16" => Ok(i16::try_from(json_i64(value)?)
                .map_err(|_| unsupported("Int16 range"))?
                .to_le_bytes()
                .to_vec()),
            "Uint16" => Ok(u16::try_from(json_u64(value)?)
                .map_err(|_| unsupported("Uint16 range"))?
                .to_le_bytes()
                .to_vec()),
            "Int32" => Ok(i32::try_from(json_i64(value)?)
                .map_err(|_| unsupported("Int32 range"))?
                .to_le_bytes()
                .to_vec()),
            "Uint32" => Ok(u32::try_from(json_u64(value)?)
                .map_err(|_| unsupported("Uint32 range"))?
                .to_le_bytes()
                .to_vec()),
            "Int64" => Ok(json_string_i64(value)?.to_le_bytes().to_vec()),
            "Uint64" | "CRUID" | "CDateTime" => Ok(json_string_u64(value)?.to_le_bytes().to_vec()),
            "Float" => Ok(json_f32(value)?.to_le_bytes().to_vec()),
            "Double" => Ok(json_f64(value)?.to_le_bytes().to_vec()),
            "CName" => Ok(self
                .name_index(storage_value(value)?)?
                .to_le_bytes()
                .to_vec()),
            "String" => encode_string(value.as_str().ok_or_else(|| unsupported("String value"))?),
            "NodeRef" => encode_string(node_ref_value(value)?),
            "TweakDBID" => Ok(tweak_db_id(storage_or_string(value)?)?
                .to_le_bytes()
                .to_vec()),
            _ if red_type.starts_with("array:") => {
                let values = value.as_array().ok_or_else(|| unsupported("array value"))?;
                let inner = &red_type[6..];
                let mut output = u32::try_from(values.len())
                    .map_err(|_| WriterError::TooLarge)?
                    .to_le_bytes()
                    .to_vec();
                for value in values {
                    output.extend_from_slice(&self.encode_new_value(value, inner)?);
                }
                Ok(output)
            }
            _ if value.is_string() => Ok(self
                .name_index(normalize_wolvenkit_enum_name(
                    value
                        .as_str()
                        .ok_or_else(|| unsupported(format!("{red_type} enum")))?,
                ))?
                .to_le_bytes()
                .to_vec()),
            _ => Err(unsupported(format!(
                "cannot synthesize missing property type {red_type}"
            ))),
        }
    }

    fn encode_device_data_appendix(
        &self,
        object: &serde_json::Map<String, Value>,
    ) -> Result<Vec<u8>, WriterError> {
        let entries = object
            .get("unk1")
            .and_then(Value::as_array)
            .ok_or_else(|| unsupported("gameDeviceResourceData.unk1"))?;
        let mut output = vec![0_u8; 4];
        output.extend_from_slice(
            &u32::try_from(entries.len())
                .map_err(|_| WriterError::TooLarge)?
                .to_le_bytes(),
        );
        for entry in entries {
            let class_name = entry
                .pointer("/className/$value")
                .and_then(Value::as_str)
                .ok_or_else(|| unsupported("device data className"))?;
            output.extend_from_slice(&encode_device_data_entry(
                entry,
                self.name_index(class_name)?,
            )?);
        }
        let size = u32::try_from(output.len()).map_err(|_| WriterError::TooLarge)?;
        write_u32_at(&mut output, 0, size)?;
        Ok(output)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the appendix fields are encoded in their fixed binary order"
    )]
    fn encode_streaming_sector_appendix<'v>(
        &self,
        object: &'v serde_json::Map<String, Value>,
        start: usize,
        end: usize,
        chunks: &mut HashMap<usize, &'v Value>,
    ) -> Result<Vec<u8>, WriterError> {
        let mut template_cursor = start
            .checked_add(12)
            .filter(|cursor| *cursor <= end)
            .ok_or_else(|| unsupported("streaming sector appendix bounds"))?;
        let (template_node_count, next) = self.vlq(template_cursor)?;
        template_cursor = next;
        let template_node_start = template_cursor;
        let _template_nodes_end = template_cursor
            .checked_add(template_node_count * 4)
            .filter(|cursor| *cursor <= end)
            .ok_or_else(|| unsupported("streaming sector node bounds"))?;

        let nodes = object
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| unsupported("worldStreamingSector.nodes"))?;
        if self.discovering_handles.get() {
            for (index, value) in nodes.iter().enumerate() {
                if index < template_node_count {
                    let pointer = template_node_start + index * 4;
                    let _ = self.encode_value(value, "handle:worldNode", pointer, 4, chunks)?;
                } else {
                    collect_handle_ids(value, &mut self.candidate_handles.borrow_mut());
                }
            }
            return self
                .template
                .get(start..end)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| unsupported("streaming sector appendix bounds"));
        }

        for property in ["persistentNodes", "variantNodes"] {
            if object
                .get(property)
                .and_then(Value::as_array)
                .is_some_and(|values| !values.is_empty())
            {
                return Err(unsupported(format!(
                    "worldStreamingSector.{property} is non-empty"
                )));
            }
        }

        let version = object
            .get("version")
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| unsupported("worldStreamingSector.version"))?;
        let buffer_index = object
            .get("nodeData")
            .and_then(|value| value.get("BufferId"))
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| unsupported("worldStreamingSector.nodeData BufferId"))?;
        let buffer_pointer = buffer_index
            .checked_add(1)
            .map(|value| value | 0x8000_0000)
            .ok_or(WriterError::TooLarge)?;

        let mut output = version.to_le_bytes().to_vec();
        output.extend_from_slice(&0_u32.to_le_bytes());
        output.extend_from_slice(&buffer_pointer.to_le_bytes());
        write_positive_vlq(
            &mut output,
            u32::try_from(nodes.len()).map_err(|_| WriterError::TooLarge)?,
        );
        for node in nodes {
            let identity = node
                .get("HandleId")
                .or_else(|| node.get("HandleRefId"))
                .and_then(Value::as_str)
                .ok_or_else(|| unsupported("streaming sector node handle identity"))?;
            let export_index = self
                .handle_exports
                .borrow()
                .get(identity)
                .copied()
                .ok_or_else(|| {
                    unsupported(format!("unknown streaming sector node handle {identity}"))
                })?;
            output.extend_from_slice(
                &u32::try_from(export_index.checked_add(1).ok_or(WriterError::TooLarge)?)
                    .map_err(|_| WriterError::TooLarge)?
                    .to_le_bytes(),
            );
        }

        let node_refs = object
            .get("nodeRefs")
            .and_then(Value::as_array)
            .ok_or_else(|| unsupported("worldStreamingSector.nodeRefs"))?;
        write_positive_vlq(
            &mut output,
            u32::try_from(node_refs.len()).map_err(|_| WriterError::TooLarge)?,
        );
        for node_ref in node_refs {
            output.extend_from_slice(&encode_string(node_ref_value(node_ref)?)?);
        }

        let variants = object
            .get("variantIndices")
            .and_then(Value::as_array)
            .ok_or_else(|| unsupported("worldStreamingSector.variantIndices"))?;
        write_positive_vlq(
            &mut output,
            u32::try_from(variants.len()).map_err(|_| WriterError::TooLarge)?,
        );
        for variant in variants {
            let value = variant
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .ok_or_else(|| unsupported("worldStreamingSector.variantIndices value"))?;
            output.extend_from_slice(&value.to_le_bytes());
        }
        let persistent_node_index = object
            .get("persistentNodeIndex")
            .and_then(Value::as_i64)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| unsupported("worldStreamingSector.persistentNodeIndex"))?;
        output.extend_from_slice(&persistent_node_index.to_le_bytes());
        let inner_size =
            u32::try_from(output.len().saturating_sub(4)).map_err(|_| WriterError::TooLarge)?;
        write_u32_at(&mut output, 4, inner_size)?;
        Ok(output)
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
            "String" => exact(encode_string_with_template(
                value.as_str().ok_or_else(|| unsupported("String value"))?,
                &self.template[template_start..template_end],
            )?),
            "NodeRef" => exact(encode_string_with_template(
                node_ref_value(value)?,
                &self.template[template_start..template_end],
            )?),
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
            "SharedDataBuffer" => {
                let Some(bytes) = value.get("Bytes").and_then(Value::as_str) else {
                    return exact(self.template[template_start..template_end].to_vec());
                };
                let bytes = STANDARD.decode(bytes)?;
                let mut output = u32::try_from(bytes.len())
                    .map_err(|_| WriterError::TooLarge)?
                    .to_le_bytes()
                    .to_vec();
                output.extend_from_slice(&bytes);
                exact(output)
            }
            "DataBuffer" | "serializationDeferredDataBuffer" => {
                exact(self.template[template_start..template_end].to_vec())
            }
            _ if is_opaque_custom_data(red_type) => {
                let bytes = value
                    .get("$rawData")
                    .and_then(Value::as_str)
                    .map(|bytes| STANDARD.decode(bytes))
                    .transpose()?
                    .unwrap_or_else(|| self.template[template_start..template_end].to_vec());
                exact(bytes)
            }
            _ if red_type.starts_with("array:") => {
                self.encode_array(value, &red_type[6..], template_start, template_size, chunks)
            }
            _ if red_type.starts_with('[') => {
                let (capacity, inner) =
                    split_fixed_array_type(red_type).ok_or_else(|| unsupported(red_type))?;
                let elements = value
                    .get("Elements")
                    .ok_or_else(|| unsupported("fixed array Elements"))?;
                if elements
                    .as_array()
                    .is_none_or(|elements| elements.len() > capacity)
                {
                    return Err(unsupported("fixed array capacity"));
                }
                self.encode_array(elements, inner, template_start, template_size, chunks)
            }
            _ if red_type.starts_with("curveData:") => self.encode_legacy_curve(
                value,
                &red_type[10..],
                template_start,
                template_size,
                chunks,
            ),
            _ if red_type.starts_with("multiChannelCurve:") => {
                self.encode_multi_channel_curve(value, template_start, template_size)
            }
            _ if red_type.starts_with("handle:") || red_type.starts_with("whandle:") => {
                if value.is_null() {
                    return exact(0_u32.to_le_bytes().to_vec());
                }
                let template_stored = self.u32(template_start)?;
                if template_stored == 0 {
                    // WolvenKit materializes some default handle objects that
                    // are represented by a null pointer on disk.
                    return exact(0_u32.to_le_bytes().to_vec());
                }
                let template_export_index = usize::try_from(
                    template_stored
                        .checked_sub(1)
                        .ok_or_else(|| unsupported("handle template index"))?,
                )
                .map_err(|_| WriterError::TooLarge)?;
                let identity = handle_identity(value, template_export_index)?;
                if self.discovering_handles.get() {
                    if let Some(data) = value.get("Data") {
                        let class_name = data
                            .get("$type")
                            .and_then(Value::as_str)
                            .ok_or_else(|| unsupported("handle class"))?;
                        let mapped_export_index =
                            self.handle_exports.borrow().get(identity.as_ref()).copied();
                        let export_index = if let Some(export_index) = mapped_export_index {
                            export_index
                        } else if self.file.exports[template_export_index].class_name == class_name
                            && self
                                .claimed_exports
                                .borrow_mut()
                                .insert(template_export_index)
                        {
                            self.handle_exports
                                .borrow_mut()
                                .insert(identity.to_string(), template_export_index);
                            template_export_index
                        } else {
                            collect_handle_ids(data, &mut self.candidate_handles.borrow_mut());
                            self.candidate_handles
                                .borrow_mut()
                                .insert(identity.to_string());
                            return exact(template_stored.to_le_bytes().to_vec());
                        };
                        if let Some(existing) = chunks.insert(export_index, data)
                            && !std::ptr::eq(existing, data)
                            && existing != data
                        {
                            return Err(unsupported(format!(
                                "conflicting handle definitions for identity {identity}"
                            )));
                        }
                    }
                    return exact(template_stored.to_le_bytes().to_vec());
                }
                let mapped_export_index = self
                    .handle_exports
                    .borrow()
                    .get(identity.as_ref())
                    .copied()
                    .or_else(|| {
                        self.export_remap
                            .borrow()
                            .get(&template_export_index)
                            .copied()
                    })
                    .ok_or_else(|| {
                        unsupported(format!(
                            "handle {identity} references pruned template export {template_export_index}"
                        ))
                    })?;
                let export_index = mapped_export_index;
                let stored =
                    u32::try_from(export_index.checked_add(1).ok_or(WriterError::TooLarge)?)
                        .map_err(|_| WriterError::TooLarge)?;
                if let Some(data) = value.get("Data") {
                    if let Some(existing) = chunks.insert(export_index, data)
                        && !std::ptr::eq(existing, data)
                        && existing != data
                    {
                        return Err(unsupported(format!(
                            "conflicting handle data for identity {identity} at export {export_index}"
                        )));
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
                } else {
                    self.used_imports.borrow_mut().insert(path.to_owned());
                    if let Some(index) = self.imports.borrow().get(path).copied() {
                        return exact(index.to_le_bytes().to_vec());
                    }
                    let flags = match value.get("Flags").and_then(Value::as_str) {
                        Some("Obligatory") => 1,
                        Some("Template") => 2,
                        Some("Soft") => 4,
                        Some("Embedded") => 8,
                        Some("Inplace") => 16,
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
            _ if self
                .bitfields
                .is_some_and(|bitfields| bitfields.contains(red_type)) =>
            {
                exact(self.encode_bitfield(value)?)
            }
            _ if self.enums.is_some_and(|enums| enums.contains(red_type)) => exact(
                self.name_index(
                    value
                        .as_str()
                        .ok_or_else(|| unsupported(format!("{red_type} enum")))?,
                )?
                .to_le_bytes()
                .to_vec(),
            ),
            _ if value.is_string() && template_size >= 4 && template_size.is_multiple_of(2) => {
                exact(self.encode_bitfield(value)?)
            }
            _ if self.classes.contains(red_type) && template_size != 2 => {
                self.encode_class(value, template_start, template_size, red_type, chunks)
            }
            _ if template_size == 2 => exact(
                self.name_index(normalize_wolvenkit_enum_name(
                    value
                        .as_str()
                        .ok_or_else(|| unsupported(format!("{red_type} enum")))?,
                ))?
                .to_le_bytes()
                .to_vec(),
            ),
            _ => exact(self.template[template_start..template_end].to_vec()),
        }
    }

    fn encode_bitfield(&self, value: &Value) -> Result<Vec<u8>, WriterError> {
        let mut output = Vec::new();
        for item in value
            .as_str()
            .ok_or_else(|| unsupported("bitfield value"))?
            .split(", ")
            .filter(|item| !item.is_empty() && *item != "0")
        {
            output.extend_from_slice(&self.name_index(item)?.to_le_bytes());
        }
        output.extend_from_slice(&0_u16.to_le_bytes());
        Ok(output)
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

    fn encode_legacy_curve<'v>(
        &self,
        value: &'v Value,
        inner: &str,
        template_start: usize,
        template_size: usize,
        chunks: &mut HashMap<usize, &'v Value>,
    ) -> Result<(Vec<u8>, usize), WriterError> {
        let object = value
            .as_object()
            .ok_or_else(|| unsupported("curve value"))?;
        let values = object
            .get("Elements")
            .and_then(Value::as_array)
            .ok_or_else(|| unsupported("curve Elements"))?;
        let template_end = template_start
            .checked_add(template_size)
            .filter(|end| *end <= self.template.len())
            .ok_or_else(|| unsupported("curve template bounds"))?;
        let values_end = template_end
            .checked_sub(2)
            .filter(|end| *end >= template_start + 4)
            .ok_or_else(|| unsupported("curve template bounds"))?;
        let template_count =
            usize::try_from(self.u32(template_start)?).map_err(|_| WriterError::TooLarge)?;
        let mut cursor = template_start + 4;
        let mut element_templates = Vec::with_capacity(template_count);
        for _ in 0..template_count {
            cursor = cursor
                .checked_add(4)
                .filter(|cursor| *cursor <= values_end)
                .ok_or_else(|| unsupported("curve point bounds"))?;
            let element_start = cursor;
            cursor = if let Some(size) = fixed_curve_class_size(inner) {
                cursor
                    .checked_add(size)
                    .filter(|cursor| *cursor <= values_end)
                    .ok_or_else(|| unsupported("fixed curve class bounds"))?
            } else {
                self.skip_value(inner, cursor, values_end)?
            };
            element_templates.push((element_start, cursor - element_start));
        }
        if cursor != values_end {
            return Err(unsupported("curve template trailing bytes"));
        }
        if values.len() != element_templates.len() {
            return Err(unsupported("curve element count change"));
        }

        let mut output = u32::try_from(values.len())
            .map_err(|_| WriterError::TooLarge)?
            .to_le_bytes()
            .to_vec();
        for (element, (element_start, element_size)) in
            values.iter().zip(element_templates.iter().copied())
        {
            output.extend_from_slice(
                &json_f32(
                    element
                        .get("Point")
                        .ok_or_else(|| unsupported("curve Point"))?,
                )?
                .to_le_bytes(),
            );
            let curve_value = element
                .get("Value")
                .ok_or_else(|| unsupported("curve Value"))?;
            let (encoded, consumed) =
                if let Some(encoded) = encode_fixed_curve_class(curve_value, inner)? {
                    (encoded, element_start + element_size)
                } else {
                    self.encode_value(curve_value, inner, element_start, element_size, chunks)?
                };
            if consumed != element_start + element_size {
                return Err(unsupported("curve element template was not consumed"));
            }
            output.extend_from_slice(&encoded);
        }
        output.push(
            interpolation_type_value(
                object
                    .get("InterpolationType")
                    .and_then(Value::as_str)
                    .ok_or_else(|| unsupported("curve InterpolationType"))?,
            )
            .ok_or_else(|| unsupported("curve InterpolationType"))?,
        );
        output.push(
            segment_link_type_value(
                object
                    .get("LinkType")
                    .and_then(Value::as_str)
                    .ok_or_else(|| unsupported("curve LinkType"))?,
            )
            .ok_or_else(|| unsupported("curve LinkType"))?,
        );
        Ok((output, template_end))
    }

    fn encode_multi_channel_curve(
        &self,
        value: &Value,
        template_start: usize,
        template_size: usize,
    ) -> Result<(Vec<u8>, usize), WriterError> {
        let object = value
            .as_object()
            .ok_or_else(|| unsupported("multi-channel curve value"))?;
        let data = STANDARD.decode(
            object
                .get("Data")
                .and_then(Value::as_str)
                .ok_or_else(|| unsupported("multi-channel curve Data"))?,
        )?;
        let mut output = u32::try_from(
            object
                .get("NumChannels")
                .and_then(Value::as_u64)
                .ok_or_else(|| unsupported("multi-channel curve NumChannels"))?,
        )
        .map_err(|_| WriterError::TooLarge)?
        .to_le_bytes()
        .to_vec();
        output.push(
            interpolation_type_value(
                object
                    .get("InterpolationType")
                    .and_then(Value::as_str)
                    .ok_or_else(|| unsupported("multi-channel curve InterpolationType"))?,
            )
            .ok_or_else(|| unsupported("multi-channel curve InterpolationType"))?,
        );
        output.push(
            channel_link_type_value(
                object
                    .get("LinkType")
                    .and_then(Value::as_str)
                    .ok_or_else(|| unsupported("multi-channel curve LinkType"))?,
            )
            .ok_or_else(|| unsupported("multi-channel curve LinkType"))?,
        );
        output.extend_from_slice(
            &u32::try_from(
                object
                    .get("Alignment")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| unsupported("multi-channel curve Alignment"))?,
            )
            .map_err(|_| WriterError::TooLarge)?
            .to_le_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(data.len())
                .map_err(|_| WriterError::TooLarge)?
                .to_le_bytes(),
        );
        output.extend_from_slice(&data);
        let template_end = template_start
            .checked_add(template_size)
            .filter(|end| *end <= self.template.len())
            .ok_or_else(|| unsupported("multi-channel curve template bounds"))?;
        Ok((output, template_end))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the type dispatch mirrors encode_value and keeps bounds logic together"
    )]
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
        if matches!(red_type, "SharedDataBuffer" | "DataBuffer") {
            return self.skip_buffer_value(red_type, start, limit);
        }
        if let Some(inner) = red_type.strip_prefix("array:") {
            let count = usize::try_from(self.u32(start)?).map_err(|_| WriterError::TooLarge)?;
            let mut cursor = start + 4;
            for _ in 0..count {
                cursor = self.skip_value(inner, cursor, limit)?;
            }
            return Ok(cursor);
        }
        if let Some((capacity, inner)) = split_fixed_array_type(red_type) {
            let count = usize::try_from(self.u32(start)?).map_err(|_| WriterError::TooLarge)?;
            if count > capacity {
                return Err(unsupported("fixed array capacity"));
            }
            let mut cursor = start + 4;
            for _ in 0..count {
                cursor = self.skip_value(inner, cursor, limit)?;
            }
            return Ok(cursor);
        }
        if let Some(inner) = red_type.strip_prefix("curveData:") {
            let count = usize::try_from(self.u32(start)?).map_err(|_| WriterError::TooLarge)?;
            let mut cursor = start + 4;
            for _ in 0..count {
                cursor = cursor
                    .checked_add(4)
                    .filter(|cursor| *cursor <= limit)
                    .ok_or_else(|| unsupported("curve point bounds"))?;
                cursor = if let Some(size) = fixed_curve_class_size(inner) {
                    cursor
                        .checked_add(size)
                        .filter(|cursor| *cursor <= limit)
                        .ok_or_else(|| unsupported("fixed curve class bounds"))?
                } else {
                    self.skip_value(inner, cursor, limit)?
                };
            }
            return cursor
                .checked_add(2)
                .filter(|end| *end <= limit)
                .ok_or_else(|| unsupported("curve trailing fields"));
        }
        if red_type.starts_with("multiChannelCurve:") {
            let size = usize::try_from(self.u32(start + 10)?).map_err(|_| WriterError::TooLarge)?;
            return start
                .checked_add(14)
                .and_then(|start| start.checked_add(size))
                .filter(|end| *end <= limit)
                .ok_or_else(|| unsupported("multi-channel curve bounds"));
        }
        if self
            .bitfields
            .is_some_and(|bitfields| bitfields.contains(red_type))
        {
            let mut cursor = start;
            loop {
                if cursor.checked_add(2).is_none_or(|end| end > limit) {
                    return Err(unsupported("bitfield bounds"));
                }
                let index = self.u16(cursor)?;
                cursor += 2;
                if index == 0 {
                    return Ok(cursor);
                }
            }
        }
        if self.enums.is_some_and(|enums| enums.contains(red_type)) {
            return start
                .checked_add(2)
                .filter(|end| *end <= limit)
                .ok_or_else(|| unsupported("enum bounds"));
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

    fn skip_buffer_value(
        &self,
        red_type: &str,
        start: usize,
        limit: usize,
    ) -> Result<usize, WriterError> {
        let encoded = self.u32(start)?;
        let size = if red_type == "DataBuffer" && encoded >= 0x8000_0000 {
            4
        } else {
            4_usize
                .checked_add(usize::try_from(encoded).map_err(|_| WriterError::TooLarge)?)
                .ok_or(WriterError::TooLarge)?
        };
        start
            .checked_add(size)
            .filter(|end| *end <= limit)
            .ok_or_else(|| unsupported(format!("{red_type} bounds")))
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

    fn vlq(&self, start: usize) -> Result<(usize, usize), WriterError> {
        let first = self.byte(start)?;
        if first & 0x80 != 0 {
            return Err(unsupported("negative streaming sector count"));
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
                    return Err(unsupported("streaming sector VLQ count"));
                }
            }
        }
        Ok((value, cursor))
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
            }
            for value in object.values() {
                collect_handle_ids(value, identities);
            }
        }
        _ => {}
    }
}

fn encode_property(
    name_index: u16,
    type_index: u16,
    payload: &[u8],
) -> Result<Vec<u8>, WriterError> {
    let encoded_size = u32::try_from(payload.len())
        .map_err(|_| WriterError::TooLarge)?
        .checked_add(4)
        .ok_or(WriterError::TooLarge)?;
    let mut output = Vec::with_capacity(payload.len() + 8);
    output.extend_from_slice(&name_index.to_le_bytes());
    output.extend_from_slice(&type_index.to_le_bytes());
    output.extend_from_slice(&encoded_size.to_le_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

fn compact_export_indices<T>(chunks: &HashMap<usize, T>) -> (Vec<usize>, HashMap<usize, usize>) {
    let mut indices: Vec<_> = chunks.keys().copied().collect();
    indices.sort_unstable();
    let remap = indices
        .iter()
        .copied()
        .enumerate()
        .map(|(compact, source)| (source, compact))
        .collect();
    (indices, remap)
}

fn compact_import_indices(
    file: &Cr2wInspection,
    new_imports: &[NewImport],
    used: &HashSet<String>,
) -> (Vec<usize>, HashMap<usize, usize>) {
    let mut indices = Vec::with_capacity(file.imports.len() + new_imports.len());
    indices.extend(
        file.imports
            .iter()
            .enumerate()
            .filter_map(|(index, import)| used.contains(&import.depot_path).then_some(index)),
    );
    indices.extend(
        new_imports
            .iter()
            .enumerate()
            .filter_map(|(index, import)| {
                used.contains(&import.depot_path)
                    .then_some(file.imports.len() + index)
            }),
    );
    let remap = indices
        .iter()
        .copied()
        .enumerate()
        .map(|(compact, source)| (source, compact))
        .collect();
    (indices, remap)
}

fn class_property<'a>(
    classes: &'a BTreeMap<String, schema::RedClass>,
    class_name: &str,
    property: &str,
) -> Option<&'a schema::RedProperty> {
    let mut current = Some(class_name);
    let mut visited = HashSet::new();
    while let Some(name) = current {
        if !visited.insert(name) {
            return None;
        }
        let class = classes.get(name)?;
        if let Some(property) = class.properties.get(property) {
            return Some(property);
        }
        current = class.base.as_deref();
    }
    None
}

fn red_type_from_cs(cs_type: &str) -> Option<String> {
    let compact: String = cs_type
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let primitive = match compact.as_str() {
        "CBool" => "Bool",
        "CInt8" => "Int8",
        "CUInt8" => "Uint8",
        "CInt16" => "Int16",
        "CUInt16" => "Uint16",
        "CInt32" => "Int32",
        "CUInt32" => "Uint32",
        "CInt64" => "Int64",
        "CUInt64" => "Uint64",
        "CFloat" => "Float",
        "CDouble" => "Double",
        "CName" => "CName",
        "CString" => "String",
        "NodeRef" => "NodeRef",
        "TweakDBID" => "TweakDBID",
        "CRUID" => "CRUID",
        _ => {
            if let Some(inner) = compact
                .strip_prefix("CEnum<")
                .and_then(|value| value.strip_suffix('>'))
            {
                return Some(inner.to_owned());
            }
            if let Some(inner) = compact
                .strip_prefix("CArray<")
                .and_then(|value| value.strip_suffix('>'))
            {
                return red_type_from_cs(inner).map(|red_type| format!("array:{red_type}"));
            }
            return None;
        }
    };
    Some(primitive.to_owned())
}

fn is_default_missing_value(value: &Value, red_type: &str) -> bool {
    if value.is_null()
        || value.as_bool() == Some(false)
        || value.as_i64() == Some(0)
        || value.as_u64() == Some(0)
        || value.as_f64() == Some(0.0)
        || value.as_array().is_some_and(Vec::is_empty)
    {
        return true;
    }
    if value
        .as_str()
        .is_some_and(|value| value.is_empty() || value.starts_with("default__"))
    {
        return true;
    }
    let stored = value.get("$value").and_then(Value::as_str);
    matches!(red_type, "NodeRef" | "TweakDBID" | "CName")
        && stored.is_some_and(|value| matches!(value, "" | "0" | "None"))
}

fn handle_identity(
    value: &Value,
    template_export_index: usize,
) -> Result<Cow<'_, str>, WriterError> {
    if let Some(identity) = value
        .get("HandleId")
        .or_else(|| value.get("HandleRefId"))
        .and_then(Value::as_str)
    {
        return Ok(Cow::Borrowed(identity));
    }
    if value.get("Data").is_some() {
        let identity = template_export_index
            .checked_sub(1)
            .ok_or_else(|| unsupported("root handle identity"))?;
        return Ok(Cow::Owned(identity.to_string()));
    }
    Err(unsupported("handle identity"))
}

fn encode_device_data_entry(entry: &Value, class_name_index: u16) -> Result<Vec<u8>, WriterError> {
    let mut output = entry
        .get("hash")
        .ok_or_else(|| unsupported("device data hash"))
        .and_then(json_string_u64)?
        .to_le_bytes()
        .to_vec();
    output.extend_from_slice(&class_name_index.to_le_bytes());
    for field in ["children", "parents"] {
        let values = entry
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| unsupported(format!("device data {field}")))?;
        write_positive_vlq(
            &mut output,
            u32::try_from(values.len()).map_err(|_| WriterError::TooLarge)?,
        );
        for value in values {
            output.extend_from_slice(&json_string_u64(value)?.to_le_bytes());
        }
    }
    for component in ["X", "Y", "Z"] {
        output.extend_from_slice(
            &entry
                .get("nodePosition")
                .and_then(|position| position.get(component))
                .ok_or_else(|| unsupported(format!("device data nodePosition.{component}")))
                .and_then(json_f32)?
                .to_le_bytes(),
        );
    }
    Ok(output)
}

fn area_shape_outline_buffer(value: &Value) -> Result<Vec<u8>, WriterError> {
    let buffer = value
        .get("buffer")
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported("AreaShapeOutline.buffer"))?;
    Ok(STANDARD.decode(buffer)?)
}

fn collect_new_exports<'a>(
    document: &'a Value,
    file: &Cr2wInspection,
    candidate_handles: &RefCell<HashSet<String>>,
    handle_exports: &RefCell<HashMap<String, usize>>,
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
    let handle_exports = handle_exports.borrow();
    let mut new_exports = Vec::new();
    let mut seen = HashMap::<String, &Value>::new();
    for (handle_id, value) in definitions {
        if !candidate_handles.contains(&handle_id) || handle_exports.contains_key(&handle_id) {
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
            .enumerate()
            .filter(|(_, export)| export.class_name == class_name)
            .max_by_key(|(_, export)| export.data_size)
            .map(|(index, _)| index)
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
    plan: &PrefixPlan<'_, '_>,
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
        let mut table_data = if table_index == 2 {
            Vec::with_capacity(plan.import_indices.len() * 8)
        } else if table_index == 4 {
            Vec::with_capacity(plan.export_indices.len() * EXPORT_SIZE)
        } else if old_count == 0 {
            Vec::new()
        } else {
            template
                .get(old_start..old_end)
                .ok_or_else(|| unsupported("template table bounds"))?
                .to_vec()
        };

        if table_index == 0 {
            for name in plan.names.iter().skip(file.names.len()) {
                table_data.extend_from_slice(name.as_bytes());
                table_data.push(0);
            }
            for import in plan.new_imports {
                table_data.extend_from_slice(import.depot_path.as_bytes());
                table_data.push(0);
            }
        } else if table_index == 1 {
            let mut string_offset = usize::try_from(file.header.tables[0].item_count)
                .map_err(|_| WriterError::TooLarge)?;
            for name in plan.names.iter().skip(file.names.len()) {
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
                plan.names
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
            let none_index = plan
                .names
                .iter()
                .position(|name| name == "None")
                .and_then(|index| u16::try_from(index).ok())
                .ok_or_else(|| unsupported("CName table has no None entry"))?;
            let mut new_string_offsets = Vec::with_capacity(plan.new_imports.len());
            for import in plan.new_imports {
                new_string_offsets.push(string_offset);
                string_offset = string_offset
                    .checked_add(import.depot_path.len() + 1)
                    .ok_or(WriterError::TooLarge)?;
            }
            let old_table =
                usize::try_from(descriptor.offset).map_err(|_| WriterError::TooLarge)?;
            for source_index in plan.import_indices {
                if *source_index < file.imports.len() {
                    let entry_start = old_table
                        .checked_add(source_index.checked_mul(8).ok_or(WriterError::TooLarge)?)
                        .ok_or(WriterError::TooLarge)?;
                    let entry_end = entry_start.checked_add(8).ok_or(WriterError::TooLarge)?;
                    table_data.extend_from_slice(
                        template
                            .get(entry_start..entry_end)
                            .ok_or_else(|| unsupported("template import table bounds"))?,
                    );
                } else {
                    let new_index = *source_index - file.imports.len();
                    let import = &plan.new_imports[new_index];
                    table_data.extend_from_slice(
                        &u32::try_from(new_string_offsets[new_index])
                            .map_err(|_| WriterError::TooLarge)?
                            .to_le_bytes(),
                    );
                    table_data.extend_from_slice(&none_index.to_le_bytes());
                    table_data.extend_from_slice(&import.flags.to_le_bytes());
                }
            }
        } else if table_index == 4 {
            let old_table =
                usize::try_from(descriptor.offset).map_err(|_| WriterError::TooLarge)?;
            for source_index in plan.export_indices {
                if let Some(export) = file.exports.get(*source_index) {
                    let entry_start = old_table
                        .checked_add(
                            source_index
                                .checked_mul(EXPORT_SIZE)
                                .ok_or(WriterError::TooLarge)?,
                        )
                        .ok_or(WriterError::TooLarge)?;
                    let entry_end = entry_start
                        .checked_add(EXPORT_SIZE)
                        .ok_or(WriterError::TooLarge)?;
                    let mut entry = template
                        .get(entry_start..entry_end)
                        .ok_or_else(|| unsupported("template export table bounds"))?
                        .to_vec();
                    if export.parent_id != 0 {
                        let parent_source = usize::try_from(export.parent_id - 1)
                            .map_err(|_| WriterError::TooLarge)?;
                        let parent_compact = plan
                            .export_remap
                            .get(&parent_source)
                            .copied()
                            .ok_or_else(|| unsupported("retained export parent was pruned"))?;
                        let parent_id = u32::try_from(
                            parent_compact.checked_add(1).ok_or(WriterError::TooLarge)?,
                        )
                        .map_err(|_| WriterError::TooLarge)?;
                        write_u32_at(&mut entry, 4, parent_id)?;
                    }
                    table_data.extend_from_slice(&entry);
                } else {
                    let export = &plan.new_exports[*source_index - file.exports.len()];
                    let class_index = plan
                        .names
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
        } else if table_index == 6 {
            for (embedded_index, embedded) in file.embedded.iter().enumerate() {
                let import_source = usize::try_from(
                    embedded
                        .import_index
                        .checked_sub(1)
                        .ok_or(WriterError::TooLarge)?,
                )
                .map_err(|_| WriterError::TooLarge)?;
                let import_compact = plan
                    .import_remap
                    .get(&import_source)
                    .copied()
                    .ok_or_else(|| unsupported("embedded file import was pruned"))?;
                let chunk_source =
                    usize::try_from(embedded.chunk_index).map_err(|_| WriterError::TooLarge)?;
                let chunk_compact = plan
                    .export_remap
                    .get(&chunk_source)
                    .copied()
                    .ok_or_else(|| unsupported("embedded file chunk was pruned"))?;
                let offset = embedded_index
                    .checked_mul(16)
                    .ok_or(WriterError::TooLarge)?;
                write_u32_at(
                    &mut table_data,
                    offset,
                    u32::try_from(import_compact.checked_add(1).ok_or(WriterError::TooLarge)?)
                        .map_err(|_| WriterError::TooLarge)?,
                )?;
                write_u32_at(
                    &mut table_data,
                    offset + 4,
                    u32::try_from(chunk_compact).map_err(|_| WriterError::TooLarge)?,
                )?;
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
            if object
                .get("Type")
                .and_then(Value::as_str)
                .is_some_and(|value| value.contains("RedPackage"))
            {
                return Ok(());
            }
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
                    if bytes.is_empty() {
                        None
                    } else {
                        Some(BufferOverride {
                            bytes: STANDARD.decode(bytes)?,
                            stored: false,
                            memory_size: 0,
                        })
                    }
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

fn remap_buffer_overrides(
    overrides: &mut HashMap<usize, BufferOverride>,
    file: &Cr2wInspection,
    template: &[u8],
    kraken_path: &OsStr,
) -> Result<(), WriterError> {
    let mut pending = std::mem::take(overrides).into_iter().collect::<Vec<_>>();
    pending.sort_by_key(|(index, _)| *index);
    let uncompressed = (0..file.buffers.len())
        .map(|index| uncompressed_template_buffer(file, template, index, kraken_path).ok())
        .collect::<Vec<_>>();
    let mut claimed = HashSet::new();
    for (requested, replacement) in pending {
        let mut candidates = Vec::new();
        for (index, buffer) in file.buffers.iter().enumerate() {
            let matches = if replacement.stored {
                let start = usize::try_from(buffer.offset).map_err(|_| WriterError::TooLarge)?;
                let size = usize::try_from(buffer.disk_size).map_err(|_| WriterError::TooLarge)?;
                start
                    .checked_add(size)
                    .and_then(|end| template.get(start..end))
                    == Some(replacement.bytes.as_slice())
            } else {
                uncompressed[index]
                    .as_ref()
                    .is_some_and(|bytes| bytes.as_slice() == replacement.bytes.as_slice())
            };
            if matches {
                candidates.push(index);
            }
        }
        let Some(target) = candidates
            .iter()
            .copied()
            .find(|index| *index == requested && !claimed.contains(index))
            .or_else(|| {
                candidates
                    .iter()
                    .copied()
                    .find(|index| !claimed.contains(index))
            })
        else {
            continue;
        };
        claimed.insert(target);
        overrides.insert(target, replacement);
    }
    Ok(())
}

fn redpackage_ordinal_map(expected: &Value, template: &Value) -> HashMap<usize, usize> {
    fn collect(expected: &Value, template: &Value, result: &mut HashMap<usize, usize>) {
        match (expected, template) {
            (Value::Array(expected), Value::Array(template)) => {
                for (expected, template) in expected.iter().zip(template) {
                    collect(expected, template, result);
                }
            }
            (Value::Object(expected), Value::Object(template)) => {
                let expected_is_package = expected
                    .get("Type")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.contains("RedPackage"));
                let template_is_package = template
                    .get("Type")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.contains("RedPackage"));
                if expected_is_package && template_is_package {
                    let expected_id = expected
                        .get("BufferId")
                        .and_then(Value::as_str)
                        .and_then(|value| value.parse::<usize>().ok());
                    let template_id = template
                        .get("BufferId")
                        .and_then(Value::as_str)
                        .and_then(|value| value.parse::<usize>().ok());
                    if let (Some(expected_id), Some(template_id)) = (expected_id, template_id) {
                        result.entry(expected_id).or_insert(template_id);
                    }
                    return;
                }
                for (key, expected) in expected {
                    if let Some(template) = template.get(key) {
                        collect(expected, template, result);
                    }
                }
            }
            _ => {}
        }
    }

    let mut result = HashMap::new();
    collect(expected, template, &mut result);
    result
}

struct RedPackageContext<'a> {
    file: &'a Cr2wInspection,
    template: &'a [u8],
    classes: &'a BTreeSet<String>,
    kraken_path: &'a OsStr,
    ordinals: &'a HashMap<usize, usize>,
}

fn collect_redpackage_overrides(
    value: &Value,
    context: &RedPackageContext<'_>,
    result: &mut HashMap<usize, BufferOverride>,
    claimed: &mut HashSet<usize>,
) -> Result<(), WriterError> {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_redpackage_overrides(value, context, result, claimed)?;
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
                let Ok((index, template_package)) = resolve_redpackage_template_buffer(
                    context,
                    index,
                    data,
                    claimed,
                    context.ordinals.get(&index).copied(),
                ) else {
                    // Unsupported package variants remain lossless because the
                    // top-level template buffer is retained unchanged.
                    return Ok(());
                };
                let imports_as_hash = redpackage::imports_are_hashed(&template_package)?;
                let Ok(bytes) = redpackage::encode_with_template(
                    &template_package,
                    data,
                    context.classes,
                    PackageSettings {
                        imports_as_hash,
                        handle_id_base: 0,
                    },
                ) else {
                    return Ok(());
                };
                result.insert(
                    index,
                    BufferOverride {
                        bytes,
                        stored: false,
                        memory_size: 0,
                    },
                );
                claimed.insert(index);
                return Ok(());
            }
            for child in object.values() {
                collect_redpackage_overrides(child, context, result, claimed)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn resolve_redpackage_template_buffer(
    context: &RedPackageContext<'_>,
    requested_index: usize,
    data: &Value,
    claimed: &HashSet<usize>,
    aligned_ordinal: Option<usize>,
) -> Result<(usize, Vec<u8>), WriterError> {
    let expected_roots = redpackage_root_types(data);
    let mut packages = Vec::new();
    for index in 0..context.file.buffers.len() {
        let Ok(bytes) = uncompressed_template_buffer(
            context.file,
            context.template,
            index,
            context.kraken_path,
        ) else {
            continue;
        };
        if redpackage::imports_are_hashed(&bytes).is_err() {
            continue;
        }
        packages.push((index, bytes));
    }
    if let Some(aligned) = aligned_ordinal.and_then(|ordinal| packages.get(ordinal)) {
        return Ok(aligned.clone());
    }

    let mut matches = Vec::new();
    for (index, bytes) in &packages {
        let imports_as_hash = redpackage::imports_are_hashed(bytes)?;
        let Ok(decoded) = redpackage::decode(
            bytes,
            context.classes,
            PackageSettings {
                imports_as_hash,
                handle_id_base: 0,
            },
        ) else {
            continue;
        };
        if redpackage_root_types(&decoded) == expected_roots {
            matches.push((
                *index,
                bytes.clone(),
                semantic_overlap_score(data, &decoded),
            ));
        }
    }
    let ordinal_index = packages.get(requested_index).map(|(index, _)| *index);
    if !matches.is_empty() {
        let position = select_redpackage_match(&matches, ordinal_index, claimed);
        let (index, bytes, _) = matches.swap_remove(position);
        return Ok((index, bytes));
    }
    if let Some(index) = ordinal_index
        && let Some(position) = packages
            .iter()
            .position(|(candidate, _)| *candidate == index)
    {
        return Ok(packages.swap_remove(position));
    }
    Err(unsupported("RedPackage template buffer not found"))
}

fn select_redpackage_match(
    matches: &[(usize, Vec<u8>, i64)],
    ordinal: Option<usize>,
    claimed: &HashSet<usize>,
) -> usize {
    let best_score = matches
        .iter()
        .map(|(_, _, score)| *score)
        .max()
        .expect("non-empty matches have a score");
    ordinal
        .and_then(|ordinal| {
            matches.iter().position(|(index, _, score)| {
                *index == ordinal && *score == best_score && !claimed.contains(index)
            })
        })
        .or_else(|| {
            matches
                .iter()
                .position(|(index, _, score)| *score == best_score && !claimed.contains(index))
        })
        .or_else(|| {
            ordinal.and_then(|ordinal| {
                matches
                    .iter()
                    .position(|(index, _, score)| *index == ordinal && *score == best_score)
            })
        })
        .or_else(|| {
            matches
                .iter()
                .position(|(_, _, score)| *score == best_score)
        })
        .expect("the maximum score came from a match")
}

fn redpackage_root_types(data: &Value) -> Vec<&str> {
    data.get("Chunks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|chunk| chunk.get("$type").and_then(Value::as_str))
        .collect()
}

fn semantic_overlap_score(expected: &Value, actual: &Value) -> i64 {
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            let overlap = actual
                .iter()
                .filter(|(key, _)| !is_ignored_semantic_key(key))
                .filter_map(|(key, actual)| {
                    expected
                        .get(key)
                        .map(|expected| semantic_overlap_score(expected, actual))
                })
                .sum::<i64>();
            let omitted_defaults = expected
                .iter()
                .filter(|(key, _)| !is_ignored_semantic_key(key))
                .filter(|(key, _)| !actual.contains_key(*key))
                .map(|(_, expected)| omitted_default_score(expected))
                .sum::<i64>();
            overlap + omitted_defaults
        }
        (Value::Array(expected), Value::Array(actual)) => expected
            .iter()
            .zip(actual)
            .map(|(expected, actual)| semantic_overlap_score(expected, actual))
            .sum(),
        (Value::Number(expected), Value::Number(actual))
            if expected.as_f64() == actual.as_f64() =>
        {
            1
        }
        (expected, actual) if expected == actual => 1,
        _ => -1,
    }
}

fn is_ignored_semantic_key(key: &str) -> bool {
    matches!(
        key,
        "HandleId" | "HandleRefId" | "BufferId" | "$rawData" | "$rawTail"
    )
}

fn omitted_default_score(value: &Value) -> i64 {
    let Value::Object(object) = value else {
        return 0;
    };
    let Some(default) = object.get("$value").and_then(Value::as_str) else {
        return 0;
    };
    if !default.eq_ignore_ascii_case("default") {
        return 0;
    }
    object
        .iter()
        .filter(|(key, _)| !is_ignored_semantic_key(key))
        .map(|(_, value)| semantic_leaf_count(value))
        .sum()
}

fn semantic_leaf_count(value: &Value) -> i64 {
    match value {
        Value::Array(values) => values.iter().map(semantic_leaf_count).sum(),
        Value::Object(object) => object
            .iter()
            .filter(|(key, _)| !is_ignored_semantic_key(key))
            .map(|(_, value)| semantic_leaf_count(value))
            .sum(),
        _ => 1,
    }
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
    match archive::decompress_payload_isolated(
        &stored[8..],
        usize::try_from(declared).map_err(|_| WriterError::TooLarge)?,
        kraken_path,
    ) {
        Ok(bytes) => Ok(bytes == replacement),
        // Preserve the template if the native decoder cannot compare it.
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

fn encode_string_with_template(value: &str, template: &[u8]) -> Result<Vec<u8>, WriterError> {
    if value.is_empty() && matches!(template, [0 | 0x80]) {
        return Ok(template.to_vec());
    }
    encode_string(value)
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

fn write_positive_vlq(output: &mut Vec<u8>, value: u32) {
    let mut remaining = value;
    let low = u8::try_from(remaining & 0x3f).expect("masked to six bits");
    remaining >>= 6;
    output.push(low | if remaining > 0 { 0x40 } else { 0 });
    while remaining > 0 {
        let byte = u8::try_from(remaining & 0x7f).expect("masked to seven bits");
        remaining >>= 7;
        output.push(byte | if remaining > 0 { 0x80 } else { 0 });
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
        value if value.starts_with("handle:") || value.starts_with("whandle:") => Some(4),
        value if value.starts_with("rRef:") || value.starts_with("raRef:") => Some(2),
        _ => None,
    }
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

fn split_fixed_array_type(value: &str) -> Option<(usize, &str)> {
    let value = value.strip_prefix('[')?;
    let (count, inner) = value.split_once(']')?;
    (!inner.is_empty()).then_some((count.parse().ok()?, inner))
}

fn interpolation_type_value(value: &str) -> Option<u8> {
    [
        "Constant",
        "Linear",
        "BezierQuadratic",
        "BezierCubic",
        "Hermite",
    ]
    .iter()
    .position(|candidate| *candidate == value)
    .and_then(|value| u8::try_from(value).ok())
}

fn segment_link_type_value(value: &str) -> Option<u8> {
    ["ESLT_Normal", "ESLT_Smooth", "ESLT_SmoothSymmetric"]
        .iter()
        .position(|candidate| *candidate == value)
        .and_then(|value| u8::try_from(value).ok())
}

fn channel_link_type_value(value: &str) -> Option<u8> {
    ["Normal", "Smooth", "SmoothSymmertric"]
        .iter()
        .position(|candidate| *candidate == value)
        .and_then(|value| u8::try_from(value).ok())
}

fn encode_fixed_curve_class(value: &Value, red_type: &str) -> Result<Option<Vec<u8>>, WriterError> {
    let properties: &[&str] = match red_type {
        "Vector2" => &["X", "Y"],
        "Vector3" => &["X", "Y", "Z"],
        "Vector4" => &["X", "Y", "Z", "W"],
        "HDRColor" => &["Red", "Green", "Blue", "Alpha"],
        _ => return Ok(None),
    };
    let mut output = Vec::with_capacity(properties.len() * 4);
    for property in properties {
        output.extend_from_slice(
            &json_f32(
                value
                    .get(*property)
                    .ok_or_else(|| unsupported(format!("{red_type}.{property}")))?,
            )?
            .to_le_bytes(),
        );
    }
    Ok(Some(output))
}

fn storage_value(value: &Value) -> Result<&str, WriterError> {
    value
        .get("$value")
        .and_then(Value::as_str)
        .ok_or_else(|| unsupported("storage value"))
}

fn node_ref_value(value: &Value) -> Result<&str, WriterError> {
    let stored = storage_value(value)?;
    if stored == "0"
        && value
            .get("$storage")
            .and_then(Value::as_str)
            .is_some_and(|storage| storage == "uint64")
    {
        Ok("")
    } else {
        Ok(stored)
    }
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
    if let Some(value) = value.as_f64() {
        return Ok(value);
    }
    match value.as_str().map(str::to_ascii_lowercase).as_deref() {
        Some("inf" | "+inf" | "infinity" | "+infinity") => Ok(f64::INFINITY),
        Some("-inf" | "-infinity") => Ok(f64::NEG_INFINITY),
        Some("nan" | "+nan" | "-nan") => Ok(f64::NAN),
        _ => Err(unsupported("float value")),
    }
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

fn normalize_wolvenkit_enum_name(value: &str) -> &str {
    match value {
        "false_" => "false",
        "true_" => "true",
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        area_shape_outline_buffer, buffer_matches, channel_link_type_value, class_property,
        collect_handle_ids, compact_export_indices, encode_device_data_entry,
        encode_string_with_template, handle_identity, interpolation_type_value,
        is_default_missing_value, json_bool, json_f32, node_ref_value,
        normalize_wolvenkit_enum_name, read_json, red_type_from_cs, redpackage_ordinal_map,
        segment_link_type_value, select_redpackage_match, semantic_overlap_score,
        split_fixed_array_type, write_positive_vlq, write_with_template,
    };
    use crate::{codec, cr2w, kraken, schema};
    use serde_json::{Value, json};
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        env,
        ffi::OsStr,
        fs,
        path::PathBuf,
    };

    #[test]
    fn write_positive_vlq_encodes_single_and_multi_byte_counts() {
        let mut output = Vec::new();

        for value in [0, 63, 64, 8_191, 8_192] {
            write_positive_vlq(&mut output, value);
        }

        assert_eq!(
            output,
            [0x00, 0x3f, 0x40, 0x01, 0x7f, 0x7f, 0x40, 0x80, 0x01]
        );
    }

    #[test]
    fn reads_deep_wolvenkit_json() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("deep.json");
        let depth = 256;
        let json = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
        fs::write(&path, json).unwrap();

        assert!(read_json(&path).is_ok());
    }

    #[test]
    fn compares_kark_buffers_using_the_header_size() {
        let replacement = b"repeated native kraken buffer repeated native kraken buffer";
        let payload = kraken::encode(replacement);
        let mut stored = b"KARK".to_vec();
        stored.extend_from_slice(&u32::try_from(replacement.len()).unwrap().to_le_bytes());
        stored.extend_from_slice(&payload);

        assert!(buffer_matches(&stored, replacement, OsStr::new("missing-kraken.dll")).unwrap());
    }

    #[test]
    fn parses_wolvenkit_non_finite_floats() {
        let negative = json_f32(&Value::String("-inf".to_owned())).unwrap();
        assert!(negative.is_infinite() && negative.is_sign_negative());
        let positive = json_f32(&Value::String("+inf".to_owned())).unwrap();
        assert!(positive.is_infinite() && positive.is_sign_positive());
        assert!(json_f32(&Value::String("nan".to_owned())).unwrap().is_nan());
        assert!(json_f32(&Value::String("not-a-float".to_owned())).is_err());
    }

    #[test]
    fn preserves_both_valid_empty_string_encodings() {
        assert_eq!(encode_string_with_template("", &[0]).unwrap(), [0]);
        assert_eq!(encode_string_with_template("", &[0x80]).unwrap(), [0x80]);
        assert_eq!(
            encode_string_with_template("text", &[0]).unwrap(),
            [0x84, b't', b'e', b'x', b't']
        );
    }

    #[test]
    fn maps_hashed_zero_node_ref_to_an_empty_string() {
        let value = json!({
            "$type": "NodeRef",
            "$storage": "uint64",
            "$value": "0"
        });

        assert_eq!(node_ref_value(&value).unwrap(), "");
    }

    #[test]
    fn wolvenkit_boolean_enum_names_map_to_red_names() {
        assert_eq!(normalize_wolvenkit_enum_name("true_"), "true");
        assert_eq!(normalize_wolvenkit_enum_name("false_"), "false");
        assert_eq!(
            normalize_wolvenkit_enum_name("default__false_"),
            "default__false_"
        );
    }

    #[test]
    fn parses_fixed_array_type() {
        assert_eq!(split_fixed_array_type("[6]Float"), Some((6, "Float")));
        assert_eq!(split_fixed_array_type("static:6,Float"), None);
    }

    #[test]
    fn maps_legacy_curve_enums() {
        assert_eq!(interpolation_type_value("BezierQuadratic"), Some(2));
        assert_eq!(segment_link_type_value("ESLT_SmoothSymmetric"), Some(2));
        assert_eq!(channel_link_type_value("SmoothSymmertric"), Some(2));
        assert_eq!(interpolation_type_value("Unknown"), None);
        assert_eq!(segment_link_type_value("Unknown"), None);
        assert_eq!(channel_link_type_value("Unknown"), None);
    }

    #[test]
    fn semantic_overlap_prefers_matching_sparse_template() {
        let expected = serde_json::json!({
            "$type": "Chunk",
            "defaultOnly": 10,
            "value": "wanted",
            "HandleId": "0"
        });
        let matching = serde_json::json!({
            "$type": "Chunk",
            "value": "wanted",
            "HandleId": "42"
        });
        let other = serde_json::json!({
            "$type": "Chunk",
            "value": "other",
            "HandleId": "0"
        });
        assert!(
            semantic_overlap_score(&expected, &matching)
                > semantic_overlap_score(&expected, &other)
        );
    }

    #[test]
    fn schema_types_map_to_red_property_types() {
        assert_eq!(red_type_from_cs("CBool"), Some("Bool".to_owned()));
        assert_eq!(
            red_type_from_cs("CEnum<gameAlwaysSpawnedState>"),
            Some("gameAlwaysSpawnedState".to_owned())
        );
        assert_eq!(
            red_type_from_cs("CArray<CName>"),
            Some("array:CName".to_owned())
        );
        assert_eq!(red_type_from_cs("CHandle<worldNode>"), None);
    }

    #[test]
    fn missing_default_properties_remain_implicit() {
        assert!(is_default_missing_value(
            &json!({"$type": "NodeRef", "$storage": "uint64", "$value": "0"}),
            "NodeRef"
        ));
        assert!(is_default_missing_value(&json!([]), "array:CName"));
        assert!(is_default_missing_value(
            &json!("default__false_"),
            "gameAlwaysSpawnedState"
        ));
        assert!(!is_default_missing_value(&json!(1), "Bool"));
        assert!(!is_default_missing_value(
            &json!([{"$type": "CName", "$storage": "string", "$value": "custom"}]),
            "array:CName"
        ));
    }

    #[test]
    fn class_property_resolves_inherited_schema_fields() {
        let classes = BTreeMap::from([
            (
                "Base".to_owned(),
                schema::RedClass {
                    base: None,
                    properties: std::collections::BTreeMap::from([(
                        "enabled".to_owned(),
                        schema::RedProperty {
                            cs_type: "CBool".to_owned(),
                            ordinal: Some(0),
                            red_type: None,
                            offset: None,
                            flags: None,
                        },
                    )]),
                    flags: None,
                    size: None,
                    alignment: None,
                },
            ),
            (
                "Child".to_owned(),
                schema::RedClass {
                    base: Some("Base".to_owned()),
                    properties: std::collections::BTreeMap::new(),
                    flags: None,
                    size: None,
                    alignment: None,
                },
            ),
        ]);

        let property = class_property(&classes, "Child", "enabled").unwrap();

        assert_eq!(property.cs_type, "CBool");
        assert_eq!(property.ordinal, Some(0));
    }

    #[test]
    fn collect_handle_ids_includes_nested_definitions() {
        let value = json!({
            "HandleId": "phase",
            "Data": {
                "$type": "gameJournalQuestPhase",
                "entries": [{
                    "HandleId": "objective",
                    "Data": {
                        "$type": "gameJournalQuestObjective",
                        "entries": [{
                            "HandleId": "mappin",
                            "Data": {"$type": "gameJournalQuestMapPin"}
                        }]
                    }
                }]
            }
        });
        let mut identities = HashSet::new();

        collect_handle_ids(&value, &mut identities);

        assert_eq!(
            identities,
            HashSet::from([
                "phase".to_owned(),
                "objective".to_owned(),
                "mappin".to_owned()
            ])
        );
    }

    #[test]
    fn compact_export_indices_preserves_order_and_maps_sparse_template_chunks() {
        let chunks = HashMap::from([(0, &Value::Null), (8, &Value::Null), (3, &Value::Null)]);

        let (indices, remap) = compact_export_indices(&chunks);

        assert_eq!(indices, [0, 3, 8]);
        assert_eq!(remap, HashMap::from([(0, 0), (3, 1), (8, 2)]));
    }

    #[test]
    fn handle_identity_uses_template_export_for_wolvenkit_definition_without_id() {
        let value = json!({
            "Data": {
                "$type": "gameDeviceResourceData",
                "version": 2
            }
        });

        assert_eq!(handle_identity(&value, 1).unwrap(), "0");
    }

    #[test]
    fn handle_identity_rejects_anonymous_reference() {
        let error = handle_identity(&json!({}), 0).unwrap_err();

        assert!(error.to_string().contains("handle identity"));
    }

    #[test]
    fn device_data_entry_encodes_wolvenkit_appendix_fields() {
        let entry = json!({
            "hash": "9344050286950689347",
            "children": ["11"],
            "parents": ["22"],
            "nodePosition": {"X": -1078.0032, "Y": 1317.9282, "Z": 5.174_843}
        });

        let encoded = encode_device_data_entry(&entry, 7).unwrap();

        assert_eq!(
            u64::from_le_bytes(encoded[0..8].try_into().unwrap()),
            9_344_050_286_950_689_347
        );
        assert_eq!(u16::from_le_bytes(encoded[8..10].try_into().unwrap()), 7);
        assert_eq!(encoded[10], 1);
        assert_eq!(u64::from_le_bytes(encoded[11..19].try_into().unwrap()), 11);
        assert_eq!(encoded[19], 1);
        assert_eq!(u64::from_le_bytes(encoded[20..28].try_into().unwrap()), 22);
        assert!(
            (f32::from_le_bytes(encoded[28..32].try_into().unwrap()) + 1078.0032).abs() < 0.001
        );
        assert!(
            (f32::from_le_bytes(encoded[32..36].try_into().unwrap()) - 1317.9282).abs() < 0.001
        );
        assert!(
            (f32::from_le_bytes(encoded[36..40].try_into().unwrap()) - 5.174_843).abs() < 0.001
        );
    }

    #[test]
    fn semantic_overlap_treats_omitted_red_value_as_explicit_default() {
        let expected = serde_json::json!({
            "$type": "Chunk",
            "meshAppearance": {
                "$type": "CName",
                "$storage": "string",
                "$value": "default"
            }
        });
        let omitted_default = serde_json::json!({
            "$type": "Chunk"
        });
        let non_default = serde_json::json!({
            "$type": "Chunk",
            "meshAppearance": {
                "$type": "CName",
                "$storage": "string",
                "$value": "thermal"
            }
        });
        assert!(
            semantic_overlap_score(&expected, &omitted_default)
                > semantic_overlap_score(&expected, &non_default)
        );
    }

    #[test]
    fn redpackage_match_prefers_an_unclaimed_best_template() {
        let matches = vec![(3, vec![], 10), (7, vec![], 10), (9, vec![], 8)];
        let claimed = HashSet::from([3]);
        assert_eq!(select_redpackage_match(&matches, Some(3), &claimed), 1);
    }

    #[test]
    fn redpackage_ordinals_follow_matching_outer_structure() {
        let expected = serde_json::json!({
            "appearances": [
                {"compiledData": {"Type": "DataBuffer (RedPackage)", "BufferId": "0"}},
                {"compiledData": {"Type": "DataBuffer (RedPackage)", "BufferId": "1"}}
            ]
        });
        let template = serde_json::json!({
            "appearances": [
                {"compiledData": {"Type": "DataBuffer (RedPackage)", "BufferId": "7"}},
                {"compiledData": {"Type": "DataBuffer (RedPackage)", "BufferId": "3"}}
            ]
        });
        assert_eq!(
            redpackage_ordinal_map(&expected, &template),
            HashMap::from([(0, 7), (1, 3)])
        );
    }

    #[test]
    fn area_shape_outline_uses_authored_wolvenkit_buffer() {
        let value = json!({"buffer": "AQIDBA=="});

        assert_eq!(area_shape_outline_buffer(&value).unwrap(), [1, 2, 3, 4]);
    }

    #[test]
    #[ignore = "real CR2W round-trip test; requires CR2W_FIXTURE and RED_SCHEMA"]
    fn serialized_cr2w_fixture_round_trips_and_applies_edits() {
        let fixture = env::var_os("CR2W_FIXTURE").map(PathBuf::from).unwrap();
        let schema_path = env::var_os("RED_SCHEMA").map(PathBuf::from).unwrap();
        let classes: BTreeMap<String, schema::RedClass> =
            serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
        let class_names: BTreeSet<String> = classes.keys().cloned().collect();
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
            &classes,
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
            &classes,
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

    #[test]
    #[ignore = "real topology-shrink fixture; requires CR2W_PRUNE_JSON, CR2W_PRUNE_TEMPLATE, CR2W_PRUNE_EXPORTS, CR2W_PRUNE_IMPORTS, and RED_SCHEMA"]
    fn serialized_cr2w_fixture_prunes_unreachable_exports() {
        let json_path = env::var_os("CR2W_PRUNE_JSON").map(PathBuf::from).unwrap();
        let fixture = env::var_os("CR2W_PRUNE_TEMPLATE")
            .map(PathBuf::from)
            .unwrap();
        let expected_exports = env::var("CR2W_PRUNE_EXPORTS")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let expected_imports = env::var("CR2W_PRUNE_IMPORTS")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let schema_path = env::var_os("RED_SCHEMA").map(PathBuf::from).unwrap();
        let classes: BTreeMap<String, schema::RedClass> =
            serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
        let class_names: BTreeSet<String> = classes.keys().cloned().collect();
        let workspace = tempfile::tempdir().unwrap();
        let output_path = workspace.path().join("pruned.cr2w");
        let missing_dll = OsStr::new("missing-kraken.dll");

        write_with_template(
            &json_path,
            &fixture,
            &output_path,
            &class_names,
            &classes,
            missing_dll,
        )
        .unwrap();

        let template_exports = cr2w::inspect(&fixture).unwrap().exports.len();
        let output = cr2w::inspect(&output_path).unwrap();
        let output_exports = output.exports.len();
        assert!(
            output_exports < template_exports,
            "expected authored graph to prune template exports"
        );
        assert_eq!(output_exports, expected_exports);
        assert_eq!(output.imports.len(), expected_imports);
        codec::decode_wkit(&output_path, &class_names, missing_dll).unwrap();
    }

    #[test]
    #[ignore = "real authored-handle fixture; requires CR2W_HANDLE_JSON, CR2W_HANDLE_TEMPLATE, and RED_SCHEMA"]
    fn serialized_cr2w_fixture_preserves_authored_handle_graph_after_pruning() {
        let json_path = env::var_os("CR2W_HANDLE_JSON").map(PathBuf::from).unwrap();
        let fixture = env::var_os("CR2W_HANDLE_TEMPLATE")
            .map(PathBuf::from)
            .unwrap();
        let schema_path = env::var_os("RED_SCHEMA").map(PathBuf::from).unwrap();
        let classes: BTreeMap<String, schema::RedClass> =
            serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
        let class_names: BTreeSet<String> = classes.keys().cloned().collect();
        let authored: Value = serde_json::from_slice(&fs::read(&json_path).unwrap()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let output_path = workspace.path().join("authored-handles.cr2w");
        let missing_dll = OsStr::new("missing-kraken.dll");

        write_with_template(
            &json_path,
            &fixture,
            &output_path,
            &class_names,
            &classes,
            missing_dll,
        )
        .unwrap();

        let decoded = codec::decode_wkit(&output_path, &class_names, missing_dll).unwrap();
        let authored_nodes = authored
            .pointer("/Data/RootChunk/graph/Data/nodes")
            .and_then(Value::as_array)
            .unwrap();
        let decoded_nodes = decoded
            .pointer("/Data/RootChunk/graph/Data/nodes")
            .and_then(Value::as_array)
            .unwrap();
        let node_signature = |nodes: &[Value]| {
            nodes
                .iter()
                .map(|node| {
                    (
                        node.pointer("/Data/$type")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        node.pointer("/Data/id").and_then(Value::as_i64),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            node_signature(decoded_nodes),
            node_signature(authored_nodes),
            "serialized quest node population differs from the authored graph"
        );
        let logical_and = decoded_nodes
            .iter()
            .find(|node| {
                node.pointer("/Data/$type").and_then(Value::as_str)
                    == Some("questLogicalAndNodeDefinition")
            })
            .unwrap();
        assert_eq!(
            logical_and
                .pointer("/Data/inputSocketCount")
                .and_then(Value::as_i64),
            Some(3)
        );
        assert_eq!(
            logical_and
                .pointer("/Data/sockets")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(5),
            "parallel join sockets were not preserved"
        );
    }

    #[test]
    #[ignore = "real missing-property fixture; requires CR2W_SCALAR_JSON, CR2W_SCALAR_TEMPLATE, and RED_SCHEMA"]
    fn serialized_cr2w_fixture_adds_missing_schema_properties() {
        let json_path = env::var_os("CR2W_SCALAR_JSON").map(PathBuf::from).unwrap();
        let fixture = env::var_os("CR2W_SCALAR_TEMPLATE")
            .map(PathBuf::from)
            .unwrap();
        let schema_path = env::var_os("RED_SCHEMA").map(PathBuf::from).unwrap();
        let classes: BTreeMap<String, schema::RedClass> =
            serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
        let class_names: BTreeSet<String> = classes.keys().cloned().collect();
        let authored: Value = serde_json::from_slice(&fs::read(&json_path).unwrap()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let output_path = workspace.path().join("scalar.cr2w");
        let missing_dll = OsStr::new("missing-kraken.dll");

        write_with_template(
            &json_path,
            &fixture,
            &output_path,
            &class_names,
            &classes,
            missing_dll,
        )
        .unwrap();
        let decoded = codec::decode_wkit(&output_path, &class_names, missing_dll).unwrap();

        let active = "/Data/RootChunk/nodes/2/Data/communitiesData/0/entriesInitialState/0/entryActiveOnStart";
        assert_eq!(
            json_bool(decoded.pointer(active).unwrap()).unwrap(),
            json_bool(authored.pointer(active).unwrap()).unwrap()
        );
        let always_spawned = "/Data/RootChunk/nodes/2/Data/communitiesData/0/template/Data/entries/0/Data/phases/0/Data/alwaysSpawned";
        assert_eq!(
            decoded.pointer(always_spawned).and_then(Value::as_str),
            authored
                .pointer(always_spawned)
                .and_then(Value::as_str)
                .map(normalize_wolvenkit_enum_name)
        );
        let appearances = "/Data/RootChunk/nodes/2/Data/communitiesData/0/template/Data/entries/0/Data/phases/0/Data/appearances";
        assert_eq!(
            decoded.pointer(appearances),
            authored.pointer(appearances),
            "missing appearance property differs"
        );
    }

    #[test]
    #[ignore = "real RedPackage fixture; requires REDPACKAGE_JSON, REDPACKAGE_TEMPLATE, and RED_SCHEMA"]
    fn redpackage_fixture_resolves_buffer_identity_and_preserves_device_state() {
        let json_path = env::var_os("REDPACKAGE_JSON").map(PathBuf::from).unwrap();
        let fixture = env::var_os("REDPACKAGE_TEMPLATE")
            .map(PathBuf::from)
            .unwrap();
        let schema_path = env::var_os("RED_SCHEMA").map(PathBuf::from).unwrap();
        let classes: BTreeMap<String, schema::RedClass> =
            serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
        let class_names: BTreeSet<String> = classes.keys().cloned().collect();
        let workspace = tempfile::tempdir().unwrap();
        let output_path = workspace.path().join("redpackage.streamingsector");
        let missing_dll = OsStr::new("missing-kraken.dll");

        write_with_template(
            &json_path,
            &fixture,
            &output_path,
            &class_names,
            &classes,
            missing_dll,
        )
        .unwrap();
        let decoded = codec::decode_wkit(&output_path, &class_names, missing_dll).unwrap();
        let json = serde_json::to_string(&decoded).unwrap();
        for expected in [
            "ComputerControllerPS",
            "filesStructure",
            "SIGNAL DELAY",
            "gqt001_document_read",
            "onscreens/emails/quests/minor_quest/gqt001/files/diagnostic",
        ] {
            assert!(json.contains(expected), "missing {expected}");
        }
    }

    #[test]
    #[ignore = "real RedPackage fixture; requires REDPACKAGE_JSON, REDPACKAGE_TEMPLATE, and RED_SCHEMA"]
    fn redpackage_fixture_grows_array_and_adds_nested_handle() {
        let source_path = env::var_os("REDPACKAGE_JSON").map(PathBuf::from).unwrap();
        let fixture = env::var_os("REDPACKAGE_TEMPLATE")
            .map(PathBuf::from)
            .unwrap();
        let schema_path = env::var_os("RED_SCHEMA").map(PathBuf::from).unwrap();
        let classes: BTreeMap<String, schema::RedClass> =
            serde_json::from_slice(&fs::read(schema_path).unwrap()).unwrap();
        let class_names: BTreeSet<String> = classes.keys().cloned().collect();
        let workspace = tempfile::tempdir().unwrap();
        let json_path = workspace.path().join("grown.json");
        let output_path = workspace.path().join("grown.streamingsector");
        let missing_dll = OsStr::new("missing-kraken.dll");
        let mut document: Value = serde_json::from_slice(&fs::read(source_path).unwrap()).unwrap();

        assert!(grow_files_structure(&mut document));
        fs::write(&json_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
        write_with_template(
            &json_path,
            &fixture,
            &output_path,
            &class_names,
            &classes,
            missing_dll,
        )
        .unwrap();

        let decoded = codec::decode_wkit(&output_path, &class_names, missing_dll).unwrap();
        assert!(
            serde_json::to_string(&decoded)
                .unwrap()
                .contains("REDPACKAGE_GROWTH_TEST")
        );
        assert!(has_files_structure_length(&decoded, 2));
    }

    fn grow_files_structure(value: &mut Value) -> bool {
        match value {
            Value::Object(object) => {
                if let Some(Value::Array(files)) = object.get_mut("filesStructure")
                    && files.len() == 1
                    && serde_json::to_string(&files[0])
                        .is_ok_and(|json| json.contains("gameJournalPath"))
                {
                    let mut added = files[0].clone();
                    assert!(rewrite_journal_handle(&mut added));
                    if let Some(content) = added.pointer_mut("/content/0/content") {
                        let original = content.as_str().unwrap().to_owned();
                        *content = Value::String(format!("{original}\nREDPACKAGE_GROWTH_TEST"));
                    }
                    files.push(added);
                    return true;
                }
                object.values_mut().any(grow_files_structure)
            }
            Value::Array(values) => values.iter_mut().any(grow_files_structure),
            _ => false,
        }
    }

    fn rewrite_journal_handle(value: &mut Value) -> bool {
        match value {
            Value::Object(object) => {
                if object
                    .get("Data")
                    .and_then(|data| data.get("$type"))
                    .and_then(Value::as_str)
                    == Some("gameJournalPath")
                {
                    object.insert("HandleId".to_owned(), Value::String("999999".to_owned()));
                    return true;
                }
                object.values_mut().any(rewrite_journal_handle)
            }
            Value::Array(values) => values.iter_mut().any(rewrite_journal_handle),
            _ => false,
        }
    }

    fn has_files_structure_length(value: &Value, minimum: usize) -> bool {
        match value {
            Value::Object(object) => {
                object
                    .get("filesStructure")
                    .and_then(Value::as_array)
                    .is_some_and(|files| files.len() >= minimum)
                    || object
                        .values()
                        .any(|value| has_files_structure_length(value, minimum))
            }
            Value::Array(values) => values
                .iter()
                .any(|value| has_files_structure_length(value, minimum)),
            _ => false,
        }
    }
}
