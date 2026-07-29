//! Native Cyberpunk 2077 `.mesh` to binary glTF export.

use crate::{codec, schema::RedSchema};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use half::f16;
use serde_json::{Map, Value, json};
use std::{
    ffi::OsStr,
    fs,
    io::{self, Write},
    path::Path,
};
use thiserror::Error;

const GLB_MAGIC: u32 = 0x4654_6C67;
const GLB_JSON_CHUNK: u32 = 0x4E4F_534A;
const GLB_BIN_CHUNK: u32 = 0x004E_4942;
const GLTF_FLOAT: u32 = 5126;
const GLTF_UNSIGNED_SHORT: u32 = 5123;

#[derive(Debug, Error)]
pub enum MeshError {
    #[error("could not decode mesh CR2W: {0}")]
    Codec(#[from] codec::CodecError),
    #[error("could not access mesh output: {0}")]
    Io(#[from] io::Error),
    #[error("could not decode mesh buffer: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("malformed mesh: {0}")]
    Malformed(String),
}

#[derive(Debug)]
struct RawMesh {
    name: String,
    positions: Vec<[f32; 3]>,
    normals: Vec<[f32; 3]>,
    tangents: Vec<[f32; 4]>,
    colors: Vec<[f32; 4]>,
    tex_coords: Vec<[f32; 2]>,
    tex_coords_1: Vec<[f32; 2]>,
    indices: Vec<u16>,
    material_names: Vec<String>,
}

#[derive(Debug, Default)]
struct GlbBuilder {
    binary: Vec<u8>,
    buffer_views: Vec<Value>,
    accessors: Vec<Value>,
}

impl GlbBuilder {
    fn push_f32_vectors<const N: usize>(
        &mut self,
        values: &[[f32; N]],
        accessor_type: &str,
        bounds: Option<(&[f32; N], &[f32; N])>,
    ) -> usize {
        self.align_binary();
        let byte_offset = self.binary.len();
        for value in values {
            for component in value {
                self.binary.extend_from_slice(&component.to_le_bytes());
            }
        }
        let view = self.push_view(byte_offset, self.binary.len() - byte_offset);
        let mut accessor = Map::from_iter([
            ("bufferView".to_owned(), json!(view)),
            ("componentType".to_owned(), json!(GLTF_FLOAT)),
            ("count".to_owned(), json!(values.len())),
            ("type".to_owned(), json!(accessor_type)),
        ]);
        if let Some((minimum, maximum)) = bounds {
            accessor.insert("min".to_owned(), json!(&minimum[..]));
            accessor.insert("max".to_owned(), json!(&maximum[..]));
        }
        self.accessors.push(Value::Object(accessor));
        self.accessors.len() - 1
    }

    fn push_indices(&mut self, values: &[u16]) -> usize {
        self.align_binary();
        let byte_offset = self.binary.len();
        for value in values {
            self.binary.extend_from_slice(&value.to_le_bytes());
        }
        let view = self.push_view(byte_offset, self.binary.len() - byte_offset);
        self.accessors.push(json!({
            "bufferView": view,
            "componentType": GLTF_UNSIGNED_SHORT,
            "count": values.len(),
            "type": "SCALAR"
        }));
        self.accessors.len() - 1
    }

    fn push_view(&mut self, byte_offset: usize, byte_length: usize) -> usize {
        self.buffer_views.push(json!({
            "buffer": 0,
            "byteOffset": byte_offset,
            "byteLength": byte_length
        }));
        self.buffer_views.len() - 1
    }

    fn align_binary(&mut self) {
        while !self.binary.len().is_multiple_of(4) {
            self.binary.push(0);
        }
    }
}

/// Exports the first-level-of-detail geometry in a Cyberpunk `.mesh` as GLB.
///
/// The GLB includes WolvenKit-compatible `materialNames` extras. A neighboring
/// `.Material.json` and its material repository can therefore be consumed by
/// the `WolvenKit` Blender add-on without changing the geometry importer.
///
/// # Errors
///
/// Returns [`MeshError`] when CR2W decoding fails, the mesh buffer is malformed,
/// or the output cannot be written.
pub fn export_glb(
    input: &Path,
    schema: &RedSchema,
    output: &Path,
    kraken_path: &OsStr,
    lod_filter: bool,
) -> Result<(), MeshError> {
    let document = codec::decode_wkit_with_red_schema(input, schema, kraken_path)?;
    let meshes = decode_meshes(&document, lod_filter)?;
    let glb = build_glb(&meshes)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, glb)?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "keeping the vertex stream layout together makes binary-format auditing safer"
)]
fn decode_meshes(document: &Value, lod_filter: bool) -> Result<Vec<RawMesh>, MeshError> {
    let root = member_path(document, &["Data", "RootChunk"])?;
    let render_blob = member_path(root, &["renderResourceBlob", "Data"])?;
    let header = member(render_blob, "header")?;
    let render_buffer = string_member(member(render_blob, "renderBuffer")?, "Bytes")?;
    let render_buffer = STANDARD.decode(render_buffer)?;
    let quantization_scale = quantization_vector(member(header, "quantizationScale")?)?;
    let quantization_offset = quantization_vector(member(header, "quantizationOffset")?)?;
    let index_buffer_offset = usize_member(header, "indexBufferOffset")?;
    let appearances = decode_appearances(root)?;
    let chunks = array_member(header, "renderChunkInfos")?;
    let mut meshes = Vec::with_capacity(chunks.len());

    for (chunk_index, chunk) in chunks.iter().enumerate() {
        let lod = u64_member_or_default(chunk, "lodMask")?;
        if lod_filter && lod != 1 {
            continue;
        }
        let vertex_count = usize_member(chunk, "numVertices")?;
        let index_count = usize_member(chunk, "numIndices")?;
        let vertices = member(chunk, "chunkVertices")?;
        let layout = member(vertices, "vertexLayout")?;
        let byte_offsets = usize_array(member(vertices, "byteOffsets")?)?;
        let slot_strides = usize_array(member(layout, "slotStrides")?)?;
        let elements = array_member(layout, "elements")?;
        let position_offset = offset_for_usage(elements, &byte_offsets, "PS_Position", 0)?
            .ok_or_else(|| malformed("vertex layout has no position stream"))?;
        let position_stride = *slot_strides
            .first()
            .ok_or_else(|| malformed("vertex layout has no position stride"))?;
        let tex_coord_offset = offset_for_usage(elements, &byte_offsets, "PS_TexCoord", 0)?;
        let tex_coord_1_offset = offset_for_usage(elements, &byte_offsets, "PS_TexCoord", 1)?;
        let normal_offset = offset_for_usage(elements, &byte_offsets, "PS_Normal", 0)?;
        let tangent_offset = offset_for_usage(elements, &byte_offsets, "PS_Tangent", 0)?;
        let color_offset = offset_for_usage(elements, &byte_offsets, "PS_Color", 0)?;
        let normal_stride = if tangent_offset.is_some() { 8 } else { 4 };
        let color_stride = if tex_coord_1_offset.is_some() { 8 } else { 4 };

        let positions = decode_positions(
            &render_buffer,
            position_offset,
            position_stride,
            vertex_count,
            quantization_scale,
            quantization_offset,
        )?;
        let normals = normal_offset.map_or_else(
            || Ok(Vec::new()),
            |offset| decode_normals(&render_buffer, offset, normal_stride, vertex_count),
        )?;
        let tangents = tangent_offset.map_or_else(
            || Ok(Vec::new()),
            |offset| {
                decode_tangents(
                    &render_buffer,
                    offset + usize::from(normal_offset.is_some()) * 4,
                    normal_stride,
                    vertex_count,
                )
            },
        )?;
        let colors = color_offset.map_or_else(
            || Ok(Vec::new()),
            |offset| decode_colors(&render_buffer, offset, color_stride, vertex_count),
        )?;
        let tex_coords = tex_coord_offset.map_or_else(
            || Ok(Vec::new()),
            |offset| decode_tex_coords(&render_buffer, offset, 4, vertex_count, true),
        )?;
        let tex_coords_1 = tex_coord_1_offset.map_or_else(
            || Ok(Vec::new()),
            |offset| {
                decode_tex_coords(
                    &render_buffer,
                    offset + usize::from(color_offset.is_some()) * 4,
                    color_stride,
                    vertex_count,
                    false,
                )
            },
        )?;
        let relative_indices_offset = member(chunk, "chunkIndices")?
            .get("teOffset")
            .and_then(Value::as_u64)
            .map(usize::try_from)
            .transpose()
            .map_err(|_| malformed("index buffer offset exceeds platform size"))?
            .unwrap_or(0);
        let indices_offset = index_buffer_offset
            .checked_add(relative_indices_offset)
            .ok_or_else(|| malformed("index buffer offset overflow"))?;
        let indices = decode_indices(&render_buffer, indices_offset, index_count, positions.len())?;
        let material_names = appearances
            .iter()
            .map(|materials| material_for_chunk(materials, chunk_index, chunks.len()))
            .collect();

        meshes.push(RawMesh {
            name: format!("submesh_{chunk_index:02}_LOD_{lod}"),
            positions,
            normals,
            tangents,
            colors,
            tex_coords,
            tex_coords_1,
            indices,
            material_names,
        });
    }
    if meshes.is_empty() {
        return Err(malformed("mesh has no exportable render chunks"));
    }
    Ok(meshes)
}

fn decode_appearances(root: &Value) -> Result<Vec<Vec<String>>, MeshError> {
    array_member(root, "appearances")?
        .iter()
        .map(|appearance| {
            let data = member(appearance, "Data")?;
            array_member(data, "chunkMaterials")?
                .iter()
                .map(red_string)
                .collect()
        })
        .collect()
}

fn material_for_chunk(materials: &[String], chunk_index: usize, chunk_count: usize) -> String {
    if materials.is_empty() {
        return "default".to_owned();
    }
    if chunk_index < materials.len() {
        return materials[chunk_index].clone();
    }
    let repeated_index = (chunk_index - materials.len()) % materials.len().min(chunk_count);
    materials[repeated_index].clone()
}

fn decode_positions(
    bytes: &[u8],
    offset: usize,
    stride: usize,
    count: usize,
    scale: [f32; 3],
    translation: [f32; 3],
) -> Result<Vec<[f32; 3]>, MeshError> {
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let start = checked_element_offset(offset, stride, index, 6, bytes.len())?;
        let x = f32::from(read_i16(bytes, start)?) / 32_767.0 * scale[0] + translation[0];
        let y = f32::from(read_i16(bytes, start + 2)?) / 32_767.0 * scale[1] + translation[1];
        let z = f32::from(read_i16(bytes, start + 4)?) / 32_767.0 * scale[2] + translation[2];
        result.push([x, z, -y]);
    }
    Ok(result)
}

fn decode_normals(
    bytes: &[u8],
    offset: usize,
    stride: usize,
    count: usize,
) -> Result<Vec<[f32; 3]>, MeshError> {
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let start = checked_element_offset(offset, stride, index, 4, bytes.len())?;
        let packed = read_u32(bytes, start)?;
        let decoded = decode_dec4(packed);
        result.push(normalize([decoded[0], decoded[2], -decoded[1]]));
    }
    Ok(result)
}

fn decode_tangents(
    bytes: &[u8],
    offset: usize,
    stride: usize,
    count: usize,
) -> Result<Vec<[f32; 4]>, MeshError> {
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let start = checked_element_offset(offset, stride, index, 4, bytes.len())?;
        let decoded = decode_dec4(read_u32(bytes, start)?);
        let normalized = normalize([decoded[0], decoded[2], -decoded[1]]);
        result.push([normalized[0], normalized[1], normalized[2], decoded[3]]);
    }
    Ok(result)
}

fn decode_colors(
    bytes: &[u8],
    offset: usize,
    stride: usize,
    count: usize,
) -> Result<Vec<[f32; 4]>, MeshError> {
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let start = checked_element_offset(offset, stride, index, 4, bytes.len())?;
        result.push([
            f32::from(bytes[start]) / 255.0,
            f32::from(bytes[start + 1]) / 255.0,
            f32::from(bytes[start + 2]) / 255.0,
            f32::from(bytes[start + 3]) / 255.0,
        ]);
    }
    Ok(result)
}

fn decode_tex_coords(
    bytes: &[u8],
    offset: usize,
    stride: usize,
    count: usize,
    flip_vertical: bool,
) -> Result<Vec<[f32; 2]>, MeshError> {
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let start = checked_element_offset(offset, stride, index, 4, bytes.len())?;
        let vertical = f32::from(f16::from_bits(read_u16(bytes, start + 2)?));
        result.push([
            f32::from(f16::from_bits(read_u16(bytes, start)?)),
            if flip_vertical {
                1.0 - vertical
            } else {
                vertical
            },
        ]);
    }
    Ok(result)
}

fn decode_indices(
    bytes: &[u8],
    offset: usize,
    count: usize,
    vertex_count: usize,
) -> Result<Vec<u16>, MeshError> {
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let start = checked_element_offset(offset, 2, index, 2, bytes.len())?;
        let value = read_u16(bytes, start)?;
        if usize::from(value) >= vertex_count {
            return Err(malformed(format!(
                "index {value} exceeds vertex count {vertex_count}"
            )));
        }
        result.push(value);
    }
    for triangle in result.chunks_exact_mut(3) {
        triangle.swap(0, 1);
    }
    Ok(result)
}

fn build_glb(meshes: &[RawMesh]) -> Result<Vec<u8>, MeshError> {
    let mut builder = GlbBuilder::default();
    let mut gltf_meshes = Vec::with_capacity(meshes.len());
    let mut nodes = Vec::with_capacity(meshes.len());

    for (mesh_index, mesh) in meshes.iter().enumerate() {
        let (minimum, maximum) = position_bounds(&mesh.positions)?;
        let positions =
            builder.push_f32_vectors(&mesh.positions, "VEC3", Some((&minimum, &maximum)));
        let mut attributes = Map::from_iter([("POSITION".to_owned(), json!(positions))]);
        if !mesh.normals.is_empty() {
            attributes.insert(
                "NORMAL".to_owned(),
                json!(builder.push_f32_vectors(&mesh.normals, "VEC3", None)),
            );
        }
        if !mesh.tangents.is_empty() {
            attributes.insert(
                "TANGENT".to_owned(),
                json!(builder.push_f32_vectors(&mesh.tangents, "VEC4", None)),
            );
        }
        if !mesh.colors.is_empty() {
            attributes.insert(
                "COLOR_0".to_owned(),
                json!(builder.push_f32_vectors(&mesh.colors, "VEC4", None)),
            );
        }
        if !mesh.tex_coords.is_empty() {
            attributes.insert(
                "TEXCOORD_0".to_owned(),
                json!(builder.push_f32_vectors(&mesh.tex_coords, "VEC2", None)),
            );
        }
        if !mesh.tex_coords_1.is_empty() {
            attributes.insert(
                "TEXCOORD_1".to_owned(),
                json!(builder.push_f32_vectors(&mesh.tex_coords_1, "VEC2", None)),
            );
        }
        let indices = builder.push_indices(&mesh.indices);
        gltf_meshes.push(json!({
            "name": mesh.name,
            "extras": {"materialNames": mesh.material_names},
            "primitives": [{
                "attributes": attributes,
                "indices": indices,
                "material": 0
            }]
        }));
        nodes.push(json!({"name": mesh.name, "mesh": mesh_index}));
    }

    builder.align_binary();
    let document = json!({
        "asset": {
            "generator": format!("ghostline-red {}", env!("CARGO_PKG_VERSION")),
            "version": "2.0"
        },
        "extras": {"ExperimentalMergedMeshes": false},
        "scene": 0,
        "scenes": [{"name": "Scene", "nodes": (0..nodes.len()).collect::<Vec<_>>()}],
        "nodes": nodes,
        "meshes": gltf_meshes,
        "materials": [{"name": "Default", "doubleSided": true, "pbrMetallicRoughness": {}}],
        "buffers": [{"byteLength": builder.binary.len()}],
        "bufferViews": builder.buffer_views,
        "accessors": builder.accessors
    });
    encode_glb(&document, &builder.binary)
}

fn encode_glb(document: &Value, binary: &[u8]) -> Result<Vec<u8>, MeshError> {
    let mut json_bytes =
        serde_json::to_vec(document).map_err(|error| malformed(error.to_string()))?;
    while !json_bytes.len().is_multiple_of(4) {
        json_bytes.push(b' ');
    }
    let mut binary = binary.to_vec();
    while !binary.len().is_multiple_of(4) {
        binary.push(0);
    }
    let total_length = 12_usize
        .checked_add(8 + json_bytes.len())
        .and_then(|value| value.checked_add(8 + binary.len()))
        .ok_or_else(|| malformed("GLB length overflow"))?;
    let total_length =
        u32::try_from(total_length).map_err(|_| malformed("GLB exceeds four gigabytes"))?;
    let mut output = Vec::with_capacity(total_length as usize);
    output.write_all(&GLB_MAGIC.to_le_bytes())?;
    output.write_all(&2_u32.to_le_bytes())?;
    output.write_all(&total_length.to_le_bytes())?;
    output.write_all(
        &u32::try_from(json_bytes.len())
            .map_err(|_| malformed("GLB JSON chunk is too large"))?
            .to_le_bytes(),
    )?;
    output.write_all(&GLB_JSON_CHUNK.to_le_bytes())?;
    output.write_all(&json_bytes)?;
    output.write_all(
        &u32::try_from(binary.len())
            .map_err(|_| malformed("GLB binary chunk is too large"))?
            .to_le_bytes(),
    )?;
    output.write_all(&GLB_BIN_CHUNK.to_le_bytes())?;
    output.write_all(&binary)?;
    Ok(output)
}

fn position_bounds(positions: &[[f32; 3]]) -> Result<([f32; 3], [f32; 3]), MeshError> {
    let first = *positions
        .first()
        .ok_or_else(|| malformed("render chunk has no positions"))?;
    let mut minimum = first;
    let mut maximum = first;
    for position in &positions[1..] {
        for axis in 0..3 {
            minimum[axis] = minimum[axis].min(position[axis]);
            maximum[axis] = maximum[axis].max(position[axis]);
        }
    }
    Ok((minimum, maximum))
}

fn offset_for_usage(
    elements: &[Value],
    byte_offsets: &[usize],
    usage: &str,
    usage_index: u64,
) -> Result<Option<usize>, MeshError> {
    let element = elements.iter().find(|element| {
        element.get("usage").and_then(Value::as_str) == Some(usage)
            && element
                .get("usageIndex")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                == usage_index
    });
    let Some(element) = element else {
        return Ok(None);
    };
    let stream_index = element
        .get("streamIndex")
        .and_then(Value::as_u64)
        .map(usize::try_from)
        .transpose()
        .map_err(|_| malformed("vertex stream index exceeds platform size"))?
        .unwrap_or(0);
    byte_offsets
        .get(stream_index)
        .copied()
        .map(Some)
        .ok_or_else(|| malformed(format!("stream index {stream_index} is out of range")))
}

fn member_path<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value, MeshError> {
    path.iter()
        .try_fold(value, |current, name| member(current, name))
}

fn member<'a>(value: &'a Value, name: &str) -> Result<&'a Value, MeshError> {
    value
        .get(name)
        .ok_or_else(|| malformed(format!("missing {name}")))
}

fn array_member<'a>(value: &'a Value, name: &str) -> Result<&'a [Value], MeshError> {
    member(value, name)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| malformed(format!("{name} is not an array")))
}

fn string_member<'a>(value: &'a Value, name: &str) -> Result<&'a str, MeshError> {
    member(value, name)?
        .as_str()
        .ok_or_else(|| malformed(format!("{name} is not a string")))
}

fn usize_member(value: &Value, name: &str) -> Result<usize, MeshError> {
    usize::try_from(u64_member(value, name)?)
        .map_err(|_| malformed(format!("{name} exceeds platform size")))
}

fn u64_member(value: &Value, name: &str) -> Result<u64, MeshError> {
    member(value, name)?
        .as_u64()
        .ok_or_else(|| malformed(format!("{name} is not an unsigned integer")))
}

fn u64_member_or_default(value: &Value, name: &str) -> Result<u64, MeshError> {
    value.get(name).map_or(Ok(0), |member| {
        member
            .as_u64()
            .ok_or_else(|| malformed(format!("{name} is not an unsigned integer")))
    })
}

fn usize_array(value: &Value) -> Result<Vec<usize>, MeshError> {
    value
        .as_array()
        .ok_or_else(|| malformed("expected integer array"))?
        .iter()
        .map(|item| {
            item.as_u64()
                .and_then(|number| usize::try_from(number).ok())
                .ok_or_else(|| malformed("array contains an invalid offset"))
        })
        .collect()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "RED Vector4 components are stored as 32-bit floats and JSON exposes them as f64"
)]
fn quantization_vector(value: &Value) -> Result<[f32; 3], MeshError> {
    let component = |name| {
        member(value, name)?
            .as_f64()
            .map(|number| number as f32)
            .ok_or_else(|| malformed(format!("{name} is not a number")))
    };
    Ok([component("X")?, component("Y")?, component("Z")?])
}

fn red_string(value: &Value) -> Result<String, MeshError> {
    value
        .get("$value")
        .or_else(|| value.get("DepotPath"))
        .or_else(|| value.as_str().map(|_| value))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| malformed("invalid RED string"))
}

fn checked_element_offset(
    base: usize,
    stride: usize,
    index: usize,
    width: usize,
    buffer_len: usize,
) -> Result<usize, MeshError> {
    let start = index
        .checked_mul(stride)
        .and_then(|offset| base.checked_add(offset))
        .ok_or_else(|| malformed("mesh buffer offset overflow"))?;
    let end = start
        .checked_add(width)
        .ok_or_else(|| malformed("mesh buffer range overflow"))?;
    if end > buffer_len {
        return Err(malformed(format!(
            "mesh buffer range {start}..{end} exceeds {buffer_len} bytes"
        )));
    }
    Ok(start)
}

fn read_i16(bytes: &[u8], offset: usize) -> Result<i16, MeshError> {
    Ok(i16::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, MeshError> {
    Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, MeshError> {
    Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], MeshError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| malformed(format!("could not read {N} bytes at offset {offset}")))
}

#[expect(
    clippy::cast_precision_loss,
    reason = "10-bit packed components are exactly representable by f32"
)]
fn decode_dec4(value: u32) -> [f32; 4] {
    let scale = 1.0 / 1023.0;
    let component = |shift| (((value >> shift) & 0x3ff_u32) as f32 * 2.0 * scale) - 1.0;
    let w = match value >> 30 {
        0 => 1.0,
        3 => -1.0,
        _ => 0.0,
    };
    [component(0), component(10), component(20), w]
}

fn normalize(value: [f32; 3]) -> [f32; 3] {
    let length = (value[0] * value[0] + value[1] * value[1] + value[2] * value[2]).sqrt();
    if length <= f32::EPSILON {
        return [0.0, 0.0, 1.0];
    }
    [value[0] / length, value[1] / length, value[2] / length]
}

fn malformed(reason: impl Into<String>) -> MeshError {
    MeshError::Malformed(reason.into())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_dec4, encode_glb, material_for_chunk, normalize, quantization_vector,
        u64_member_or_default,
    };
    use serde_json::json;

    #[test]
    fn material_for_chunk_repeats_short_appearance_lists() {
        let materials = vec!["first".to_owned(), "second".to_owned()];

        assert_eq!(material_for_chunk(&materials, 3, 4), "second");
    }

    #[test]
    fn decode_dec4_maps_endpoints_to_signed_unit_range() {
        let decoded = decode_dec4(0x3ff | (0x3ff << 10) | (0x3ff << 20));

        assert!(
            decoded
                .iter()
                .all(|component| (*component - 1.0).abs() < f32::EPSILON)
        );
    }

    #[test]
    fn normalize_returns_a_unit_vector() {
        let normalized = normalize([3.0, 0.0, 4.0]);

        assert!((normalized[0] - 0.6).abs() < f32::EPSILON);
        assert!(normalized[1].abs() < f32::EPSILON);
        assert!((normalized[2] - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn encode_glb_writes_glb_version_two_header() {
        let result = encode_glb(&json!({"asset": {"version": "2.0"}}), &[]).unwrap();

        assert_eq!(&result[..8], b"glTF\x02\0\0\0");
    }

    #[test]
    fn u64_member_or_default_returns_zero_for_omitted_red_property() {
        let value = json!({"$type": "rendChunk"});

        assert_eq!(u64_member_or_default(&value, "lodMask").unwrap(), 0);
    }

    #[test]
    fn quantization_vector_ignores_unused_non_numeric_w_component() {
        let value = json!({"$type": "Vector4", "X": 0.5, "Y": 1.0, "Z": 1.5, "W": null});
        let decoded = quantization_vector(&value).unwrap();

        assert!(
            decoded
                .iter()
                .zip([0.5, 1.0, 1.5])
                .all(|(actual, expected)| (*actual - expected).abs() < f32::EPSILON)
        );
    }
}
