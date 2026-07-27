//! Native extraction of mesh materials and their render-time dependencies.

use crate::{
    archive::{self, ArchiveIndex},
    codec,
    schema::RedSchema,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rayon::prelude::*;
use serde_json::{Map, Value, json};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::OsStr,
    fmt::Write as _,
    fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
};
use tempfile::NamedTempFile;
use texture2ddecoder::{
    decode_bc1, decode_bc3, decode_bc4, decode_bc5, decode_bc6_signed, decode_bc6_unsigned,
    decode_bc7,
};
use thiserror::Error;

const DEPOT_EXTENSIONS: &[&str] = &[
    "mi",
    "mt",
    "remt",
    "xbm",
    "mlmask",
    "mlsetup",
    "mltemplate",
    "gradient",
    "hp",
    "texarray",
];

static DEPENDENCY_LOCKS: LazyLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Error)]
pub enum MaterialError {
    #[error("could not access material data: {0}")]
    Io(#[from] io::Error),
    #[error("could not read game archive: {0}")]
    Archive(#[from] archive::ArchiveError),
    #[error("could not decode material CR2W: {0}")]
    Codec(#[from] codec::CodecError),
    #[error("could not decode embedded bytes: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("could not encode material JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("malformed material data: {0}")]
    Malformed(String),
    #[error("unsupported texture compression: {0}")]
    UnsupportedTexture(String),
    #[error("texture decoder failed: {0}")]
    Texture(String),
    #[error("game resource was not found in the indexed archives: {0}")]
    ResourceNotFound(String),
    #[error("failed to export dependency {path}: {source}")]
    Dependency {
        path: String,
        #[source]
        source: Box<MaterialError>,
    },
}

#[derive(Debug)]
struct ArchiveSource {
    path: PathBuf,
    index: ArchiveIndex,
}

/// An in-memory hash index over the game's archive files.
#[derive(Debug)]
pub struct ArchiveSet {
    sources: Vec<ArchiveSource>,
    locations: HashMap<u64, (usize, usize)>,
}

#[derive(Debug)]
struct MaterialRecord {
    name: String,
    base_material: String,
    material_template: String,
    enable_mask: bool,
    data: Map<String, Value>,
}

#[derive(Debug, Default)]
pub struct ExportSummary {
    pub materials: usize,
    pub dependencies: usize,
    pub textures: usize,
    pub masks: usize,
}

impl ArchiveSet {
    /// Indexes every `.archive` beneath a game archive directory.
    ///
    /// # Errors
    ///
    /// Returns [`MaterialError`] when the directory cannot be traversed or an
    /// archive index is invalid.
    pub fn open(root: &Path) -> Result<Self, MaterialError> {
        let mut paths = Vec::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for item in fs::read_dir(&directory)? {
                let path = item?.path();
                if path.is_dir() {
                    pending.push(path);
                } else if path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("archive"))
                {
                    paths.push(path);
                }
            }
        }
        paths.sort();
        let indexed: Result<Vec<_>, archive::ArchiveError> = paths
            .par_iter()
            .map(|path| {
                Ok(ArchiveSource {
                    path: path.clone(),
                    index: archive::read_archive(path)?,
                })
            })
            .collect();
        let sources = indexed?;
        let mut locations = HashMap::new();
        for (source_index, source) in sources.iter().enumerate() {
            for (entry_index, entry) in source.index.entries.iter().enumerate() {
                // Later archives take precedence, matching the game's patch-like
                // replacement behavior while remaining deterministic.
                locations.insert(entry.name_hash, (source_index, entry_index));
            }
        }
        Ok(Self { sources, locations })
    }

    /// Extracts an exact depot path using the already-built archive index.
    ///
    /// # Errors
    ///
    /// Returns [`MaterialError`] when the resource is absent or its archive
    /// payload cannot be read or decompressed.
    pub fn read_resource(
        &self,
        depot_path: &str,
        kraken_path: &OsStr,
    ) -> Result<Vec<u8>, MaterialError> {
        let hash = archive::depot_path_hash(depot_path);
        let &(source_index, entry_index) = self
            .locations
            .get(&hash)
            .ok_or_else(|| MaterialError::ResourceNotFound(depot_path.to_owned()))?;
        let source = &self.sources[source_index];
        Ok(archive::extract_entry_bytes(
            &source.path,
            &source.index,
            entry_index,
            kraken_path,
        )?)
    }
}

/// Writes a WolvenKit-compatible `.Material.json` and native material repo.
///
/// # Errors
///
/// Returns [`MaterialError`] for malformed mesh/material resources, missing
/// dependencies, unsupported textures, archive failures, or output I/O errors.
#[expect(
    clippy::too_many_lines,
    reason = "the function keeps the sidecar's mesh-to-material mapping in one auditable flow"
)]
pub fn export_mesh_materials(
    mesh_input: &Path,
    schema: &RedSchema,
    archives: &ArchiveSet,
    repository: &Path,
    sidecar: &Path,
    kraken_path: &OsStr,
    appearance: Option<&str>,
) -> Result<ExportSummary, MaterialError> {
    let mesh = codec::decode_wkit_with_red_schema(mesh_input, schema, kraken_path)?;
    let root = path(&mesh, &["Data", "RootChunk"])?;
    let entries = array(root, "materialEntries")?;
    let embedded = path(root, &["localMaterialBuffer", "rawData"])?;
    let embedded_bytes = STANDARD.decode(string(embedded, "Bytes")?)?;
    let headers = array(path(root, &["localMaterialBuffer"])?, "rawDataHeaders")?;
    let external = root
        .get("externalMaterials")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let all_appearances = decode_appearances(root)?;
    let selected_names = appearance
        .map(|name| {
            all_appearances
                .get(name)
                .and_then(Value::as_array)
                .ok_or_else(|| malformed("requested mesh appearance was not found"))
                .and_then(|values| {
                    values
                        .iter()
                        .map(red_string)
                        .collect::<Result<HashSet<_>, _>>()
                })
        })
        .transpose()?;

    let mut materials = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = red_string(
            entry
                .get("name")
                .ok_or_else(|| malformed("material entry has no name"))?,
        )?;
        if selected_names
            .as_ref()
            .is_some_and(|selected| !selected.contains(&name))
        {
            continue;
        }
        let index = usize_value(entry.get("index").unwrap_or(&Value::Null)).unwrap_or(0);
        let document = if entry
            .get("isLocalInstance")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let header = headers
                .get(index)
                .ok_or_else(|| malformed("local material index is outside the header table"))?;
            let offset = usize_value(header.get("offset").unwrap_or(&Value::Null)).unwrap_or(0);
            let size = usize_value(
                header
                    .get("size")
                    .ok_or_else(|| malformed("local material header has no size"))?,
            )
            .ok_or_else(|| malformed("local material size is invalid"))?;
            let end = offset
                .checked_add(size)
                .ok_or_else(|| malformed("local material byte range overflows"))?;
            decode_bytes(
                embedded_bytes
                    .get(offset..end)
                    .ok_or_else(|| malformed("local material byte range is outside the buffer"))?,
                schema,
                kraken_path,
            )?
        } else {
            let depot_path = external
                .get(index)
                .ok_or_else(|| malformed("external material index is outside the table"))
                .and_then(red_depot_path)?;
            decode_bytes(
                &archives.read_resource(&depot_path, kraken_path)?,
                schema,
                kraken_path,
            )?
        };
        materials.push(resolve_material(
            name,
            &document,
            archives,
            schema,
            kraken_path,
            0,
        )?);
    }

    let appearances = if let Some(name) = appearance {
        Map::from_iter([(
            name.to_owned(),
            all_appearances
                .get(name)
                .cloned()
                .ok_or_else(|| malformed("requested mesh appearance was not found"))?,
        )])
    } else {
        all_appearances
    };
    let mut queue = VecDeque::new();
    for material in &materials {
        collect_depot_paths(&Value::Object(material.data.clone()), &mut queue);
    }
    let mut dependency_exporter =
        DependencyExporter::new(archives, schema, repository, kraken_path);
    dependency_exporter.export(queue)?;

    if let Some(parent) = sidecar.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(repository)?;
    let texture_list: Vec<_> = dependency_exporter.textures.iter().cloned().collect();
    let material_values: Vec<_> = materials
        .iter()
        .map(|material| {
            json!({
                "Name": material.name,
                "BaseMaterial": material.base_material,
                "MaterialTemplate": material.material_template,
                "EnableMask": material.enable_mask,
                "Data": material.data,
            })
        })
        .collect();
    let templates: Vec<_> = materials
        .iter()
        .map(|material| {
            json!({
                "Name": material.material_template,
                "EnableMask": material.enable_mask,
                "Data": template_defaults(&material.material_template),
            })
        })
        .collect();
    let document = json!({
        "Header": {"MaterialJsonVersion": "1.0.0"},
        "MaterialRepo": repository.canonicalize().unwrap_or_else(|_| repository.to_path_buf()),
        "Materials": material_values,
        "TexturesList": texture_list,
        "MaterialTemplates": templates,
        "Appearances": appearances,
    });
    fs::write(sidecar, serde_json::to_vec_pretty(&document)?)?;
    Ok(ExportSummary {
        materials: materials.len(),
        dependencies: dependency_exporter.visited.len(),
        textures: dependency_exporter.textures.len(),
        masks: dependency_exporter.masks,
    })
}

fn resolve_material(
    name: String,
    document: &Value,
    archives: &ArchiveSet,
    schema: &RedSchema,
    kraken_path: &OsStr,
    depth: usize,
) -> Result<MaterialRecord, MaterialError> {
    if depth > 16 {
        return Err(malformed(
            "material inheritance is deeper than 16 resources",
        ));
    }
    let root = path(document, &["Data", "RootChunk"])?;
    let base_material = root
        .get("baseMaterial")
        .map(red_depot_path)
        .transpose()?
        .unwrap_or_default();
    let mut data = Map::new();
    let mut material_template = base_material.clone();
    let mut enable_mask = root
        .get("enableMask")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if extension(&base_material) == Some("mi") {
        let parent_document = decode_bytes(
            &archives.read_resource(&base_material, kraken_path)?,
            schema,
            kraken_path,
        )?;
        let parent = resolve_material(
            name.clone(),
            &parent_document,
            archives,
            schema,
            kraken_path,
            depth + 1,
        )?;
        data = parent.data;
        material_template = parent.material_template;
        enable_mask |= parent.enable_mask;
    }
    if let Some(values) = root.get("values").and_then(Value::as_array) {
        for value in values {
            let object = value
                .as_object()
                .ok_or_else(|| malformed("material value is not an object"))?;
            for (key, item) in object {
                if !key.starts_with('$') {
                    data.insert(key.clone(), normalize_value(item));
                }
            }
        }
    }
    Ok(MaterialRecord {
        name,
        base_material,
        material_template,
        enable_mask,
        data,
    })
}

fn decode_appearances(root: &Value) -> Result<Map<String, Value>, MaterialError> {
    let mut result = Map::new();
    for (index, appearance) in array(root, "appearances")?.iter().enumerate() {
        let data = appearance.get("Data").unwrap_or(appearance);
        let name = data
            .get("name")
            .map(red_string)
            .transpose()?
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("default{index}"));
        let materials = data
            .get("chunkMaterials")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("mesh appearance has no chunk material array"))?
            .iter()
            .map(red_string)
            .collect::<Result<Vec<_>, _>>()?;
        result.insert(name, json!(materials));
    }
    Ok(result)
}

struct DependencyExporter<'a> {
    archives: &'a ArchiveSet,
    schema: &'a RedSchema,
    repository: &'a Path,
    kraken_path: &'a OsStr,
    visited: HashSet<String>,
    textures: HashSet<String>,
    masks: usize,
}

impl<'a> DependencyExporter<'a> {
    fn new(
        archives: &'a ArchiveSet,
        schema: &'a RedSchema,
        repository: &'a Path,
        kraken_path: &'a OsStr,
    ) -> Self {
        Self {
            archives,
            schema,
            repository,
            kraken_path,
            visited: HashSet::new(),
            textures: HashSet::new(),
            masks: 0,
        }
    }

    fn export(&mut self, mut queue: VecDeque<String>) -> Result<(), MaterialError> {
        while let Some(depot_path) = queue.pop_front() {
            let normalized = depot_path.replace('/', "\\").to_lowercase();
            if !self.visited.insert(normalized.clone()) {
                continue;
            }
            let Some(extension) = extension(&normalized) else {
                continue;
            };
            if !DEPOT_EXTENSIONS.contains(&extension) {
                continue;
            }
            let result = (|| {
                let output = repo_path(self.repository, &normalized)?;
                let resource_lock = dependency_lock(&output);
                let _resource_guard = resource_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if extension == "xbm" && output.with_extension("png").is_file() {
                    self.textures.insert(normalized.clone());
                    return Ok(());
                }
                if extension == "mlmask" && output.with_extension("masklist").is_file() {
                    self.masks += 1;
                    return Ok(());
                }
                let json_output = repo_path(self.repository, &format!("{normalized}.json"))?;
                if !matches!(extension, "xbm" | "mlmask") && json_output.is_file() {
                    let document: Value = serde_json::from_slice(&fs::read(&json_output)?)?;
                    collect_depot_paths(&document, &mut queue);
                    return Ok(());
                }
                let bytes = self.archives.read_resource(&normalized, self.kraken_path)?;
                let mut document = decode_bytes(&bytes, self.schema, self.kraken_path)?;
                complete_blender_defaults(&mut document, extension)?;
                match extension {
                    "xbm" => {
                        export_xbm(&document, &output)?;
                        self.textures.insert(normalized.clone());
                    }
                    "mlmask" => {
                        export_mlmask(&document, &output)?;
                        self.masks += 1;
                    }
                    _ => {
                        write_json(&json_output, &document)?;
                        collect_depot_paths(&document, &mut queue);
                    }
                }
                Ok(())
            })();
            result.map_err(|source| MaterialError::Dependency {
                path: normalized,
                source: Box::new(source),
            })?;
        }
        Ok(())
    }
}

fn dependency_lock(path: &Path) -> Arc<Mutex<()>> {
    let mut locks = DEPENDENCY_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(
        locks
            .entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

fn export_xbm(document: &Value, output: &Path) -> Result<(), MaterialError> {
    let root = path(document, &["Data", "RootChunk"])?;
    let compression = string(path(root, &["setup"])?, "compression")?;
    let blob = path(
        root,
        &["renderTextureResource", "renderResourceBlobPC", "Data"],
    )?;
    let header = path(blob, &["header"])?;
    let size_info = path(header, &["sizeInfo"])?;
    let width = required_usize(size_info, "width")?;
    let height = required_usize(size_info, "height")?;
    let mip = array(header, "mipMapInfo")?
        .first()
        .ok_or_else(|| malformed("texture has no mipmaps"))?;
    let placement = path(mip, &["placement"])?;
    let offset = usize_value(placement.get("offset").unwrap_or(&Value::Null)).unwrap_or(0);
    let size = usize_value(
        placement
            .get("size")
            .ok_or_else(|| malformed("texture mip has no size"))?,
    )
    .ok_or_else(|| malformed("texture mip size is invalid"))?;
    let encoded = string(path(blob, &["textureData"])?, "Bytes")?;
    let bytes = STANDARD.decode(encoded)?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| malformed("texture mip range overflows"))?;
    let data = bytes
        .get(offset..end)
        .ok_or_else(|| malformed("texture mip range is outside its buffer"))?;

    let mut pixels = vec![0_u32; width * height];
    match compression {
        "TCM_DXTNoAlpha" => decode_bc1(data, width, height, &mut pixels),
        "TCM_DXTAlpha" | "TCM_DXTAlphaLinear" => decode_bc3(data, width, height, &mut pixels),
        "TCM_Normalmap" | "TCM_QualityRG" => decode_bc5(data, width, height, &mut pixels),
        "TCM_QualityR" => decode_bc4(data, width, height, &mut pixels),
        "TCM_QualityColor" => decode_bc7(data, width, height, &mut pixels),
        "TCM_HalfHDR" => decode_bc6_unsigned(data, width, height, &mut pixels),
        "TCM_HalfHDRSigned" => decode_bc6_signed(data, width, height, &mut pixels),
        "TCM_None" => {
            return export_uncompressed_texture(root, data, width, height, output);
        }
        other => return Err(MaterialError::UnsupportedTexture(other.to_owned())),
    }
    .map_err(|error| {
        MaterialError::Texture(format!(
            "{error} ({compression}, {width}x{height}, {} bytes)",
            data.len()
        ))
    })?;

    let grayscale = compression == "TCM_QualityR";
    let mut rgba = Vec::with_capacity(pixels.len() * 4);
    for row in pixels.rchunks_exact(width) {
        for pixel in row {
            let [blue, green, red, alpha] = pixel.to_le_bytes();
            if grayscale {
                rgba.extend_from_slice(&[red, red, red, alpha]);
            } else {
                rgba.extend_from_slice(&[red, green, blue, alpha]);
            }
        }
    }
    write_png(output.with_extension("png").as_path(), width, height, &rgba)
}

fn export_uncompressed_texture(
    root: &Value,
    data: &[u8],
    width: usize,
    height: usize,
    output: &Path,
) -> Result<(), MaterialError> {
    let raw_format = root
        .get("setup")
        .and_then(|setup| setup.get("rawFormat"))
        .and_then(Value::as_str)
        .unwrap_or("TRF_TrueColor");
    let rgba = match raw_format {
        "TRF_Grayscale" if data.len() >= width * height => data[..width * height]
            .iter()
            .flat_map(|value| [*value, *value, *value, 255])
            .collect(),
        _ if data.len() >= width * height * 4 => data[..width * height * 4].to_vec(),
        _ => return Err(malformed("uncompressed texture payload is too small")),
    };
    write_png(output.with_extension("png").as_path(), width, height, &rgba)
}

fn export_mlmask(document: &Value, output: &Path) -> Result<(), MaterialError> {
    let blob = path(
        document,
        &[
            "Data",
            "RootChunk",
            "renderResourceBlob",
            "renderResourceBlobPC",
            "Data",
        ],
    )?;
    let header = path(blob, &["header"])?;
    let atlas_width = required_usize(header, "atlasWidth")?;
    let atlas_height = required_usize(header, "atlasHeight")?;
    let mask_count = required_usize(header, "numLayers")?;
    let mask_width = required_usize(header, "maskWidth")?;
    let mask_height = required_usize(header, "maskHeight")?;
    let low_width = required_usize(header, "maskWidthLow")?;
    let low_height = required_usize(header, "maskHeightLow")?;
    let tile_size = required_usize(header, "maskTileSize")?;
    if tile_size == 0 {
        return Err(malformed("multilayer mask tile size is zero"));
    }
    let atlas_bytes = STANDARD.decode(string(path(blob, &["atlasData"])?, "Bytes")?)?;
    let mut atlas_pixels = vec![0_u32; atlas_width * atlas_height];
    decode_bc4(&atlas_bytes, atlas_width, atlas_height, &mut atlas_pixels)
        .map_err(|error| MaterialError::Texture(error.to_owned()))?;
    let atlas: Vec<u8> = atlas_pixels
        .into_iter()
        .map(|pixel| pixel.to_le_bytes()[2])
        .collect();
    let tile_bytes = STANDARD.decode(string(path(blob, &["tilesData"])?, "Bytes")?)?;
    let tiles: Vec<u32> = tile_bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four-byte chunk")))
        .collect();

    let stem = output
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| malformed("multilayer mask output has no file stem"))?;
    let parent = output
        .parent()
        .ok_or_else(|| malformed("multilayer mask output has no parent"))?;
    let layer_directory = parent.join(format!("{stem}_layers"));
    fs::create_dir_all(&layer_directory)?;
    let mut mask_list = String::new();
    for layer_index in 0..mask_count {
        let full = decode_mask_layer(
            &atlas,
            atlas_width,
            &tiles,
            mask_width,
            mask_height,
            low_width,
            tile_size,
            layer_index,
        );
        let high_resolution =
            has_high_resolution(&tiles, mask_width, mask_height, tile_size, layer_index);
        let (pixels, width, height) =
            if high_resolution || low_width == 0 || low_height == 0 || low_width == mask_width {
                (full, mask_width, mask_height)
            } else {
                (
                    downscale_nearest(&full, mask_width, mask_height, low_width, low_height),
                    low_width,
                    low_height,
                )
            };
        let rgba: Vec<u8> = pixels
            .iter()
            .flat_map(|value| [*value, *value, *value, 255])
            .collect();
        let name = format!("{stem}_{layer_index}.png");
        write_png(&layer_directory.join(&name), width, height, &rgba)?;
        writeln!(mask_list, "{stem}_layers/{name}")
            .expect("writing a multilayer mask path to a String cannot fail");
    }
    fs::write(output.with_extension("masklist"), mask_list)?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the dimensions mirror the independently versioned mask header fields"
)]
fn decode_mask_layer(
    atlas: &[u8],
    atlas_width: usize,
    tiles: &[u32],
    mask_width: usize,
    mask_height: usize,
    low_width: usize,
    tile_size: usize,
    layer_index: usize,
) -> Vec<u8> {
    let mut output = vec![0_u8; mask_width * mask_height];
    let full_width_tiles = mask_width.div_ceil(tile_size);
    let full_height_tiles = mask_height.div_ceil(tile_size);
    let low_offset = full_width_tiles * full_height_tiles;
    let small_scale = if low_width == 0 || mask_width < low_width {
        1
    } else {
        mask_width / low_width
    };
    let low_width_tiles = (mask_width / small_scale).div_ceil(tile_size);
    for y in 0..mask_height {
        for x in 0..mask_width {
            if !decode_mask_pixel(
                atlas,
                atlas_width,
                tiles,
                x,
                y,
                layer_index,
                0,
                1,
                full_width_tiles,
                tile_size,
                &mut output,
                mask_width,
            ) {
                decode_mask_pixel(
                    atlas,
                    atlas_width,
                    tiles,
                    x,
                    y,
                    layer_index,
                    low_offset,
                    small_scale,
                    low_width_tiles,
                    tile_size,
                    &mut output,
                    mask_width,
                );
            }
        }
    }
    output
}

#[expect(
    clippy::too_many_arguments,
    reason = "this is the direct tile lookup operation defined by the mask format"
)]
fn decode_mask_pixel(
    atlas: &[u8],
    atlas_width: usize,
    tiles: &[u32],
    x: usize,
    y: usize,
    layer_index: usize,
    tiles_offset: usize,
    small_scale: usize,
    width_in_tiles: usize,
    tile_size: usize,
    output: &mut [u8],
    mask_width: usize,
) -> bool {
    let tile_index = width_in_tiles * (y / tile_size / small_scale)
        + (x / tile_size / small_scale)
        + tiles_offset;
    let Some((&parameter_offset, &parameter_bits)) =
        tiles.get(tile_index * 2).zip(tiles.get(tile_index * 2 + 1))
    else {
        return false;
    };
    let layer_bit = 1_u32.checked_shl(u32::try_from(layer_index).unwrap_or(u32::MAX));
    let Some(layer_bit) = layer_bit else {
        return false;
    };
    if parameter_bits & layer_bit == 0 {
        return false;
    }
    let preceding = parameter_bits & layer_bit.saturating_sub(1);
    let declaration_index =
        usize::try_from(parameter_offset).unwrap_or(usize::MAX) + preceding.count_ones() as usize;
    let Some(&declaration) = tiles.get(declaration_index) else {
        return false;
    };
    let dx = usize::try_from(declaration & 0x3ff).unwrap_or(0);
    let dy = usize::try_from((declaration >> 10) & 0x3ff).unwrap_or(0);
    let sx = usize::try_from((declaration >> 20) & 0xf).unwrap_or(0);
    let sy = usize::try_from((declaration >> 24) & 0xf).unwrap_or(0);
    let local_x = ((x >> sx) % tile_size).min(tile_size - 1);
    let local_y = ((y >> sy) % tile_size).min(tile_size - 1);
    let atlas_tile_size = tile_size + 2;
    let atlas_index =
        local_x + 1 + dx * atlas_tile_size + (local_y + 1 + dy * atlas_tile_size) * atlas_width;
    let Some(&pixel) = atlas.get(atlas_index) else {
        return false;
    };
    if let Some(target) = output.get_mut(x + y * mask_width) {
        *target = pixel;
        true
    } else {
        false
    }
}

fn has_high_resolution(
    tiles: &[u32],
    width: usize,
    height: usize,
    tile_size: usize,
    layer_index: usize,
) -> bool {
    let Some(layer_bit) = 1_u32.checked_shl(u32::try_from(layer_index).unwrap_or(u32::MAX)) else {
        return false;
    };
    (0..width.div_ceil(tile_size) * height.div_ceil(tile_size)).any(|index| {
        tiles
            .get(index * 2 + 1)
            .is_some_and(|bits| bits & layer_bit != 0)
    })
}

fn downscale_nearest(
    source: &[u8],
    source_width: usize,
    source_height: usize,
    width: usize,
    height: usize,
) -> Vec<u8> {
    let mut output = vec![0_u8; width * height];
    for y in 0..height {
        for x in 0..width {
            let source_x = (x * source_width / width).min(source_width - 1);
            let source_y = (y * source_height / height).min(source_height - 1);
            output[x + y * width] = source[source_x + source_y * source_width];
        }
    }
    output
}

fn write_png(path: &Path, width: usize, height: usize, rgba: &[u8]) -> Result<(), MaterialError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = fs::File::create(path)?;
    let mut encoder = png::Encoder::new(
        file,
        u32::try_from(width).map_err(|_| malformed("PNG width does not fit u32"))?,
        u32::try_from(height).map_err(|_| malformed("PNG height does not fit u32"))?,
    );
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .map_err(|error| io::Error::other(error.to_string()))?
        .write_image_data(rgba)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

fn decode_bytes(
    bytes: &[u8],
    schema: &RedSchema,
    kraken_path: &OsStr,
) -> Result<Value, MaterialError> {
    let mut temporary = NamedTempFile::new()?;
    temporary.write_all(bytes)?;
    Ok(codec::decode_wkit_with_red_schema(
        temporary.path(),
        schema,
        kraken_path,
    )?)
}

fn collect_depot_paths(value: &Value, queue: &mut VecDeque<String>) {
    match value {
        Value::Object(object) => {
            if let Some(path) = object
                .get("DepotPath")
                .and_then(|value| value.get("$value"))
                .and_then(Value::as_str)
            {
                queue.push_back(path.to_owned());
            }
            for value in object.values() {
                collect_depot_paths(value, queue);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_depot_paths(value, queue);
            }
        }
        Value::String(value)
            if extension(value).is_some_and(|ext| DEPOT_EXTENSIONS.contains(&ext)) =>
        {
            queue.push_back(value.to_owned());
        }
        _ => {}
    }
}

fn normalize_value(value: &Value) -> Value {
    if let Ok(path) = red_depot_path(value) {
        return Value::String(path);
    }
    match value {
        Value::Object(object) => {
            if let Some(value) = object.get("$value") {
                return normalize_value(value);
            }
            Value::Object(
                object
                    .iter()
                    .filter(|(key, _)| !key.starts_with('$') && *key != "Flags")
                    .map(|(key, value)| (key.clone(), normalize_value(value)))
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.iter().map(normalize_value).collect()),
        other => other.clone(),
    }
}

fn complete_blender_defaults(document: &mut Value, extension: &str) -> Result<(), MaterialError> {
    if let Some(header) = document.get_mut("Header").and_then(Value::as_object_mut) {
        header.insert(
            "WolvenKitVersion".to_owned(),
            json!("8.17-compatible (ghostline-red 0.1.0)"),
        );
    }
    let root = document
        .get_mut("Data")
        .and_then(|value| value.get_mut("RootChunk"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| malformed("resource JSON has no root chunk"))?;
    match extension {
        "mlsetup" => {
            root.entry("ratio").or_insert(json!(1));
            root.entry("useNormal").or_insert(json!(1));
            if let Some(layers) = root.get_mut("layers").and_then(Value::as_array_mut) {
                for layer in layers {
                    let layer = layer
                        .as_object_mut()
                        .ok_or_else(|| malformed("multilayer setup layer is not an object"))?;
                    layer.entry("matTile").or_insert(json!(1));
                    layer.entry("mbTile").or_insert(json!(1));
                    layer.entry("microblendContrast").or_insert(json!(0.5));
                    layer.entry("microblendOffsetU").or_insert(json!(0));
                    layer.entry("microblendOffsetV").or_insert(json!(0));
                    layer.entry("offsetU").or_insert(json!(0));
                    layer.entry("offsetV").or_insert(json!(0));
                    layer.entry("opacity").or_insert(json!(1));
                    layer.entry("overrides").or_insert(json!({
                        "$type": "CName",
                        "$storage": "string",
                        "$value": "None"
                    }));
                }
            }
        }
        "mltemplate" => {
            root.entry("colorMaskLevelsOut")
                .or_insert(json!({"Elements": [0, 0]}));
            root.entry("tilingMultiplier").or_insert(json!(1));
            root.entry("defaultOverrides").or_insert(json!({
                "$type": "Multilayer_LayerOverrideSelection",
                "colorScale": red_name("null_null"),
                "metalLevelsIn": red_name("null"),
                "metalLevelsOut": red_name("null"),
                "normalStrength": red_name("null"),
                "roughLevelsIn": red_name("null"),
                "roughLevelsOut": red_name("null")
            }));
        }
        _ => {}
    }
    Ok(())
}

fn red_name(value: &str) -> Value {
    json!({"$type": "CName", "$storage": "string", "$value": value})
}

fn template_defaults(template: &str) -> Value {
    if template.ends_with("multilayered.mt") {
        json!({
            "GlobalNormal": "engine\\textures\\editor\\normal.xbm",
            "MultilayerMask": "engine\\materials\\defaults\\multilayer_default.mlmask",
            "MultilayerSetup": "engine\\materials\\defaults\\multilayer_default.mlsetup",
            "GlobalNormalIntensity": 1,
            "GlobalNormalUVScale": {"X": 1, "Y": 1, "Z": 0, "W": 0},
            "GlobalNormalUVBias": {"X": 0, "Y": 0, "Z": 0, "W": 0},
            "MaskAtlas": "",
            "MaskTiles": null,
            "Layers": null,
            "LayersStartIndex": 0,
            "SurfaceTexAspectRatio": 0,
            "MaskToTileScale": {"X": 0, "Y": 0, "Z": 0, "W": 0},
            "MaskTileSize": 0,
            "MaskAtlasDims": {"X": 0, "Y": 0, "Z": 0, "W": 0},
            "MaskBaseResolution": {"X": 0, "Y": 0, "Z": 0, "W": 0},
            "SetupLayerMask": 0,
            "NormalsTextureDDXYMultiplier": 1,
            "MicroblendsTextureDDXYMultiplier": 1
        })
    } else {
        json!({})
    }
}

fn repo_path(repository: &Path, depot_path: &str) -> Result<PathBuf, MaterialError> {
    let mut result = repository.to_path_buf();
    for component in Path::new(&depot_path.replace('\\', "/")).components() {
        match component {
            Component::Normal(value) => result.push(value),
            _ => return Err(malformed("depot path is not relative and normalized")),
        }
    }
    Ok(result)
}

fn write_json(output: &Path, document: &Value) -> Result<(), MaterialError> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, serde_json::to_vec_pretty(document)?)?;
    Ok(())
}

fn red_depot_path(value: &Value) -> Result<String, MaterialError> {
    value
        .get("DepotPath")
        .and_then(|value| value.get("$value"))
        .or_else(|| value.get("$value"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| malformed("resource reference has no depot path"))
}

fn red_string(value: &Value) -> Result<String, MaterialError> {
    value
        .get("$value")
        .and_then(Value::as_str)
        .or_else(|| value.as_str())
        .map(str::to_owned)
        .ok_or_else(|| malformed("RED string value is missing"))
}

fn path<'a>(value: &'a Value, members: &[&str]) -> Result<&'a Value, MaterialError> {
    members.iter().try_fold(value, |current, member| {
        current
            .get(*member)
            .ok_or_else(|| malformed("required object member is missing"))
    })
}

fn array<'a>(value: &'a Value, member: &str) -> Result<&'a Vec<Value>, MaterialError> {
    value
        .get(member)
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("required array member is missing"))
}

fn string<'a>(value: &'a Value, member: &str) -> Result<&'a str, MaterialError> {
    value
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("required string member is missing"))
}

fn required_usize(value: &Value, member: &str) -> Result<usize, MaterialError> {
    value
        .get(member)
        .and_then(usize_value)
        .ok_or_else(|| malformed("required integer member is missing"))
}

fn usize_value(value: &Value) -> Option<usize> {
    value.as_u64().and_then(|value| usize::try_from(value).ok())
}

fn extension(path: &str) -> Option<&str> {
    path.rsplit_once('.').map(|(_, extension)| extension)
}

fn malformed(message: &str) -> MaterialError {
    MaterialError::Malformed(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{downscale_nearest, normalize_value, repo_path};
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn normalizes_red_values_for_material_sidecars() {
        let value = json!({
            "$type": "rRef:ITexture",
            "DepotPath": {
                "$type": "ResourcePath",
                "$storage": "string",
                "$value": "base\\texture.xbm"
            },
            "Flags": "Default"
        });
        assert_eq!(normalize_value(&value), json!("base\\texture.xbm"));
    }

    #[test]
    fn rejects_escaping_depot_paths() {
        assert!(repo_path(Path::new("repo"), "..\\outside.xbm").is_err());
    }

    #[test]
    fn nearest_downscale_samples_source_grid() {
        assert_eq!(
            downscale_nearest(&[0, 1, 2, 3, 4, 5, 6, 7, 8], 3, 3, 2, 2),
            vec![0, 1, 3, 4]
        );
    }
}
