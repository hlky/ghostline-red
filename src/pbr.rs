//! Standard PBR material baking for selected Cyberpunk mesh appearances.

use image::{ImageBuffer, ImageError, Rgba, RgbaImage, imageops::FilterType};
use rayon::prelude::*;
use serde_json::{Map, Value, json};
use sha1::{Digest, Sha1};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::{Component, Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
};
use thiserror::Error;

const GLB_MAGIC: u32 = 0x4654_6c67;
const GLB_JSON_CHUNK: u32 = 0x4e4f_534a;
const GLB_BIN_CHUNK: u32 = 0x004e_4942;
const DEFAULT_BAKE_SIZE: u32 = 512;

static BAKE_LOCKS: LazyLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Material templates used by the equipment database's selected appearances.
pub const SUPPORTED_TEMPLATES: &[&str] = &[
    r"base\fx\_shaders\invisible.mt",
    r"base\fx\shaders\device_diode.mt",
    r"base\fx\shaders\hologram.mt",
    r"base\fx\shaders\metal_base_glitter.mt",
    r"base\fx\shaders\parallaxscreen.mt",
    r"base\fx\shaders\parallaxscreen_transparent.mt",
    r"base\fx\shaders\signages.mt",
    r"base\materials\glass.mt",
    r"base\materials\glass_cracked_edge.mt",
    r"base\materials\glass_deferred.mt",
    r"base\materials\glass_onesided.mt",
    r"base\materials\fillable_fluid.mt",
    r"base\materials\lights_interactive.mt",
    r"base\materials\metal_base_det.mt",
    r"base\materials\metal_base_det_dithered.mt",
    r"base\materials\metal_base_dithered.mt",
    r"base\materials\metal_base_gradientmap_recolor.mt",
    r"base\materials\metal_base_ui.mt",
    r"base\materials\mesh_decal.mt",
    r"base\materials\mesh_decal_emissive.mt",
    r"base\materials\mesh_decal_gradientmap_recolor.mt",
    r"base\materials\mesh_decal_parallax.mt",
    r"base\materials\multilayered_terrain.mt",
    r"base\materials\vehicle_destr_blendshape.mt",
    r"base\materials\vehicle_mesh_decal.mt",
    r"base\materials\window_parallax_interior.mt",
    r"engine\materials\metal_base.remt",
    r"engine\materials\metal_base_proxy.mt",
    r"engine\materials\multilayered.mt",
];

#[derive(Debug, Error)]
pub enum PbrError {
    #[error("could not access PBR material data: {0}")]
    Io(#[from] io::Error),
    #[error("could not decode PBR material JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("could not decode or encode PBR texture: {0}")]
    Image(#[from] ImageError),
    #[error("malformed PBR material data: {0}")]
    Malformed(String),
    #[error("unsupported material template: {0}")]
    UnsupportedTemplate(String),
    #[error("material texture was not extracted: {0}")]
    MissingTexture(PathBuf),
}

/// Summary of PBR materials attached to one selected-appearance GLB.
#[derive(Debug, Default)]
pub struct BakeSummary {
    pub materials: usize,
    pub generated_textures: usize,
    pub reused_textures: usize,
}

#[derive(Clone, Debug)]
struct PbrMaterial {
    name: String,
    base_color_texture: Option<PathBuf>,
    base_color_factor: [f32; 4],
    metallic_roughness_texture: Option<PathBuf>,
    metallic_factor: f32,
    roughness_factor: f32,
    normal_texture: Option<PathBuf>,
    emissive_texture: Option<PathBuf>,
    emissive_factor: [f32; 3],
    emissive_strength: f32,
    alpha_mode: &'static str,
    alpha_cutoff: Option<f32>,
    transmission: f32,
    double_sided: bool,
}

impl PbrMaterial {
    fn new(name: String) -> Self {
        Self {
            name,
            base_color_texture: None,
            base_color_factor: [1.0; 4],
            metallic_roughness_texture: None,
            metallic_factor: 0.0,
            roughness_factor: 0.5,
            normal_texture: None,
            emissive_texture: None,
            emissive_factor: [0.0; 3],
            emissive_strength: 1.0,
            alpha_mode: "OPAQUE",
            alpha_cutoff: None,
            transmission: 0.0,
            double_sided: true,
        }
    }
}

struct BakeContext<'a> {
    repository: &'a Path,
    size: u32,
    generated: usize,
    reused: usize,
}

/// Bakes the sidecar's selected appearance and attaches standard glTF PBR materials.
///
/// The source GLB geometry is preserved. Generated textures are content-addressed
/// beneath the shared material repository and reused across meshes.
///
/// # Errors
///
/// Returns [`PbrError`] when the sidecar is malformed, a referenced dependency
/// is missing, a template is unsupported, or the GLB cannot be rewritten.
pub fn bake_sidecar_into_glb(
    sidecar: &Path,
    glb: &Path,
    appearance: &str,
    size: Option<u32>,
) -> Result<BakeSummary, PbrError> {
    let document: Value = serde_json::from_slice(&fs::read(sidecar)?)?;
    let repository = PathBuf::from(
        document
            .get("MaterialRepo")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed("sidecar has no MaterialRepo"))?,
    );
    let appearance_materials = document
        .get("Appearances")
        .and_then(|value| value.get(appearance))
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(format!("appearance {appearance:?} was not found")))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| malformed("appearance material name is not a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let records = document
        .get("Materials")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("sidecar has no Materials array"))?;
    let by_name: HashMap<_, _> = records
        .iter()
        .filter_map(|record| {
            record
                .get("Name")
                .and_then(Value::as_str)
                .map(|name| (name.to_owned(), record))
        })
        .collect();
    let selected: HashSet<_> = appearance_materials.iter().collect();
    let mut context = BakeContext {
        repository: &repository,
        size: size.unwrap_or(DEFAULT_BAKE_SIZE).max(1),
        generated: 0,
        reused: 0,
    };
    let mut materials = Vec::with_capacity(selected.len());
    for name in appearance_materials
        .iter()
        .filter(|name| selected.contains(name))
    {
        if materials
            .iter()
            .any(|material: &PbrMaterial| material.name == *name)
        {
            continue;
        }
        let record = by_name
            .get(name)
            .ok_or_else(|| malformed(format!("material {name:?} has no sidecar record")))?;
        materials.push(bake_material(record, &mut context)?);
    }
    attach_materials(glb, &appearance_materials, &materials)?;
    Ok(BakeSummary {
        materials: materials.len(),
        generated_textures: context.generated,
        reused_textures: context.reused,
    })
}

fn bake_material(record: &Value, context: &mut BakeContext<'_>) -> Result<PbrMaterial, PbrError> {
    let name = required_string(record, "Name")?.to_owned();
    let template = required_string(record, "MaterialTemplate")?
        .replace('/', "\\")
        .to_lowercase();
    if !SUPPORTED_TEMPLATES.contains(&template.as_str()) {
        return Err(PbrError::UnsupportedTemplate(template));
    }
    let data = record
        .get("Data")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed("material Data is not an object"))?;
    let enable_mask = record
        .get("EnableMask")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    match template.as_str() {
        r"engine\materials\multilayered.mt" | r"base\materials\multilayered_terrain.mt" => {
            bake_multilayered(name, record, data, context)
        }
        r"engine\materials\metal_base.remt"
        | r"engine\materials\metal_base_proxy.mt"
        | r"base\fx\shaders\device_diode.mt"
        | r"base\fx\shaders\metal_base_glitter.mt"
        | r"base\materials\lights_interactive.mt"
        | r"base\materials\metal_base_det.mt"
        | r"base\materials\metal_base_gradientmap_recolor.mt"
        | r"base\materials\metal_base_ui.mt"
        | r"base\materials\vehicle_destr_blendshape.mt" => {
            bake_metal_base(name, record, data, context, enable_mask)
        }
        r"base\materials\metal_base_dithered.mt" | r"base\materials\metal_base_det_dithered.mt" => {
            bake_metal_base(name, record, data, context, true)
        }
        r"base\materials\mesh_decal.mt"
        | r"base\materials\mesh_decal_gradientmap_recolor.mt"
        | r"base\materials\mesh_decal_parallax.mt"
        | r"base\materials\vehicle_mesh_decal.mt" => bake_decal(name, record, data, context),
        r"base\materials\mesh_decal_emissive.mt" => bake_emissive_decal(name, data, context),
        r"base\materials\fillable_fluid.mt"
        | r"base\materials\glass.mt"
        | r"base\materials\glass_cracked_edge.mt"
        | r"base\materials\glass_deferred.mt"
        | r"base\materials\glass_onesided.mt" => bake_glass(name, record, data, context),
        r"base\fx\shaders\parallaxscreen.mt" | r"base\fx\shaders\parallaxscreen_transparent.mt" => {
            bake_screen(name, data, context)
        }
        r"base\fx\shaders\signages.mt" => bake_signage(name, data, context),
        r"base\fx\shaders\hologram.mt" => bake_hologram(name, data, context),
        r"base\materials\window_parallax_interior.mt" => bake_window_parallax(name, data, context),
        r"base\fx\_shaders\invisible.mt" => Ok(bake_invisible(name)),
        _ => Err(PbrError::UnsupportedTemplate(template)),
    }
}

fn bake_metal_base(
    name: String,
    record: &Value,
    data: &Map<String, Value>,
    context: &mut BakeContext<'_>,
    enable_mask: bool,
) -> Result<PbrMaterial, PbrError> {
    let mut material = PbrMaterial::new(name);
    material.base_color_texture = optional_texture(context.repository, data, "BaseColor")?;
    material.base_color_factor = gamma_color(data.get("BaseColorScale"), [1.0; 4]);
    material.normal_texture = optional_texture(context.repository, data, "Normal")?;
    let roughness = optional_texture(context.repository, data, "Roughness")?;
    let metallic = optional_texture(context.repository, data, "Metalness")?;
    let roughness_scale = scalar(data, "RoughnessScale", 1.0);
    let roughness_bias = scalar(data, "RoughnessBias", 0.0);
    let metallic_scale = scalar(data, "MetalnessScale", 1.0);
    let metallic_bias = scalar(data, "MetalnessBias", 0.0);
    if roughness.is_some() || metallic.is_some() {
        material.metallic_roughness_texture = Some(pack_metallic_roughness(
            record,
            roughness.as_deref(),
            metallic.as_deref(),
            roughness_scale,
            roughness_bias,
            metallic_scale,
            metallic_bias,
            context,
        )?);
        material.roughness_factor = 1.0;
        material.metallic_factor = 1.0;
    } else {
        material.roughness_factor = roughness_bias.clamp(0.0, 1.0);
        material.metallic_factor = metallic_bias.clamp(0.0, 1.0);
    }
    if enable_mask {
        material.alpha_mode = "MASK";
        let cutoff = scalar(data, "AlphaThreshold", 0.5).clamp(0.0, 1.0);
        material.alpha_cutoff = Some(cutoff);
    }
    if let Some(path) = optional_texture(context.repository, data, "Emissive")? {
        material.emissive_texture = Some(path);
        material.emissive_factor = color(
            data.get("EmissiveColor")
                .or_else(|| data.get("EmissiveColor1"))
                .or_else(|| data.get("DebugLightsIntensity")),
            [1.0, 1.0, 1.0, 1.0],
        )[..3]
            .try_into()
            .expect("three-element color slice");
        material.emissive_strength =
            scalar(data, "EmissiveEV", scalar(data, "Zone0EmissiveEV", 1.0)).max(0.0);
    }
    Ok(material)
}

fn bake_decal(
    name: String,
    record: &Value,
    data: &Map<String, Value>,
    context: &mut BakeContext<'_>,
) -> Result<PbrMaterial, PbrError> {
    let mut material = PbrMaterial::new(name);
    material.base_color_texture = optional_texture(context.repository, data, "DiffuseTexture")?;
    material.base_color_factor = gamma_color(data.get("DiffuseColor"), [1.0; 4]);
    material.normal_texture = optional_texture(context.repository, data, "NormalTexture")?;
    let roughness = optional_texture(context.repository, data, "RoughnessTexture")?;
    let metallic = optional_texture(context.repository, data, "MetalnessTexture")?;
    if roughness.is_some() || metallic.is_some() {
        material.metallic_roughness_texture = Some(pack_metallic_roughness(
            record,
            roughness.as_deref(),
            metallic.as_deref(),
            scalar(data, "RoughnessScale", 1.0),
            scalar(data, "RoughnessBias", 0.0),
            scalar(data, "MetalnessScale", 1.0),
            scalar(data, "MetalnessBias", 0.0),
            context,
        )?);
        material.roughness_factor = 1.0;
        material.metallic_factor = 1.0;
    }
    material.base_color_factor[3] =
        scalar(data, "DiffuseAlpha", 1.0).max(scalar(data, "NormalAlpha", 0.0));
    material.alpha_mode = "BLEND";
    Ok(material)
}

fn bake_emissive_decal(
    name: String,
    data: &Map<String, Value>,
    context: &BakeContext<'_>,
) -> Result<PbrMaterial, PbrError> {
    let mut material = PbrMaterial::new(name);
    material.base_color_factor = gamma_color(data.get("DiffuseColor2"), [0.0, 0.0, 0.0, 1.0]);
    material.emissive_texture = optional_texture(context.repository, data, "DiffuseTexture")?;
    material.emissive_factor = color(data.get("DiffuseColor"), [1.0, 1.0, 1.0, 1.0])[..3]
        .try_into()
        .expect("three-element color slice");
    material.emissive_strength = scalar(data, "EmissiveEV", 1.0).max(0.0);
    material.base_color_factor[3] = scalar(data, "DiffuseAlpha", 1.0).clamp(0.0, 1.0);
    material.alpha_mode = "BLEND";
    Ok(material)
}

fn bake_glass(
    name: String,
    record: &Value,
    data: &Map<String, Value>,
    context: &mut BakeContext<'_>,
) -> Result<PbrMaterial, PbrError> {
    let mut material = PbrMaterial::new(name);
    material.base_color_texture = optional_texture(context.repository, data, "MaskTexture")?;
    material.base_color_factor = color(
        data.get("TintColor")
            .or_else(|| data.get("GlassSpecularColor")),
        [0.75, 0.85, 0.95, 1.0],
    );
    material.base_color_factor[3] = scalar(data, "Opacity", 0.35).clamp(0.02, 1.0);
    material.normal_texture = optional_texture(context.repository, data, "Normal")?;
    let roughness = optional_texture(context.repository, data, "Roughness")?;
    if roughness.is_some() {
        material.metallic_roughness_texture = Some(pack_metallic_roughness(
            record,
            roughness.as_deref(),
            None,
            1.0,
            scalar(data, "GlassRoughnessBias", 0.0),
            0.0,
            0.0,
            context,
        )?);
        material.roughness_factor = 1.0;
    } else {
        material.roughness_factor = scalar(data, "GlassRoughnessBias", 0.08).clamp(0.0, 1.0);
    }
    material.alpha_mode = "BLEND";
    material.transmission = 1.0 - scalar(data, "MaskOpacity", 0.0).clamp(0.0, 1.0);
    Ok(material)
}

fn bake_screen(
    name: String,
    data: &Map<String, Value>,
    context: &BakeContext<'_>,
) -> Result<PbrMaterial, PbrError> {
    let mut material = PbrMaterial::new(name);
    let texture = optional_texture(context.repository, data, "ParalaxTexture")?;
    material.base_color_texture.clone_from(&texture);
    material.emissive_texture = texture;
    material.base_color_factor = color(data.get("EmissiveColor"), [1.0; 4]);
    material.emissive_factor = material.base_color_factor[..3]
        .try_into()
        .expect("three-element color slice");
    material.emissive_strength = scalar(data, "EmissiveEV", scalar(data, "Emissive", 2.0)).max(0.0);
    material.metallic_factor = scalar(data, "Metalness", 0.0).clamp(0.0, 1.0);
    material.roughness_factor = scalar(data, "Roughness", 0.35).clamp(0.0, 1.0);
    Ok(material)
}

fn bake_window_parallax(
    name: String,
    data: &Map<String, Value>,
    context: &BakeContext<'_>,
) -> Result<PbrMaterial, PbrError> {
    let mut material = PbrMaterial::new(name);
    let texture = optional_texture(context.repository, data, "RoomAtlas")?
        .or(optional_texture(context.repository, data, "LayerAtlas")?)
        .or(optional_texture(context.repository, data, "WindowTexture")?);
    material.base_color_texture.clone_from(&texture);
    material.emissive_texture = texture;
    material.base_color_factor = color(data.get("TintColorAtNight"), [1.0; 4]);
    material.emissive_factor = material.base_color_factor[..3]
        .try_into()
        .expect("three-element color slice");
    material.emissive_strength = scalar(data, "EmissiveEV", 1.0).max(0.0);
    material.normal_texture = optional_texture(context.repository, data, "Normal")?;
    material.roughness_factor = 0.35;
    Ok(material)
}

fn bake_invisible(name: String) -> PbrMaterial {
    let mut material = PbrMaterial::new(name);
    material.base_color_factor[3] = 0.0;
    material.alpha_mode = "BLEND";
    material
}

fn bake_signage(
    name: String,
    data: &Map<String, Value>,
    context: &BakeContext<'_>,
) -> Result<PbrMaterial, PbrError> {
    let mut material = PbrMaterial::new(name);
    let texture = optional_texture(context.repository, data, "MainTexture")?;
    material.base_color_texture.clone_from(&texture);
    material.emissive_texture = texture;
    material.base_color_factor = color(data.get("ColorOneStart"), [1.0; 4]);
    material.emissive_factor = material.base_color_factor[..3]
        .try_into()
        .expect("three-element color slice");
    material.emissive_strength = (scalar(data, "EmissiveEV", 1.0) * 10.0).max(0.0);
    material.metallic_factor = scalar(data, "Metalness", 0.0).clamp(0.0, 1.0);
    material.roughness_factor = scalar(data, "Roughness", 0.3).clamp(0.0, 1.0);
    material.alpha_mode = "BLEND";
    Ok(material)
}

fn bake_hologram(
    name: String,
    data: &Map<String, Value>,
    context: &BakeContext<'_>,
) -> Result<PbrMaterial, PbrError> {
    let mut material = PbrMaterial::new(name);
    let texture = optional_texture(context.repository, data, "Diffuse")?.or(optional_texture(
        context.repository,
        data,
        "Scanline",
    )?);
    material.base_color_texture.clone_from(&texture);
    material.emissive_texture = texture;
    material.base_color_factor = color(
        data.get("DotsColor").or_else(|| data.get("SurfaceColor")),
        [0.15, 0.65, 1.0, 1.0],
    );
    material.emissive_factor = material.base_color_factor[..3]
        .try_into()
        .expect("three-element color slice");
    material.emissive_strength = 30.0 * scalar(data, "GlowStrength", 1.0).max(0.1);
    material.base_color_factor[3] = scalar(data, "Opacity", 0.34).clamp(0.02, 1.0);
    material.roughness_factor = 1.0;
    material.alpha_mode = "BLEND";
    Ok(material)
}

#[expect(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    reason = "the bake loop keeps all per-pixel channels together; texture dimensions fit exactly enough in f32"
)]
fn bake_multilayered(
    name: String,
    record: &Value,
    data: &Map<String, Value>,
    context: &mut BakeContext<'_>,
) -> Result<PbrMaterial, PbrError> {
    let setup_depot = required_resource(data, "MultilayerSetup")?;
    let mask_depot = required_resource(data, "MultilayerMask")?;
    let setup_path = depot_json_path(context.repository, setup_depot);
    let setup_document: Value = serde_json::from_slice(&fs::read(&setup_path)?)?;
    let setup = root_chunk(&setup_document)?;
    let layers = setup
        .get("layers")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(format!("{} has no layers", setup_path.display())))?;
    if layers.is_empty() {
        return Err(malformed(format!(
            "{} has no material layers",
            setup_path.display()
        )));
    }

    let cache = cache_directory(context.repository, record, context.size)?;
    let cache_lock = bake_lock(&cache);
    let _cache_guard = cache_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let base_path = cache.join("base.png");
    let mr_path = cache.join("metallic-roughness.png");
    let normal_path = cache.join("normal.png");
    if base_path.is_file() && mr_path.is_file() && normal_path.is_file() {
        context.reused += 3;
    } else {
        fs::create_dir_all(&cache)?;
        let masks = load_layer_masks(context.repository, mask_depot, layers.len(), context.size)?;
        let global_normal = optional_texture(context.repository, data, "GlobalNormal")?
            .map(|path| load_rgba(&path, context.size))
            .transpose()?;

        let mut surfaces = Vec::with_capacity(layers.len());
        for layer in layers {
            surfaces.push(load_multilayer_surface(
                context.repository,
                layer,
                context.size,
            )?);
        }

        let pixel_count = context
            .size
            .checked_mul(context.size)
            .ok_or_else(|| malformed("PBR texture dimensions overflow"))?;
        let pixels = (0..pixel_count)
            .into_par_iter()
            .map(|pixel_index| {
                let x = pixel_index % context.size;
                let y = pixel_index / context.size;
                let u = (x as f32 + 0.5) / context.size as f32;
                let v = (y as f32 + 0.5) / context.size as f32;
                let mut out_color = [0.0, 0.0, 0.0, 1.0];
                let mut out_roughness = 0.5;
                let mut out_metallic = 0.0;
                let mut out_normal = [0.0, 0.0, 1.0];
                for (index, (layer, surface)) in layers.iter().zip(&surfaces).enumerate() {
                    let mask = if index == 0 {
                        1.0
                    } else {
                        masks
                            .get(index)
                            .map_or(0.0, |image| sample_repeat(image, u, v)[0])
                    };
                    let opacity = scalar_object(layer, "opacity", 1.0);
                    let alpha = (mask * opacity).clamp(0.0, 1.0);
                    if alpha <= f32::EPSILON {
                        continue;
                    }
                    let tile = scalar_object(layer, "matTile", 1.0) * surface.tiling;
                    let sample_u = u * tile + scalar_object(layer, "offsetU", 0.0);
                    let sample_v = v * tile + scalar_object(layer, "offsetV", 0.0);
                    let sampled_color = sample_repeat(&surface.color, sample_u, sample_v);
                    let sampled_roughness =
                        sample_repeat(&surface.roughness, sample_u, sample_v)[0];
                    let sampled_metallic = sample_repeat(&surface.metallic, sample_u, sample_v)[0];
                    let sampled_normal =
                        decode_normal(sample_repeat(&surface.normal, sample_u, sample_v));
                    for channel in 0..3 {
                        let source =
                            srgb_to_linear(sampled_color[channel]) * surface.color_scale[channel];
                        out_color[channel] = lerp(out_color[channel], source, alpha);
                        out_normal[channel] =
                            lerp(out_normal[channel], sampled_normal[channel], alpha);
                    }
                    out_roughness = lerp(
                        out_roughness,
                        apply_levels(
                            apply_levels(sampled_roughness, surface.roughness_in),
                            surface.roughness_out,
                        ),
                        alpha,
                    );
                    out_metallic = lerp(
                        out_metallic,
                        apply_levels(
                            apply_levels(sampled_metallic, surface.metallic_in),
                            surface.metallic_out,
                        ),
                        alpha,
                    );
                }
                if let Some(global) = &global_normal {
                    let extra = decode_normal(sample_repeat(global, u, v));
                    out_normal[0] += extra[0];
                    out_normal[1] += extra[1];
                }
                out_normal = normalize(out_normal);
                (
                    [
                        unit_to_byte(linear_to_srgb(out_color[0])),
                        unit_to_byte(linear_to_srgb(out_color[1])),
                        unit_to_byte(linear_to_srgb(out_color[2])),
                        255,
                    ],
                    [
                        255,
                        unit_to_byte(out_roughness),
                        unit_to_byte(out_metallic),
                        255,
                    ],
                    encode_normal(out_normal).0,
                )
            })
            .collect::<Vec<_>>();
        let byte_capacity = usize::try_from(pixel_count)
            .map_err(|_| malformed("PBR texture exceeds platform size"))?
            .checked_mul(4)
            .ok_or_else(|| malformed("PBR texture byte size overflow"))?;
        let mut base_bytes = Vec::with_capacity(byte_capacity);
        let mut mr_bytes = Vec::with_capacity(byte_capacity);
        let mut normal_bytes = Vec::with_capacity(byte_capacity);
        for (base_pixel, mr_pixel, normal_pixel) in pixels {
            base_bytes.extend_from_slice(&base_pixel);
            mr_bytes.extend_from_slice(&mr_pixel);
            normal_bytes.extend_from_slice(&normal_pixel);
        }
        let base = RgbaImage::from_raw(context.size, context.size, base_bytes)
            .ok_or_else(|| malformed("could not construct baked base-color texture"))?;
        let mr = RgbaImage::from_raw(context.size, context.size, mr_bytes)
            .ok_or_else(|| malformed("could not construct baked metallic-roughness texture"))?;
        let normal = RgbaImage::from_raw(context.size, context.size, normal_bytes)
            .ok_or_else(|| malformed("could not construct baked normal texture"))?;
        save_png(&base, &base_path)?;
        save_png(&mr, &mr_path)?;
        save_png(&normal, &normal_path)?;
        context.generated += 3;
    }

    let mut material = PbrMaterial::new(name);
    material.base_color_texture = Some(base_path);
    material.metallic_roughness_texture = Some(mr_path);
    material.normal_texture = Some(normal_path);
    material.metallic_factor = 1.0;
    material.roughness_factor = 1.0;
    Ok(material)
}

struct MultilayerSurface {
    color: RgbaImage,
    roughness: RgbaImage,
    metallic: RgbaImage,
    normal: RgbaImage,
    color_scale: [f32; 3],
    roughness_in: [f32; 2],
    roughness_out: [f32; 2],
    metallic_in: [f32; 2],
    metallic_out: [f32; 2],
    tiling: f32,
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "RED material scalar values and image computations intentionally use f32"
)]
fn load_multilayer_surface(
    repository: &Path,
    layer: &Value,
    size: u32,
) -> Result<MultilayerSurface, PbrError> {
    let template_depot = resource_string(
        layer
            .get("material")
            .ok_or_else(|| malformed("multilayer layer has no material"))?,
    )
    .ok_or_else(|| malformed("multilayer layer material has no depot path"))?;
    let template_path = depot_json_path(repository, template_depot);
    let document: Value = serde_json::from_slice(&fs::read(&template_path)?)?;
    let template = root_chunk(&document)?;
    let overrides = template
        .get("overrides")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed(format!("{} has no overrides", template_path.display())))?;
    let defaults = template.get("defaultOverrides").unwrap_or(&Value::Null);

    let color_choice = red_name(layer.get("colorScale"))
        .or_else(|| red_name(defaults.get("colorScale")))
        .unwrap_or("null");
    let rough_in_choice = red_name(layer.get("roughLevelsIn"))
        .or_else(|| red_name(defaults.get("roughLevelsIn")))
        .unwrap_or("null");
    let rough_out_choice = red_name(layer.get("roughLevelsOut"))
        .or_else(|| red_name(defaults.get("roughLevelsOut")))
        .unwrap_or("null");
    let metal_in_choice = red_name(layer.get("metalLevelsIn"))
        .or_else(|| red_name(defaults.get("metalLevelsIn")))
        .unwrap_or("null");
    let metal_out_choice = red_name(layer.get("metalLevelsOut"))
        .or_else(|| red_name(defaults.get("metalLevelsOut")))
        .unwrap_or("null");

    Ok(MultilayerSurface {
        color: load_rgba(
            &required_texture_from_value(repository, template, "colorTexture")?,
            size,
        )?,
        roughness: load_rgba(
            &required_texture_from_value(repository, template, "roughnessTexture")?,
            size,
        )?,
        metallic: load_rgba(
            &required_texture_from_value(repository, template, "metalnessTexture")?,
            size,
        )?,
        normal: load_rgba(
            &required_texture_from_value(repository, template, "normalTexture")?,
            size,
        )?,
        color_scale: lookup_override(overrides, "colorScale", color_choice, &[1.0, 1.0, 1.0])
            .try_into()
            .map_err(|_| malformed("invalid multilayer color override"))?,
        roughness_in: lookup_override(overrides, "roughLevelsIn", rough_in_choice, &[1.0, 0.0])
            .try_into()
            .map_err(|_| malformed("invalid multilayer roughness input override"))?,
        roughness_out: lookup_override(overrides, "roughLevelsOut", rough_out_choice, &[1.0, 0.0])
            .try_into()
            .map_err(|_| malformed("invalid multilayer roughness output override"))?,
        metallic_in: lookup_override(overrides, "metalLevelsIn", metal_in_choice, &[1.0, 0.0])
            .try_into()
            .map_err(|_| malformed("invalid multilayer metallic input override"))?,
        metallic_out: lookup_override(overrides, "metalLevelsOut", metal_out_choice, &[1.0, 0.0])
            .try_into()
            .map_err(|_| malformed("invalid multilayer metallic output override"))?,
        tiling: template
            .get("tilingMultiplier")
            .and_then(Value::as_f64)
            .unwrap_or(1.0) as f32,
    })
}

fn load_layer_masks(
    repository: &Path,
    depot: &str,
    count: usize,
    size: u32,
) -> Result<Vec<RgbaImage>, PbrError> {
    let source = depot_to_path(repository, depot, "png");
    let stem = source
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| malformed("multilayer mask has no filename"))?;
    let directory = source.with_file_name(format!("{stem}_layers"));
    (0..count)
        .map(|index| {
            let path = directory.join(format!("{stem}_{index}.png"));
            if path.is_file() {
                load_rgba(&path, size)
            } else {
                Ok(ImageBuffer::from_pixel(size, size, Rgba([0, 0, 0, 255])))
            }
        })
        .collect()
}

#[expect(
    clippy::too_many_arguments,
    reason = "the four scale/bias values are the explicit source material controls"
)]
fn pack_metallic_roughness(
    record: &Value,
    roughness: Option<&Path>,
    metallic: Option<&Path>,
    roughness_scale: f32,
    roughness_bias: f32,
    metallic_scale: f32,
    metallic_bias: f32,
    context: &mut BakeContext<'_>,
) -> Result<PathBuf, PbrError> {
    let output =
        cache_directory(context.repository, record, context.size)?.join("metallic-roughness.png");
    let output_lock = bake_lock(&output);
    let _output_guard = output_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if output.is_file() {
        context.reused += 1;
        return Ok(output);
    }
    let roughness_image = roughness
        .map(|path| load_rgba(path, context.size))
        .transpose()?;
    let metallic_image = metallic
        .map(|path| load_rgba(path, context.size))
        .transpose()?;
    let mut packed = RgbaImage::new(context.size, context.size);
    for y in 0..context.size {
        for x in 0..context.size {
            let rough = roughness_image
                .as_ref()
                .map_or(1.0, |image| f32::from(image.get_pixel(x, y)[0]) / 255.0);
            let metal = metallic_image
                .as_ref()
                .map_or(1.0, |image| f32::from(image.get_pixel(x, y)[0]) / 255.0);
            packed.put_pixel(
                x,
                y,
                Rgba([
                    255,
                    unit_to_byte(rough * roughness_scale + roughness_bias),
                    unit_to_byte(metal * metallic_scale + metallic_bias),
                    255,
                ]),
            );
        }
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    save_png(&packed, &output)?;
    context.generated += 1;
    Ok(output)
}

fn attach_materials(
    glb_path: &Path,
    appearance: &[String],
    materials: &[PbrMaterial],
) -> Result<(), PbrError> {
    let bytes = fs::read(glb_path)?;
    let (mut document, binary) = decode_glb(&bytes)?;
    let mut textures = Vec::new();
    let mut images = Vec::new();
    let glb_dir = glb_path.parent().unwrap_or_else(|| Path::new("."));
    let material_json = materials
        .iter()
        .map(|material| pbr_material_json(material, glb_dir, &mut textures, &mut images))
        .collect::<Result<Vec<_>, PbrError>>()?;
    let root = document
        .as_object_mut()
        .ok_or_else(|| malformed("GLB root is not an object"))?;
    root.insert("materials".to_owned(), Value::Array(material_json));
    if !textures.is_empty() {
        root.insert("textures".to_owned(), Value::Array(textures));
        root.insert("images".to_owned(), Value::Array(images));
        root.insert(
            "samplers".to_owned(),
            json!([{"magFilter": 9729, "minFilter": 9987, "wrapS": 10497, "wrapT": 10497}]),
        );
    }
    if materials.iter().any(|material| material.transmission > 0.0) {
        root.insert(
            "extensionsUsed".to_owned(),
            json!(["KHR_materials_transmission"]),
        );
    }
    let material_indices: HashMap<_, _> = materials
        .iter()
        .enumerate()
        .map(|(index, material)| (material.name.as_str(), index))
        .collect();
    let meshes = root
        .get_mut("meshes")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| malformed("GLB has no meshes"))?;
    let mesh_count = meshes.len();
    for (index, mesh) in meshes.iter_mut().enumerate() {
        let name = material_for_chunk(appearance, index, mesh_count);
        let material_index = material_indices
            .get(name)
            .ok_or_else(|| malformed(format!("no baked material for {name:?}")))?;
        for primitive in mesh
            .get_mut("primitives")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| malformed("GLB mesh has no primitives"))?
        {
            let primitive = primitive
                .as_object_mut()
                .ok_or_else(|| malformed("GLB primitive is not an object"))?;
            primitive.insert("material".to_owned(), json!(material_index));
            // Cyberpunk uses its vertex-color stream as shader data rather than
            // the glTF base-color multiplier. Keeping COLOR_0 would desaturate
            // baked textures in standards-compliant importers.
            if let Some(attributes) = primitive
                .get_mut("attributes")
                .and_then(Value::as_object_mut)
            {
                attributes.remove("COLOR_0");
            }
        }
    }
    fs::write(glb_path, encode_glb(&document, binary.as_deref())?)?;
    Ok(())
}

fn pbr_material_json(
    material: &PbrMaterial,
    glb_dir: &Path,
    textures: &mut Vec<Value>,
    images: &mut Vec<Value>,
) -> Result<Value, PbrError> {
    let mut pbr = Map::new();
    pbr.insert(
        "baseColorFactor".to_owned(),
        json!(material.base_color_factor),
    );
    pbr.insert("metallicFactor".to_owned(), json!(material.metallic_factor));
    pbr.insert(
        "roughnessFactor".to_owned(),
        json!(material.roughness_factor),
    );
    if let Some(path) = &material.base_color_texture {
        pbr.insert(
            "baseColorTexture".to_owned(),
            texture_reference(path, glb_dir, textures, images)?,
        );
    }
    if let Some(path) = &material.metallic_roughness_texture {
        pbr.insert(
            "metallicRoughnessTexture".to_owned(),
            texture_reference(path, glb_dir, textures, images)?,
        );
    }
    let mut value = json!({
        "name": material.name,
        "doubleSided": material.double_sided,
        "alphaMode": material.alpha_mode,
        "pbrMetallicRoughness": pbr,
    });
    if let Some(cutoff) = material.alpha_cutoff {
        value["alphaCutoff"] = json!(cutoff);
    }
    if let Some(path) = &material.normal_texture {
        value["normalTexture"] = texture_reference(path, glb_dir, textures, images)?;
    }
    if let Some(path) = &material.emissive_texture {
        value["emissiveTexture"] = texture_reference(path, glb_dir, textures, images)?;
        value["emissiveFactor"] = json!(material.emissive_factor);
        if material.emissive_strength > 1.0 {
            value["extensions"]["KHR_materials_emissive_strength"] =
                json!({"emissiveStrength": material.emissive_strength});
        }
    }
    if material.transmission > 0.0 {
        value["extensions"]["KHR_materials_transmission"] =
            json!({"transmissionFactor": material.transmission});
    }
    Ok(value)
}

fn texture_reference(
    path: &Path,
    glb_dir: &Path,
    textures: &mut Vec<Value>,
    images: &mut Vec<Value>,
) -> Result<Value, PbrError> {
    let relative = pathdiff::diff_paths(path, glb_dir).ok_or_else(|| {
        malformed(format!(
            "cannot make {} relative to {}",
            path.display(),
            glb_dir.display()
        ))
    })?;
    let uri = relative.to_string_lossy().replace('\\', "/");
    let image_index = images.len();
    images.push(json!({"uri": uri}));
    let texture_index = textures.len();
    textures.push(json!({"sampler": 0, "source": image_index}));
    Ok(json!({"index": texture_index}))
}

fn optional_texture(
    repository: &Path,
    data: &Map<String, Value>,
    key: &str,
) -> Result<Option<PathBuf>, PbrError> {
    let Some(depot) = data.get(key).and_then(resource_string) else {
        return Ok(None);
    };
    if depot.is_empty() {
        return Ok(None);
    }
    let path = depot_to_path(repository, depot, "png");
    if !path.is_file() {
        return Err(PbrError::MissingTexture(path));
    }
    Ok(Some(path))
}

fn required_texture_from_value(
    repository: &Path,
    value: &Value,
    key: &str,
) -> Result<PathBuf, PbrError> {
    let depot = value
        .get(key)
        .and_then(resource_string)
        .ok_or_else(|| malformed(format!("missing texture {key}")))?;
    let path = depot_to_path(repository, depot, "png");
    if !path.is_file() {
        return Err(PbrError::MissingTexture(path));
    }
    Ok(path)
}

fn required_resource<'a>(data: &'a Map<String, Value>, key: &str) -> Result<&'a str, PbrError> {
    data.get(key)
        .and_then(resource_string)
        .ok_or_else(|| malformed(format!("missing resource {key}")))
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, PbrError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(format!("missing string {key}")))
}

fn resource_string(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("$value").and_then(Value::as_str))
        .or_else(|| value.get("DepotPath").and_then(resource_string))
}

fn red_name(value: Option<&Value>) -> Option<&str> {
    value.and_then(resource_string)
}

fn depot_to_path(repository: &Path, depot: &str, extension: &str) -> PathBuf {
    let mut path = repository.to_path_buf();
    for component in Path::new(&depot.replace('\\', "/")).components() {
        if let Component::Normal(part) = component {
            path.push(part);
        }
    }
    path.set_extension(extension);
    path
}

fn depot_json_path(repository: &Path, depot: &str) -> PathBuf {
    let path = depot_to_path(
        repository,
        depot,
        Path::new(depot)
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or(""),
    );
    PathBuf::from(format!("{}.json", path.display()))
}

fn root_chunk(document: &Value) -> Result<&Value, PbrError> {
    document
        .pointer("/Data/RootChunk")
        .ok_or_else(|| malformed("resource JSON has no Data.RootChunk"))
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "RED material scalar values are represented as f32 by the renderer"
)]
fn scalar(data: &Map<String, Value>, key: &str, default: f32) -> f32 {
    data.get(key)
        .and_then(Value::as_f64)
        .map_or(default, |value| value as f32)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "RED material scalar values are represented as f32 by the renderer"
)]
fn scalar_object(data: &Value, key: &str, default: f32) -> f32 {
    data.get(key)
        .and_then(Value::as_f64)
        .map_or(default, |value| value as f32)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "RED color components are represented as f32 by the renderer"
)]
fn color(value: Option<&Value>, default: [f32; 4]) -> [f32; 4] {
    let Some(value) = value else {
        return default;
    };
    let names = if value.get("Red").is_some() {
        ["Red", "Green", "Blue", "Alpha"]
    } else {
        ["X", "Y", "Z", "W"]
    };
    let mut result = default;
    for (index, name) in names.iter().enumerate() {
        if let Some(component) = value.get(name).and_then(Value::as_f64) {
            result[index] = component as f32;
        }
    }
    result
}

fn gamma_color(value: Option<&Value>, default: [f32; 4]) -> [f32; 4] {
    let mut result = color(value, default);
    for component in &mut result[..3] {
        *component = component.max(0.0).powf(2.2);
    }
    result
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "RED material override values are represented as f32 by the renderer"
)]
fn lookup_override(
    overrides: &Map<String, Value>,
    kind: &str,
    selected: &str,
    default: &[f32],
) -> Vec<f32> {
    overrides
        .get(kind)
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| red_name(entry.get("n")) == Some(selected))
        })
        .and_then(|entry| {
            entry
                .pointer("/v/Elements")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_f64)
                        .map(|value| value as f32)
                        .collect()
                })
        })
        .filter(|values: &Vec<f32>| values.len() == default.len())
        .unwrap_or_else(|| default.to_vec())
}

fn cache_directory(repository: &Path, record: &Value, size: u32) -> Result<PathBuf, PbrError> {
    let mut hasher = Sha1::new();
    hasher.update(b"ghostline-pbr-v4");
    hasher.update(serde_json::to_vec(record)?);
    hasher.update(size.to_le_bytes());
    Ok(repository
        .join("_ghostline_pbr")
        .join(format!("{:x}", hasher.finalize())))
}

fn bake_lock(path: &Path) -> Arc<Mutex<()>> {
    let mut locks = BAKE_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(
        locks
            .entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(()))),
    )
}

fn load_rgba(path: &Path, size: u32) -> Result<RgbaImage, PbrError> {
    if !path.is_file() {
        return Err(PbrError::MissingTexture(path.to_path_buf()));
    }
    let image = image::open(path)?.into_rgba8();
    if image.width() == size && image.height() == size {
        Ok(image)
    } else {
        Ok(image::imageops::resize(
            &image,
            size,
            size,
            FilterType::Triangle,
        ))
    }
}

fn save_png(image: &RgbaImage, path: &Path) -> Result<(), PbrError> {
    image.save(path)?;
    Ok(())
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "wrapped normalized coordinates are non-negative and bounded by image dimensions"
)]
fn sample_repeat(image: &RgbaImage, u: f32, v: f32) -> [f32; 4] {
    let x = (u.rem_euclid(1.0) * image.width() as f32).floor() as u32 % image.width();
    let y = (v.rem_euclid(1.0) * image.height() as f32).floor() as u32 % image.height();
    let pixel = image.get_pixel(x, y);
    [
        f32::from(pixel[0]) / 255.0,
        f32::from(pixel[1]) / 255.0,
        f32::from(pixel[2]) / 255.0,
        f32::from(pixel[3]) / 255.0,
    ]
}

fn decode_normal(pixel: [f32; 4]) -> [f32; 3] {
    let x = pixel[0] * 2.0 - 1.0;
    let y = pixel[1] * 2.0 - 1.0;
    let z = (1.0 - x * x - y * y).max(0.0).sqrt();
    normalize([x, y, z])
}

fn encode_normal(value: [f32; 3]) -> Rgba<u8> {
    Rgba([
        unit_to_byte(value[0] * 0.5 + 0.5),
        unit_to_byte(value[1] * 0.5 + 0.5),
        unit_to_byte(value[2] * 0.5 + 0.5),
        255,
    ])
}

fn normalize(value: [f32; 3]) -> [f32; 3] {
    let length = (value[0] * value[0] + value[1] * value[1] + value[2] * value[2]).sqrt();
    if length <= f32::EPSILON {
        [0.0, 0.0, 1.0]
    } else {
        [value[0] / length, value[1] / length, value[2] / length]
    }
}

fn srgb_to_linear(value: f32) -> f32 {
    if value <= 0.04045 {
        value / 12.92
    } else {
        ((value + 0.055) / 1.055).powf(2.4)
    }
}

fn linear_to_srgb(value: f32) -> f32 {
    if value <= 0.003_130_8 {
        value * 12.92
    } else {
        1.055 * value.max(0.0).powf(1.0 / 2.4) - 0.055
    }
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to the exact u8 range before conversion"
)]
fn unit_to_byte(value: f32) -> u8 {
    (value.clamp(0.0, 1.0) * 255.0).round() as u8
}

fn lerp(left: f32, right: f32, factor: f32) -> f32 {
    left + (right - left) * factor
}

fn apply_levels(value: f32, levels: [f32; 2]) -> f32 {
    (value * levels[0] + levels[1]).clamp(0.0, 1.0)
}

fn material_for_chunk(materials: &[String], index: usize, chunks: usize) -> &str {
    if materials.is_empty() {
        return "";
    }
    let scaled = index.saturating_mul(materials.len()) / chunks.max(1);
    &materials[scaled.min(materials.len() - 1)]
}

fn decode_glb(bytes: &[u8]) -> Result<(Value, Option<Vec<u8>>), PbrError> {
    if bytes.len() < 20 || u32::from_le_bytes(bytes[0..4].try_into().unwrap()) != GLB_MAGIC {
        return Err(malformed("input is not a GLB"));
    }
    let mut offset = 12;
    let mut document = None;
    let mut binary = None;
    while offset + 8 <= bytes.len() {
        let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let kind = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        offset += 8;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| malformed("GLB chunk length overflow"))?;
        let payload = bytes
            .get(offset..end)
            .ok_or_else(|| malformed("GLB chunk exceeds file"))?;
        match kind {
            GLB_JSON_CHUNK => document = Some(serde_json::from_slice(payload)?),
            GLB_BIN_CHUNK => binary = Some(payload.to_vec()),
            _ => {}
        }
        offset = end;
    }
    Ok((
        document.ok_or_else(|| malformed("GLB has no JSON chunk"))?,
        binary,
    ))
}

fn encode_glb(document: &Value, binary: Option<&[u8]>) -> Result<Vec<u8>, PbrError> {
    let mut json_bytes = serde_json::to_vec(document)?;
    while json_bytes.len() % 4 != 0 {
        json_bytes.push(b' ');
    }
    let binary_length = binary.map_or(0, |value| (value.len() + 3) & !3);
    let total = 12
        + 8
        + json_bytes.len()
        + if binary.is_some() {
            8 + binary_length
        } else {
            0
        };
    let mut output = Vec::with_capacity(total);
    output.extend_from_slice(&GLB_MAGIC.to_le_bytes());
    output.extend_from_slice(&2_u32.to_le_bytes());
    output.extend_from_slice(
        &u32::try_from(total)
            .map_err(|_| malformed("GLB exceeds four GiB"))?
            .to_le_bytes(),
    );
    output.extend_from_slice(
        &u32::try_from(json_bytes.len())
            .map_err(|_| malformed("GLB JSON exceeds four GiB"))?
            .to_le_bytes(),
    );
    output.extend_from_slice(&GLB_JSON_CHUNK.to_le_bytes());
    output.extend_from_slice(&json_bytes);
    if let Some(binary) = binary {
        output.extend_from_slice(
            &u32::try_from(binary_length)
                .map_err(|_| malformed("GLB binary exceeds four GiB"))?
                .to_le_bytes(),
        );
        output.extend_from_slice(&GLB_BIN_CHUNK.to_le_bytes());
        output.extend_from_slice(binary);
        output.resize(total, 0);
    }
    Ok(output)
}

fn malformed(reason: impl Into<String>) -> PbrError {
    PbrError::Malformed(reason.into())
}

#[cfg(test)]
mod tests {
    use super::apply_levels;

    #[test]
    fn levels_apply_multiply_then_add_and_clamp() {
        assert!((apply_levels(0.5, [2.0, -0.4]) - 0.6).abs() < 1e-6);
        assert!((apply_levels(1.0, [2.0, 0.0]) - 1.0).abs() < f32::EPSILON);
        assert!(apply_levels(0.0, [1.0, -1.0]).abs() < f32::EPSILON);
    }
}
