//! Generates a compact RED reflection schema from the pinned `WolvenKit` source.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("could not access WolvenKit source: {0}")]
    Io(#[from] io::Error),
    #[error("invalid schema parser expression: {0}")]
    Regex(#[from] regex::Error),
    #[error("could not encode schema: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedClass {
    pub base: Option<String>,
    pub properties: BTreeMap<String, RedProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedProperty {
    pub cs_type: String,
    pub ordinal: Option<u32>,
}

/// Extracts class inheritance and RED property names from generated `WolvenKit`
/// class declarations and writes a deterministic JSON schema.
///
/// # Errors
///
/// Returns [`SchemaError`] if the source tree cannot be traversed, expressions
/// cannot compile, or the output cannot be encoded.
pub fn generate(wolvenkit: &Path, output: &Path) -> Result<usize, SchemaError> {
    let class_re = Regex::new(
        r"(?m)\b(?:partial\s+)?class\s+(?P<name>[A-Za-z0-9_]+)\s*(?::\s*(?P<base>[A-Za-z0-9_]+))?",
    )?;
    let red_alias_re = Regex::new(r#"\[RED\("(?P<alias>[^"]+)"\)\]\s*(?:public\s+)?$"#)?;
    let property_re = Regex::new(
        r#"(?s)(?:\[Ordinal\((?P<ordinal>\d+)\)\]\s*)?\[RED\("(?P<red>[^"]+)"[^\]]*\)\]\s*public\s+(?P<type>[A-Za-z0-9_<>,\s]+?)\s+[A-Za-z0-9_]+\s*\{"#,
    )?;
    let mut classes = BTreeMap::<String, RedClass>::new();
    for path in cs_files(wolvenkit)? {
        let text = fs::read_to_string(path)?;
        let Some(class_capture) = class_re.captures(&text) else {
            continue;
        };
        let class_start = class_capture.get(0).map_or(0, |capture| capture.start());
        let mut prefix_start = class_start.saturating_sub(256);
        while !text.is_char_boundary(prefix_start) {
            prefix_start += 1;
        }
        let name = red_alias_re
            .captures(&text[prefix_start..class_start])
            .map_or_else(
                || class_capture["name"].to_owned(),
                |capture| capture["alias"].to_owned(),
            );
        let base = class_capture
            .name("base")
            .map(|value| value.as_str().to_owned());
        let properties: BTreeMap<String, RedProperty> = property_re
            .captures_iter(&text)
            .map(|capture| {
                let red_name = capture["red"].to_owned();
                let cs_type = capture["type"]
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                let ordinal = capture
                    .name("ordinal")
                    .and_then(|value| value.as_str().parse().ok());
                (red_name, RedProperty { cs_type, ordinal })
            })
            .collect();
        classes
            .entry(name)
            .and_modify(|class| {
                if class.base.is_none() {
                    class.base.clone_from(&base);
                }
                class.properties.extend(properties.clone());
            })
            .or_insert(RedClass { base, properties });
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, serde_json::to_vec_pretty(&classes)?)?;
    Ok(classes.len())
}

fn cs_files(root: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "cs") {
                files.push(path);
            }
        }
    }
    Ok(files)
}
