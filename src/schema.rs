//! Generates a compact RED reflection schema from the pinned `WolvenKit` source.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedProperty {
    pub cs_type: String,
    pub ordinal: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub red_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<u64>,
}

/// Holds RED reflection types from legacy schemas or official `REDmod` metadata.
#[derive(Debug, Clone, Default)]
pub struct RedSchema {
    pub classes: BTreeMap<String, RedClass>,
    pub enums: BTreeSet<String>,
    pub bitfields: BTreeSet<String>,
    pub aliases: BTreeMap<String, String>,
    pub simple_types: BTreeSet<String>,
}

impl RedSchema {
    /// Parses either Ghostline's legacy class map or `REDmod` RTTI metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError::Json`] when `bytes` are not a supported JSON
    /// schema document.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SchemaError> {
        let document: SchemaDocument = serde_json::from_slice(bytes)?;
        Ok(match document {
            SchemaDocument::Legacy(classes) => Self {
                classes,
                ..Self::default()
            },
            SchemaDocument::Redmod(metadata) => metadata.into(),
        })
    }

    /// Merges another schema into this one.
    ///
    /// Classes and properties absent from `other` are retained. Metadata
    /// present in `other` takes precedence, so callers can load a broad
    /// compatibility schema first and overlay official `REDmod` metadata.
    pub fn merge(&mut self, other: Self) {
        for (name, incoming) in other.classes {
            self.classes
                .entry(name)
                .and_modify(|class| {
                    if incoming.base.is_some() {
                        class.base.clone_from(&incoming.base);
                    }
                    class.properties.extend(incoming.properties.clone());
                    if incoming.flags.is_some() {
                        class.flags = incoming.flags;
                    }
                    if incoming.size.is_some() {
                        class.size = incoming.size;
                    }
                    if incoming.alignment.is_some() {
                        class.alignment = incoming.alignment;
                    }
                })
                .or_insert(incoming);
        }
        self.enums.extend(other.enums);
        self.bitfields.extend(other.bitfields);
        self.aliases.extend(other.aliases);
        self.simple_types.extend(other.simple_types);
    }

    /// Returns every reflected class name.
    #[must_use]
    pub fn class_names(&self) -> BTreeSet<String> {
        let mut names = self.classes.keys().cloned().collect::<BTreeSet<_>>();
        for alias in self.aliases.keys() {
            let mut target = alias.as_str();
            let mut visited = BTreeSet::new();
            while let Some(next) = self.aliases.get(target) {
                if !visited.insert(target) {
                    break;
                }
                target = next;
            }
            if self.classes.contains_key(target) {
                names.insert(alias.clone());
            }
        }
        names
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SchemaDocument {
    Redmod(RedmodMetadata),
    Legacy(BTreeMap<String, RedClass>),
}

#[derive(Debug, Deserialize)]
struct RedmodMetadata {
    #[serde(default)]
    simple_types: Vec<RedmodNamedType>,
    classes: Vec<RedmodClass>,
    #[serde(default)]
    enums: Vec<RedmodNamedType>,
    #[serde(default)]
    bitfields: Vec<RedmodNamedType>,
    #[serde(default)]
    aliases: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct RedmodClass {
    name: String,
    #[serde(default)]
    parent: String,
    flags: u64,
    size: usize,
    alignment: usize,
    #[serde(default)]
    properties: Vec<RedmodProperty>,
}

#[derive(Debug, Deserialize)]
struct RedmodProperty {
    name: String,
    #[serde(rename = "type")]
    red_type: String,
    offset: usize,
    flags: u64,
}

#[derive(Debug, Deserialize)]
struct RedmodNamedType {
    name: String,
}

impl From<RedmodMetadata> for RedSchema {
    fn from(metadata: RedmodMetadata) -> Self {
        let classes = metadata
            .classes
            .into_iter()
            .map(|class| {
                let name = class.name;
                let properties = class
                    .properties
                    .into_iter()
                    .map(|property| {
                        let red_type = property.red_type;
                        (
                            property.name,
                            RedProperty {
                                cs_type: red_type.clone(),
                                ordinal: None,
                                red_type: Some(red_type),
                                offset: Some(property.offset),
                                flags: Some(property.flags),
                            },
                        )
                    })
                    .collect();
                (
                    name,
                    RedClass {
                        base: (!class.parent.is_empty()).then_some(class.parent),
                        properties,
                        flags: Some(class.flags),
                        size: Some(class.size),
                        alignment: Some(class.alignment),
                    },
                )
            })
            .collect();
        Self {
            classes,
            enums: metadata.enums.into_iter().map(|value| value.name).collect(),
            bitfields: metadata
                .bitfields
                .into_iter()
                .map(|value| value.name)
                .collect(),
            aliases: metadata.aliases,
            simple_types: metadata
                .simple_types
                .into_iter()
                .map(|value| value.name)
                .collect(),
        }
    }
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
                (
                    red_name,
                    RedProperty {
                        cs_type,
                        ordinal,
                        red_type: None,
                        offset: None,
                        flags: None,
                    },
                )
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
            .or_insert(RedClass {
                base,
                properties,
                flags: None,
                size: None,
                alignment: None,
            });
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

#[cfg(test)]
mod tests {
    use super::RedSchema;

    #[test]
    fn loads_legacy_class_map() {
        let schema = RedSchema::from_slice(
            br#"{
                "Derived": {
                    "base": "Base",
                    "properties": {
                        "value": {"cs_type": "CInt32", "ordinal": 1}
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(schema.classes["Derived"].base.as_deref(), Some("Base"));
        assert_eq!(
            schema.classes["Derived"].properties["value"]
                .red_type
                .as_deref(),
            None
        );
        assert!(schema.enums.is_empty());
    }

    #[test]
    fn loads_official_redmod_metadata() {
        let schema = RedSchema::from_slice(
            br#"{
                "simple_types": [{"name": "Int32"}],
                "classes": [{
                    "name": "Derived",
                    "parent": "Base",
                    "flags": 2,
                    "size": 16,
                    "alignment": 8,
                    "properties": [{
                        "name": "mode",
                        "type": "ExampleMode",
                        "offset": 4,
                        "flags": 17
                    }],
                    "functions": [],
                    "static_functions": []
                }],
                "enums": [{
                    "name": "ExampleMode",
                    "size": 4,
                    "options": {"First": 0}
                }],
                "bitfields": [{
                    "name": "ExampleFlags",
                    "size": 4,
                    "alignment": 1,
                    "bits": {"Visible": 0}
                }],
                "aliases": {"OldDerived": "Derived"},
                "global_functions": []
            }"#,
        )
        .unwrap();

        let property = &schema.classes["Derived"].properties["mode"];
        assert_eq!(property.red_type.as_deref(), Some("ExampleMode"));
        assert_eq!(property.offset, Some(4));
        assert_eq!(property.flags, Some(17));
        assert!(schema.enums.contains("ExampleMode"));
        assert!(schema.bitfields.contains("ExampleFlags"));
        assert_eq!(schema.aliases["OldDerived"], "Derived");
        assert!(schema.class_names().contains("OldDerived"));
    }

    #[test]
    fn official_overlay_preserves_legacy_only_classes_and_properties() {
        let mut schema = RedSchema::from_slice(
            br#"{
                "LegacyOnly": {"base": null, "properties": {}},
                "Shared": {
                    "base": "LegacyBase",
                    "properties": {
                        "legacyProperty": {"cs_type": "CInt32", "ordinal": 1},
                        "mode": {"cs_type": "LegacyMode", "ordinal": 2}
                    }
                }
            }"#,
        )
        .unwrap();
        let official = RedSchema::from_slice(
            br#"{
                "simple_types": [],
                "classes": [{
                    "name": "Shared",
                    "parent": "OfficialBase",
                    "flags": 2,
                    "size": 16,
                    "alignment": 8,
                    "properties": [{
                        "name": "mode",
                        "type": "OfficialMode",
                        "offset": 4,
                        "flags": 17
                    }]
                }],
                "enums": [{"name": "OfficialMode"}],
                "bitfields": [],
                "aliases": {}
            }"#,
        )
        .unwrap();

        schema.merge(official);

        assert!(schema.classes.contains_key("LegacyOnly"));
        assert_eq!(
            schema.classes["Shared"].base.as_deref(),
            Some("OfficialBase")
        );
        assert!(
            schema.classes["Shared"]
                .properties
                .contains_key("legacyProperty")
        );
        assert_eq!(
            schema.classes["Shared"].properties["mode"]
                .red_type
                .as_deref(),
            Some("OfficialMode")
        );
    }
}
