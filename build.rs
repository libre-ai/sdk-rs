use schemars::schema::RootSchema;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use typify::{TypeSpace, TypeSpaceSettings};

type BoxError = Box<dyn Error + Send + Sync>;

fn main() -> Result<(), BoxError> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let schema_dir = manifest_dir
        .join("../../contracts/schemas")
        .canonicalize()?;
    println!("cargo:rerun-if-changed={}", schema_dir.display());

    let mut schema_paths = fs::read_dir(&schema_dir)?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<Result<Vec<_>, _>>()?;
    schema_paths.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    schema_paths.sort();

    let mut documents = BTreeMap::new();
    for path in &schema_paths {
        let canonical = path.canonicalize()?;
        let document: Value = serde_json::from_str(&fs::read_to_string(&canonical)?)?;
        documents.insert(canonical, document);
    }

    let output_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::write(
        output_dir.join("embedded_schemas.rs"),
        embedded_schema_source(&schema_paths, &documents)?,
    )?;
    fs::write(
        output_dir.join("generated_types.rs"),
        generated_type_source(&schema_paths, &documents)?,
    )?;

    Ok(())
}

fn embedded_schema_source(
    schema_paths: &[PathBuf],
    documents: &BTreeMap<PathBuf, Value>,
) -> Result<String, BoxError> {
    let mut source = String::from("pub const EMBEDDED_SCHEMAS: &[(&str, &str)] = &[\n");
    for path in schema_paths {
        let canonical = path.canonicalize()?;
        let name = file_name(&canonical)?;
        let document = serde_json::to_string(
            documents
                .get(&canonical)
                .ok_or_else(|| format!("schema not loaded: {}", canonical.display()))?,
        )?;
        source.push_str(&format!("    ({name:?}, {document:?}),\n"));
    }
    source.push_str("];\n");
    Ok(source)
}

fn generated_type_source(
    schema_paths: &[PathBuf],
    documents: &BTreeMap<PathBuf, Value>,
) -> Result<String, BoxError> {
    let mut source = String::from(
        "// Generated from canonical JSON Schema. Runtime validation remains authoritative.\n",
    );
    let mut projected_names = Vec::new();

    for path in schema_paths {
        let canonical = path.canonicalize()?;
        let name = file_name(&canonical)?;
        if name == "common.v1.schema.json" {
            continue;
        }

        let document = documents
            .get(&canonical)
            .ok_or_else(|| format!("schema not loaded: {}", canonical.display()))?;
        let projected = project_schema(document, &canonical, documents, &mut BTreeSet::new())?;
        let root_schema: RootSchema = serde_json::from_value(projected)?;
        let mut settings = TypeSpaceSettings::default();
        settings.with_struct_builder(false);
        let mut type_space = TypeSpace::new(&settings);
        type_space.add_root_schema(root_schema)?;

        let module_name = rust_module_name(name);
        source.push_str(&format!(
            "pub mod {module_name} {{\n#![allow(clippy::all, missing_docs)]\n{}\n}}\n",
            type_space.to_stream()
        ));
        projected_names.push(name.to_owned());
    }

    source.push_str("pub const GENERATED_TYPE_SCHEMA_NAMES: &[&str] = &[\n");
    for name in projected_names {
        source.push_str(&format!("    {name:?},\n"));
    }
    source.push_str("];\n");
    Ok(source)
}

fn project_schema(
    value: &Value,
    current_path: &Path,
    documents: &BTreeMap<PathBuf, Value>,
    stack: &mut BTreeSet<String>,
) -> Result<Value, BoxError> {
    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| project_schema(value, current_path, documents, stack))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                if object.len() != 1 {
                    return Err(format!(
                        "static projection does not support $ref siblings in {}",
                        current_path.display()
                    )
                    .into());
                }
                let (target_path, fragment) = resolve_reference(current_path, reference)?;
                let key = format!("{}#{fragment}", target_path.display());
                let target_document = documents.get(&target_path).ok_or_else(|| {
                    format!("unregistered schema reference: {}", target_path.display())
                })?;
                let target = if fragment.is_empty() {
                    target_document
                } else {
                    target_document
                        .pointer(&fragment)
                        .ok_or_else(|| format!("unknown schema pointer: {key}"))?
                };
                if !stack.insert(key.clone()) {
                    if target.get("$comment").and_then(Value::as_str)
                        == Some("libre-ai-static-projection-recursion=opaque")
                    {
                        return Ok(Value::Bool(true));
                    }
                    return Err(
                        format!("recursive schema reference is not projectable: {key}").into(),
                    );
                }
                let projected = project_schema(target, &target_path, documents, stack)?;
                stack.remove(&key);
                return Ok(projected);
            }

            let mut projected = Map::new();
            for (key, nested) in object {
                if matches!(
                    key.as_str(),
                    "$schema"
                        | "$id"
                        | "if"
                        | "then"
                        | "else"
                        | "not"
                        | "contains"
                        | "minContains"
                        | "maxContains"
                        | "contentEncoding"
                ) {
                    continue;
                }
                if key == "allOf" {
                    let entries = nested
                        .as_array()
                        .ok_or_else(|| "allOf must be an array".to_owned())?;
                    let unconditional = entries
                        .iter()
                        .filter(|entry| {
                            !entry
                                .as_object()
                                .is_some_and(|entry| entry.contains_key("if"))
                        })
                        .map(|entry| project_schema(entry, current_path, documents, stack))
                        .collect::<Result<Vec<_>, _>>()?;
                    if !unconditional.is_empty() {
                        projected.insert(key.clone(), Value::Array(unconditional));
                    }
                    continue;
                }
                projected.insert(
                    key.clone(),
                    project_schema(nested, current_path, documents, stack)?,
                );
            }
            Ok(Value::Object(projected))
        }
        _ => Ok(value.clone()),
    }
}

fn resolve_reference(current_path: &Path, reference: &str) -> Result<(PathBuf, String), BoxError> {
    let (relative_path, fragment) = reference.split_once('#').unwrap_or((reference, ""));
    let target_path = if relative_path.is_empty() {
        current_path.to_path_buf()
    } else {
        current_path
            .parent()
            .ok_or_else(|| format!("schema has no parent: {}", current_path.display()))?
            .join(relative_path)
            .canonicalize()?
    };
    let pointer = if fragment.is_empty() {
        String::new()
    } else if fragment.starts_with('/') {
        fragment.to_owned()
    } else {
        return Err(format!("unsupported non-pointer schema fragment: {reference}").into());
    };
    Ok((target_path, pointer))
}

fn rust_module_name(file_name: &str) -> String {
    file_name
        .strip_suffix(".schema.json")
        .unwrap_or(file_name)
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn file_name(path: &Path) -> Result<&str, BoxError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid UTF-8 schema path: {}", path.display()).into())
}
