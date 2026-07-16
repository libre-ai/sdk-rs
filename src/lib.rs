#![forbid(unsafe_code)]

use jsonschema::{Draft, Registry, Validator};
use serde_json::Value;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_schemas.rs"));
}

/// Disposable static projections. Canonical runtime validation remains mandatory.
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated_types.rs"));
}

/// A validation issue that deliberately excludes the rejected value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractValidationIssue {
    pub instance_path: String,
    pub schema_path: String,
    pub keyword: String,
}

#[derive(Debug)]
pub enum ContractRegistryError {
    InvalidEmbeddedSchema { schema_name: String, reason: String },
    DuplicateSchemaId(String),
    UnknownSchema(String),
}

impl Display for ContractRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEmbeddedSchema {
                schema_name,
                reason,
            } => {
                write!(formatter, "invalid embedded schema {schema_name}: {reason}")
            }
            Self::DuplicateSchemaId(schema_id) => {
                write!(formatter, "duplicate schema id: {schema_id}")
            }
            Self::UnknownSchema(schema_name) => {
                write!(formatter, "unknown canonical contract: {schema_name}")
            }
        }
    }
}

impl Error for ContractRegistryError {}

/// A fail-closed, in-memory registry built only from embedded canonical schemas.
pub struct ContractRegistry {
    validators: BTreeMap<String, Validator>,
}

impl ContractRegistry {
    pub fn embedded() -> Result<Self, ContractRegistryError> {
        let mut documents = Vec::with_capacity(embedded::EMBEDDED_SCHEMAS.len());
        let mut registry = Registry::new();
        let mut schema_ids = BTreeMap::new();

        for (schema_name, source) in embedded::EMBEDDED_SCHEMAS {
            let document: Value = serde_json::from_str(source).map_err(|error| {
                ContractRegistryError::InvalidEmbeddedSchema {
                    schema_name: (*schema_name).to_owned(),
                    reason: error.to_string(),
                }
            })?;
            let schema_id = document
                .get("$id")
                .and_then(Value::as_str)
                .ok_or_else(|| ContractRegistryError::InvalidEmbeddedSchema {
                    schema_name: (*schema_name).to_owned(),
                    reason: "missing canonical $id".to_owned(),
                })?
                .to_owned();
            if schema_ids
                .insert(schema_id.clone(), (*schema_name).to_owned())
                .is_some()
            {
                return Err(ContractRegistryError::DuplicateSchemaId(schema_id));
            }
            registry = registry.add(schema_id, document.clone()).map_err(|error| {
                ContractRegistryError::InvalidEmbeddedSchema {
                    schema_name: (*schema_name).to_owned(),
                    reason: error.to_string(),
                }
            })?;
            documents.push(((*schema_name).to_owned(), document));
        }

        let registry =
            registry
                .prepare()
                .map_err(|error| ContractRegistryError::InvalidEmbeddedSchema {
                    schema_name: "registry".to_owned(),
                    reason: error.to_string(),
                })?;
        let mut validators = BTreeMap::new();
        for (schema_name, document) in documents {
            let validator = jsonschema::options()
                .with_draft(Draft::Draft202012)
                .with_registry(&registry)
                .should_validate_formats(true)
                .build(&document)
                .map_err(|error| ContractRegistryError::InvalidEmbeddedSchema {
                    schema_name: schema_name.clone(),
                    reason: error.to_string(),
                })?;
            validators.insert(schema_name, validator);
        }
        Ok(Self { validators })
    }

    pub fn schema_names(&self) -> impl Iterator<Item = &str> {
        self.validators.keys().map(String::as_str)
    }

    pub fn validate(
        &self,
        schema_name: &str,
        value: &Value,
    ) -> Result<Vec<ContractValidationIssue>, ContractRegistryError> {
        let validator = self
            .validators
            .get(schema_name)
            .ok_or_else(|| ContractRegistryError::UnknownSchema(schema_name.to_owned()))?;
        Ok(validator
            .iter_errors(value)
            .map(|error| {
                let schema_path = error.schema_path().as_str().to_owned();
                let keyword = schema_path
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                ContractValidationIssue {
                    instance_path: if error.instance_path().as_str().is_empty() {
                        "/".to_owned()
                    } else {
                        error.instance_path().as_str().to_owned()
                    },
                    schema_path,
                    keyword,
                }
            })
            .collect())
    }

    pub fn is_valid(
        &self,
        schema_name: &str,
        value: &Value,
    ) -> Result<bool, ContractRegistryError> {
        Ok(self.validate(schema_name, value)?.is_empty())
    }
}
