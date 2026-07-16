use libre_ai_contract_types::{ContractRegistry, ContractRegistryError};
use serde_json::{Map, Value};

fn mutate(input: &Value, mutation: &Value) -> Value {
    let mut output = input.clone();
    let path = mutation["path"].as_str().expect("mutation path");
    let segments = path
        .split('/')
        .skip(1)
        .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>();
    let (last, parents) = segments.split_last().expect("non-empty mutation path");
    let mut target = &mut output;
    for segment in parents {
        target = match target {
            Value::Object(object) => object.get_mut(segment).expect("known object mutation path"),
            Value::Array(array) => &mut array[segment.parse::<usize>().expect("array index")],
            _ => panic!("mutation path traverses a scalar"),
        };
    }
    if mutation.get("remove").and_then(Value::as_bool) == Some(true) {
        match target {
            Value::Object(object) => {
                object.remove(last).expect("known object removal path");
            }
            Value::Array(array) => {
                array.remove(last.parse::<usize>().expect("array index"));
            }
            _ => panic!("mutation path targets a scalar"),
        }
    } else {
        let replacement = mutation.get("value").cloned().unwrap_or(Value::Null);
        match target {
            Value::Object(object) => {
                object.insert(last.clone(), replacement);
            }
            Value::Array(array) => {
                array[last.parse::<usize>().expect("array index")] = replacement;
            }
            _ => panic!("mutation path targets a scalar"),
        }
    }
    output
}

#[test]
fn every_schema_compiles_and_every_fixture_matches_in_both_directions() {
    let registry = ContractRegistry::embedded().expect("canonical schemas must compile");
    assert_eq!(registry.schema_names().count(), 31);
    assert_eq!(
        libre_ai_contract_types::generated::GENERATED_TYPE_SCHEMA_NAMES.len(),
        30
    );

    let fixtures: Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/schema-fixtures.v1.json"
    ))
    .expect("fixture document");
    let cases = fixtures["cases"].as_array().expect("fixture cases");
    assert_eq!(cases.len(), 30);

    for case in cases {
        let schema_name = case["schema"].as_str().expect("schema name");
        let valid = &case["valid"];
        assert!(
            registry.is_valid(schema_name, valid).expect("known schema"),
            "canonical fixture rejected for {schema_name}"
        );
        assert!(
            !registry
                .is_valid(schema_name, &Value::Null)
                .expect("known schema")
        );

        let mut unknown = valid.clone();
        unknown
            .as_object_mut()
            .expect("root object")
            .insert("__unexpected".to_owned(), Value::Bool(true));
        assert!(
            !registry
                .is_valid(schema_name, &unknown)
                .expect("known schema")
        );

        if valid.get("schemaVersion").and_then(Value::as_str).is_some() {
            let mut unknown_version = valid.clone();
            unknown_version
                .as_object_mut()
                .expect("root object")
                .insert(
                    "schemaVersion".to_owned(),
                    Value::String("libre-ai.unknown.v999".to_owned()),
                );
            assert!(
                !registry
                    .is_valid(schema_name, &unknown_version)
                    .expect("known schema"),
                "unknown contract version accepted for {schema_name}"
            );
        }

        for mutation in case["invalidMutations"]
            .as_array()
            .expect("invalid mutations")
        {
            let invalid = mutate(valid, mutation);
            assert!(
                !registry
                    .is_valid(schema_name, &invalid)
                    .expect("known schema"),
                "negative fixture accepted for {schema_name}: {}",
                mutation["name"].as_str().unwrap_or("unnamed")
            );
        }
    }
}

#[test]
fn validation_issues_do_not_echo_private_values() {
    let registry = ContractRegistry::embedded().expect("canonical schemas must compile");
    let private_value = "private-value-must-not-leak";
    let invalid = Value::Object(Map::from_iter([(
        "sessionDigest".to_owned(),
        Value::String(private_value.to_owned()),
    )]));
    let issues = registry
        .validate("browser-session.v1.schema.json", &invalid)
        .expect("known schema");
    assert!(!issues.is_empty());
    assert!(!format!("{issues:?}").contains(private_value));
}

#[test]
fn unknown_schema_fails_closed() {
    let registry = ContractRegistry::embedded().expect("canonical schemas must compile");
    assert!(matches!(
        registry.is_valid("missing.schema.json", &Value::Null),
        Err(ContractRegistryError::UnknownSchema(_))
    ));
}
