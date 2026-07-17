use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct Vectors {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    id: String,
    digest_field: String,
    unsigned_payload: Value,
    expected_digest: String,
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("JSON string must serialize"),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            let properties = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("JSON key must serialize"),
                        canonical_json(object.get(key).expect("sorted key must exist"))
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{properties}}}")
        }
    }
}

#[test]
fn rust_projection_matches_agent_orchestration_digest_vectors() {
    let document = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/agent-orchestration-v1/digest-vectors.v1.json"
    ));
    let vectors: Vectors = serde_json::from_str(document).expect("digest vectors must parse");

    for vector in vectors.vectors {
        let object = vector
            .unsigned_payload
            .as_object()
            .expect("unsigned payload must be an object");
        assert!(!object.contains_key(&vector.digest_field), "{}", vector.id);
        assert!(!object.contains_key("signature"), "{}", vector.id);
        let digest = Sha256::digest(canonical_json(&vector.unsigned_payload).as_bytes());
        let actual = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, vector.expected_digest, "{}", vector.id);
    }
}
