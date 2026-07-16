use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt::Write as _;

fn canonical_json(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();
    write_canonical(value, &mut output);
    output
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => {
            serde_json::to_writer(output, value).expect("validated golden scalar")
        }
        Value::Number(number) => output.extend_from_slice(jcs_number(number).as_bytes()),
        Value::Array(values) => {
            output.push(b'[');
            for (index, nested) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical(nested, output);
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                assert!(key.is_ascii(), "policy-core golden object keys are ASCII");
                if index > 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).expect("validated golden key");
                output.push(b':');
                write_canonical(&object[key], output);
            }
            output.push(b'}');
        }
    }
}

fn jcs_number(number: &serde_json::Number) -> String {
    let value = number.as_f64().expect("validated finite binary64 number");
    assert!(value.is_finite(), "JCS excludes NaN and infinity");
    if value == 0.0 {
        return "0".to_owned();
    }
    if (1e-6..1e21).contains(&value.abs()) {
        return value.to_string();
    }

    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("scientific notation");
    let exponent = exponent.parse::<i32>().expect("binary64 exponent");
    format!(
        "{mantissa}e{}{exponent}",
        if exponent >= 0 { "+" } else { "" }
    )
}

fn type_rank(value: &Value) -> u8 {
    match value {
        Value::Bool(_) => 0,
        Value::Number(_) => 1,
        Value::String(_) => 2,
        _ => panic!("policy fact must be scalar"),
    }
}

fn compare_bytes(left: &[u8], right: &[u8]) -> Ordering {
    left.cmp(right)
}

fn compare_facts(left: &Value, right: &Value, include_source: bool) -> Ordering {
    let left_object = left.as_object().expect("fact object");
    let right_object = right.as_object().expect("fact object");
    left_object["name"]
        .as_str()
        .expect("fact name")
        .as_bytes()
        .cmp(right_object["name"].as_str().expect("fact name").as_bytes())
        .then_with(|| type_rank(&left_object["value"]).cmp(&type_rank(&right_object["value"])))
        .then_with(|| {
            compare_bytes(
                &canonical_json(&left_object["value"]),
                &canonical_json(&right_object["value"]),
            )
        })
        .then_with(|| {
            if include_source {
                compare_bytes(
                    &canonical_json(&left_object["source"]),
                    &canonical_json(&right_object["source"]),
                )
            } else {
                Ordering::Equal
            }
        })
}

fn normalize(mut value: Value, kind: &str) -> Value {
    let object = value.as_object_mut().expect("digest projection object");
    match kind {
        "policy" => {
            let rules = object["rules"].as_array_mut().expect("policy rules");
            for rule in rules.iter_mut() {
                let rule = rule.as_object_mut().expect("policy rule");
                if matches!(rule["operator"].as_str(), Some("in" | "not-in")) {
                    rule["value"]
                        .as_array_mut()
                        .expect("policy set")
                        .sort_by(|left, right| {
                            compare_bytes(&canonical_json(left), &canonical_json(right))
                        });
                }
            }
            rules.sort_by(|left, right| {
                left["id"]
                    .as_str()
                    .expect("rule id")
                    .as_bytes()
                    .cmp(right["id"].as_str().expect("rule id").as_bytes())
            });
        }
        "snapshot" | "need" => object["facts"]
            .as_array_mut()
            .expect("facts")
            .sort_by(|left, right| compare_facts(left, right, kind == "snapshot")),
        _ => panic!("unknown normalization kind"),
    }
    value
}

fn digest(label: &str, value: Value, kind: Option<&str>) -> String {
    let normalized = kind.map_or(value.clone(), |_| normalize(value, kind.expect("kind")));
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(canonical_json(&normalized));
    let mut encoded = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}").expect("write to string");
    }
    encoded
}

fn without(value: &Value, keys: &[&str]) -> Value {
    let mut projection = value.clone();
    let object = projection.as_object_mut().expect("projection object");
    for key in keys {
        object.remove(*key);
    }
    projection
}

#[test]
fn rust_test_canonicalizer_matches_rfc_8785_number_rendering() {
    for (value, expected) in [
        (json!(1.5), "1.5"),
        (json!(0.000001), "0.000001"),
        (json!(1e-7), "1e-7"),
        (json!(1e21), "1e+21"),
        (
            serde_json::from_str("333333333.33333329").unwrap(),
            "333333333.3333333",
        ),
        (json!(-0.0), "0"),
    ] {
        assert_eq!(String::from_utf8(canonical_json(&value)).unwrap(), expected);
    }
}

#[test]
fn policy_core_golden_hashes_are_portable_and_order_stable() {
    let golden: Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/policy-core-v1/golden.json"
    ))
    .expect("policy-core golden vectors");
    assert_eq!(
        golden["schemaVersion"],
        "libre-ai.policy-core-golden-vectors.v1"
    );
    assert_eq!(golden["engineVersion"], "1.0.0");

    let cases = golden["cases"].as_array().expect("golden cases");
    assert_eq!(cases.len(), 17);
    let mut order_outputs = Vec::new();
    let mut saw_fractional_number = false;
    let mut saw_tenant_mismatch = false;
    let mut saw_invalid_duplicate = false;
    let mut saw_duplicate_rule_id = false;

    for case in cases {
        let case_id = case["id"].as_str().expect("case id");
        if case_id == "duplicate-exact-fact" {
            assert_eq!(case["expectedError"]["code"], "policy.input_invalid");
            saw_invalid_duplicate = true;
            continue;
        }

        let policy = &case["policy"];
        let policy_subject = json!({
            "schemaVersion": policy["schemaVersion"],
            "id": policy["id"],
            "tenantId": policy["tenantId"],
            "version": policy["version"],
            "status": policy["status"],
            "rules": policy["rules"],
        });
        let policy_digest = digest(
            "libre-ai.policy-definition.v1",
            policy_subject,
            Some("policy"),
        );
        assert_eq!(policy["digest"], policy_digest, "{case_id}: policy digest");
        assert_eq!(
            policy["approval"]["subjectDigest"], policy_digest,
            "{case_id}: approval subject digest"
        );

        let snapshot = &case["snapshot"];
        assert_eq!(
            snapshot["digest"],
            digest(
                "libre-ai.model-snapshot.v1",
                without(snapshot, &["digest"]),
                Some("snapshot")
            ),
            "{case_id}: snapshot digest"
        );
        let need = &case["need"];
        assert_eq!(
            need["digest"],
            digest(
                "libre-ai.policy-need.v1",
                without(need, &["digest"]),
                Some("need")
            ),
            "{case_id}: need digest"
        );

        if let Some(error) = case.get("expectedError") {
            match error["code"].as_str().expect("error code") {
                "policy.tenant_mismatch" => saw_tenant_mismatch = true,
                "policy.rule_id_duplicate" => saw_duplicate_rule_id = true,
                code => panic!("unexpected schema-valid error vector: {code}"),
            }
            continue;
        }

        let evaluation = &case["expectedEvaluation"];
        let evaluation_digest = digest(
            "libre-ai.policy-evaluation.v1",
            without(evaluation, &["id", "digest"]),
            None,
        );
        assert_eq!(
            evaluation["digest"], evaluation_digest,
            "{case_id}: evaluation digest"
        );
        assert_eq!(
            evaluation["id"],
            format!("urn:libre-ai:evaluation:{evaluation_digest}"),
            "{case_id}: evaluation id"
        );

        let rule_ids = evaluation["ruleResults"]
            .as_array()
            .expect("rule results")
            .iter()
            .map(|result| result["ruleId"].as_str().expect("rule id"))
            .collect::<Vec<_>>();
        assert!(
            rule_ids.windows(2).all(|pair| pair[0] < pair[1]),
            "{case_id}: rule results are not strictly sorted"
        );
        if case_id.starts_with("order-independence-") {
            order_outputs.push(evaluation.clone());
        }
        if case_id == "fractional-number-jcs" {
            assert_eq!(case["snapshot"]["facts"][0]["value"], json!(0.000001));
            saw_fractional_number = true;
        }
    }

    assert!(saw_fractional_number);
    assert!(saw_tenant_mismatch);
    assert!(saw_invalid_duplicate);
    assert!(saw_duplicate_rule_id);
    assert_eq!(order_outputs.len(), 2);
    assert_eq!(order_outputs[0], order_outputs[1]);
}

#[test]
fn policy_core_operator_fixture_covers_the_closed_matrix() {
    let operators: Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/policy-core-v1/operators.json"
    ))
    .expect("policy-core operator vectors");
    assert_eq!(
        operators["schemaVersion"],
        "libre-ai.policy-core-operator-vectors.v1"
    );
    assert_eq!(operators["vectors"].as_array().expect("vectors").len(), 28);
    assert!(
        operators["aggregationVectors"]
            .as_array()
            .expect("aggregation vectors")
            .len()
            >= 5
    );
    assert!(
        operators["invalidPolicyVectors"]
            .as_array()
            .expect("invalid vectors")
            .len()
            >= 10
    );
}
