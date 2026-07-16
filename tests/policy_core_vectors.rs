use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt::{self, Write as _};
use std::fs;

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

struct StrictJsonSeed;

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.is_finite() {
            Ok(())
        } else {
            Err(E::custom("non-finite JSON number"))
        }
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(StrictJsonSeed)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("duplicate JSON object member"));
            }
            object.next_value_seed(StrictJsonSeed)?;
        }
        Ok(())
    }
}

fn decode_strict_json(bytes: &[u8]) -> Result<(), String> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err("UTF-8 BOM is forbidden".to_owned());
    }
    let input = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let mut deserializer = serde_json::Deserializer::from_str(input);
    StrictJsonSeed
        .deserialize(&mut deserializer)
        .map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}").expect("write to string");
    }
    encoded
}

#[test]
fn policy_core_raw_inputs_are_rejected_before_schema_validation() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/policy-core-invalid-json/manifest.json"
    ))
    .expect("policy-core raw input manifest");
    assert_eq!(
        manifest["schemaVersion"],
        "libre-ai.policy-core-raw-input-vectors.v1"
    );
    let cases = manifest["cases"].as_array().expect("raw input cases");
    assert_eq!(cases.len(), 9);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures/policy-core-invalid-json");
    let mut ids = HashSet::new();
    let mut defects = HashSet::new();

    for case in cases {
        let id = case["id"].as_str().expect("raw input id");
        assert!(ids.insert(id), "duplicate raw input id: {id}");
        let file = case["file"].as_str().expect("raw input file");
        assert!(
            file.ends_with(".bin")
                && file.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || b"-.".contains(&byte)),
            "unsafe raw input file name: {file}"
        );
        let bytes = fs::read(root.join(file)).expect("raw input bytes");
        assert_eq!(
            bytes.len() as u64,
            case["byteLength"].as_u64().expect("raw byte length"),
            "{id}: byte length"
        );
        assert_eq!(
            sha256_hex(&bytes),
            case["inputSha256"].as_str().expect("raw input digest"),
            "{id}: SHA-256"
        );

        let defect = case["defect"].as_str().expect("raw input defect");
        defects.insert(defect);
        let strict_error = decode_strict_json(&bytes).expect_err("forbidden input accepted");
        match defect {
            "bom" => assert!(bytes.starts_with(&[0xef, 0xbb, 0xbf])),
            "invalid-utf8" => assert!(std::str::from_utf8(&bytes).is_err()),
            "duplicate-member" => {
                assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
                assert!(strict_error.contains("duplicate JSON object member"));
            }
            "unpaired-surrogate" | "invalid-number" => {
                assert!(serde_json::from_slice::<Value>(&bytes).is_err());
            }
            other => panic!("unknown raw input defect: {other}"),
        }

        for (major, message) in [
            ("policy-core-v1", "input does not conform to policy-core-v1"),
            ("policy-core-v2", "input does not conform to policy-core-v2"),
        ] {
            let expected = &case["expectedErrors"][major];
            assert_eq!(expected["code"], "policy.input_invalid", "{id}: {major}");
            assert_eq!(expected["message"], message, "{id}: {major}");
        }
    }

    assert_eq!(
        defects,
        HashSet::from([
            "bom",
            "invalid-utf8",
            "duplicate-member",
            "unpaired-surrogate",
            "invalid-number",
        ])
    );
    decode_strict_json(
        br#"{"key":1,"\u006bEy":2,"value":"\uD834\uDD1E","numbers":[0,-1.25,1e+20]}"#,
    )
    .expect("valid strict JSON control");
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
fn policy_core_v2_golden_hashes_are_portable_and_enforce_approval_separation() {
    let golden: Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/policy-core-v2/golden.json"
    ))
    .expect("policy-core v2 golden vectors");
    assert_eq!(
        golden["schemaVersion"],
        "libre-ai.policy-core-golden-vectors.v2"
    );
    assert_eq!(golden["engineVersion"], "2.0.0");

    let cases = golden["cases"].as_array().expect("golden cases");
    assert_eq!(cases.len(), 18);
    let mut order_outputs = Vec::new();
    let mut saw_fractional_number = false;
    let mut saw_tenant_mismatch = false;
    let mut saw_invalid_duplicate = false;
    let mut saw_duplicate_rule_id = false;
    let mut saw_self_approval = false;

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
            "proposedBy": policy["proposedBy"],
            "rules": policy["rules"],
        });
        let policy_digest = digest(
            "libre-ai.policy-definition.v2",
            policy_subject,
            Some("policy"),
        );
        assert_eq!(policy["digest"], policy_digest, "{case_id}: policy digest");
        assert_eq!(
            policy["approval"]["subjectDigest"], policy_digest,
            "{case_id}: approval subject digest"
        );
        let self_approval = policy["approval"]["approverId"] == policy["proposedBy"];

        let snapshot = &case["snapshot"];
        assert_eq!(
            snapshot["digest"],
            digest(
                "libre-ai.model-snapshot.v2",
                without(snapshot, &["digest"]),
                Some("snapshot")
            ),
            "{case_id}: snapshot digest"
        );
        let need = &case["need"];
        assert_eq!(
            need["digest"],
            digest(
                "libre-ai.policy-need.v2",
                without(need, &["digest"]),
                Some("need")
            ),
            "{case_id}: need digest"
        );

        if let Some(error) = case.get("expectedError") {
            match error["code"].as_str().expect("error code") {
                "policy.tenant_mismatch" => saw_tenant_mismatch = true,
                "policy.rule_id_duplicate" => saw_duplicate_rule_id = true,
                "policy.approval_invalid" => {
                    assert!(
                        self_approval,
                        "approval error must demonstrate self-approval"
                    );
                    saw_self_approval = true;
                }
                code => panic!("unexpected schema-valid v2 error vector: {code}"),
            }
            continue;
        }
        assert!(!self_approval, "{case_id}: successful input self-approves");

        let evaluation = &case["expectedEvaluation"];
        let evaluation_digest = digest(
            "libre-ai.policy-evaluation.v2",
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
    assert!(saw_self_approval);
    assert_eq!(order_outputs.len(), 2);
    assert_eq!(order_outputs[0], order_outputs[1]);
}

#[test]
fn policy_core_v2_resource_budgets_match_schema_maxima() {
    let budgets: Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/policy-core-v2/resource-budgets.v1.json"
    ))
    .expect("policy-core v2 resource budgets");
    assert_eq!(
        budgets["schemaVersion"],
        "libre-ai.policy-core-resource-budgets.v1"
    );
    assert_eq!(budgets["status"], "candidate-preimplementation");

    let bytes = &budgets["byteLimits"];
    let policy_bytes = bytes["policyInput"].as_u64().expect("policy bytes");
    let snapshot_bytes = bytes["snapshotInput"].as_u64().expect("snapshot bytes");
    let need_bytes = bytes["needInput"].as_u64().expect("need bytes");
    assert_eq!(policy_bytes, 8 * 1024 * 1024);
    assert_eq!(snapshot_bytes, 8 * 1024 * 1024);
    assert_eq!(need_bytes, 8 * 1024 * 1024);
    assert_eq!(
        bytes["totalJsonInput"].as_u64(),
        Some(policy_bytes + snapshot_bytes + need_bytes)
    );
    assert_eq!(bytes["evaluatedAt"], 64);
    assert_eq!(bytes["successfulOutput"], 2 * 1024 * 1024);

    let cardinality = &budgets["cardinalityLimits"];
    let rules = cardinality["rules"].as_u64().expect("rules");
    let model_facts = cardinality["modelFacts"].as_u64().expect("model facts");
    let need_facts = cardinality["needFacts"].as_u64().expect("need facts");
    let set_members = cardinality["setMembersPerRule"]
        .as_u64()
        .expect("set members");
    let policy_schema: Value = serde_json::from_str(include_str!(
        "../../../contracts/schemas/policy-definition.v2.schema.json"
    ))
    .expect("policy schema");
    let snapshot_schema: Value = serde_json::from_str(include_str!(
        "../../../contracts/schemas/model-snapshot.v2.schema.json"
    ))
    .expect("snapshot schema");
    let need_schema: Value = serde_json::from_str(include_str!(
        "../../../contracts/schemas/policy-need.v2.schema.json"
    ))
    .expect("need schema");
    assert_eq!(policy_schema["properties"]["rules"]["maxItems"], rules);
    assert_eq!(
        snapshot_schema["properties"]["facts"]["maxItems"],
        model_facts
    );
    assert_eq!(need_schema["properties"]["facts"]["maxItems"], need_facts);
    let schema_set_members = policy_schema["$defs"]["factSet"]["oneOf"]
        .as_array()
        .expect("fact set variants")
        .iter()
        .filter_map(|variant| variant["maxItems"].as_u64())
        .max()
        .expect("fact set maximum");
    assert_eq!(set_members, schema_set_members);
    assert_eq!(cardinality["setMembersAcrossPolicy"], rules * set_members);

    let matched_pairs = rules * model_facts.max(need_facts);
    let comparisons_per_lookup = u64::from(set_members.ilog2() + 1);
    let cpu = &budgets["cpuQualification"];
    assert_eq!(cpu["ruleOccurrenceEvaluations"], matched_pairs);
    assert_eq!(cpu["setMemberComparisonsPerLookup"], comparisons_per_lookup);
    assert_eq!(
        cpu["setMemberComparisons"],
        matched_pairs * comparisons_per_lookup
    );
    assert_eq!(
        cpu["setLookup"],
        "sorted-binary-search-or-equivalent-bounded-lookup"
    );
    assert_eq!(cpu["duplicateDetection"], "canonical-hash-or-ordered-index");
    assert!(cpu["wallClockLimit"].is_null());
    assert_eq!(
        budgets["memoryQualification"]["peakComponentLinearMemoryBytes"],
        256 * 1024 * 1024
    );
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

    let operators_v2: Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/policy-core-v2/operators.json"
    ))
    .expect("policy-core v2 operator vectors");
    assert_eq!(
        operators_v2["schemaVersion"],
        "libre-ai.policy-core-operator-vectors.v2"
    );
    assert_eq!(
        operators_v2["vectors"].as_array().expect("vectors").len(),
        28
    );
}
