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

#[derive(Clone, Copy)]
struct StrictJsonSeed {
    depth: usize,
    maximum_depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > self.maximum_depth {
            return Err(D::Error::custom("maximum JSON depth exceeded"));
        }
        deserializer.deserialize_any(StrictJsonVisitor {
            depth: self.depth,
            maximum_depth: self.maximum_depth,
        })
    }
}

struct StrictJsonVisitor {
    depth: usize,
    maximum_depth: usize,
}

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
        let nested = StrictJsonSeed {
            depth: self.depth + 1,
            maximum_depth: self.maximum_depth,
        };
        while sequence.next_element_seed(nested)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let nested = StrictJsonSeed {
            depth: self.depth + 1,
            maximum_depth: self.maximum_depth,
        };
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("duplicate JSON object member"));
            }
            object.next_value_seed(nested)?;
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
    StrictJsonSeed {
        depth: 0,
        maximum_depth: 64,
    }
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

        let v1_error = &case["expectedErrors"]["policy-core-v1"];
        assert_eq!(v1_error.as_object().expect("v1 error").len(), 2, "{id}: v1");
        assert_eq!(v1_error["code"], "policy.input_invalid", "{id}: v1");
        assert_eq!(
            v1_error["message"], "input does not conform to policy-core-v1",
            "{id}: v1"
        );
        let v2_error = &case["expectedErrors"]["policy-core-v2"];
        assert_eq!(v2_error.as_object().expect("v2 error").len(), 1, "{id}: v2");
        assert_eq!(v2_error["variant"], "input-invalid", "{id}: v2");
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
    assert_eq!(cases.len(), 20);
    let mut order_outputs = Vec::new();
    let mut error_variants = HashSet::new();
    let mut saw_fractional_number = false;
    let mut saw_tenant_mismatch = false;
    let mut saw_invalid_duplicate = false;
    let mut saw_duplicate_rule_id = false;
    let mut saw_evaluated_at_invalid = false;
    let mut saw_digest_mismatch = false;
    let mut saw_self_approval = false;

    for case in cases {
        let case_id = case["id"].as_str().expect("case id");
        let error_variant = case
            .get("expectedError")
            .map(|error| error["variant"].as_str().expect("WIT error variant"));
        if let Some(variant) = error_variant {
            error_variants.insert(variant);
        }
        if case_id == "duplicate-exact-fact" {
            assert_eq!(error_variant, Some("input-invalid"));
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
        let policy_digest_valid = policy["digest"] == policy_digest
            && policy["approval"]["subjectDigest"] == policy_digest;
        let self_approval = policy["approval"]["approverId"] == policy["proposedBy"];
        let policy_rule_ids = policy["rules"]
            .as_array()
            .expect("policy rules")
            .iter()
            .map(|rule| rule["id"].as_str().expect("rule id"))
            .collect::<Vec<_>>();
        let duplicate_rule_id =
            policy_rule_ids.iter().collect::<HashSet<_>>().len() != policy_rule_ids.len();
        let tenants_match = policy["tenantId"] == case["snapshot"]["tenantId"]
            && policy["tenantId"] == case["need"]["tenantId"];

        let snapshot = &case["snapshot"];
        let snapshot_digest_valid = snapshot["digest"]
            == digest(
                "libre-ai.model-snapshot.v2",
                without(snapshot, &["digest"]),
                Some("snapshot"),
            );
        let need = &case["need"];
        let need_digest_valid = need["digest"]
            == digest(
                "libre-ai.policy-need.v2",
                without(need, &["digest"]),
                Some("need"),
            );
        let all_digests_valid = policy_digest_valid && snapshot_digest_valid && need_digest_valid;
        assert_eq!(
            all_digests_valid,
            error_variant != Some("digest-mismatch"),
            "{case_id}: digest condition"
        );
        assert_eq!(
            duplicate_rule_id,
            error_variant == Some("rule-id-duplicate"),
            "{case_id}: duplicate rule condition"
        );
        assert_eq!(
            self_approval,
            error_variant == Some("approval-invalid"),
            "{case_id}: approval separation condition"
        );
        assert_eq!(
            tenants_match,
            error_variant != Some("tenant-mismatch"),
            "{case_id}: tenant condition"
        );
        let evaluated_at_valid = chrono::NaiveDateTime::parse_from_str(
            case["evaluatedAt"].as_str().expect("evaluatedAt"),
            "%Y-%m-%dT%H:%M:%SZ",
        )
        .is_ok();
        assert_eq!(
            evaluated_at_valid,
            error_variant != Some("evaluated-at-invalid"),
            "{case_id}: evaluatedAt condition"
        );

        if let Some(variant) = error_variant {
            match variant {
                "tenant-mismatch" => saw_tenant_mismatch = true,
                "rule-id-duplicate" => saw_duplicate_rule_id = true,
                "evaluated-at-invalid" => saw_evaluated_at_invalid = true,
                "digest-mismatch" => saw_digest_mismatch = true,
                "approval-invalid" => saw_self_approval = true,
                other => panic!("unexpected schema-valid v2 error vector: {other}"),
            }
            continue;
        }

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
    assert!(saw_evaluated_at_invalid);
    assert!(saw_digest_mismatch);
    assert!(saw_self_approval);
    assert_eq!(
        error_variants,
        HashSet::from([
            "input-invalid",
            "evaluated-at-invalid",
            "rule-id-duplicate",
            "approval-invalid",
            "digest-mismatch",
            "tenant-mismatch",
        ])
    );
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

    let boundary_cases = budgets["byteBoundaryCases"]
        .as_array()
        .expect("byte boundary cases");
    assert_eq!(boundary_cases.len(), 10);
    let mut boundary_ids = HashSet::new();
    for case in boundary_cases {
        let id = case["id"].as_str().expect("boundary id");
        assert!(boundary_ids.insert(id), "duplicate boundary id: {id}");
        let (target, limit, expected) = match id {
            "policy-at-limit" => ("policyInput", policy_bytes, "within-limit"),
            "policy-over-limit" => ("policyInput", policy_bytes + 1, "input-invalid"),
            "snapshot-at-limit" => ("snapshotInput", snapshot_bytes, "within-limit"),
            "snapshot-over-limit" => ("snapshotInput", snapshot_bytes + 1, "input-invalid"),
            "need-at-limit" => ("needInput", need_bytes, "within-limit"),
            "need-over-limit" => ("needInput", need_bytes + 1, "input-invalid"),
            "evaluated-at-at-limit" => ("evaluatedAt", 64, "within-limit"),
            "evaluated-at-over-limit" => ("evaluatedAt", 65, "input-invalid"),
            "output-at-limit" => ("successfulOutput", 2 * 1024 * 1024, "within-limit"),
            "output-over-limit" => ("successfulOutput", 2 * 1024 * 1024 + 1, "input-invalid"),
            other => panic!("unknown boundary id: {other}"),
        };
        assert_eq!(case["target"], target, "{id}: target");
        assert_eq!(case["byteLength"], limit, "{id}: byte length");
        let generated = vec![0_u8; usize::try_from(limit).expect("boundary fits usize")];
        let target_limit = bytes[target].as_u64().expect("target byte limit");
        let actual = if generated.len() as u64 > target_limit {
            "input-invalid"
        } else {
            "within-limit"
        };
        assert_eq!(actual, expected, "{id}: preflight");
        if expected == "input-invalid" {
            assert_eq!(case["expectedError"], expected, "{id}: expected error");
        } else {
            assert_eq!(
                case["expectedPreflight"], expected,
                "{id}: expected preflight"
            );
        }
    }

    let maximum_depth = budgets["decoderQualification"]["maximumJsonDepth"]
        .as_u64()
        .expect("maximum JSON depth");
    assert_eq!(maximum_depth, 64);
    let nested_json =
        |depth: usize| format!("{}0{}", "[".repeat(depth), "]".repeat(depth)).into_bytes();
    decode_strict_json(&nested_json(maximum_depth as usize)).expect("exact JSON depth");
    let depth_error = decode_strict_json(&nested_json(maximum_depth as usize + 1))
        .expect_err("excessive JSON depth accepted");
    assert!(depth_error.contains("maximum JSON depth exceeded"));

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
