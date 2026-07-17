use libre_ai_contract_types::quorum::{
    AgentReviewFacts, AgentReviewQuorumFacts, evaluate_agent_review_quorum,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    evaluation_time: String,
    subject_digest: String,
    evidence_digests: Vec<String>,
    lineage_digest: String,
    lineage_subject_digest: String,
    lineage_signature_valid: bool,
    lineage_complete: bool,
    contributor_agent_ids: Vec<String>,
    diversity_requirements: Vec<String>,
    base_reviews: Vec<Value>,
    cases: Vec<VectorCase>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorCase {
    id: String,
    mutation: Option<Mutation>,
    root_mutation: Option<RootMutation>,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct RootMutation {
    field: String,
    value: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Mutation {
    review: usize,
    field: String,
    value: Option<Value>,
    copy_from_review: Option<usize>,
}

#[test]
fn agent_review_quorum_vectors_match_candidate_semantics() {
    let document = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/agent-orchestration-v1/quorum-vectors.v1.json"
    ));
    let vectors: Vectors = serde_json::from_str(document).expect("quorum vectors must parse");

    for case in vectors.cases {
        let mut reviews = vectors.base_reviews.clone();
        if let Some(mutation) = case.mutation {
            let value = if let Some(source) = mutation.copy_from_review {
                reviews
                    .get(source)
                    .and_then(Value::as_object)
                    .and_then(|object| object.get(&mutation.field))
                    .cloned()
                    .expect("copy mutation source must exist")
            } else {
                mutation.value.expect("literal mutation must contain value")
            };
            reviews
                .get_mut(mutation.review)
                .and_then(Value::as_object_mut)
                .expect("mutation target review must exist")
                .insert(mutation.field, value);
        }

        let reviews: Vec<AgentReviewFacts> = reviews
            .into_iter()
            .map(|review| serde_json::from_value(review).expect("review vector must parse"))
            .collect();
        let mut facts = AgentReviewQuorumFacts {
            evaluation_time: vectors.evaluation_time.clone(),
            subject_digest: vectors.subject_digest.clone(),
            evidence_digests: vectors.evidence_digests.clone(),
            lineage_digest: vectors.lineage_digest.clone(),
            lineage_subject_digest: vectors.lineage_subject_digest.clone(),
            lineage_signature_valid: vectors.lineage_signature_valid,
            lineage_complete: vectors.lineage_complete,
            contributor_agent_ids: vectors.contributor_agent_ids.clone(),
            diversity_requirements: vectors.diversity_requirements.clone(),
            reviews,
        };
        if let Some(mutation) = case.root_mutation {
            match mutation.field.as_str() {
                "lineageSignatureValid" => {
                    facts.lineage_signature_valid =
                        mutation.value.as_bool().expect("boolean mutation")
                }
                "lineageComplete" => {
                    facts.lineage_complete = mutation.value.as_bool().expect("boolean mutation")
                }
                "lineageSubjectDigest" => {
                    facts.lineage_subject_digest = mutation
                        .value
                        .as_str()
                        .expect("lineage subject mutation")
                        .to_owned()
                }
                "diversityRequirements" => {
                    facts.diversity_requirements =
                        serde_json::from_value(mutation.value).expect("diversity mutation")
                }
                field => panic!("unsupported root mutation {field}"),
            }
        }

        assert_eq!(
            evaluate_agent_review_quorum(&facts).code(),
            case.expected,
            "vector {}",
            case.id
        );
    }
}
