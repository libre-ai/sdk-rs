use libre_ai_contract_types::event_chain::{
    AcceptedEventCollision, OrchestratorCausalEventFacts, evaluate_orchestrator_event_chain,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Vectors {
    pair: Value,
    genesis: Value,
    cases: Vec<VectorCase>,
}

#[derive(Debug, Deserialize)]
struct VectorCase {
    id: String,
    scenario: String,
    mutations: Vec<Mutation>,
    collision: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct Mutation {
    target: String,
    path: String,
    value: Value,
}

fn set_path(target: &mut Value, path: &str, value: Value) {
    let mut segments = path.split('.').peekable();
    let mut cursor = target;
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            cursor
                .as_object_mut()
                .expect("mutation parent must be an object")
                .insert(segment.to_owned(), value);
            return;
        }
        cursor = cursor
            .as_object_mut()
            .and_then(|object| object.get_mut(segment))
            .expect("mutation path must exist");
    }
    panic!("mutation path cannot be empty");
}

fn collision(mode: &str, current: &OrchestratorCausalEventFacts) -> Option<AcceptedEventCollision> {
    match mode {
        "none" => None,
        "exact-current" => Some(AcceptedEventCollision {
            id: current.id.clone(),
            sequence: current.sequence,
            event_digest: current.event_digest.clone(),
        }),
        "same-id-different-digest" => Some(AcceptedEventCollision {
            id: current.id.clone(),
            sequence: current.sequence,
            event_digest: "b".repeat(64),
        }),
        "same-sequence-different-id" => Some(AcceptedEventCollision {
            id: "urn:libre-ai:event:collision".to_owned(),
            sequence: current.sequence,
            event_digest: "b".repeat(64),
        }),
        _ => panic!("unknown collision mode {mode}"),
    }
}

#[test]
fn rust_projection_matches_event_chain_vectors() {
    let document = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/fixtures/agent-orchestration-v1/event-chain-vectors.v1.json"
    ));
    let vectors: Vectors = serde_json::from_str(document).expect("event-chain vectors must parse");

    for case in vectors.cases {
        let mut scenario = match case.scenario.as_str() {
            "pair" => vectors.pair.clone(),
            "genesis" => vectors.genesis.clone(),
            scenario => panic!("unknown scenario {scenario}"),
        };
        for mutation in case.mutations {
            let target = scenario
                .as_object_mut()
                .and_then(|object| object.get_mut(&mutation.target))
                .expect("mutation target must exist");
            set_path(target, &mutation.path, mutation.value);
        }

        let object = scenario.as_object().expect("scenario must be an object");
        let previous: Option<OrchestratorCausalEventFacts> =
            serde_json::from_value(object.get("previous").expect("previous must exist").clone())
                .expect("previous event must parse");
        let current: OrchestratorCausalEventFacts =
            serde_json::from_value(object.get("current").expect("current must exist").clone())
                .expect("current event must parse");
        let collision = collision(&case.collision, &current);

        assert_eq!(
            evaluate_orchestrator_event_chain(previous.as_ref(), &current, collision.as_ref())
                .code(),
            case.expected,
            "{}",
            case.id
        );
    }
}
