use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrchestratorBudgetCounters {
    pub duration_seconds: u64,
    pub tool_calls: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub processes_started: u64,
    pub files_changed: u64,
    pub changed_bytes: u64,
}

impl OrchestratorBudgetCounters {
    fn values(&self) -> [u64; 7] {
        [
            self.duration_seconds,
            self.tool_calls,
            self.input_tokens,
            self.output_tokens,
            self.processes_started,
            self.files_changed,
            self.changed_bytes,
        ]
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrchestratorCausalEventFacts {
    pub id: String,
    pub event_digest: String,
    pub tenant_id: String,
    pub mission_id: String,
    pub run_id: String,
    pub orchestrator_id: String,
    pub plan_digest: String,
    pub authorization_digest: String,
    pub sequence: u64,
    pub previous_event_digest: Option<String>,
    pub attempt: u64,
    pub budget_delta: OrchestratorBudgetCounters,
    pub budget_total: OrchestratorBudgetCounters,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptedEventCollision {
    pub id: String,
    pub sequence: u64,
    pub event_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestratorEventChainResult {
    Valid,
    IdempotentDuplicate,
    DuplicateDivergent,
    GenesisInvalid,
    IdentityMismatch,
    SequenceInvalid,
    PreviousDigestMismatch,
    AttemptDecreased,
    BudgetDecreased,
    BudgetArithmeticInvalid,
}

impl OrchestratorEventChainResult {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::IdempotentDuplicate => "idempotent-duplicate",
            Self::DuplicateDivergent => "duplicate-divergent",
            Self::GenesisInvalid => "genesis-invalid",
            Self::IdentityMismatch => "identity-mismatch",
            Self::SequenceInvalid => "sequence-invalid",
            Self::PreviousDigestMismatch => "previous-digest-mismatch",
            Self::AttemptDecreased => "attempt-decreased",
            Self::BudgetDecreased => "budget-decreased",
            Self::BudgetArithmeticInvalid => "budget-arithmetic-invalid",
        }
    }
}

fn same_run_authority(
    previous: &OrchestratorCausalEventFacts,
    current: &OrchestratorCausalEventFacts,
) -> bool {
    previous.tenant_id == current.tenant_id
        && previous.mission_id == current.mission_id
        && previous.run_id == current.run_id
        && previous.orchestrator_id == current.orchestrator_id
        && previous.plan_digest == current.plan_digest
        && previous.authorization_digest == current.authorization_digest
}

/// Evaluates one schema-validated event against accepted causal state without logging values.
#[must_use]
pub fn evaluate_orchestrator_event_chain(
    previous: Option<&OrchestratorCausalEventFacts>,
    current: &OrchestratorCausalEventFacts,
    collision: Option<&AcceptedEventCollision>,
) -> OrchestratorEventChainResult {
    use OrchestratorEventChainResult as Result;

    if let Some(collision) = collision {
        let same_id = current.id == collision.id;
        let same_sequence = current.sequence == collision.sequence;
        if same_id && same_sequence && current.event_digest == collision.event_digest {
            return Result::IdempotentDuplicate;
        }
        if same_id || same_sequence {
            return Result::DuplicateDivergent;
        }
    }

    let Some(previous) = previous else {
        if current.sequence != 1 || current.previous_event_digest.is_some() {
            return Result::GenesisInvalid;
        }
        if current.budget_total.values() != current.budget_delta.values() {
            return Result::BudgetArithmeticInvalid;
        }
        return Result::Valid;
    };

    if !same_run_authority(previous, current) {
        return Result::IdentityMismatch;
    }
    if current.sequence != previous.sequence + 1 {
        return Result::SequenceInvalid;
    }
    if current.previous_event_digest.as_deref() != Some(previous.event_digest.as_str()) {
        return Result::PreviousDigestMismatch;
    }
    if current.attempt < previous.attempt {
        return Result::AttemptDecreased;
    }

    for ((previous, delta), total) in previous
        .budget_total
        .values()
        .into_iter()
        .zip(current.budget_delta.values())
        .zip(current.budget_total.values())
    {
        if total < previous {
            return Result::BudgetDecreased;
        }
        if previous.checked_add(delta) != Some(total) {
            return Result::BudgetArithmeticInvalid;
        }
    }

    Result::Valid
}
