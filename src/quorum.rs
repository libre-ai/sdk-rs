use chrono::DateTime;
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentReviewFacts {
    pub reviewer_agent_id: String,
    pub reviewer_run_id: String,
    pub reviewer_pool_id: String,
    pub runtime_family: String,
    pub model_family: String,
    pub provider_id: String,
    pub subject_digest: String,
    pub evidence_digests: Vec<String>,
    pub lineage_digest: String,
    pub contributor_agent_ids: Vec<String>,
    pub verdict: String,
    pub blind_review: bool,
    pub sibling_review_disclosed: bool,
    pub reviewer_identity_attested: bool,
    pub isolation_attested: bool,
    pub non_disclosure_attested: bool,
    pub signing_key_active: bool,
    pub signature_valid: bool,
    pub nonce_claimed: bool,
    pub nonce: String,
    pub signature: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
pub struct AgentReviewQuorumFacts {
    pub evaluation_time: String,
    pub subject_digest: String,
    pub evidence_digests: Vec<String>,
    pub lineage_digest: String,
    pub lineage_subject_digest: String,
    pub lineage_signature_valid: bool,
    pub lineage_complete: bool,
    pub contributor_agent_ids: Vec<String>,
    pub diversity_requirements: Vec<String>,
    pub reviews: Vec<AgentReviewFacts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentReviewQuorumResult {
    Valid,
    ReviewCountInvalid,
    ReviewRejected,
    LineageInvalid,
    ReviewerIdentityInvalid,
    ReviewIsolationInvalid,
    NonDisclosureInvalid,
    SigningKeyInvalid,
    ReviewerIsContributor,
    DuplicateReviewer,
    DuplicateReviewRun,
    DuplicateNonce,
    DuplicateSignature,
    DiversityRequirementViolated,
    SubjectMismatch,
    EvidenceMismatch,
    LineageMismatch,
    LineageSubjectMismatch,
    LineageContributorsMismatch,
    SignatureInvalid,
    NonceReplayed,
    BlindReviewViolated,
    ReviewExpired,
    ReviewTimeInvalid,
}

impl AgentReviewQuorumResult {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ReviewCountInvalid => "review-count-invalid",
            Self::ReviewRejected => "review-rejected",
            Self::LineageInvalid => "lineage-invalid",
            Self::ReviewerIdentityInvalid => "reviewer-identity-invalid",
            Self::ReviewIsolationInvalid => "review-isolation-invalid",
            Self::NonDisclosureInvalid => "non-disclosure-invalid",
            Self::SigningKeyInvalid => "signing-key-invalid",
            Self::ReviewerIsContributor => "reviewer-is-contributor",
            Self::DuplicateReviewer => "duplicate-reviewer",
            Self::DuplicateReviewRun => "duplicate-review-run",
            Self::DuplicateNonce => "duplicate-nonce",
            Self::DuplicateSignature => "duplicate-signature",
            Self::DiversityRequirementViolated => "diversity-requirement-violated",
            Self::SubjectMismatch => "subject-mismatch",
            Self::EvidenceMismatch => "evidence-mismatch",
            Self::LineageMismatch => "lineage-mismatch",
            Self::LineageSubjectMismatch => "lineage-subject-mismatch",
            Self::LineageContributorsMismatch => "lineage-contributors-mismatch",
            Self::SignatureInvalid => "signature-invalid",
            Self::NonceReplayed => "nonce-replayed",
            Self::BlindReviewViolated => "blind-review-violated",
            Self::ReviewExpired => "review-expired",
            Self::ReviewTimeInvalid => "review-time-invalid",
        }
    }
}

fn same_string_set(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

fn has_duplicate<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = HashSet::new();
    values.any(|value| !seen.insert(value))
}

/// Evaluates authenticated facts. Signature verification and atomic nonce claiming are mandatory
/// boundary operations represented here by their fail-closed boolean outcomes.
#[must_use]
pub fn evaluate_agent_review_quorum(facts: &AgentReviewQuorumFacts) -> AgentReviewQuorumResult {
    use AgentReviewQuorumResult as Result;

    if facts.reviews.len() != 2 {
        return Result::ReviewCountInvalid;
    }

    let Ok(evaluation_time) = DateTime::parse_from_rfc3339(&facts.evaluation_time) else {
        return Result::ReviewTimeInvalid;
    };
    if !facts.lineage_signature_valid || !facts.lineage_complete {
        return Result::LineageInvalid;
    }
    if facts.lineage_subject_digest != facts.subject_digest {
        return Result::LineageSubjectMismatch;
    }

    for review in &facts.reviews {
        if review.verdict != "approve" {
            return Result::ReviewRejected;
        }
        if !review.reviewer_identity_attested {
            return Result::ReviewerIdentityInvalid;
        }
        if !review.isolation_attested {
            return Result::ReviewIsolationInvalid;
        }
        if !review.non_disclosure_attested {
            return Result::NonDisclosureInvalid;
        }
        if !review.signing_key_active {
            return Result::SigningKeyInvalid;
        }
        if facts
            .contributor_agent_ids
            .contains(&review.reviewer_agent_id)
        {
            return Result::ReviewerIsContributor;
        }
        if review.subject_digest != facts.subject_digest {
            return Result::SubjectMismatch;
        }
        if !same_string_set(&review.evidence_digests, &facts.evidence_digests) {
            return Result::EvidenceMismatch;
        }
        if review.lineage_digest != facts.lineage_digest {
            return Result::LineageMismatch;
        }
        if !same_string_set(&review.contributor_agent_ids, &facts.contributor_agent_ids) {
            return Result::LineageContributorsMismatch;
        }
        if !review.blind_review || review.sibling_review_disclosed {
            return Result::BlindReviewViolated;
        }
        if !review.signature_valid {
            return Result::SignatureInvalid;
        }
        if !review.nonce_claimed {
            return Result::NonceReplayed;
        }

        let (Ok(issued_at), Ok(expires_at)) = (
            DateTime::parse_from_rfc3339(&review.issued_at),
            DateTime::parse_from_rfc3339(&review.expires_at),
        ) else {
            return Result::ReviewTimeInvalid;
        };
        if issued_at >= expires_at {
            return Result::ReviewTimeInvalid;
        }
        if evaluation_time < issued_at {
            return Result::ReviewTimeInvalid;
        }
        if evaluation_time >= expires_at {
            return Result::ReviewExpired;
        }
    }

    if has_duplicate(
        facts
            .reviews
            .iter()
            .map(|review| review.reviewer_agent_id.as_str()),
    ) {
        return Result::DuplicateReviewer;
    }
    if has_duplicate(
        facts
            .reviews
            .iter()
            .map(|review| review.reviewer_run_id.as_str()),
    ) {
        return Result::DuplicateReviewRun;
    }
    if has_duplicate(facts.reviews.iter().map(|review| review.nonce.as_str())) {
        return Result::DuplicateNonce;
    }
    if has_duplicate(facts.reviews.iter().map(|review| review.signature.as_str())) {
        return Result::DuplicateSignature;
    }

    for requirement in &facts.diversity_requirements {
        let duplicate = match requirement.as_str() {
            "reviewer-pool" => has_duplicate(
                facts
                    .reviews
                    .iter()
                    .map(|review| review.reviewer_pool_id.as_str()),
            ),
            "runtime-family" => has_duplicate(
                facts
                    .reviews
                    .iter()
                    .map(|review| review.runtime_family.as_str()),
            ),
            "model-family" => has_duplicate(
                facts
                    .reviews
                    .iter()
                    .map(|review| review.model_family.as_str()),
            ),
            "provider" => has_duplicate(
                facts
                    .reviews
                    .iter()
                    .map(|review| review.provider_id.as_str()),
            ),
            _ => return Result::DiversityRequirementViolated,
        };
        if duplicate {
            return Result::DiversityRequirementViolated;
        }
    }

    Result::Valid
}
