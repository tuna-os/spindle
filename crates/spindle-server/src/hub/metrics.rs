//! Hub mode's counters on `/metrics` (#22).
//!
//! Every label is one of a fixed handful of words: no room, server or event
//! ever becomes a label, so the series count is the same on a server in
//! one hub room and in ten thousand (the cardinality rule of #166).

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// One counter: a family and the one label value it counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Counter {
    SubmissionPlaced,
    SubmissionStaleRetry,
    SubmissionFallback,
    SequencedAppended,
    SequencedStale,
    SequencedRefused,
    AttestationAccepted,
    AttestationDuplicate,
    AttestationRejected,
    ProofConflictingEntries,
    ProofBrokenChain,
    ProofTruncation,
    CheckpointSigned,
    CheckpointVerified,
    CheckpointStateMatched,
    CheckpointStateMismatch,
    CheckpointRejected,
    HandoffCosigned,
    HandoffCompleted,
    HandoffRefused,
    FailoverClaimed,
    FailoverAbandoned,
}

impl Counter {
    const ALL: [Self; 22] = [
        Self::SubmissionPlaced,
        Self::SubmissionStaleRetry,
        Self::SubmissionFallback,
        Self::SequencedAppended,
        Self::SequencedStale,
        Self::SequencedRefused,
        Self::AttestationAccepted,
        Self::AttestationDuplicate,
        Self::AttestationRejected,
        Self::ProofConflictingEntries,
        Self::ProofBrokenChain,
        Self::ProofTruncation,
        Self::CheckpointSigned,
        Self::CheckpointVerified,
        Self::CheckpointStateMatched,
        Self::CheckpointStateMismatch,
        Self::CheckpointRejected,
        Self::HandoffCosigned,
        Self::HandoffCompleted,
        Self::HandoffRefused,
        Self::FailoverClaimed,
        Self::FailoverAbandoned,
    ];

    /// `(family index into FAMILIES, label value)`.
    fn series(self) -> (usize, &'static str) {
        match self {
            Self::SubmissionPlaced => (0, "placed"),
            Self::SubmissionStaleRetry => (0, "stale_retry"),
            Self::SubmissionFallback => (0, "fallback"),
            Self::SequencedAppended => (1, "appended"),
            Self::SequencedStale => (1, "stale"),
            Self::SequencedRefused => (1, "refused"),
            Self::AttestationAccepted => (2, "accepted"),
            Self::AttestationDuplicate => (2, "duplicate"),
            Self::AttestationRejected => (2, "rejected"),
            Self::ProofConflictingEntries => (3, "conflicting_entries"),
            Self::ProofBrokenChain => (3, "broken_chain"),
            Self::ProofTruncation => (3, "truncation"),
            Self::CheckpointSigned => (4, "signed"),
            Self::CheckpointVerified => (4, "verified"),
            Self::CheckpointStateMatched => (4, "state_matched"),
            Self::CheckpointStateMismatch => (4, "state_mismatch"),
            Self::CheckpointRejected => (4, "rejected"),
            Self::HandoffCosigned => (5, "cosigned"),
            Self::HandoffCompleted => (5, "completed"),
            Self::HandoffRefused => (5, "refused"),
            Self::FailoverClaimed => (6, "claimed"),
            Self::FailoverAbandoned => (6, "abandoned"),
        }
    }

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|counter| *counter == self)
            .unwrap_or(0)
    }
}

/// `(name, help, label name)`, in the order [`Counter::series`] indexes.
const FAMILIES: [(&str, &str, &str); 7] = [
    (
        "spindle_hub_submissions_total",
        "As participant: events submitted to a room's hub, by outcome.",
        "result",
    ),
    (
        "spindle_hub_sequenced_total",
        "As hub: participant submissions, by what the hub did with them.",
        "result",
    ),
    (
        "spindle_hub_attestations_total",
        "As participant: hub attestations received, by verdict.",
        "result",
    ),
    (
        "spindle_hub_proofs_total",
        "Proofs recorded against a hub, by what they prove.",
        "kind",
    ),
    (
        "spindle_hub_checkpoints_total",
        "Hub checkpoints signed, and received by verdict.",
        "result",
    ),
    (
        "spindle_hub_handoffs_total",
        "Planned hub handoffs, by outcome.",
        "result",
    ),
    (
        "spindle_hub_failovers_total",
        "Failover claims this server made or gave up on.",
        "result",
    ),
];

/// Hub mode's counters, held in the server's one metrics registry.
#[derive(Debug, Default)]
pub struct HubMetrics {
    counters: [AtomicU64; Counter::ALL.len()],
}

/// A snapshot of hub mode's counters, for tests and the admin surface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HubCounts {
    /// As participant: events the hub placed.
    pub submitted: u64,
    /// As participant: rebuilds after a stale answer.
    pub stale_retries: u64,
    /// As participant: events sent the ordinary way instead.
    pub fallbacks: u64,
    /// As hub: participant events appended.
    pub sequenced: u64,
    /// As hub: submissions answered "stale head".
    pub stale_answers: u64,
    /// As participant: attestations verified and kept.
    pub attestations_accepted: u64,
    /// As participant: attestations refused (bad signature or shape).
    pub attestations_rejected: u64,
    /// Proofs recorded, of every kind.
    pub equivocations: u64,
    /// Of which: epochs refused for dropping an attested entry.
    pub truncations: u64,
    /// As hub: checkpoints signed.
    pub checkpoints_signed: u64,
    /// As participant: checkpoints whose signature verified.
    pub checkpoints_verified: u64,
    /// Checkpoints whose state root this server recomputed and matched.
    pub checkpoint_states_matched: u64,
    /// Checkpoints whose state root this server's own state contradicted.
    pub checkpoint_state_mismatches: u64,
    /// As outgoing hub: handoffs co-signed.
    pub handoffs_cosigned: u64,
    /// As incoming hub: handoffs completed.
    pub handoffs_completed: u64,
    /// Failover claims made.
    pub failovers: u64,
}

impl HubMetrics {
    pub(crate) fn bump(&self, counter: Counter) {
        self.counters[counter.index()].fetch_add(1, Ordering::Relaxed);
    }

    fn get(&self, counter: Counter) -> u64 {
        self.counters[counter.index()].load(Ordering::Relaxed)
    }

    /// The counters, now.
    #[must_use]
    pub fn counts(&self) -> HubCounts {
        HubCounts {
            submitted: self.get(Counter::SubmissionPlaced),
            stale_retries: self.get(Counter::SubmissionStaleRetry),
            fallbacks: self.get(Counter::SubmissionFallback),
            sequenced: self.get(Counter::SequencedAppended),
            stale_answers: self.get(Counter::SequencedStale),
            attestations_accepted: self.get(Counter::AttestationAccepted),
            attestations_rejected: self.get(Counter::AttestationRejected),
            equivocations: self.get(Counter::ProofConflictingEntries)
                + self.get(Counter::ProofBrokenChain)
                + self.get(Counter::ProofTruncation),
            truncations: self.get(Counter::ProofTruncation),
            checkpoints_signed: self.get(Counter::CheckpointSigned),
            checkpoints_verified: self.get(Counter::CheckpointVerified),
            checkpoint_states_matched: self.get(Counter::CheckpointStateMatched),
            checkpoint_state_mismatches: self.get(Counter::CheckpointStateMismatch),
            handoffs_cosigned: self.get(Counter::HandoffCosigned),
            handoffs_completed: self.get(Counter::HandoffCompleted),
            failovers: self.get(Counter::FailoverClaimed),
        }
    }

    /// The families, in the Prometheus text format; every series always
    /// present, at zero until counted.
    pub fn render(&self, out: &mut String) {
        for (family, (name, help, label)) in FAMILIES.iter().enumerate() {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
            for counter in Counter::ALL {
                let (owner, value) = counter.series();
                if owner == family {
                    let _ = writeln!(out, "{name}{{{label}=\"{value}\"}} {}", self.get(counter));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_counter_renders_under_one_family_with_a_fixed_label() {
        let metrics = HubMetrics::default();
        metrics.bump(Counter::ProofTruncation);
        let mut out = String::new();
        metrics.render(&mut out);
        assert!(
            out.contains("spindle_hub_proofs_total{kind=\"truncation\"} 1"),
            "{out}"
        );
        let series = out.lines().filter(|line| !line.starts_with('#')).count();
        assert_eq!(series, Counter::ALL.len());
        assert_eq!(metrics.counts().truncations, 1);
        assert_eq!(metrics.counts().equivocations, 1);
    }
}
