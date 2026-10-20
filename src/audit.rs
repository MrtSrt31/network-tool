//! Tamper-evident hash chain over the engagement's `action_log`.
//!
//! Each `ActionRun` carries two derived fields: `prev_hash` (the hash of the
//! previous entry, or the engagement-specific genesis string for the first
//! entry) and `hash` (SHA-256 over `prev_hash` concatenated with a canonical
//! encoding of this entry's content fields). A single flipped character
//! anywhere in the chain breaks every subsequent hash, so hand-editing the
//! JSON file is detectable.
//!
//! The chain is a *log-integrity* mechanism, not a replacement for signatures
//! or notarisation — a determined operator can always re-seal their own
//! chain. It raises the bar: evidence can be shown to be unchanged *since
//! the operator wrote it*, which is what matters for an audit trail.
//!
//! Workflow:
//! - [`seal_new_action`] stamps a new entry with its `prev_hash` and `hash`
//!   just before it is pushed into `engagement.action_log`.
//! - [`verify_action_log`] walks the chain from genesis and reports the first
//!   broken entry, if any.
//! - [`chain_head`] returns the current head hash — used in the report and
//!   RoE footer so the delivered documents commit to a specific log state.
//! - [`reseal_chain`] rebuilds the hashes for a legacy log that pre-dates
//!   this feature (every pre-existing `ActionRun` has empty `prev_hash` and
//!   `hash`). Called transparently on save when needed.

use crate::model::{ActionRun, Engagement};
use sha2::{Digest, Sha256};

const GENESIS_PREFIX: &str = "ntool-engagement-";

/// Genesis string for an engagement's chain. Includes the engagement id so
/// moving an action between engagements breaks the chain.
pub fn genesis(engagement_id: &str) -> String {
    format!("{GENESIS_PREFIX}{engagement_id}")
}

/// Compute the hash for an entry given its predecessor's hash. The entry's
/// own `prev_hash` and `hash` fields are **not** inputs — only the content.
pub fn compute_hash(prev_hash: &str, a: &ActionRun) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(b"\0");
    h.update(a.id.as_bytes());
    h.update(b"\0");
    h.update(a.at.to_rfc3339().as_bytes());
    h.update(b"\0");
    h.update(a.module_id.as_bytes());
    h.update(b"\0");
    h.update(a.module_name.as_bytes());
    h.update(b"\0");
    h.update(a.target.as_bytes());
    h.update(b"\0");
    h.update(a.command.as_bytes());
    h.update(b"\0");
    h.update([
        u8::from(a.disruptive),
        u8::from(a.dry_run),
        u8::from(a.timed_out),
    ]);
    h.update(b"\0");
    match a.exit_code {
        Some(c) => {
            h.update(b"S");
            h.update(c.to_le_bytes());
        }
        None => h.update(b"N"),
    }
    h.update(b"\0");
    h.update(a.summary.as_bytes());
    h.update(b"\0");
    h.update(a.operator.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The current hash chain head: the last action's `hash`, or the genesis
/// string if the log is empty.
pub fn chain_head(e: &Engagement) -> String {
    match e.action_log.last() {
        Some(a) if !a.hash.is_empty() => a.hash.clone(),
        _ => genesis(&e.id),
    }
}

/// Stamp a freshly-constructed action with its `prev_hash` and `hash`, ready
/// to be pushed into the engagement's log.
pub fn seal_new_action(e: &Engagement, mut a: ActionRun) -> ActionRun {
    a.prev_hash = chain_head(e);
    a.hash = compute_hash(&a.prev_hash, &a);
    a
}

/// First place where the chain is broken, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditBreak {
    pub index: usize,
    pub reason: String,
}

/// Walk the chain from genesis and verify every link.
pub fn verify_action_log(e: &Engagement) -> Result<(), AuditBreak> {
    let mut prev = genesis(&e.id);
    for (i, a) in e.action_log.iter().enumerate() {
        if a.prev_hash.is_empty() || a.hash.is_empty() {
            return Err(AuditBreak {
                index: i,
                reason: "entry has empty prev_hash or hash (legacy or tampered)".into(),
            });
        }
        if a.prev_hash != prev {
            return Err(AuditBreak {
                index: i,
                reason: format!(
                    "prev_hash does not chain: entry claims {}, expected {}",
                    short(&a.prev_hash),
                    short(&prev),
                ),
            });
        }
        let expected = compute_hash(&prev, a);
        if a.hash != expected {
            return Err(AuditBreak {
                index: i,
                reason: format!(
                    "content hash mismatch: stored {}, recomputed {}",
                    short(&a.hash),
                    short(&expected),
                ),
            });
        }
        prev = a.hash.clone();
    }
    Ok(())
}

fn short(h: &str) -> String {
    if h.len() > 12 {
        format!("{}…", &h[..12])
    } else {
        h.to_string()
    }
}

/// Re-stamp every entry in the log. Used to migrate an engagement that
/// pre-dates this feature (all entries have empty `prev_hash`/`hash`). Also
/// useful if an operator deliberately truncated the chain and needs it
/// re-sealed. Does nothing to a chain that already verifies.
pub fn reseal_chain(e: &mut Engagement) {
    let mut prev = genesis(&e.id);
    for a in e.action_log.iter_mut() {
        a.prev_hash = prev.clone();
        a.hash = compute_hash(&prev, a);
        prev = a.hash.clone();
    }
}

/// Does the log have any entry missing its hash fields? If so,
/// [`reseal_chain`] can be called transparently to migrate.
pub fn has_legacy_entries(e: &Engagement) -> bool {
    e.action_log
        .iter()
        .any(|a| a.prev_hash.is_empty() || a.hash.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ActionRun;
    use chrono::Utc;

    fn action(id: &str, cmd: &str) -> ActionRun {
        ActionRun {
            id: id.into(),
            at: Utc::now(),
            module_id: "m".into(),
            module_name: "M".into(),
            target: "".into(),
            command: cmd.into(),
            disruptive: false,
            dry_run: true,
            exit_code: Some(0),
            timed_out: false,
            summary: "".into(),
            operator: "op".into(),
            prev_hash: "".into(),
            hash: "".into(),
        }
    }

    #[test]
    fn empty_log_head_is_genesis() {
        let e = Engagement::new("E".into());
        assert_eq!(chain_head(&e), genesis(&e.id));
        assert!(verify_action_log(&e).is_ok());
    }

    #[test]
    fn seal_and_verify_round_trip() {
        let mut e = Engagement::new("E".into());
        for i in 0..5 {
            let a = seal_new_action(&e, action(&format!("a{i}"), &format!("cmd {i}")));
            e.action_log.push(a);
        }
        assert!(verify_action_log(&e).is_ok());
    }

    #[test]
    fn tampering_with_command_breaks_chain() {
        let mut e = Engagement::new("E".into());
        for i in 0..3 {
            let a = seal_new_action(&e, action(&format!("a{i}"), &format!("cmd {i}")));
            e.action_log.push(a);
        }
        e.action_log[1].command = "DIFFERENT".into();
        let br = verify_action_log(&e).expect_err("tamper must break chain");
        assert_eq!(br.index, 1);
    }

    #[test]
    fn tampering_at_index_zero_is_caught() {
        let mut e = Engagement::new("E".into());
        for i in 0..3 {
            let a = seal_new_action(&e, action(&format!("a{i}"), &format!("c{i}")));
            e.action_log.push(a);
        }
        e.action_log[0].summary = "evil".into();
        let br = verify_action_log(&e).expect_err("tamper");
        assert_eq!(br.index, 0);
    }

    #[test]
    fn truncating_last_entry_leaves_valid_chain_at_new_head() {
        let mut e = Engagement::new("E".into());
        for i in 0..4 {
            let a = seal_new_action(&e, action(&format!("a{i}"), &format!("c{i}")));
            e.action_log.push(a);
        }
        e.action_log.pop();
        // The chain up to the new last entry is still valid — a truncated
        // tail is not detectable without an external anchor.
        assert!(verify_action_log(&e).is_ok());
    }

    #[test]
    fn reseal_fixes_legacy_log() {
        let mut e = Engagement::new("E".into());
        for i in 0..3 {
            let mut a = action(&format!("a{i}"), &format!("c{i}"));
            a.prev_hash = String::new();
            a.hash = String::new();
            e.action_log.push(a);
        }
        assert!(has_legacy_entries(&e));
        assert!(verify_action_log(&e).is_err());
        reseal_chain(&mut e);
        assert!(!has_legacy_entries(&e));
        assert!(verify_action_log(&e).is_ok());
    }

    #[test]
    fn moving_entry_between_engagements_breaks_chain() {
        let mut a_eng = Engagement::new("A".into());
        let a0 = seal_new_action(&a_eng, action("x", "c"));
        a_eng.action_log.push(a0.clone());

        // Try to replay the same action into a different engagement — the
        // genesis differs so the first entry's prev_hash will not match.
        let mut b_eng = Engagement::new("B".into());
        b_eng.action_log.push(a0);
        assert!(verify_action_log(&b_eng).is_err());
    }
}
