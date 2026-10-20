//! Tests for the engagement store's concurrency guarantees:
//! optimistic-concurrency version check, atomic write, and the
//! advisory `flock` lock that serialises writes across processes.

use network_tool::model::Engagement;
use network_tool::store::{self, SaveError};
use std::sync::{Arc, Barrier, Mutex, MutexGuard, OnceLock};
use std::thread;

// All tests in this file touch the process-global `NETWORKTOOL_DATA` env var
// and must not run in parallel; this mutex serialises them. Each test should
// take the guard first and hold it for the test's duration.
static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn fresh_data_dir(label: &str) -> (MutexGuard<'static, ()>, std::path::PathBuf) {
    let guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let dir = std::env::temp_dir().join(format!(
        "ntool-store-{}-{}-{}",
        label,
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::env::set_var("NETWORKTOOL_DATA", &dir);
    (guard, dir)
}

#[test]
fn save_bumps_version_from_zero_to_one() {
    let _env = fresh_data_dir("version-bump");
    let mut e = Engagement::new("E".into());
    assert_eq!(e.version, 0);
    store::save(&mut e).expect("first save");
    assert_eq!(e.version, 1);
    store::save(&mut e).expect("second save");
    assert_eq!(e.version, 2);
}

#[test]
fn conflicting_save_is_rejected() {
    let _env = fresh_data_dir("conflict");
    // Writer A creates the engagement.
    let mut a = Engagement::new("E".into());
    store::save(&mut a).expect("A initial save");
    // Writer B loads the same version A just wrote.
    let mut b = store::load(&a.id).expect("B load");
    assert_eq!(a.version, b.version);
    // A modifies and saves first — now disk has v=2, A has v=2.
    a.name = "A-modified".into();
    store::save(&mut a).expect("A second save");
    assert_eq!(a.version, 2);
    // B tries to save with its stale v=1 → conflict.
    b.name = "B-modified".into();
    let err = store::save(&mut b).expect_err("B should fail");
    match err {
        SaveError::Conflict { on_disk, incoming } => {
            assert_eq!(on_disk, 2);
            assert_eq!(incoming, 1);
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
    // B's in-memory version must not have advanced (rollback on failure).
    assert_eq!(b.version, 1);
    // A's write is the one preserved on disk.
    let final_state = store::load(&a.id).unwrap();
    assert_eq!(final_state.name, "A-modified");
    assert_eq!(final_state.version, 2);
}

#[test]
fn concurrent_writers_both_cannot_win() {
    // Two threads both load v=0, both try to save v=1. Exactly one must
    // succeed; the other must get Conflict. No silent overwrites.
    let _env = fresh_data_dir("concurrent");
    let mut seed = Engagement::new("E".into());
    store::save(&mut seed).unwrap();
    let id = seed.id.clone();

    let gate = Arc::new(Barrier::new(2));
    let id1 = id.clone();
    let gate1 = Arc::clone(&gate);
    let id2 = id.clone();
    let gate2 = Arc::clone(&gate);

    let a = thread::spawn(move || {
        let mut e = store::load(&id1).unwrap();
        e.name = "A".into();
        gate1.wait();
        store::save(&mut e)
    });
    let b = thread::spawn(move || {
        let mut e = store::load(&id2).unwrap();
        e.name = "B".into();
        gate2.wait();
        store::save(&mut e)
    });

    let ra = a.join().unwrap();
    let rb = b.join().unwrap();
    let ok = [ra.is_ok(), rb.is_ok()];
    let successes = ok.iter().filter(|x| **x).count();
    assert_eq!(successes, 1, "exactly one writer must succeed; got {ok:?}");

    let final_state = store::load(&id).unwrap();
    assert_eq!(final_state.version, 2);
    assert!(final_state.name == "A" || final_state.name == "B");
}

#[test]
fn load_sees_either_old_or_new_never_partial() {
    // The write-then-rename pattern means a concurrent reader either sees
    // the old file or the new one — never a half-written JSON. We can't
    // easily race rename vs read deterministically, but we at least verify
    // that after a save the JSON on disk is valid and parses.
    let _env = fresh_data_dir("atomic-write");
    let mut e = Engagement::new("E".into());
    e.name = "with newlines\nand quotes\"".into();
    store::save(&mut e).unwrap();
    let round_tripped = store::load(&e.id).unwrap();
    assert_eq!(round_tripped.name, e.name);
    assert_eq!(round_tripped.version, 1);
    // No stray .tmp file left behind.
    let tmp_path = store::data_dir().join(format!("{}.json.tmp", e.id));
    assert!(!tmp_path.exists(), "tmp file must not linger");
}
