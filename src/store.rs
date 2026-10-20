//! Persistence: one JSON file per engagement under a data directory.
//!
//! The store gives three guarantees that the GUI (which now runs
//! thread-per-request) and the CLI need to coexist safely:
//!
//! 1. **Atomic writes.** Each save writes `<id>.json.tmp` then renames it
//!    over `<id>.json`. A crash mid-write leaves either the old file or the
//!    new file — never a half-written one.
//! 2. **Cross-process exclusion.** Each save takes an exclusive advisory
//!    lock on `<id>.lock` (POSIX `flock`), so a concurrent CLI command and
//!    GUI click cannot interleave their writes.
//! 3. **Optimistic-concurrency conflict detection.** Every save compares
//!    the incoming `version` against the on-disk one. A mismatch returns
//!    [`SaveError::Conflict`], so a stale form submission cannot silently
//!    overwrite someone else's changes.
//!
//! Override the data location with the `NETWORKTOOL_DATA` env variable.

use crate::audit;
use crate::model::Engagement;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("NETWORKTOOL_DATA") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".networktool").join("engagements")
}

pub fn ensure_dir() -> io::Result<PathBuf> {
    let d = data_dir();
    fs::create_dir_all(&d)?;
    Ok(d)
}

fn path_for(id: &str) -> PathBuf {
    data_dir().join(format!("{id}.json"))
}

fn lock_path_for(id: &str) -> PathBuf {
    data_dir().join(format!("{id}.lock"))
}

fn tmp_path_for(id: &str) -> PathBuf {
    data_dir().join(format!("{id}.json.tmp"))
}

/// What can go wrong when saving. Callers in the GUI should surface
/// `Conflict` as a "reload and try again" message; the CLI prints it.
#[derive(Debug)]
pub enum SaveError {
    Io(io::Error),
    Conflict { on_disk: u64, incoming: u64 },
}

impl fmt::Display for SaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SaveError::Io(e) => write!(f, "{e}"),
            SaveError::Conflict { on_disk, incoming } => write!(
                f,
                "conflict: another writer updated this engagement (on disk v{on_disk}, you have v{incoming}); reload and try again"
            ),
        }
    }
}

impl std::error::Error for SaveError {}

impl From<io::Error> for SaveError {
    fn from(e: io::Error) -> Self {
        SaveError::Io(e)
    }
}

/// RAII wrapper over a POSIX advisory `flock(LOCK_EX)`. The lock is released
/// when the `FileLock` is dropped (SIGKILL still works — kernel releases).
struct FileLock {
    _file: fs::File,
}

impl FileLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        // SAFETY: libc::flock is thread-safe and operates on the fd we own.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileLock { _file: file })
    }
}

fn to_io(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Read just the `version` field from the on-disk engagement, or `None` if
/// the file does not exist yet.
fn disk_version(id: &str) -> io::Result<Option<u64>> {
    match fs::read_to_string(path_for(id)) {
        Ok(s) => {
            let v: serde_json::Value = serde_json::from_str(&s).map_err(to_io)?;
            Ok(Some(v.get("version").and_then(|x| x.as_u64()).unwrap_or(0)))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Save an engagement with optimistic-concurrency conflict detection.
///
/// The caller passes `&mut Engagement`; on success the engagement's `version`
/// is bumped (so the same binding may be saved again in a loop without a
/// fresh load).
///
/// Fails with [`SaveError::Conflict`] if the on-disk version does not match
/// the incoming one — meaning another writer wrote first and the caller's
/// view is stale.
pub fn save(e: &mut Engagement) -> Result<(), SaveError> {
    ensure_dir()?;
    let _lock = FileLock::acquire(&lock_path_for(&e.id))?;

    let on_disk = disk_version(&e.id)?;
    if let Some(disk_v) = on_disk {
        if disk_v != e.version {
            log::warn!(
                "save conflict · engagement={} on_disk={} incoming={}",
                e.id,
                disk_v,
                e.version
            );
            return Err(SaveError::Conflict {
                on_disk: disk_v,
                incoming: e.version,
            });
        }
    }

    // Transparently seal any legacy action-log entries (pre-P0.5 engagements
    // whose actions have empty prev_hash/hash). This runs at most once per
    // engagement after the upgrade.
    if audit::has_legacy_entries(e) {
        audit::reseal_chain(e);
    }

    // Commit the next version atomically: write a tmp file, then rename it
    // over the real one. POSIX rename within the same directory is atomic.
    let next = e.version + 1;
    let previous = e.version;
    e.version = next;
    let payload = serde_json::to_string_pretty(e).map_err(to_io);
    let payload = match payload {
        Ok(p) => p,
        Err(err) => {
            e.version = previous; // roll back the in-memory bump on failure
            return Err(SaveError::Io(err));
        }
    };
    let tmp = tmp_path_for(&e.id);
    if let Err(err) = fs::write(&tmp, &payload) {
        e.version = previous;
        return Err(SaveError::Io(err));
    }
    if let Err(err) = fs::rename(&tmp, path_for(&e.id)) {
        let _ = fs::remove_file(&tmp);
        e.version = previous;
        return Err(SaveError::Io(err));
    }
    Ok(())
}

pub fn load(id: &str) -> io::Result<Engagement> {
    let data = fs::read_to_string(path_for(id))?;
    serde_json::from_str(&data).map_err(to_io)
}

pub fn list() -> io::Result<Vec<Engagement>> {
    ensure_dir()?;
    let mut out = Vec::new();
    for entry in fs::read_dir(data_dir())? {
        let entry = entry?;
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(s) = fs::read_to_string(&p) {
                if let Ok(e) = serde_json::from_str::<Engagement>(&s) {
                    out.push(e);
                }
            }
        }
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    Ok(out)
}
