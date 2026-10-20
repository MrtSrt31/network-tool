//! Structured logging to a daily rotating file and (optionally) stderr.
//!
//! A single logger is installed through the `log` facade at process start.
//! Every call site in the codebase that uses `log::info!`, `log::warn!`,
//! `log::error!`, etc. ends up here. The file is `networktool-YYYYMMDD.log`
//! under `<data_dir>/logs/` — one file per UTC day for painless post-run
//! review. With `--verbose` / `-v`, log lines are also mirrored to stderr.
//!
//! The point of this layer is **field evidence**: after a 10-minute GUI or
//! CLI session we can reconstruct exactly what the operator ran, when, who
//! authenticated, and what was blocked by the safety gate.

use crate::store;
use log::{Log, Metadata, Record};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;

struct DailyFileLogger {
    file: Mutex<Option<fs::File>>,
    mirror_stderr: bool,
}

impl Log for DailyFileLogger {
    fn enabled(&self, _m: &Metadata) -> bool {
        true // level filtering is done by `log::set_max_level`
    }

    fn log(&self, record: &Record) {
        let line = format!(
            "{} [{:5}] {} :: {}\n",
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            record.level(),
            record.target(),
            record.args(),
        );
        if self.mirror_stderr {
            let _ = io::stderr().write_all(line.as_bytes());
        }
        if let Ok(mut guard) = self.file.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }

    fn flush(&self) {
        let _ = io::stderr().flush();
        if let Ok(mut guard) = self.file.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = f.flush();
            }
        }
    }
}

/// Compute the path of today's log file.
pub fn log_file_path() -> PathBuf {
    let dir = store::data_dir().join("logs");
    let name = format!("networktool-{}.log", chrono::Utc::now().format("%Y%m%d"));
    dir.join(name)
}

/// Install the global logger. Idempotent — a second call is a no-op (so
/// tests that run `init` repeatedly don't panic).
pub fn init(verbose: bool) -> io::Result<()> {
    let path = log_file_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let logger = DailyFileLogger {
        file: Mutex::new(Some(file)),
        mirror_stderr: verbose,
    };
    let level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    // Ignore SetLoggerError — happens when init runs twice.
    let _ = log::set_boxed_logger(Box::new(logger));
    log::set_max_level(level);
    Ok(())
}
