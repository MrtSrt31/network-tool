//! Active test-execution modules.
//!
//! These modules ORCHESTRATE the operator's own installed, authorized wireless
//! tooling (the aircrack-ng suite, reaver/wash, hcxdumptool, airbase-ng). They
//! build and run a command for an external tool, capture its output, and record
//! the invocation to the engagement's action log.
//!
//! Safety model — every real execution must pass `gate()`:
//!   * the engagement must have a signed authorization on file;
//!   * a `disruptive` module additionally requires `authorization.disruptive_allowed`
//!     and an explicit confirmation;
//!   * a target BSSID is checked against the engagement's in-scope BSSID list.
//!
//! Dry-run (command preview) never executes anything and downgrades gate
//! failures to warnings so the operator can plan.
//!
//! For authorized engagements only.

use crate::model::Engagement;
use crate::validate::{self, ParamKind};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone)]
pub struct Param {
    pub key: &'static str,
    pub label: &'static str,
    pub required: bool,
    pub placeholder: &'static str,
    pub kind: ParamKind,
}

fn p(
    key: &'static str,
    label: &'static str,
    required: bool,
    placeholder: &'static str,
    kind: ParamKind,
) -> Param {
    Param {
        key,
        label,
        required,
        placeholder,
        kind,
    }
}

pub struct ModuleSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub tactic: &'static str,
    pub technique: &'static str,
    pub disruptive: bool,
    pub tools: &'static [&'static str],
    pub description: &'static str,
    pub params: Vec<Param>,
}

pub fn registry() -> Vec<ModuleSpec> {
    vec![
        ModuleSpec {
            id: "airmon_start",
            name: "Enable monitor mode",
            category: "Setup",
            tactic: "Reconnaissance",
            technique: "T1595",
            disruptive: false,
            tools: &["airmon-ng"],
            description: "Put a wireless interface into monitor mode (airmon-ng start).",
            params: vec![p("iface", "Interface", true, "wlan0", ParamKind::Iface)],
        },
        ModuleSpec {
            id: "airmon_stop",
            name: "Disable monitor mode",
            category: "Setup",
            tactic: "Reconnaissance",
            technique: "—",
            disruptive: false,
            tools: &["airmon-ng"],
            description: "Return the interface to managed mode (airmon-ng stop).",
            params: vec![p("iface", "Monitor interface", true, "wlan0mon", ParamKind::Iface)],
        },
        ModuleSpec {
            id: "scan",
            name: "Survey / discovery scan",
            category: "Reconnaissance",
            tactic: "Discovery",
            technique: "T1018",
            disruptive: false,
            tools: &["airodump-ng"],
            description: "Capture a wide survey to CSV (airodump-ng). Import the CSV afterwards to build the asset inventory.",
            params: vec![
                p("iface", "Monitor interface", true, "wlan0mon", ParamKind::Iface),
                p("prefix", "Output prefix", false, "ntool-scan", ParamKind::Prefix),
            ],
        },
        ModuleSpec {
            id: "scan_target",
            name: "Targeted capture (handshake)",
            category: "Encryption & Authentication",
            tactic: "Credential Access",
            technique: "T1557",
            disruptive: false,
            tools: &["airodump-ng"],
            description: "Lock airodump-ng to one BSSID/channel and write a capture (to catch a WPA handshake). Pair with a deauth if RoE permits.",
            params: vec![
                p("bssid", "Target BSSID", true, "AA:BB:CC:11:22:33", ParamKind::Mac),
                p("channel", "Channel", true, "6", ParamKind::Channel),
                p("iface", "Monitor interface", true, "wlan0mon", ParamKind::Iface),
                p("prefix", "Output prefix", false, "ntool-hs", ParamKind::Prefix),
            ],
        },
        ModuleSpec {
            id: "deauth",
            name: "Deauthentication",
            category: "Management Frame Protection",
            tactic: "Credential Access",
            technique: "T1557",
            disruptive: true,
            tools: &["aireplay-ng"],
            description: "Send deauth frames (aireplay-ng) to force a reconnect/handshake and to test 802.11w (PMF). Disruptive to clients.",
            params: vec![
                p("bssid", "Target BSSID", true, "AA:BB:CC:11:22:33", ParamKind::Mac),
                p("iface", "Monitor interface", true, "wlan0mon", ParamKind::Iface),
                p("count", "Frame count", false, "5", ParamKind::Count),
                p("client", "Client MAC (optional)", false, "A0:B0:C0:D0:E0:F0", ParamKind::Mac),
            ],
        },
        ModuleSpec {
            id: "wpa_crack",
            name: "WPA PSK offline analysis",
            category: "Encryption & Authentication",
            tactic: "Credential Access",
            technique: "T1110",
            disruptive: false,
            tools: &["aircrack-ng"],
            description: "Offline dictionary analysis of a captured handshake (aircrack-ng) to assess PSK resilience. No transmission.",
            params: vec![
                p("wordlist", "Wordlist path", true, "/usr/share/wordlists/rockyou.txt", ParamKind::Path),
                p("bssid", "Target BSSID", true, "AA:BB:CC:11:22:33", ParamKind::Mac),
                p("capture", "Capture file", true, "ntool-hs-01.cap", ParamKind::Path),
            ],
        },
        ModuleSpec {
            id: "wps_scan",
            name: "WPS discovery",
            category: "WPS",
            tactic: "Discovery",
            technique: "T1018",
            disruptive: false,
            tools: &["wash"],
            description: "List WPS-enabled access points in range (wash).",
            params: vec![p("iface", "Monitor interface", true, "wlan0mon", ParamKind::Iface)],
        },
        ModuleSpec {
            id: "wps_attack",
            name: "WPS PIN assessment",
            category: "WPS",
            tactic: "Initial Access",
            technique: "T1110",
            disruptive: true,
            tools: &["reaver"],
            description: "Assess WPS PIN exposure (reaver). Intrusive — can lock or stress the AP.",
            params: vec![
                p("iface", "Monitor interface", true, "wlan0mon", ParamKind::Iface),
                p("bssid", "Target BSSID", true, "AA:BB:CC:11:22:33", ParamKind::Mac),
                p("channel", "Channel (optional)", false, "6", ParamKind::Channel),
            ],
        },
        ModuleSpec {
            id: "pmkid",
            name: "PMKID capture",
            category: "Encryption & Authentication",
            tactic: "Credential Access",
            technique: "T1557",
            disruptive: true,
            tools: &["hcxdumptool"],
            description: "Capture PMKID material (hcxdumptool). Actively associates with APs — treat as intrusive.",
            params: vec![
                p("iface", "Monitor interface", true, "wlan0mon", ParamKind::Iface),
                p("out", "Output file", false, "ntool-pmkid.pcapng", ParamKind::Path),
            ],
        },
        ModuleSpec {
            id: "evil_twin",
            name: "Rogue AP / evil twin",
            category: "Rogue / Evil Twin & Client-side",
            tactic: "Initial Access",
            technique: "T1557",
            disruptive: true,
            tools: &["airbase-ng"],
            description: "Stand up a rogue AP (airbase-ng) to test client auto-join and evil-twin resistance. Highly disruptive — isolate to a test SSID where possible.",
            params: vec![
                p("essid", "ESSID to advertise", true, "EvsuCorp", ParamKind::Essid),
                p("channel", "Channel", true, "6", ParamKind::Channel),
                p("iface", "Monitor interface", true, "wlan0mon", ParamKind::Iface),
            ],
        },
    ]
}

pub fn find(id: &str) -> Option<ModuleSpec> {
    registry().into_iter().find(|m| m.id == id)
}

/// Enforce the safety gate. Returns warnings on success, or an error that blocks
/// a real run. In dry-run mode, gate violations become warnings instead of errors.
pub fn gate(
    e: &Engagement,
    spec: &ModuleSpec,
    params: &std::collections::HashMap<String, String>,
    dry_run: bool,
    confirm: bool,
) -> Result<Vec<String>, String> {
    // Parameter presence + format validation. An ill-formed value is rejected
    // even in dry-run mode: there is no useful "preview" of invalid input, and
    // the whole point of this layer is to stop argument injection before the
    // operator ever sees the previewed command line.
    for prm in &spec.params {
        match params.get(prm.key).map(|s| s.trim()) {
            Some(v) if !v.is_empty() => {
                if let Err(reason) = validate::check(prm.kind, v) {
                    return Err(format!("invalid {}: {}", prm.label, reason));
                }
            }
            _ => {
                if prm.required {
                    return Err(format!("missing required parameter: {}", prm.label));
                }
            }
        }
    }

    let mut warnings = Vec::new();

    // Authorization gate.
    if !e.active_testing_unlocked() {
        if dry_run {
            warnings.push(
                "engagement is NOT authorized — preview only; execution is blocked".to_string(),
            );
        } else {
            return Err(
                "active testing is LOCKED: record a signed authorization before running modules"
                    .to_string(),
            );
        }
    }

    // Disruptive gate.
    if spec.disruptive {
        if !e.authorization.disruptive_allowed {
            if dry_run {
                warnings.push(
                    "disruptive technique not permitted by RoE (disruptive_allowed = false) — preview only"
                        .to_string(),
                );
            } else {
                return Err(
                    "disruptive techniques are not permitted by the recorded RoE (disruptive_allowed = false)"
                        .to_string(),
                );
            }
        }
        if !dry_run && !confirm {
            return Err("disruptive module requires explicit confirmation".to_string());
        }
    }

    // Scope gate (when a BSSID target is present).
    if let Some(bssid) = params.get("bssid") {
        let b = bssid.trim();
        if !b.is_empty() {
            if e.scope.in_scope_bssids.is_empty() {
                warnings.push("no in-scope BSSID list defined — scope not enforced".to_string());
            } else {
                let in_scope = e
                    .scope
                    .in_scope_bssids
                    .iter()
                    .any(|x| x.trim().eq_ignore_ascii_case(b));
                if !in_scope {
                    let msg = format!("target {b} is not in the engagement's in-scope BSSID list");
                    if dry_run {
                        warnings.push(msg);
                    } else {
                        return Err(msg);
                    }
                }
            }
        }
    }

    Ok(warnings)
}

/// Build the external command (program + args) for a module from its parameters.
pub fn build_command(
    spec: &ModuleSpec,
    params: &std::collections::HashMap<String, String>,
) -> (String, Vec<String>) {
    let g = |k: &str| -> String {
        params
            .get(k)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let or = |k: &str, d: &str| -> String {
        let v = g(k);
        if v.is_empty() {
            d.to_string()
        } else {
            v
        }
    };

    match spec.id {
        "airmon_start" => ("airmon-ng".into(), vec!["start".into(), g("iface")]),
        "airmon_stop" => ("airmon-ng".into(), vec!["stop".into(), g("iface")]),
        "scan" => (
            "airodump-ng".into(),
            vec![
                "--output-format".into(),
                "csv".into(),
                "-w".into(),
                or("prefix", "ntool-scan"),
                g("iface"),
            ],
        ),
        "scan_target" => (
            "airodump-ng".into(),
            vec![
                "--bssid".into(),
                g("bssid"),
                "-c".into(),
                g("channel"),
                "-w".into(),
                or("prefix", "ntool-hs"),
                g("iface"),
            ],
        ),
        "deauth" => {
            let mut a = vec!["--deauth".into(), or("count", "5"), "-a".into(), g("bssid")];
            if !g("client").is_empty() {
                a.push("-c".into());
                a.push(g("client"));
            }
            a.push(g("iface"));
            ("aireplay-ng".into(), a)
        }
        "wpa_crack" => (
            "aircrack-ng".into(),
            vec![
                "-w".into(),
                g("wordlist"),
                "-b".into(),
                g("bssid"),
                g("capture"),
            ],
        ),
        "wps_scan" => ("wash".into(), vec!["-i".into(), g("iface")]),
        "wps_attack" => {
            let mut a = vec![
                "-i".into(),
                g("iface"),
                "-b".into(),
                g("bssid"),
                "-vv".into(),
            ];
            if !g("channel").is_empty() {
                a.push("-c".into());
                a.push(g("channel"));
            }
            ("reaver".into(), a)
        }
        "pmkid" => (
            "hcxdumptool".into(),
            vec![
                "-i".into(),
                g("iface"),
                "-o".into(),
                or("out", "ntool-pmkid.pcapng"),
                "--enable_status=1".into(),
            ],
        ),
        "evil_twin" => (
            "airbase-ng".into(),
            vec![
                "-e".into(),
                g("essid"),
                "-c".into(),
                g("channel"),
                g("iface"),
            ],
        ),
        _ => (spec.id.to_string(), vec![]),
    }
}

pub fn display_command(program: &str, args: &[String]) -> String {
    let mut s = String::from(program);
    for a in args {
        s.push(' ');
        if a.contains(char::is_whitespace) || a.is_empty() {
            s.push('"');
            s.push_str(a);
            s.push('"');
        } else {
            s.push_str(a);
        }
    }
    s
}

/// Is an executable of this name present on PATH?
pub fn tool_available(name: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

pub struct RunResult {
    pub command: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    /// True when the run was aborted via the `stop` flag (external cancel).
    pub cancelled: bool,
}

/// Which pipe a line of output came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineTag {
    Stdout,
    Stderr,
}

/// A single line of output as it was produced by the child process.
#[derive(Clone, Debug)]
pub struct Line {
    pub tag: LineTag,
    pub text: String,
}

/// Run an external command, streaming each line of output through `on_line`
/// as it is produced. Pipes are drained by dedicated reader threads so the
/// child cannot deadlock on a full stdout/stderr buffer.
///
/// * `timeout_secs > 0` arms a watchdog that kills the child after the
///   deadline (`RunResult.timed_out = true`).
/// * `stop` is an optional external cancel flag; set it to `true` to request
///   termination (`RunResult.cancelled = true`). Both signals are polled on
///   the same 200 ms tick, so cancel/timeout latency is sub-second.
///
/// The returned `RunResult` also carries the aggregated stdout and stderr for
/// the action log; the callback sees them line-by-line in real time.
pub fn execute_streaming<F>(
    program: &str,
    args: &[String],
    timeout_secs: u64,
    stop: Option<Arc<AtomicBool>>,
    mut on_line: F,
) -> std::io::Result<RunResult>
where
    F: FnMut(Line),
{
    let cmdline = display_command(program, args);

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let stderr_pipe = child.stderr.take().expect("piped stderr");

    let (tx, rx) = mpsc::channel::<Line>();
    let tx_err = tx.clone();

    // Dedicated reader thread per pipe — no interleave starvation, no deadlock.
    let out_handle = thread::spawn(move || {
        let reader = BufReader::new(stdout_pipe);
        for line in reader.lines().map_while(Result::ok) {
            if tx
                .send(Line {
                    tag: LineTag::Stdout,
                    text: line,
                })
                .is_err()
            {
                break;
            }
        }
    });
    let err_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr_pipe);
        for line in reader.lines().map_while(Result::ok) {
            if tx_err
                .send(Line {
                    tag: LineTag::Stderr,
                    text: line,
                })
                .is_err()
            {
                break;
            }
        }
    });

    let timed_out = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let child = Arc::new(Mutex::new(child));

    // Watchdog: polls timeout AND external stop flag; kills the child on either.
    let watchdog = {
        let w = Arc::clone(&child);
        let to_flag = Arc::clone(&timed_out);
        let cx_flag = Arc::clone(&cancelled);
        let stop = stop.clone();
        thread::spawn(move || {
            let step = Duration::from_millis(200);
            let deadline = Duration::from_secs(timeout_secs);
            let mut waited = Duration::from_millis(0);
            loop {
                thread::sleep(step);
                waited += step;
                let mut guard = match w.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                match guard.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => {
                        if let Some(s) = &stop {
                            if s.load(Ordering::SeqCst) {
                                cx_flag.store(true, Ordering::SeqCst);
                                let _ = guard.kill();
                                return;
                            }
                        }
                        if timeout_secs > 0 && waited >= deadline {
                            to_flag.store(true, Ordering::SeqCst);
                            let _ = guard.kill();
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        })
    };

    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();
    for line in rx {
        match line.tag {
            LineTag::Stdout => {
                stdout_buf.push_str(&line.text);
                stdout_buf.push('\n');
            }
            LineTag::Stderr => {
                stderr_buf.push_str(&line.text);
                stderr_buf.push('\n');
            }
        }
        on_line(line);
    }

    let status = { child.lock().unwrap().wait()? };
    let _ = out_handle.join();
    let _ = err_handle.join();
    let _ = watchdog.join();

    Ok(RunResult {
        command: cmdline,
        exit_code: status.code(),
        stdout: stdout_buf,
        stderr: stderr_buf,
        timed_out: timed_out.load(Ordering::SeqCst),
        cancelled: cancelled.load(Ordering::SeqCst),
    })
}

/// Backwards-compatible wrapper: runs the command, discards per-line events
/// and returns the aggregated output. Prefer [`execute_streaming`] in new code.
pub fn execute(program: &str, args: &[String], timeout_secs: u64) -> std::io::Result<RunResult> {
    execute_streaming(program, args, timeout_secs, None, |_| {})
}

/// A short one-line summary for the action log.
pub fn summarize(r: &RunResult) -> String {
    if r.cancelled {
        return "cancelled by operator (stop requested)".to_string();
    }
    if r.timed_out {
        return "timed out (watchdog killed the process)".to_string();
    }
    let first = r
        .stdout
        .lines()
        .find(|l| !l.trim().is_empty())
        .or_else(|| r.stderr.lines().find(|l| !l.trim().is_empty()))
        .unwrap_or("");
    let code = r
        .exit_code
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string());
    let mut s = format!("exit {code}");
    if !first.is_empty() {
        s.push_str(" · ");
        let trimmed: String = first.chars().take(160).collect();
        s.push_str(&trimmed);
    }
    s
}
