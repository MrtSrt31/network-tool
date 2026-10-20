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
//! Dry-run (command preview) never executes anything and downgrades gate failures
//! to warnings so the operator can plan.
//!
//! For authorized engagements only.

use crate::model::Engagement;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone)]
pub struct Param {
    pub key: &'static str,
    pub label: &'static str,
    pub required: bool,
    pub placeholder: &'static str,
}

fn p(key: &'static str, label: &'static str, required: bool, placeholder: &'static str) -> Param {
    Param {
        key,
        label,
        required,
        placeholder,
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
            params: vec![p("iface", "Interface", true, "wlan0")],
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
            params: vec![p("iface", "Monitor interface", true, "wlan0mon")],
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
                p("iface", "Monitor interface", true, "wlan0mon"),
                p("prefix", "Output prefix", false, "ntool-scan"),
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
                p("bssid", "Target BSSID", true, "AA:BB:CC:11:22:33"),
                p("channel", "Channel", true, "6"),
                p("iface", "Monitor interface", true, "wlan0mon"),
                p("prefix", "Output prefix", false, "ntool-hs"),
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
                p("bssid", "Target BSSID", true, "AA:BB:CC:11:22:33"),
                p("iface", "Monitor interface", true, "wlan0mon"),
                p("count", "Frame count", false, "5"),
                p("client", "Client MAC (optional)", false, "A0:B0:C0:D0:E0:F0"),
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
                p("wordlist", "Wordlist path", true, "/usr/share/wordlists/rockyou.txt"),
                p("bssid", "Target BSSID", true, "AA:BB:CC:11:22:33"),
                p("capture", "Capture file", true, "ntool-hs-01.cap"),
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
            params: vec![p("iface", "Monitor interface", true, "wlan0mon")],
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
                p("iface", "Monitor interface", true, "wlan0mon"),
                p("bssid", "Target BSSID", true, "AA:BB:CC:11:22:33"),
                p("channel", "Channel (optional)", false, "6"),
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
                p("iface", "Monitor interface", true, "wlan0mon"),
                p("out", "Output file", false, "ntool-pmkid.pcapng"),
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
                p("essid", "ESSID to advertise", true, "EvsuCorp"),
                p("channel", "Channel", true, "6"),
                p("iface", "Monitor interface", true, "wlan0mon"),
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
    // Required parameters.
    for prm in &spec.params {
        if prm.required {
            let missing = params
                .get(prm.key)
                .map(|s| s.trim().is_empty())
                .unwrap_or(true);
            if missing {
                return Err(format!("missing required parameter: {}", prm.label));
            }
        }
    }

    let mut warnings = Vec::new();

    // Authorization gate.
    if !e.active_testing_unlocked() {
        if dry_run {
            warnings.push("engagement is NOT authorized — preview only; execution is blocked".to_string());
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
        params.get(k).map(|s| s.trim().to_string()).unwrap_or_default()
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
            let mut a = vec!["-i".into(), g("iface"), "-b".into(), g("bssid"), "-vv".into()];
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
}

/// Run an external command, capturing output. If `timeout_secs > 0`, a watchdog
/// kills the process after the deadline.
pub fn execute(program: &str, args: &[String], timeout_secs: u64) -> std::io::Result<RunResult> {
    let cmdline = display_command(program, args);

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut out = child.stdout.take().expect("piped stdout");
    let mut err = child.stderr.take().expect("piped stderr");

    let timed_out = Arc::new(AtomicBool::new(false));
    let child = Arc::new(Mutex::new(child));

    let watchdog = if timeout_secs > 0 {
        let w = Arc::clone(&child);
        let flag = Arc::clone(&timed_out);
        Some(thread::spawn(move || {
            let deadline = Duration::from_secs(timeout_secs);
            let step = Duration::from_millis(200);
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
                        if waited >= deadline {
                            flag.store(true, Ordering::SeqCst);
                            let _ = guard.kill();
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        }))
    } else {
        None
    };

    let mut stdout = String::new();
    let _ = out.read_to_string(&mut stdout);
    let mut stderr = String::new();
    let _ = err.read_to_string(&mut stderr);

    let status = { child.lock().unwrap().wait()? };
    if let Some(h) = watchdog {
        let _ = h.join();
    }

    Ok(RunResult {
        command: cmdline,
        exit_code: status.code(),
        stdout,
        stderr,
        timed_out: timed_out.load(Ordering::SeqCst),
    })
}

/// A short one-line summary for the action log.
pub fn summarize(r: &RunResult) -> String {
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
