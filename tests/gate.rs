//! Integration tests for the safety gate: authorization, disruptive-permission,
//! BSSID scope, and parameter validation. This is the single most load-bearing
//! function in the tool — if it regresses, we lose the "safe to run" promise.

use network_tool::model::{Authorization, Engagement, Scope};
use network_tool::modules::{self, gate, ModuleSpec};
use std::collections::HashMap;

fn blank_engagement() -> Engagement {
    Engagement::new("Test engagement".to_string())
}

fn authorized_engagement(disruptive: bool) -> Engagement {
    let mut e = blank_engagement();
    e.authorization = Authorization {
        authorized: true,
        authorizer_name: "Client CISO".into(),
        authorizer_title: "CISO".into(),
        signed_date: "2026-10-20".into(),
        roe_reference: "ROE-001".into(),
        disruptive_allowed: disruptive,
        emergency_contact: "ops@client.example".into(),
    };
    e
}

fn scoped_engagement(bssids: &[&str]) -> Engagement {
    let mut e = authorized_engagement(true);
    e.scope = Scope {
        in_scope_bssids: bssids.iter().map(|s| (*s).to_string()).collect(),
        ..Scope::default()
    };
    e
}

fn spec(id: &str) -> ModuleSpec {
    modules::find(id).expect("module exists in registry")
}

fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

// ---------- authorization gate ----------

#[test]
fn unauthorized_blocks_real_run() {
    let e = blank_engagement();
    let s = spec("scan");
    let p = params(&[("iface", "wlan0mon")]);
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_err(), "unauthorized engagement must block real run");
    assert!(res.unwrap_err().contains("LOCKED"));
}

#[test]
fn unauthorized_allows_dry_run_with_warning() {
    let e = blank_engagement();
    let s = spec("scan");
    let p = params(&[("iface", "wlan0mon")]);
    let res = gate(&e, &s, &p, true, false);
    let warnings = res.expect("dry-run must downgrade auth error to warning");
    assert!(warnings.iter().any(|w| w.contains("NOT authorized")));
}

#[test]
fn authorized_passive_runs_clean() {
    let e = authorized_engagement(false);
    let s = spec("scan");
    let p = params(&[("iface", "wlan0mon")]);
    let warnings = gate(&e, &s, &p, false, false).expect("passive module should pass");
    assert!(
        warnings.is_empty() || !warnings.iter().any(|w| w.contains("LOCKED")),
        "unexpected warnings: {warnings:?}"
    );
}

// ---------- disruptive gate ----------

#[test]
fn disruptive_blocked_when_roe_disallows() {
    let e = authorized_engagement(false); // disruptive = false
    let s = spec("deauth");
    let p = params(&[("bssid", "AA:BB:CC:11:22:33"), ("iface", "wlan0mon")]);
    let res = gate(&e, &s, &p, false, true);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("disruptive"));
}

#[test]
fn disruptive_requires_confirmation() {
    let e = authorized_engagement(true);
    let s = spec("deauth");
    let p = params(&[("bssid", "AA:BB:CC:11:22:33"), ("iface", "wlan0mon")]);
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("confirm"));
}

#[test]
fn disruptive_passes_with_roe_and_confirm() {
    let e = authorized_engagement(true);
    let s = spec("deauth");
    let p = params(&[("bssid", "AA:BB:CC:11:22:33"), ("iface", "wlan0mon")]);
    let res = gate(&e, &s, &p, false, true);
    // May warn about empty scope list, but should not block.
    assert!(res.is_ok(), "expected pass, got {res:?}");
}

// ---------- BSSID scope gate ----------

#[test]
fn out_of_scope_bssid_blocks_real_run() {
    let e = scoped_engagement(&["AA:BB:CC:11:22:33"]);
    let s = spec("deauth");
    let p = params(&[("bssid", "DE:AD:BE:EF:00:01"), ("iface", "wlan0mon")]);
    let res = gate(&e, &s, &p, false, true);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .contains("not in the engagement's in-scope"));
}

#[test]
fn in_scope_bssid_passes_case_insensitively() {
    let e = scoped_engagement(&["AA:BB:CC:11:22:33"]);
    let s = spec("deauth");
    let p = params(&[("bssid", "aa:bb:cc:11:22:33"), ("iface", "wlan0mon")]);
    assert!(gate(&e, &s, &p, false, true).is_ok());
}

#[test]
fn empty_scope_list_warns_but_passes() {
    let e = authorized_engagement(true);
    let s = spec("deauth");
    let p = params(&[("bssid", "AA:BB:CC:11:22:33"), ("iface", "wlan0mon")]);
    let warnings = gate(&e, &s, &p, false, true).expect("empty scope list should warn, not block");
    assert!(warnings.iter().any(|w| w.contains("scope not enforced")));
}

// ---------- parameter validation ----------

#[test]
fn essid_starting_with_dash_is_rejected() {
    let e = authorized_engagement(true);
    let s = spec("evil_twin");
    let p = params(&[("essid", "-x"), ("channel", "6"), ("iface", "wlan0mon")]);
    let res = gate(&e, &s, &p, false, true);
    assert!(res.is_err(), "ESSID starting with '-' must be rejected");
    let msg = res.unwrap_err();
    assert!(msg.contains("invalid ESSID"), "got: {msg}");
}

#[test]
fn essid_starting_with_dash_is_rejected_even_in_dry_run() {
    let e = authorized_engagement(true);
    let s = spec("evil_twin");
    let p = params(&[("essid", "--help"), ("channel", "6"), ("iface", "wlan0mon")]);
    // Dry-run must still reject invalid input — there is no useful preview of
    // broken input, and the whole point of validation is to stop injection
    // before the operator sees the previewed command line.
    let res = gate(&e, &s, &p, true, false);
    assert!(res.is_err());
}

#[test]
fn malformed_bssid_is_rejected() {
    let e = authorized_engagement(true);
    let s = spec("deauth");
    let p = params(&[("bssid", "AA-BB-CC-DD-EE-FF"), ("iface", "wlan0mon")]);
    assert!(gate(&e, &s, &p, false, true).is_err());
}

#[test]
fn out_of_range_channel_is_rejected() {
    let e = authorized_engagement(true);
    let s = spec("evil_twin");
    let p = params(&[
        ("essid", "GuestWiFi"),
        ("channel", "9999"),
        ("iface", "wlan0mon"),
    ]);
    let res = gate(&e, &s, &p, false, true);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Channel"));
}

#[test]
fn path_traversal_in_wordlist_is_rejected() {
    let e = authorized_engagement(false);
    let s = spec("wpa_crack");
    let p = params(&[
        ("wordlist", "../../../etc/passwd"),
        ("bssid", "AA:BB:CC:11:22:33"),
        ("capture", "scan-01.cap"),
    ]);
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Wordlist"));
}

#[test]
fn shell_metachars_in_capture_path_are_rejected() {
    let e = authorized_engagement(false);
    let s = spec("wpa_crack");
    let p = params(&[
        ("wordlist", "/usr/share/wordlists/rockyou.txt"),
        ("bssid", "AA:BB:CC:11:22:33"),
        ("capture", "scan.cap; rm -rf /"),
    ]);
    assert!(gate(&e, &s, &p, false, false).is_err());
}

#[test]
fn iface_with_space_is_rejected() {
    let e = authorized_engagement(false);
    let s = spec("scan");
    let p = params(&[("iface", "wlan 0")]);
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("interface"));
}

#[test]
fn missing_required_param_is_rejected() {
    let e = authorized_engagement(false);
    let s = spec("scan");
    let p = params(&[]); // no iface
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("missing required parameter"));
}

#[test]
fn empty_optional_param_is_fine() {
    let e = authorized_engagement(false);
    let s = spec("scan");
    let p = params(&[("iface", "wlan0mon"), ("prefix", "")]);
    assert!(gate(&e, &s, &p, false, false).is_ok());
}

#[test]
fn optional_param_still_validates_if_present() {
    let e = authorized_engagement(false);
    let s = spec("scan");
    let p = params(&[("iface", "wlan0mon"), ("prefix", "-rf")]);
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_err(), "non-empty optional must validate");
    assert!(res.unwrap_err().contains("prefix"));
}

#[test]
fn optional_client_mac_in_deauth_still_validates() {
    let e = authorized_engagement(true);
    let s = spec("deauth");
    let p = params(&[
        ("bssid", "AA:BB:CC:11:22:33"),
        ("iface", "wlan0mon"),
        ("client", "not-a-mac"),
    ]);
    let res = gate(&e, &s, &p, false, true);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Client MAC"));
}

// ---------- nmap_scan (P1.1a) ----------

#[test]
fn nmap_scan_in_scope_cidr_passes() {
    let mut e = authorized_engagement(false);
    e.scope.in_scope_cidrs = vec!["10.0.0.0/24".into()];
    let s = spec("nmap_scan");
    let p = params(&[("cidr", "10.0.0.0/24")]);
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_ok(), "expected pass, got {res:?}");
}

#[test]
fn nmap_scan_out_of_scope_cidr_is_blocked() {
    let mut e = authorized_engagement(false);
    e.scope.in_scope_cidrs = vec!["10.0.0.0/24".into()];
    let s = spec("nmap_scan");
    let p = params(&[("cidr", "10.1.0.0/24")]);
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("in-scope CIDR"));
}

#[test]
fn nmap_scan_malformed_cidr_is_rejected() {
    let mut e = authorized_engagement(false);
    e.scope.in_scope_cidrs = vec!["10.0.0.0/24".into()];
    let s = spec("nmap_scan");
    let p = params(&[("cidr", "10.0.0.0/99")]);
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Target"));
}

#[test]
fn nmap_scan_empty_scope_cidrs_warns_but_passes() {
    let e = authorized_engagement(false);
    let s = spec("nmap_scan");
    let p = params(&[("cidr", "10.0.0.0/24")]);
    let warnings = gate(&e, &s, &p, false, false).expect("empty scope must warn only");
    assert!(warnings.iter().any(|w| w.contains("in-scope CIDR")));
}

#[test]
fn arp_discovery_without_cidr_uses_localnet_and_passes() {
    let e = authorized_engagement(false);
    let s = spec("arp_discovery");
    let p = params(&[("iface", "eth0")]);
    assert!(gate(&e, &s, &p, false, false).is_ok());
}

#[test]
fn arp_discovery_with_cidr_respects_scope() {
    let mut e = authorized_engagement(false);
    e.scope.in_scope_cidrs = vec!["10.0.0.0/24".into()];
    let s = spec("arp_discovery");
    let in_scope = params(&[("iface", "eth0"), ("cidr", "10.0.0.0/24")]);
    assert!(gate(&e, &s, &in_scope, false, false).is_ok());
    let out_of_scope = params(&[("iface", "eth0"), ("cidr", "10.1.0.0/24")]);
    let res = gate(&e, &s, &out_of_scope, false, false);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("in-scope CIDR"));
}

#[test]
fn nmap_scan_ports_validation_rejects_metachars() {
    let mut e = authorized_engagement(false);
    e.scope.in_scope_cidrs = vec!["10.0.0.0/24".into()];
    let s = spec("nmap_scan");
    let p = params(&[("cidr", "10.0.0.0/24"), ("ports", "22;rm -rf /")]);
    let res = gate(&e, &s, &p, false, false);
    assert!(res.is_err());
}
