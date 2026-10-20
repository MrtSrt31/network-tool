//! Unit-style tests for the parameter validator. See `src/validate.rs`.
//!
//! The validator is the first line of defense against argument injection into
//! external wireless tools, so each kind gets both positive and negative
//! coverage.

use network_tool::validate::{check, ParamKind};

fn ok(k: ParamKind, v: &str) {
    assert!(check(k, v).is_ok(), "expected {v:?} to pass {k:?}");
}

fn bad(k: ParamKind, v: &str) {
    assert!(
        check(k, v).is_err(),
        "expected {v:?} to be rejected for {k:?}"
    );
}

// ---------- MAC / BSSID ----------

#[test]
fn mac_accepts_canonical_forms() {
    ok(ParamKind::Mac, "AA:BB:CC:DD:EE:FF");
    ok(ParamKind::Mac, "aa:bb:cc:dd:ee:ff");
    ok(ParamKind::Mac, "A0:B0:C0:D0:E0:F0");
    ok(ParamKind::Mac, "00:00:00:00:00:00");
}

#[test]
fn mac_rejects_wrong_length() {
    bad(ParamKind::Mac, "AA:BB:CC:DD:EE");
    bad(ParamKind::Mac, "AA:BB:CC:DD:EE:FF:00");
    bad(ParamKind::Mac, "");
}

#[test]
fn mac_rejects_dash_or_dot_separator() {
    bad(ParamKind::Mac, "AA-BB-CC-DD-EE-FF");
    bad(ParamKind::Mac, "AABB.CCDD.EEFF");
}

#[test]
fn mac_rejects_non_hex() {
    bad(ParamKind::Mac, "GG:BB:CC:DD:EE:FF");
    bad(ParamKind::Mac, "ZZ:BB:CC:DD:EE:FF");
}

#[test]
fn mac_rejects_argument_injection() {
    bad(ParamKind::Mac, "-AA:BB:CC:DD:EE:FF");
    bad(ParamKind::Mac, "--help");
    bad(ParamKind::Mac, "AA:BB:CC:DD:EE:FF;rm -rf /");
}

// ---------- Channel ----------

#[test]
fn channel_accepts_valid_range() {
    ok(ParamKind::Channel, "1");
    ok(ParamKind::Channel, "6");
    ok(ParamKind::Channel, "36");
    ok(ParamKind::Channel, "165");
    ok(ParamKind::Channel, "196");
}

#[test]
fn channel_rejects_out_of_range() {
    bad(ParamKind::Channel, "0");
    bad(ParamKind::Channel, "197");
    bad(ParamKind::Channel, "9999");
}

#[test]
fn channel_rejects_non_numeric() {
    bad(ParamKind::Channel, "6a");
    bad(ParamKind::Channel, "-1");
    bad(ParamKind::Channel, "+6");
    bad(ParamKind::Channel, "6.0");
    bad(ParamKind::Channel, "6; rm");
    bad(ParamKind::Channel, " 6");
}

// ---------- Interface ----------

#[test]
fn iface_accepts_common_names() {
    ok(ParamKind::Iface, "wlan0");
    ok(ParamKind::Iface, "wlan0mon");
    ok(ParamKind::Iface, "en0");
    ok(ParamKind::Iface, "wlp3s0");
    ok(ParamKind::Iface, "eth0.100");
}

#[test]
fn iface_rejects_argument_injection() {
    bad(ParamKind::Iface, "-wlan0");
    bad(ParamKind::Iface, "--iface=wlan0");
}

#[test]
fn iface_rejects_spaces_and_metachars() {
    bad(ParamKind::Iface, "wlan 0");
    bad(ParamKind::Iface, "wlan0;id");
    bad(ParamKind::Iface, "wlan0|cat");
    bad(ParamKind::Iface, "`id`");
}

#[test]
fn iface_rejects_overlength() {
    bad(ParamKind::Iface, "012345678901234567"); // 18 chars
}

#[test]
fn iface_rejects_empty() {
    bad(ParamKind::Iface, "");
}

// ---------- ESSID ----------

#[test]
fn essid_accepts_normal_names() {
    ok(ParamKind::Essid, "EvsuCorp");
    ok(ParamKind::Essid, "Guest Wi-Fi");
    ok(ParamKind::Essid, "Café");
    ok(ParamKind::Essid, "A");
    // Max 32 bytes, varied punctuation.
    ok(ParamKind::Essid, "ab_c-d.e!@#$% ^&*()+={}[]|\\:;'\",");
}

#[test]
fn essid_rejects_leading_dash() {
    bad(ParamKind::Essid, "-x");
    bad(ParamKind::Essid, "--help");
    bad(ParamKind::Essid, "-EvsuCorp");
}

#[test]
fn essid_rejects_overlength() {
    bad(ParamKind::Essid, &"A".repeat(33));
}

#[test]
fn essid_rejects_newlines_and_nulls() {
    bad(ParamKind::Essid, "line1\nline2");
    bad(ParamKind::Essid, "with\rCR");
    bad(ParamKind::Essid, "nul\0byte");
}

// ---------- Count ----------

#[test]
fn count_accepts_positive_integers() {
    ok(ParamKind::Count, "1");
    ok(ParamKind::Count, "5");
    ok(ParamKind::Count, "100");
    ok(ParamKind::Count, "999999");
}

#[test]
fn count_rejects_boundaries_and_junk() {
    bad(ParamKind::Count, "0");
    bad(ParamKind::Count, "1000000");
    bad(ParamKind::Count, "-1");
    bad(ParamKind::Count, "5x");
    bad(ParamKind::Count, "");
}

// ---------- Path ----------

#[test]
fn path_accepts_normal_paths() {
    ok(ParamKind::Path, "/usr/share/wordlists/rockyou.txt");
    ok(ParamKind::Path, "scan-01.cap");
    ok(ParamKind::Path, "evidence/handshake.pcapng");
    ok(ParamKind::Path, "./capture.cap");
}

#[test]
fn path_rejects_argument_injection() {
    bad(ParamKind::Path, "-rf");
    bad(ParamKind::Path, "--help");
}

#[test]
fn path_rejects_shell_metacharacters() {
    bad(ParamKind::Path, "/tmp/x;rm");
    bad(ParamKind::Path, "/tmp/x|cat");
    bad(ParamKind::Path, "/tmp/$(id)");
    bad(ParamKind::Path, "/tmp/`id`");
    bad(ParamKind::Path, "/tmp/x>out");
    bad(ParamKind::Path, "/tmp/x && y");
    bad(ParamKind::Path, "/path with space");
    bad(ParamKind::Path, "/path/with\"quote");
}

#[test]
fn path_rejects_traversal() {
    bad(ParamKind::Path, "../etc/passwd");
    bad(ParamKind::Path, "/home/../../etc/passwd");
    bad(ParamKind::Path, "a/../b");
}

// ---------- Prefix ----------

#[test]
fn prefix_accepts_safe_names() {
    ok(ParamKind::Prefix, "ntool-scan");
    ok(ParamKind::Prefix, "ntool-hs");
    ok(ParamKind::Prefix, "scan_01");
    ok(ParamKind::Prefix, "scan.v2");
    ok(ParamKind::Prefix, "A");
}

#[test]
fn prefix_rejects_leading_dash_or_dot() {
    bad(ParamKind::Prefix, "-scan");
    bad(ParamKind::Prefix, ".hidden");
}

#[test]
fn prefix_rejects_metachars() {
    bad(ParamKind::Prefix, "scan file");
    bad(ParamKind::Prefix, "scan;id");
    bad(ParamKind::Prefix, "scan/subdir");
    bad(ParamKind::Prefix, "scan*");
}

#[test]
fn prefix_rejects_overlength() {
    bad(ParamKind::Prefix, &"a".repeat(65));
}
