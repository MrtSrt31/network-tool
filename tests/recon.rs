//! Tests for the airodump-ng CSV importer and the draft-finding deriver.
//!
//! The fixture mimics the two-section airodump CSV format: a header for
//! access points, their rows, a blank line, then a header for associated
//! stations and their rows. We cover WEP, Open, legacy WPA (TKIP) and WPA2
//! so the derive_findings heuristics are exercised end to end.

use network_tool::model::{AssetKind, Severity};
use network_tool::recon::{derive_findings, parse_airodump_csv};

const SAMPLE: &str = "\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:11:22:33, 2026-10-20 10:00:00, 2026-10-20 10:05:00,  6,  54, WEP , WEP , SKA , -40,  200,  120,   0.  0.  0.  0,  8, LegacyWEP,
AA:BB:CC:44:55:66, 2026-10-20 10:00:00, 2026-10-20 10:05:00,  1,  54, OPN , , , -55,  180,    0,   0.  0.  0.  0,  5, Guest,
AA:BB:CC:77:88:99, 2026-10-20 10:00:00, 2026-10-20 10:05:00, 11, 130, WPA , TKIP, PSK , -60,  150,   30,   0.  0.  0.  0,  7, OldWPA,
AA:BB:CC:AA:BB:CC, 2026-10-20 10:00:00, 2026-10-20 10:05:00,  6, 540, WPA2, CCMP, PSK , -42,  420,  600,   0.  0.  0.  0,  7, Corp-WiFi,
AA:BB:CC:DD:EE:FF, 2026-10-20 10:00:00, 2026-10-20 10:05:00, 36, 866, WPA3, CCMP, SAE , -50,  110,   10,   0.  0.  0.  0,  7, NewSSID,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
AA:00:11:22:33:44, 2026-10-20 10:01:00, 2026-10-20 10:04:00,  -45,  25, AA:BB:CC:AA:BB:CC, Corp-WiFi
BB:00:11:22:33:44, 2026-10-20 10:02:00, 2026-10-20 10:04:30,  -70,   8, (not associated), ProbeSSID1
";

#[test]
fn parses_access_points_and_stations_into_separate_kinds() {
    let assets = parse_airodump_csv(SAMPLE);
    let aps: Vec<_> = assets
        .iter()
        .filter(|a| a.kind == AssetKind::AccessPoint)
        .collect();
    let stations: Vec<_> = assets
        .iter()
        .filter(|a| a.kind == AssetKind::Station)
        .collect();
    assert_eq!(aps.len(), 5, "5 access-point rows");
    assert_eq!(stations.len(), 2, "2 station rows");
}

#[test]
fn access_point_fields_round_trip_from_csv() {
    let assets = parse_airodump_csv(SAMPLE);
    let legacy = assets
        .iter()
        .find(|a| a.bssid == "AA:BB:CC:11:22:33")
        .expect("WEP AP present");
    assert_eq!(legacy.essid, "LegacyWEP");
    assert_eq!(legacy.channel, "6");
    assert!(
        legacy.encryption.to_uppercase().contains("WEP"),
        "got {:?}",
        legacy.encryption
    );
}

#[test]
fn wep_network_derives_a_critical_finding() {
    let assets = parse_airodump_csv(SAMPLE);
    let findings = derive_findings(&assets);
    let wep_finding = findings
        .iter()
        .find(|f| f.title.contains("WEP"))
        .expect("expected a WEP finding");
    assert_eq!(wep_finding.severity, Severity::Critical);
    assert!(wep_finding.auto_detected);
    assert!(wep_finding.affected_asset.contains("LegacyWEP"));
}

#[test]
fn open_network_derives_a_high_finding() {
    let assets = parse_airodump_csv(SAMPLE);
    let findings = derive_findings(&assets);
    let open = findings
        .iter()
        .find(|f| f.title.contains("Open"))
        .expect("expected an Open-network finding");
    assert_eq!(open.severity, Severity::High);
    assert!(open.affected_asset.contains("Guest"));
}

#[test]
fn legacy_wpa_derives_a_high_finding() {
    let assets = parse_airodump_csv(SAMPLE);
    let findings = derive_findings(&assets);
    let legacy_wpa = findings
        .iter()
        .find(|f| f.title.contains("Legacy WPA"))
        .expect("expected a legacy WPA finding");
    assert_eq!(legacy_wpa.severity, Severity::High);
    assert!(legacy_wpa.affected_asset.contains("OldWPA"));
}

#[test]
fn wpa2_psk_derives_a_medium_psk_finding() {
    let assets = parse_airodump_csv(SAMPLE);
    let findings = derive_findings(&assets);
    let psk = findings
        .iter()
        .filter(|f| f.title.contains("Pre-shared key"))
        .find(|f| f.affected_asset.contains("Corp-WiFi"))
        .expect("expected a PSK finding for the WPA2-PSK network");
    assert_eq!(psk.severity, Severity::Medium);
}

#[test]
fn wpa3_network_does_not_trigger_legacy_findings() {
    let assets = parse_airodump_csv(SAMPLE);
    let findings = derive_findings(&assets);
    // No WEP / Open / legacy-WPA finding should mention the WPA3 SSID.
    for f in &findings {
        if f.title.contains("WEP") || f.title.contains("Open") || f.title.contains("Legacy WPA") {
            assert!(
                !f.affected_asset.contains("NewSSID"),
                "WPA3 network should not trigger {:?}",
                f.title
            );
        }
    }
}

#[test]
fn associated_station_rows_point_back_at_their_ap_bssid() {
    let assets = parse_airodump_csv(SAMPLE);
    let st = assets
        .iter()
        .find(|a| a.kind == AssetKind::Station && a.bssid == "AA:BB:CC:AA:BB:CC")
        .expect("associated station row");
    assert!(st.notes.contains("AA:00:11:22:33:44"));
}

#[test]
fn empty_input_yields_no_assets_and_no_findings() {
    let assets = parse_airodump_csv("");
    assert!(assets.is_empty());
    assert!(derive_findings(&assets).is_empty());
}

#[test]
fn malformed_rows_are_skipped_without_panic() {
    let bad = "\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
short,row
AA:BB:CC:11:22:33, 2026-10-20, 2026-10-20, 6, 54, WPA2, CCMP, PSK, -40, 10, 0, 0, 9, Corp,
";
    let assets = parse_airodump_csv(bad);
    assert_eq!(
        assets
            .iter()
            .filter(|a| a.kind == AssetKind::AccessPoint)
            .count(),
        1,
        "only the one well-formed row should parse"
    );
}
