//! Passive reconnaissance import.
//!
//! Parses an `airodump-ng` CSV capture into a wireless asset inventory. This is
//! purely observational: it reads a file the operator already captured and turns
//! it into structured inventory + draft findings. It performs no transmission.

use crate::model::{AssetKind, Finding, Severity, WirelessAsset};

/// Parse the two-section airodump-ng CSV (APs, then associated stations).
pub fn parse_airodump_csv(content: &str) -> Vec<WirelessAsset> {
    let mut assets = Vec::new();
    // 0 = none, 1 = AP section, 2 = station section
    let mut section = 0u8;

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("BSSID,") {
            section = 1;
            continue;
        }
        if line.starts_with("Station MAC,") {
            section = 2;
            continue;
        }

        let cols: Vec<String> = line.split(',').map(|s| s.trim().to_string()).collect();

        match section {
            1 => {
                if cols.len() < 14 || cols[0].len() < 17 {
                    continue;
                }
                assets.push(WirelessAsset {
                    bssid: cols[0].clone(),
                    essid: cols.get(13).cloned().unwrap_or_default(),
                    channel: cols.get(3).cloned().unwrap_or_default(),
                    encryption: cols.get(5).cloned().unwrap_or_default(),
                    cipher: cols.get(6).cloned().unwrap_or_default(),
                    auth: cols.get(7).cloned().unwrap_or_default(),
                    signal: cols.get(8).cloned().unwrap_or_default(),
                    wps: String::new(),
                    kind: AssetKind::AccessPoint,
                    in_scope: false,
                    notes: String::new(),
                });
            }
            2 => {
                if cols.len() < 6 || cols[0].len() < 17 {
                    continue;
                }
                let associated = cols.get(5).cloned().unwrap_or_default();
                assets.push(WirelessAsset {
                    bssid: associated,
                    essid: cols.get(6).cloned().unwrap_or_default(),
                    signal: cols.get(3).cloned().unwrap_or_default(),
                    kind: AssetKind::Station,
                    notes: format!("Station MAC: {}", cols[0]),
                    ..Default::default()
                });
            }
            _ => {}
        }
    }

    assets
}

/// Derive draft findings from obvious configuration weaknesses in the inventory.
/// These are flagged `auto_detected` and must be reviewed/confirmed by the tester.
pub fn derive_findings(assets: &[WirelessAsset]) -> Vec<Finding> {
    let mut out = Vec::new();

    for a in assets.iter().filter(|a| a.kind == AssetKind::AccessPoint) {
        let enc = a.encryption.to_uppercase();
        let auth = a.auth.to_uppercase();
        let label = if a.essid.is_empty() {
            a.bssid.clone()
        } else {
            format!("{} ({})", a.essid, a.bssid)
        };

        if enc.contains("WEP") {
            out.push(mk(
                format!("Deprecated WEP encryption in use — {label}"),
                Severity::Critical,
                "Encryption & Authentication",
                "Credential Access",
                &label,
                "The access point advertises WEP, a broken encryption scheme whose key can be recovered passively. Any client traffic is effectively unprotected.",
                "Replace with WPA2-AES at minimum; prefer WPA3-SAE. Retire hardware that cannot support WPA2/3.",
            ));
        } else if enc.contains("OPN") || enc.is_empty() {
            out.push(mk(
                format!("Open (unencrypted) network — {label}"),
                Severity::High,
                "Encryption & Authentication",
                "Initial Access",
                &label,
                "The network advertises no link-layer encryption. Traffic is observable to anyone in range and clients are trivially exposed to evil-twin attacks.",
                "Require WPA2-AES/WPA3. If a guest/open network is a business need, isolate it (separate VLAN, client isolation, captive portal) and keep it off the corporate network.",
            ));
        } else if enc.contains("WPA") && !enc.contains("WPA2") && !enc.contains("WPA3") {
            out.push(mk(
                format!("Legacy WPA (TKIP-era) in use — {label}"),
                Severity::High,
                "Encryption & Authentication",
                "Credential Access",
                &label,
                "The access point advertises original WPA (TKIP), which has known weaknesses and should not be relied upon.",
                "Move to WPA2-AES minimum; prefer WPA3-SAE. Disable TKIP fallback.",
            ));
        }

        if auth.contains("PSK") {
            out.push(mk(
                format!("Pre-shared key (PSK) authentication — {label}"),
                Severity::Medium,
                "Encryption & Authentication",
                "Credential Access",
                &label,
                "PSK networks share one secret across all clients and are subject to offline cracking once a handshake is observed. Strength depends entirely on passphrase entropy.",
                "Use a long, high-entropy passphrase (>=20 chars) and rotate it on staff change. For corporate SSIDs, migrate to 802.1X/EAP-TLS (per-user credentials).",
            ));
        }
    }

    out
}

fn mk(
    title: String,
    sev: Severity,
    category: &str,
    tactic: &str,
    asset: &str,
    desc: &str,
    remediation: &str,
) -> Finding {
    let mut f = Finding::new(title);
    f.severity = sev;
    f.category = category.to_string();
    f.attack_tactic = tactic.to_string();
    f.affected_asset = asset.to_string();
    f.description = desc.to_string();
    f.remediation = remediation.to_string();
    f.auto_detected = true;
    f
}
