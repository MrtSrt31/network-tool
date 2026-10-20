//! Baked-in reference content: the wireless assessment methodology (PTES-aligned),
//! the hardening/remediation matrix, and controlled vocabularies used by both the
//! GUI dropdowns and the generated report appendices.

/// MITRE ATT&CK techniques relevant to wireless and wired-LAN assessments.
/// Each entry is `(id, name, tactic)`. `id` is what gets stored in a Finding;
/// `name` and `tactic` drive the finding form's datalist and the report's
/// human-readable column.
pub fn attack_techniques() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        ("T1595", "Active Scanning", "Reconnaissance"),
        ("T1595.001", "Scanning IP Blocks", "Reconnaissance"),
        ("T1595.002", "Vulnerability Scanning", "Reconnaissance"),
        ("T1046", "Network Service Discovery", "Discovery"),
        ("T1018", "Remote System Discovery", "Discovery"),
        ("T1087", "Account Discovery", "Discovery"),
        ("T1135", "Network Share Discovery", "Discovery"),
        (
            "T1016",
            "System Network Configuration Discovery",
            "Discovery",
        ),
        ("T1200", "Hardware Additions", "Initial Access"),
        ("T1078", "Valid Accounts", "Initial Access"),
        ("T1557", "Adversary-in-the-Middle", "Credential Access"),
        (
            "T1557.001",
            "LLMNR/NBT-NS Poisoning and SMB Relay",
            "Credential Access",
        ),
        ("T1557.002", "ARP Cache Poisoning", "Credential Access"),
        ("T1557.004", "Evil Twin", "Credential Access"),
        ("T1110", "Brute Force", "Credential Access"),
        ("T1110.001", "Password Guessing", "Credential Access"),
        ("T1110.002", "Password Cracking", "Credential Access"),
        ("T1040", "Network Sniffing", "Credential Access"),
        ("T1498", "Network Denial of Service", "Impact"),
        (
            "T1562.004",
            "Impair Defenses: Disable or Modify System Firewall",
            "Defense Evasion",
        ),
        ("T1021", "Remote Services", "Lateral Movement"),
        ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
    ]
}

/// MITRE link for a technique id (handles sub-techniques like `T1557.001`).
pub fn attack_technique_url(id: &str) -> String {
    match id.split_once('.') {
        Some((base, sub)) => format!("https://attack.mitre.org/techniques/{base}/{sub}/"),
        None => format!("https://attack.mitre.org/techniques/{id}/"),
    }
}

/// MITRE ATT&CK tactics most relevant to wireless assessments.
pub fn attack_tactics() -> &'static [&'static str] {
    &[
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Impact",
    ]
}

/// Finding categories (the wireless attack-surface taxonomy).
pub fn finding_categories() -> &'static [&'static str] {
    &[
        "Encryption & Authentication",
        "WPS",
        "Rogue / Evil Twin & Client-side",
        "Management Frame Protection",
        "Network Segmentation",
        "Management Interface & Infrastructure",
        "Monitoring & Detection",
        "Other",
    ]
}

/// PTES-aligned methodology phases rendered in the report and as an on-screen guide.
pub fn methodology_phases() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "Phase 0 — Pre-engagement (authorization & scope)",
            vec![
                "Signed authorization letter carried by every tester (physical + digital).",
                "Rules of Engagement: test windows, allowed and prohibited techniques.",
                "Scope boundaries: in-scope SSIDs/BSSIDs; neighbouring networks explicitly out of scope.",
                "Disruptive-technique approval (deauth / rogue AP) recorded, or confined to a lab/test SSID.",
                "Emergency stop condition and escalation contact agreed in writing.",
            ],
        ),
        (
            "Phase 1 — Reconnaissance & threat modeling (passive)",
            vec![
                "Passive survey: SSID/BSSID inventory, channels/bands, encryption types, client density, coverage.",
                "Scope validation: confirm which BSSIDs belong to the client; filter out neighbours.",
                "Threat model (STRIDE) per component: AP, controller, client, RADIUS.",
                "Low-touch checks: WPS status, protocol/cipher, 802.11w (PMF) presence.",
            ],
        ),
        (
            "Phase 2 — Controlled validation & post-access",
            vec![
                "Validate each hypothesis using only RoE-permitted techniques.",
                "Assess PSK resilience, WPS exposure, rogue-AP client response, session stability without MFP.",
                "On access: segmentation test, guest isolation, management-interface reachability, internal service exposure.",
                "Document every step immediately with timestamp, BSSID, technique, and result.",
            ],
        ),
        (
            "Phase 3 — Remediation, iterative retest & reporting",
            vec![
                "Apply hardening layer with client IT for each finding.",
                "Re-run the same technique after each fix; mark Mitigated / Partial / Open.",
                "Confirm detectability: do the attacks surface in the client's logs/SIEM?",
                "Deliver final report with executive summary and retest matrix.",
            ],
        ),
    ]
}

/// Finding-class -> layered hardening guidance (remediation reference).
pub fn hardening_matrix() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "WEP / WPA(TKIP) in use",
            "WPA2-AES minimum; prefer WPA3-SAE. Use transition mode deliberately and verify it cannot be downgraded.",
        ),
        (
            "Weak PSK",
            "Long, high-entropy passphrase (>=20 chars / password manager); periodic rotation; migrate corporate SSIDs to 802.1X/EAP-TLS.",
        ),
        (
            "WPS enabled",
            "Disable WPS entirely on all access points and controllers.",
        ),
        (
            "Deauth / disassociation DoS",
            "Enforce 802.11w (Protected Management Frames) in required mode.",
        ),
        (
            "Evil twin / captive-portal credential capture",
            "Certificate-validated EAP on corporate SSIDs; client policy to disable auto-join and forget open networks; deploy WIDS/WIPS for rogue-AP detection.",
        ),
        (
            "Weak segmentation",
            "Guest network on a separate VLAN with internet-only egress; enable client isolation; keep the management VLAN unreachable from wireless.",
        ),
        (
            "Default management credentials",
            "Strong unique credentials, MFA, and move the management interface out-of-band.",
        ),
        (
            "Outdated firmware / known CVEs",
            "Patch-management process and a firmware update cadence for APs and controllers.",
        ),
        (
            "Insufficient monitoring",
            "Ship AP/controller logs to SIEM; WIDS/WIPS alerts for deauth floods, rogue APs, and auth anomalies; correlation rules per ATT&CK technique.",
        ),
    ]
}
