//! Baked-in reference content: the wireless assessment methodology (PTES-aligned),
//! the hardening/remediation matrix, and controlled vocabularies used by both the
//! GUI dropdowns and the generated report appendices.

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
