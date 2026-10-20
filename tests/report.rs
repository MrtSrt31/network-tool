//! Smoke tests for the report and RoE renderers: they should never panic,
//! should always emit valid-looking HTML/Markdown, and should always
//! include the audit-chain footer the operator (and the client) rely on.

use network_tool::audit;
use network_tool::model::{
    ActionRun, AssetKind, Authorization, Dread, Engagement, Finding, FindingStatus, Scope,
    Severity, WirelessAsset,
};
use network_tool::{report, roe};

fn empty_engagement() -> Engagement {
    Engagement::new("Empty engagement".into())
}

fn populated_engagement() -> Engagement {
    let mut e = Engagement::new("Smoke engagement".into());
    e.client.name = "Smoke Client".into();
    e.tester.name = "QA".into();
    e.tester.email = "qa@local".into();
    e.scope = Scope {
        in_scope_bssids: vec!["AA:BB:CC:11:22:33".into()],
        in_scope_ssids: vec!["Corp".into()],
        ..Scope::default()
    };
    e.authorization = Authorization {
        authorized: true,
        authorizer_name: "Client CISO".into(),
        authorizer_title: "CISO".into(),
        signed_date: "2026-10-20".into(),
        roe_reference: "ROE-123".into(),
        disruptive_allowed: true,
        emergency_contact: "ops@client.local".into(),
    };
    e.assets.push(WirelessAsset {
        bssid: "AA:BB:CC:11:22:33".into(),
        essid: "Corp".into(),
        channel: "6".into(),
        encryption: "WPA2".into(),
        cipher: "CCMP".into(),
        auth: "PSK".into(),
        wps: "".into(),
        signal: "-40".into(),
        kind: AssetKind::AccessPoint,
        in_scope: true,
        notes: "".into(),
    });
    let mut f = Finding::new("Weak PSK on Corp".into());
    f.severity = Severity::High;
    f.category = "Encryption & Authentication".into();
    f.attack_tactic = "Credential Access".into();
    f.technique_id = "T1110".into();
    f.cvss_vector = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L".into();
    f.cvss_score = 7.2;
    f.affected_asset = "Corp (AA:BB:CC:11:22:33)".into();
    f.description = "Short dictionary passphrase.".into();
    f.remediation = "Rotate to 20+ chars, migrate to 802.1X.".into();
    f.status = FindingStatus::Open;
    f.dread = Dread {
        damage: 6,
        reproducibility: 7,
        exploitability: 7,
        affected_users: 8,
        discoverability: 5,
    };
    e.findings.push(f);
    let action = ActionRun {
        id: "a-smoke".into(),
        at: chrono::Utc::now(),
        module_id: "scan".into(),
        module_name: "Survey / discovery scan".into(),
        target: "wlan0mon".into(),
        command: "airodump-ng --output-format csv -w ntool-scan wlan0mon".into(),
        disruptive: false,
        dry_run: true,
        exit_code: Some(0),
        timed_out: false,
        summary: "dry-run (not executed)".into(),
        operator: "QA".into(),
        prev_hash: String::new(),
        hash: String::new(),
    };
    let sealed = audit::seal_new_action(&e, action);
    e.action_log.push(sealed);
    e
}

// ---------- report ----------

#[test]
fn report_markdown_renders_an_empty_engagement_without_panic() {
    let e = empty_engagement();
    let md = report::markdown(&e);
    assert!(md.contains("Wireless Security Assessment"));
    assert!(md.contains("Executive summary"));
}

#[test]
fn report_html_renders_an_empty_engagement_without_panic() {
    let e = empty_engagement();
    let html = report::html(&e);
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("Wireless Security Assessment"));
    assert!(html.contains("</html>"));
}

#[test]
fn report_markdown_includes_the_audit_chain_footer() {
    let e = populated_engagement();
    let md = report::markdown(&e);
    let head = audit::chain_head(&e);
    assert!(
        md.contains(&head),
        "report must commit to the chain head in its footer"
    );
    assert!(md.contains("audit verify"));
}

#[test]
fn report_html_includes_the_audit_chain_footer() {
    let e = populated_engagement();
    let html = report::html(&e);
    let head = audit::chain_head(&e);
    assert!(html.contains(&head));
    assert!(html.contains("audit verify"));
}

#[test]
fn report_html_contains_the_finding_title_and_severity() {
    let e = populated_engagement();
    let html = report::html(&e);
    assert!(html.contains("Weak PSK on Corp"));
    assert!(html.contains("High"));
}

#[test]
fn report_html_does_not_leak_raw_special_characters_from_input() {
    let mut e = empty_engagement();
    e.name = "Pentest <script>alert(1)</script>".into();
    let html = report::html(&e);
    assert!(
        !html.contains("<script>alert(1)</script>"),
        "html must escape special characters in engagement name"
    );
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
}

// ---------- RoE ----------

#[test]
fn roe_html_renders_as_draft_when_not_authorized() {
    let e = empty_engagement();
    let html = roe::html(&e);
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("DRAFT"));
}

#[test]
fn roe_html_drops_draft_banner_once_authorized() {
    let e = populated_engagement();
    let html = roe::html(&e);
    assert!(
        !html.contains("DRAFT"),
        "authorized RoE should not say DRAFT"
    );
    assert!(html.contains("Client CISO"));
    assert!(html.contains("ROE-123"));
}

#[test]
fn roe_markdown_renders_without_panic() {
    let e = populated_engagement();
    let md = roe::markdown(&e);
    assert!(md.contains("Authorization"));
    assert!(md.contains("Client CISO"));
}
