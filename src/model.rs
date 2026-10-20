//! Domain model for a wireless security assessment engagement.
//!
//! Everything is serde-serializable so an engagement persists as a single
//! human-readable JSON file (git-friendly for a consultancy).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Short, readable id (first 8 hex of a v4 UUID).
pub fn new_id() -> String {
    let s = Uuid::new_v4().simple().to_string();
    s[..8].to_string()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Engagement {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub status: EngagementStatus,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub client: Client,
    #[serde(default)]
    pub tester: Tester,
    #[serde(default)]
    pub scope: Scope,
    #[serde(default)]
    pub authorization: Authorization,
    #[serde(default)]
    pub assets: Vec<WirelessAsset>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub action_log: Vec<ActionRun>,
    /// Monotonically increasing version, bumped on every successful save.
    /// Used by `store::save` for optimistic-concurrency conflict detection.
    #[serde(default)]
    pub version: u64,
}

impl Engagement {
    pub fn new(name: String) -> Self {
        Engagement {
            id: new_id(),
            name,
            status: EngagementStatus::Planning,
            created_at: Utc::now(),
            client: Client::default(),
            tester: Tester::default(),
            scope: Scope::default(),
            authorization: Authorization::default(),
            assets: vec![],
            findings: vec![],
            action_log: vec![],
            version: 0,
        }
    }

    /// Active (intrusive) testing is only unlocked when a signed authorization
    /// is on file. This is the core safety gate of the platform.
    pub fn active_testing_unlocked(&self) -> bool {
        self.authorization.authorized
            && !self.authorization.authorizer_name.trim().is_empty()
            && !self.authorization.signed_date.trim().is_empty()
    }

    pub fn finding(&self, id: &str) -> Option<&Finding> {
        self.findings.iter().find(|f| f.id == id)
    }

    pub fn severity_counts(&self) -> [usize; 5] {
        let mut c = [0usize; 5];
        for f in &self.findings {
            c[f.severity.index()] += 1;
        }
        c
    }

    pub fn open_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.status != FindingStatus::Mitigated && f.status != FindingStatus::Accepted)
            .count()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub enum EngagementStatus {
    #[default]
    Planning,
    Active,
    Remediation,
    Closed,
}

impl EngagementStatus {
    pub fn label(&self) -> &'static str {
        match self {
            EngagementStatus::Planning => "Planning",
            EngagementStatus::Active => "Active",
            EngagementStatus::Remediation => "Remediation",
            EngagementStatus::Closed => "Closed",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "Active" => EngagementStatus::Active,
            "Remediation" => EngagementStatus::Remediation,
            "Closed" => EngagementStatus::Closed,
            _ => EngagementStatus::Planning,
        }
    }
    pub fn all_labels() -> Vec<&'static str> {
        vec!["Planning", "Active", "Remediation", "Closed"]
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Client {
    pub name: String,
    pub contact_name: String,
    pub contact_email: String,
    pub site_address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Tester {
    pub name: String,
    pub email: String,
    pub company: String,
    pub role: String,
    pub certifications: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Scope {
    /// black-box / grey-box / white-box
    pub approach: String,
    pub in_scope_ssids: Vec<String>,
    pub in_scope_bssids: Vec<String>,
    pub out_of_scope_notes: String,
    pub test_windows: String,
    pub allowed_techniques: Vec<String>,
    pub prohibited_techniques: Vec<String>,
    pub notes: String,
}

/// Signed authorization / Rules of Engagement reference. Without this the
/// platform keeps active testing locked.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Authorization {
    pub authorized: bool,
    pub authorizer_name: String,
    pub authorizer_title: String,
    pub signed_date: String,
    pub roe_reference: String,
    /// Whether disruptive techniques (deauth / rogue AP) are explicitly permitted.
    pub disruptive_allowed: bool,
    pub emergency_contact: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub enum AssetKind {
    #[default]
    AccessPoint,
    Station,
    Unknown,
}

impl AssetKind {
    pub fn label(&self) -> &'static str {
        match self {
            AssetKind::AccessPoint => "AP",
            AssetKind::Station => "Station",
            AssetKind::Unknown => "Unknown",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct WirelessAsset {
    pub bssid: String,
    pub essid: String,
    pub channel: String,
    pub encryption: String,
    pub cipher: String,
    pub auth: String,
    pub wps: String,
    pub signal: String,
    #[serde(default)]
    pub kind: AssetKind,
    pub in_scope: bool,
    pub notes: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn index(&self) -> usize {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
    pub fn color(&self) -> &'static str {
        match self {
            Severity::Info => "#5b8def",
            Severity::Low => "#3fb950",
            Severity::Medium => "#d29922",
            Severity::High => "#f0883e",
            Severity::Critical => "#f85149",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "Info" => Severity::Info,
            "Low" => Severity::Low,
            "High" => Severity::High,
            "Critical" => Severity::Critical,
            _ => Severity::Medium,
        }
    }
    pub fn all() -> [Severity; 5] {
        [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ]
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub enum FindingStatus {
    #[default]
    Open,
    Remediating,
    Retesting,
    Mitigated,
    Accepted,
}

impl FindingStatus {
    pub fn label(&self) -> &'static str {
        match self {
            FindingStatus::Open => "Open",
            FindingStatus::Remediating => "Remediating",
            FindingStatus::Retesting => "Retesting",
            FindingStatus::Mitigated => "Mitigated",
            FindingStatus::Accepted => "Accepted (risk)",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "Remediating" => FindingStatus::Remediating,
            "Retesting" => FindingStatus::Retesting,
            "Mitigated" => FindingStatus::Mitigated,
            "Accepted" => FindingStatus::Accepted,
            _ => FindingStatus::Open,
        }
    }
    pub fn all() -> [FindingStatus; 5] {
        [
            FindingStatus::Open,
            FindingStatus::Remediating,
            FindingStatus::Retesting,
            FindingStatus::Mitigated,
            FindingStatus::Accepted,
        ]
    }
}

/// DREAD risk rating, each component 0..=10.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Dread {
    pub damage: u8,
    pub reproducibility: u8,
    pub exploitability: u8,
    pub affected_users: u8,
    pub discoverability: u8,
}

impl Dread {
    pub fn score(&self) -> f32 {
        let sum = self.damage as u32
            + self.reproducibility as u32
            + self.exploitability as u32
            + self.affected_users as u32
            + self.discoverability as u32;
        sum as f32 / 5.0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub enum RetestResult {
    #[default]
    Open,
    Partial,
    Mitigated,
}

impl RetestResult {
    pub fn label(&self) -> &'static str {
        match self {
            RetestResult::Open => "Still Open",
            RetestResult::Partial => "Partially Mitigated",
            RetestResult::Mitigated => "Mitigated",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "Partial" => RetestResult::Partial,
            "Mitigated" => RetestResult::Mitigated,
            _ => RetestResult::Open,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Retest {
    pub date: String,
    pub technique: String,
    pub result: RetestResult,
    pub notes: String,
}

/// An immutable record of an active-module invocation (evidence / audit trail).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ActionRun {
    pub id: String,
    pub at: DateTime<Utc>,
    pub module_id: String,
    pub module_name: String,
    pub target: String,
    pub command: String,
    pub disruptive: bool,
    pub dry_run: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub summary: String,
    pub operator: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub category: String,
    #[serde(default)]
    pub severity: Severity,
    /// MITRE ATT&CK tactic (e.g. "Initial Access", "Credential Access").
    pub attack_tactic: String,
    /// Technique id, operator-supplied (e.g. "T1557").
    pub technique_id: String,
    pub cvss_vector: String,
    #[serde(default)]
    pub cvss_score: f32,
    #[serde(default)]
    pub dread: Dread,
    pub affected_asset: String,
    pub description: String,
    pub evidence: String,
    pub impact: String,
    pub remediation: String,
    #[serde(default)]
    pub status: FindingStatus,
    #[serde(default)]
    pub retests: Vec<Retest>,
    pub created_at: DateTime<Utc>,
    /// True when auto-suggested from a recon import (not yet operator-confirmed).
    #[serde(default)]
    pub auto_detected: bool,
}

impl Finding {
    pub fn new(title: String) -> Self {
        Finding {
            id: new_id(),
            title,
            category: String::new(),
            severity: Severity::Medium,
            attack_tactic: String::new(),
            technique_id: String::new(),
            cvss_vector: String::new(),
            cvss_score: 0.0,
            dread: Dread::default(),
            affected_asset: String::new(),
            description: String::new(),
            evidence: String::new(),
            impact: String::new(),
            remediation: String::new(),
            status: FindingStatus::Open,
            retests: vec![],
            created_at: Utc::now(),
            auto_detected: false,
        }
    }
}
