//! CVSS v3.1 Base Score parser and calculator.
//!
//! The input is a vector string that follows the FIRST specification, e.g.
//! `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. [`Vector::parse`] decodes
//! it into typed metric values; [`Vector::base_score`] produces the base
//! score and the matching qualitative severity band. Both are pure
//! functions, exhaustively covered by tests below.
//!
//! The CVSS 3.1 "roundup" function (ceiling to 1 decimal place) is
//! implemented verbatim from the spec using 100000-scaled integer math,
//! so the computed scores line up bit-for-bit with the FIRST calculator.

/// Base-metric enums. Values follow the CVSS 3.1 specification; parse errors
/// name the offending metric so operators get a clear message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cia {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vector {
    pub av: AttackVector,
    pub ac: AttackComplexity,
    pub pr: PrivilegesRequired,
    pub ui: UserInteraction,
    pub s: Scope,
    pub c: Cia,
    pub i: Cia,
    pub a: Cia,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::None => "None",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    pub fn from_score(score: f64) -> Severity {
        if score <= 0.0 {
            Severity::None
        } else if score < 4.0 {
            Severity::Low
        } else if score < 7.0 {
            Severity::Medium
        } else if score < 9.0 {
            Severity::High
        } else {
            Severity::Critical
        }
    }
}

impl Vector {
    /// Parse a `CVSS:3.1/...` vector. Returns an error message naming the
    /// first problem (bad prefix, unknown metric, bad value, missing
    /// required metric).
    pub fn parse(s: &str) -> Result<Vector, String> {
        let s = s.trim();
        let parts: Vec<&str> = s.split('/').collect();
        if parts.is_empty() || parts[0] != "CVSS:3.1" {
            return Err(format!(
                "'{s}': expected a CVSS:3.1 vector (first segment must be CVSS:3.1)"
            ));
        }
        let mut av = None;
        let mut ac = None;
        let mut pr = None;
        let mut ui = None;
        let mut sc = None;
        let mut c = None;
        let mut i = None;
        let mut a = None;
        for raw in &parts[1..] {
            let (k, v) = match raw.split_once(':') {
                Some(kv) => kv,
                None => return Err(format!("'{raw}': expected 'KEY:VALUE'")),
            };
            match k {
                "AV" => av = Some(parse_av(v)?),
                "AC" => ac = Some(parse_ac(v)?),
                "PR" => pr = Some(parse_pr(v)?),
                "UI" => ui = Some(parse_ui(v)?),
                "S" => sc = Some(parse_scope(v)?),
                "C" => c = Some(parse_cia("C", v)?),
                "I" => i = Some(parse_cia("I", v)?),
                "A" => a = Some(parse_cia("A", v)?),
                // Temporal / environmental metrics are silently accepted and
                // ignored for base-score purposes — matches the FIRST
                // calculator's behavior when only Base is requested.
                "E" | "RL" | "RC" | "CR" | "IR" | "AR" | "MAV" | "MAC" | "MPR" | "MUI" | "MS"
                | "MC" | "MI" | "MA" => {}
                other => return Err(format!("unknown CVSS metric '{other}'")),
            }
        }
        Ok(Vector {
            av: av.ok_or("missing required metric: AV".to_string())?,
            ac: ac.ok_or("missing required metric: AC".to_string())?,
            pr: pr.ok_or("missing required metric: PR".to_string())?,
            ui: ui.ok_or("missing required metric: UI".to_string())?,
            s: sc.ok_or("missing required metric: S".to_string())?,
            c: c.ok_or("missing required metric: C".to_string())?,
            i: i.ok_or("missing required metric: I".to_string())?,
            a: a.ok_or("missing required metric: A".to_string())?,
        })
    }

    /// Compute the CVSS 3.1 Base Score for this vector.
    pub fn base_score(&self) -> f64 {
        let c_val = cia_value(self.c);
        let i_val = cia_value(self.i);
        let a_val = cia_value(self.a);
        let iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val));
        let impact = match self.s {
            Scope::Unchanged => 6.42 * iss,
            Scope::Changed => 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0),
        };
        let exploitability = 8.22
            * av_value(self.av)
            * ac_value(self.ac)
            * pr_value(self.pr, self.s)
            * ui_value(self.ui);
        if impact <= 0.0 {
            return 0.0;
        }
        let base = match self.s {
            Scope::Unchanged => (impact + exploitability).min(10.0),
            Scope::Changed => (1.08 * (impact + exploitability)).min(10.0),
        };
        roundup(base)
    }

    pub fn severity(&self) -> Severity {
        Severity::from_score(self.base_score())
    }
}

fn parse_av(v: &str) -> Result<AttackVector, String> {
    match v {
        "N" => Ok(AttackVector::Network),
        "A" => Ok(AttackVector::Adjacent),
        "L" => Ok(AttackVector::Local),
        "P" => Ok(AttackVector::Physical),
        _ => Err(format!("AV: unknown value '{v}'")),
    }
}
fn parse_ac(v: &str) -> Result<AttackComplexity, String> {
    match v {
        "L" => Ok(AttackComplexity::Low),
        "H" => Ok(AttackComplexity::High),
        _ => Err(format!("AC: unknown value '{v}'")),
    }
}
fn parse_pr(v: &str) -> Result<PrivilegesRequired, String> {
    match v {
        "N" => Ok(PrivilegesRequired::None),
        "L" => Ok(PrivilegesRequired::Low),
        "H" => Ok(PrivilegesRequired::High),
        _ => Err(format!("PR: unknown value '{v}'")),
    }
}
fn parse_ui(v: &str) -> Result<UserInteraction, String> {
    match v {
        "N" => Ok(UserInteraction::None),
        "R" => Ok(UserInteraction::Required),
        _ => Err(format!("UI: unknown value '{v}'")),
    }
}
fn parse_scope(v: &str) -> Result<Scope, String> {
    match v {
        "U" => Ok(Scope::Unchanged),
        "C" => Ok(Scope::Changed),
        _ => Err(format!("S: unknown value '{v}'")),
    }
}
fn parse_cia(name: &str, v: &str) -> Result<Cia, String> {
    match v {
        "N" => Ok(Cia::None),
        "L" => Ok(Cia::Low),
        "H" => Ok(Cia::High),
        _ => Err(format!("{name}: unknown value '{v}'")),
    }
}

fn av_value(x: AttackVector) -> f64 {
    match x {
        AttackVector::Network => 0.85,
        AttackVector::Adjacent => 0.62,
        AttackVector::Local => 0.55,
        AttackVector::Physical => 0.2,
    }
}
fn ac_value(x: AttackComplexity) -> f64 {
    match x {
        AttackComplexity::Low => 0.77,
        AttackComplexity::High => 0.44,
    }
}
fn pr_value(x: PrivilegesRequired, s: Scope) -> f64 {
    match (x, s) {
        (PrivilegesRequired::None, _) => 0.85,
        (PrivilegesRequired::Low, Scope::Unchanged) => 0.62,
        (PrivilegesRequired::Low, Scope::Changed) => 0.68,
        (PrivilegesRequired::High, Scope::Unchanged) => 0.27,
        (PrivilegesRequired::High, Scope::Changed) => 0.5,
    }
}
fn ui_value(x: UserInteraction) -> f64 {
    match x {
        UserInteraction::None => 0.85,
        UserInteraction::Required => 0.62,
    }
}
fn cia_value(x: Cia) -> f64 {
    match x {
        Cia::None => 0.0,
        Cia::Low => 0.22,
        Cia::High => 0.56,
    }
}

/// CVSS 3.1 roundup: ceiling to one decimal place, implemented via
/// 100000-scaled integer math to avoid floating-point drift.
fn roundup(x: f64) -> f64 {
    let scaled = (x * 100000.0).round() as i64;
    if scaled % 10000 == 0 {
        scaled as f64 / 100000.0
    } else {
        ((scaled / 10000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(v: &str) -> f64 {
        Vector::parse(v).unwrap().base_score()
    }

    // ---------- FIRST official examples (hand-verified against the spec) ----------

    #[test]
    fn eternalblue_cvss_vector() {
        // CVE-2017-0144 (EternalBlue) — official CVSS 3.1 vector, score 8.1.
        let v = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H";
        assert_eq!(score(v), 8.1);
    }

    #[test]
    fn log4shell_cvss_vector() {
        // Log4Shell (CVE-2021-44228) — official vector, score 10.0.
        let v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";
        assert_eq!(score(v), 10.0);
    }

    #[test]
    fn heartbleed_style_vector_scores_7_5() {
        // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N — classic data-exposure.
        let v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
        assert_eq!(score(v), 7.5);
    }

    #[test]
    fn none_impact_scores_zero() {
        let v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";
        assert_eq!(score(v), 0.0);
    }

    #[test]
    fn local_physical_low_impact_vector() {
        // AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L
        // ISS = 1 - 0.78^3 = 0.52545; Impact = 6.42 * ISS = 3.3734
        // Exploitability = 8.22 * 0.2 * 0.44 * 0.27 * 0.62 = 0.1211
        // Base = min(3.4945, 10) = 3.4945 → roundup = 3.5
        let v = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L";
        assert_eq!(score(v), 3.5);
    }

    #[test]
    fn scope_change_amplifies_score() {
        let unchanged = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
        let changed = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
        assert!(changed > unchanged, "{changed} should be > {unchanged}");
    }

    // ---------- parser error paths ----------

    #[test]
    fn parse_rejects_missing_prefix() {
        assert!(Vector::parse("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err());
    }

    #[test]
    fn parse_rejects_v3_0_prefix() {
        assert!(Vector::parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err());
    }

    #[test]
    fn parse_rejects_unknown_metric_value() {
        assert!(Vector::parse("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err());
    }

    #[test]
    fn parse_rejects_missing_required_metric() {
        // Missing A: at the end.
        let err = Vector::parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H").unwrap_err();
        assert!(err.contains("missing required metric: A"), "got: {err}");
    }

    #[test]
    fn parse_accepts_and_ignores_temporal_and_env_metrics() {
        // Mix Base + Temporal/Env — must parse and score as Base-only.
        let v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/CR:H";
        let parsed = Vector::parse(v).expect("accepts temporal + env");
        assert_eq!(parsed.base_score(), 9.8);
    }

    // ---------- severity bands ----------

    #[test]
    fn severity_bands_match_cvss_spec() {
        assert_eq!(Severity::from_score(0.0), Severity::None);
        assert_eq!(Severity::from_score(0.1), Severity::Low);
        assert_eq!(Severity::from_score(3.9), Severity::Low);
        assert_eq!(Severity::from_score(4.0), Severity::Medium);
        assert_eq!(Severity::from_score(6.9), Severity::Medium);
        assert_eq!(Severity::from_score(7.0), Severity::High);
        assert_eq!(Severity::from_score(8.9), Severity::High);
        assert_eq!(Severity::from_score(9.0), Severity::Critical);
        assert_eq!(Severity::from_score(10.0), Severity::Critical);
    }

    // ---------- roundup property ----------

    #[test]
    fn roundup_preserves_exact_tenths() {
        assert_eq!(roundup(7.5), 7.5);
        assert_eq!(roundup(0.0), 0.0);
        assert_eq!(roundup(10.0), 10.0);
    }

    #[test]
    fn roundup_ceilings_to_nearest_tenth() {
        assert_eq!(roundup(4.001), 4.1);
        assert_eq!(roundup(6.19), 6.2);
    }
}
