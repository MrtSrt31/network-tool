//! Scope matching: decide whether a target (IP/CIDR, MAC, SSID) is in the
//! engagement's authorised scope.
//!
//! Three dimensions:
//! - **IPv4 subnet containment**: a target like `10.0.5.17` matches an
//!   allowed `10.0.0.0/16`. A target that is itself a CIDR (`10.0.5.0/24`)
//!   matches when its network is contained in the allowed CIDR.
//! - **MAC / BSSID**: exact match (case-insensitive) OR OUI prefix — a
//!   three-octet string like `AA:BB:CC` matches any BSSID that starts with
//!   those three octets, which is how enterprise APs with sequential
//!   BSSIDs are usually scoped.
//! - **SSID glob**: `*` matches any run of characters, `?` matches exactly
//!   one, every other character is literal. Case-insensitive.
//!
//! All matchers are pure functions, exhaustively tested below. The gate
//! calls them from `modules::gate` so a scope decision has one source of
//! truth.

/// Parse an IPv4 CIDR `A.B.C.D/N` (or a bare `A.B.C.D`, treated as /32).
/// Returns `(network, prefix_bits)` with the host bits zeroed out, so
/// callers compare networks directly.
pub fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (s, 32u8),
    };
    if prefix > 32 {
        return None;
    }
    let octets: Vec<u32> = addr
        .split('.')
        .map(|o| o.parse::<u32>().ok())
        .collect::<Option<Vec<_>>>()?;
    if octets.len() != 4 || octets.iter().any(|o| *o > 255) {
        return None;
    }
    let ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((ip & mask, prefix))
}

/// Is `target` (a single IP or a CIDR) contained in `allowed` (a CIDR)?
/// A single IP is treated as /32. Containment: the target's network, masked
/// to the allowed prefix, must equal the allowed network, and the target
/// prefix must be at least as specific (>=) as the allowed prefix.
pub fn ipv4_in_cidr(target: &str, allowed: &str) -> bool {
    let Some((t_net, t_pref)) = parse_cidr(target) else {
        return false;
    };
    let Some((a_net, a_pref)) = parse_cidr(allowed) else {
        return false;
    };
    if t_pref < a_pref {
        return false; // target is broader than the allowed range
    }
    let mask = if a_pref == 0 {
        0
    } else {
        u32::MAX << (32 - a_pref)
    };
    (t_net & mask) == (a_net & mask)
}

/// Any-of: does `target` fall into any of the allowed CIDRs?
pub fn ipv4_in_any(target: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| ipv4_in_cidr(target, a.trim()))
}

/// Does `target` MAC match `allowed`? Allowed may be a full MAC
/// `AA:BB:CC:DD:EE:FF` (exact match, case-insensitive) or an OUI
/// prefix `AA:BB:CC` (prefix match, case-insensitive).
pub fn mac_matches(target: &str, allowed: &str) -> bool {
    let t = target.trim().to_ascii_lowercase();
    let a = allowed.trim().to_ascii_lowercase();
    if a.len() == 17 {
        return t == a;
    }
    if a.len() == 8 {
        // AA:BB:CC — require the target to share the first 8 chars and
        // have a `:` as its 9th so we don't match an unrelated extension.
        return t.len() >= 9 && t.starts_with(&a) && t.as_bytes()[8] == b':';
    }
    false
}

/// Any-of over a list of allowed MACs/OUIs.
pub fn mac_matches_any(target: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| mac_matches(target, a))
}

/// Does `target` SSID match `pattern`? `*` matches any run of characters,
/// `?` matches exactly one, everything else is literal. Case-insensitive.
pub fn ssid_matches(target: &str, pattern: &str) -> bool {
    let t: Vec<char> = target.to_lowercase().chars().collect();
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    glob_recurse(&t, 0, &p, 0)
}

fn glob_recurse(t: &[char], ti: usize, p: &[char], pi: usize) -> bool {
    if pi >= p.len() {
        return ti >= t.len();
    }
    match p[pi] {
        '*' => {
            // Try to match zero or more characters.
            for skip in ti..=t.len() {
                if glob_recurse(t, skip, p, pi + 1) {
                    return true;
                }
            }
            false
        }
        '?' => {
            if ti >= t.len() {
                return false;
            }
            glob_recurse(t, ti + 1, p, pi + 1)
        }
        c => {
            if ti >= t.len() || t[ti] != c {
                return false;
            }
            glob_recurse(t, ti + 1, p, pi + 1)
        }
    }
}

/// Any-of over a list of SSID patterns.
pub fn ssid_matches_any(target: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| ssid_matches(target, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- CIDR ----------

    #[test]
    fn parse_bare_ip_is_slash32() {
        let (net, pref) = parse_cidr("10.0.0.5").unwrap();
        assert_eq!(net, 0x0a_00_00_05);
        assert_eq!(pref, 32);
    }

    #[test]
    fn parse_cidr_normalises_host_bits() {
        let (net, pref) = parse_cidr("10.0.5.17/24").unwrap();
        assert_eq!(net, 0x0a_00_05_00); // host bits zeroed
        assert_eq!(pref, 24);
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(parse_cidr("10.0").is_none());
        assert!(parse_cidr("10.0.0.256").is_none());
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("not-an-ip").is_none());
    }

    #[test]
    fn ip_in_cidr_direct_containment() {
        assert!(ipv4_in_cidr("10.0.5.17", "10.0.0.0/16"));
        assert!(ipv4_in_cidr("10.0.0.1", "10.0.0.0/24"));
        assert!(ipv4_in_cidr("10.0.0.0/24", "10.0.0.0/16"));
    }

    #[test]
    fn ip_not_in_cidr_rejected() {
        assert!(!ipv4_in_cidr("10.1.0.0", "10.0.0.0/16"));
        assert!(!ipv4_in_cidr("192.168.1.1", "10.0.0.0/8"));
    }

    #[test]
    fn broader_target_than_allowed_is_rejected() {
        // Target /16 is broader than allowed /24 — must not match.
        assert!(!ipv4_in_cidr("10.0.0.0/16", "10.0.0.0/24"));
    }

    #[test]
    fn slash_zero_matches_everything() {
        assert!(ipv4_in_cidr("1.2.3.4", "0.0.0.0/0"));
        assert!(ipv4_in_cidr("255.255.255.255/32", "0.0.0.0/0"));
    }

    #[test]
    fn any_of_short_circuits_on_match() {
        let allowed = vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()];
        assert!(ipv4_in_any("10.5.1.2", &allowed));
        assert!(ipv4_in_any("192.168.42.1", &allowed));
        assert!(!ipv4_in_any("172.16.0.1", &allowed));
    }

    // ---------- MAC / OUI ----------

    #[test]
    fn mac_exact_match_is_case_insensitive() {
        assert!(mac_matches("AA:BB:CC:11:22:33", "aa:bb:cc:11:22:33"));
        assert!(mac_matches("aa:bb:cc:11:22:33", "AA:BB:CC:11:22:33"));
    }

    #[test]
    fn mac_exact_mismatch_rejects() {
        assert!(!mac_matches("AA:BB:CC:11:22:33", "AA:BB:CC:11:22:34"));
    }

    #[test]
    fn oui_prefix_matches_same_vendor() {
        assert!(mac_matches("AA:BB:CC:11:22:33", "AA:BB:CC"));
        assert!(mac_matches("AA:BB:CC:FF:FF:FF", "aa:bb:cc"));
    }

    #[test]
    fn oui_prefix_does_not_match_other_vendors() {
        assert!(!mac_matches("DE:AD:BE:EF:00:01", "AA:BB:CC"));
    }

    #[test]
    fn oui_boundary_is_respected() {
        // Allowed "AA:BB:CC" must not match "AA:BB:CD:..." just because
        // the first few characters coincidentally overlap in some encoding.
        assert!(!mac_matches("AA:BB:CD:11:22:33", "AA:BB:CC"));
    }

    #[test]
    fn mac_matches_any_short_circuits() {
        let allowed = vec!["DE:AD:BE".into(), "AA:BB:CC:11:22:33".into()];
        assert!(mac_matches_any("de:ad:be:ef:00:01", &allowed));
        assert!(mac_matches_any("AA:BB:CC:11:22:33", &allowed));
        assert!(!mac_matches_any("FF:EE:DD:CC:BB:AA", &allowed));
    }

    // ---------- SSID glob ----------

    #[test]
    fn ssid_literal_match_is_case_insensitive() {
        assert!(ssid_matches("Corp-WiFi", "corp-wifi"));
        assert!(ssid_matches("corp-wifi", "CORP-WIFI"));
    }

    #[test]
    fn ssid_star_matches_any_run() {
        assert!(ssid_matches("EvsuCorp-Guest-01", "EvsuCorp-*"));
        assert!(ssid_matches("Guest", "*est"));
        assert!(ssid_matches("abc", "*"));
        assert!(ssid_matches("", "*"));
    }

    #[test]
    fn ssid_question_mark_matches_exactly_one_char() {
        assert!(ssid_matches("Guest", "Gu?st"));
        assert!(!ssid_matches("Guest", "Gu??st")); // too many
        assert!(!ssid_matches("Guest", "Gust")); // too few
    }

    #[test]
    fn ssid_pattern_mismatch_rejects() {
        assert!(!ssid_matches("Corp-WiFi", "Guest-*"));
    }

    #[test]
    fn ssid_matches_any_glob_list() {
        let allowed = vec!["Corp-*".into(), "Guest".into()];
        assert!(ssid_matches_any("Corp-01", &allowed));
        assert!(ssid_matches_any("Guest", &allowed));
        assert!(!ssid_matches_any("Rogue-SSID", &allowed));
    }
}
