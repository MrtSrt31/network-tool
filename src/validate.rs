//! Input validation for module parameters.
//!
//! Every parameter accepted by a module is tagged with a [`ParamKind`]. Before
//! the safety gate lets a command execute, each supplied value is run through
//! [`check`], which enforces strict format and content constraints.
//!
//! The primary goal is to prevent **argument injection** against the external
//! wireless tooling the modules orchestrate (aircrack-ng suite, reaver,
//! hcxdumptool, airbase-ng). An ESSID or path that starts with `-`, for
//! example, would otherwise be interpreted as a flag by the downstream tool.
//!
//! No `regex` crate dependency on purpose — hand-rolled validators are easier
//! to audit and keep the binary small.

/// Classification of a user-supplied parameter value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamKind {
    /// IEEE 802 MAC / BSSID: `AA:BB:CC:DD:EE:FF` (colon-separated hex).
    Mac,
    /// Wireless channel number, 1..=196.
    Channel,
    /// OS network interface name (`wlan0`, `wlan0mon`, `en0`).
    Iface,
    /// 802.11 SSID / ESSID — 1..=32 bytes UTF-8, no leading `-`.
    Essid,
    /// Positive integer count, 1..=999_999.
    Count,
    /// File path (absolute or relative), no `..`, no shell metachars, no leading `-`.
    Path,
    /// Output filename prefix: `[A-Za-z0-9._-]+`, no leading `-` or `.`.
    Prefix,
}

/// Validate a single parameter value against its declared kind.
///
/// The caller passes the already-trimmed value. An empty value is rejected
/// here; callers that treat an empty value as "parameter omitted" should check
/// for emptiness first and skip the call.
pub fn check(kind: ParamKind, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("value is empty".to_string());
    }
    for c in value.chars() {
        if c == '\0' || (c.is_control() && c != '\t') {
            return Err("value contains control or null characters".to_string());
        }
    }
    match kind {
        ParamKind::Mac => check_mac(value),
        ParamKind::Channel => check_channel(value),
        ParamKind::Iface => check_iface(value),
        ParamKind::Essid => check_essid(value),
        ParamKind::Count => check_count(value),
        ParamKind::Path => check_path(value),
        ParamKind::Prefix => check_prefix(value),
    }
}

fn check_mac(v: &str) -> Result<(), String> {
    let bytes = v.as_bytes();
    if bytes.len() != 17 {
        return Err(format!(
            "'{v}': expected MAC format AA:BB:CC:DD:EE:FF (17 characters)"
        ));
    }
    for (i, &b) in bytes.iter().enumerate() {
        let col_pos = i % 3;
        if col_pos == 2 {
            if b != b':' {
                return Err(format!("'{v}': expected ':' at position {i}"));
            }
        } else if !b.is_ascii_hexdigit() {
            return Err(format!("'{v}': non-hex character at position {i}"));
        }
    }
    Ok(())
}

fn check_channel(v: &str) -> Result<(), String> {
    // Reject leading signs / whitespace before parsing — Rust's `u32::from_str`
    // accepts "+6" which would be surprising here.
    if !v.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("'{v}': expected digits only"));
    }
    let n: u32 = v
        .parse()
        .map_err(|_| format!("'{v}': expected a positive integer"))?;
    if n == 0 || n > 196 {
        return Err(format!("'{v}': channel must be in 1..=196"));
    }
    Ok(())
}

fn check_iface(v: &str) -> Result<(), String> {
    if v.len() > 15 {
        return Err(format!("'{v}': interface name longer than 15 characters"));
    }
    let first = v.chars().next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(format!(
            "'{v}': interface must start with a letter or digit"
        ));
    }
    for c in v.chars() {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
            return Err(format!("'{v}': unexpected character '{c}' in interface"));
        }
    }
    Ok(())
}

fn check_essid(v: &str) -> Result<(), String> {
    if v.len() > 32 {
        return Err(format!(
            "'{v}': ESSID longer than 32 bytes (IEEE 802.11 limit)"
        ));
    }
    if v.starts_with('-') {
        return Err(format!(
            "'{v}': ESSID cannot start with '-' (would be parsed as a flag by the downstream tool)"
        ));
    }
    if v.contains('\n') || v.contains('\r') {
        return Err(format!("'{v}': ESSID contains a newline"));
    }
    Ok(())
}

fn check_count(v: &str) -> Result<(), String> {
    if !v.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("'{v}': expected digits only"));
    }
    let n: u64 = v
        .parse()
        .map_err(|_| format!("'{v}': expected a positive integer"))?;
    if n == 0 || n > 999_999 {
        return Err(format!("'{v}': count must be in 1..=999_999"));
    }
    Ok(())
}

fn check_path(v: &str) -> Result<(), String> {
    if v.starts_with('-') {
        return Err(format!(
            "'{v}': path cannot start with '-' (would be parsed as a flag)"
        ));
    }
    const FORBIDDEN: &[char] = &[
        ';', '|', '&', '$', '`', '>', '<', '(', ')', '*', '?', '[', ']', '{', '}', '"', '\'', '\\',
        '\n', '\r', ' ', '\t',
    ];
    for c in v.chars() {
        if FORBIDDEN.contains(&c) {
            let shown = if c == ' ' {
                "<space>".to_string()
            } else if c == '\t' {
                "<tab>".to_string()
            } else {
                c.to_string()
            };
            return Err(format!("'{v}': forbidden character {shown}"));
        }
    }
    for seg in v.split('/') {
        if seg == ".." {
            return Err(format!("'{v}': path traversal ('..') is not allowed"));
        }
    }
    Ok(())
}

fn check_prefix(v: &str) -> Result<(), String> {
    if v.len() > 64 {
        return Err(format!("'{v}': prefix longer than 64 characters"));
    }
    let first = v.chars().next().unwrap();
    if first == '-' || first == '.' {
        return Err(format!("'{v}': prefix cannot start with '-' or '.'"));
    }
    for c in v.chars() {
        if !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
            return Err(format!("'{v}': unexpected character '{c}' in prefix"));
        }
    }
    Ok(())
}
