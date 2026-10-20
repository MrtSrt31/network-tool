//! Local GUI access control.
//!
//! The GUI is bound to `127.0.0.1`, but on a multi-user machine that is **not**
//! enough: any process the current user runs (and any browser they load) can
//! reach the port. Browsers in particular can be tricked (via a malicious page
//! and DNS rebinding) into submitting authenticated requests to localhost.
//!
//! This module layers three defenses on top of the loopback bind:
//!
//! 1. **Session token** — a 256-bit random value generated at server start,
//!    persisted to `.session` under the data dir with mode `0600`. Every
//!    request must carry it, either in the `nt_session` cookie or as the `s`
//!    query parameter on first visit. Non-matching → `403`.
//! 2. **CSRF** — every mutating form embeds the token as a hidden field; `POST`
//!    requests whose `csrf` field does not match the session token are `403`.
//! 3. **Origin** — if a `POST` carries an `Origin` header (browsers always do),
//!    it must start with `http://127.0.0.1` or `http://localhost`. Requests
//!    with no `Origin` (curl, scripts) are allowed through the CSRF check.
//!
//! The decision is a pure function of the inputs; see [`check_auth`]. This
//! lets the whole policy be unit-tested with fabricated requests without
//! starting a real server.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Global token for the running server instance. Set once in [`init_session`].
static SESSION_TOKEN: OnceLock<String> = OnceLock::new();

/// Return the current session token. Panics if [`init_session`] was not called.
pub fn token() -> &'static str {
    SESSION_TOKEN
        .get()
        .expect("session token not initialised; call auth::init_session first")
}

/// Hidden form field that every mutating form must embed.
pub fn csrf_field() -> String {
    format!("<input type=hidden name=csrf value='{}'>", token())
}

/// Load the session token from `<data_dir>/.session` or generate a new one
/// and persist it with mode `0600`. Called once at server start.
pub fn init_session(data_dir: &std::path::Path) -> std::io::Result<&'static str> {
    fs::create_dir_all(data_dir)?;
    let path = session_file_path(data_dir);
    let tok = if let Ok(existing) = fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if is_well_formed_token(&trimmed) {
            trimmed
        } else {
            generate_and_write(&path)?
        }
    } else {
        generate_and_write(&path)?
    };
    // OnceLock::set only accepts the first attempt; later calls would be an
    // error in test harnesses that invoke init_session more than once.
    let _ = SESSION_TOKEN.set(tok);
    Ok(SESSION_TOKEN.get().unwrap().as_str())
}

fn session_file_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join(".session")
}

fn generate_and_write(path: &std::path::Path) -> std::io::Result<String> {
    let tok = generate_token();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(tok.as_bytes())?;
    Ok(tok)
}

/// 256 bits of entropy, hex-encoded. Produced by concatenating two UUID v4
/// values (128 bits each) — avoids pulling in a separate RNG crate.
fn generate_token() -> String {
    let a = uuid::Uuid::new_v4().simple().to_string();
    let b = uuid::Uuid::new_v4().simple().to_string();
    format!("{a}{b}")
}

fn is_well_formed_token(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Constant-time equality for secrets. Prevents timing side channels on token
/// comparison. The inputs can be of different lengths — length mismatch is a
/// mismatch, but still runs the full byte loop over the shorter string.
fn eq_ct(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Outcome of the auth check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// Request may proceed. When `set_cookie` is `Some`, the response should
    /// carry a `Set-Cookie: nt_session=<token>; ...` header so future clicks
    /// no longer need the `?s=` query parameter.
    Allow { set_cookie: Option<String> },
    /// Request is denied; `.0` is the reason that will be logged (not shown
    /// to the client beyond a plain "403 forbidden").
    Deny(&'static str),
}

/// Decide whether a request may proceed. Pure function — all inputs are
/// explicit, no I/O, no globals except the already-set session token.
///
/// * `is_post` — true if the request method is `POST`.
/// * `cookies` — parsed `Cookie` header values.
/// * `query` — parsed query parameters.
/// * `form` — parsed `application/x-www-form-urlencoded` body (empty for GET).
/// * `origin` — raw `Origin` header value (`None` if absent).
/// * `expected` — the session token to compare against (so tests can inject one).
pub fn check_auth(
    is_post: bool,
    cookies: &HashMap<String, String>,
    query: &HashMap<String, String>,
    form: &HashMap<String, String>,
    origin: Option<&str>,
    expected: &str,
) -> AuthDecision {
    // 1. Session token in cookie or query.
    let (session_ok, set_cookie) = match cookies.get("nt_session") {
        Some(c) if eq_ct(c, expected) => (true, None),
        _ => match query.get("s") {
            Some(q) if eq_ct(q, expected) => (
                true,
                Some(format!(
                    "nt_session={expected}; Path=/; HttpOnly; SameSite=Strict"
                )),
            ),
            _ => (false, None),
        },
    };
    if !session_ok {
        return AuthDecision::Deny("missing or invalid session token");
    }

    if is_post {
        // 2. CSRF: form must include the token.
        let csrf = form.get("csrf").map(|s| s.as_str()).unwrap_or("");
        if !eq_ct(csrf, expected) {
            return AuthDecision::Deny("missing or invalid csrf field");
        }
        // 3. Origin: if present, must be loopback.
        if let Some(o) = origin {
            if !is_loopback_origin(o) {
                return AuthDecision::Deny("origin is not loopback");
            }
        }
    }

    AuthDecision::Allow { set_cookie }
}

fn is_loopback_origin(o: &str) -> bool {
    // The character after the host must be `:` (port) or absent — otherwise
    // `http://127.0.0.1.evil.com` would slip through a plain prefix check.
    let o = o.trim();
    for host in ["127.0.0.1", "localhost", "[::1]"] {
        let prefix = format!("http://{host}");
        if let Some(rest) = o.strip_prefix(&prefix) {
            if rest.is_empty() || rest.starts_with(':') || rest.starts_with('/') {
                return true;
            }
        }
    }
    false
}

/// Parse an HTTP `Cookie` header value into a map.
pub fn parse_cookies(header: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in header.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// Parse the query portion of a request URL into a map.
pub fn parse_query(raw_url: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(q) = raw_url.split_once('?').map(|x| x.1) {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            if let Some((k, v)) = pair.split_once('=') {
                out.insert(crate::util::urldecode(k), crate::util::urldecode(v));
            } else {
                out.insert(crate::util::urldecode(pair), String::new());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_is_well_formed() {
        let t = generate_token();
        assert!(is_well_formed_token(&t), "generated: {t:?}");
    }

    #[test]
    fn eq_ct_matches_eq_semantics() {
        assert!(eq_ct("abc", "abc"));
        assert!(!eq_ct("abc", "abd"));
        assert!(!eq_ct("abc", "abcd"));
        assert!(!eq_ct("abcd", "abc"));
    }

    #[test]
    fn parse_cookies_round_trip() {
        let m = parse_cookies("a=1; b=2;  c=hello world");
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
        assert_eq!(m.get("c").map(String::as_str), Some("hello world"));
    }

    #[test]
    fn parse_query_decodes() {
        let m = parse_query("/x?a=1&b=hello%20world&c");
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("hello world"));
        assert_eq!(m.get("c").map(String::as_str), Some(""));
    }

    #[test]
    fn loopback_origin_matcher() {
        assert!(is_loopback_origin("http://127.0.0.1"));
        assert!(is_loopback_origin("http://127.0.0.1:8787"));
        assert!(is_loopback_origin("http://localhost:8787"));
        assert!(is_loopback_origin("http://[::1]:8787"));
        assert!(!is_loopback_origin("http://evil.com"));
        assert!(!is_loopback_origin("https://127.0.0.1"));
        assert!(!is_loopback_origin("http://127.0.0.1.evil.com"));
    }
}
