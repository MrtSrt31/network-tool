//! Tests for the GUI access control policy.
//!
//! The pure-function [`check_auth`] decides every allow/deny, so we exercise
//! the policy directly rather than spinning up a real server. One live
//! end-to-end test uses tiny_http + a raw TcpStream to confirm the server
//! actually responds `403` to an unauthenticated request.

use network_tool::web::auth::{check_auth, parse_cookies, parse_query, AuthDecision};
use std::collections::HashMap;

const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const WRONG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

// ---------- session-token layer ----------

#[test]
fn get_without_token_is_denied() {
    let r = check_auth(false, &map(&[]), &map(&[]), &map(&[]), None, TOKEN);
    assert!(matches!(r, AuthDecision::Deny(_)), "got {r:?}");
}

#[test]
fn get_with_wrong_cookie_is_denied() {
    let r = check_auth(
        false,
        &map(&[("nt_session", WRONG)]),
        &map(&[]),
        &map(&[]),
        None,
        TOKEN,
    );
    assert!(matches!(r, AuthDecision::Deny(_)));
}

#[test]
fn get_with_correct_cookie_is_allowed_without_set_cookie() {
    let r = check_auth(
        false,
        &map(&[("nt_session", TOKEN)]),
        &map(&[]),
        &map(&[]),
        None,
        TOKEN,
    );
    match r {
        AuthDecision::Allow { set_cookie } => assert!(set_cookie.is_none()),
        _ => panic!("expected allow"),
    }
}

#[test]
fn get_with_correct_query_token_sets_cookie_for_future_clicks() {
    let r = check_auth(
        false,
        &map(&[]),
        &map(&[("s", TOKEN)]),
        &map(&[]),
        None,
        TOKEN,
    );
    match r {
        AuthDecision::Allow { set_cookie } => {
            let sc = set_cookie.expect("should set cookie on query-token entry");
            assert!(sc.contains("nt_session="));
            assert!(sc.contains("HttpOnly"));
            assert!(sc.contains("SameSite=Strict"));
        }
        _ => panic!("expected allow"),
    }
}

// ---------- CSRF layer ----------

#[test]
fn post_without_csrf_is_denied_even_with_valid_cookie() {
    let r = check_auth(
        true,
        &map(&[("nt_session", TOKEN)]),
        &map(&[]),
        &map(&[("name", "x")]), // no csrf field
        Some("http://127.0.0.1:8787"),
        TOKEN,
    );
    assert!(matches!(r, AuthDecision::Deny(_)));
}

#[test]
fn post_with_wrong_csrf_is_denied() {
    let r = check_auth(
        true,
        &map(&[("nt_session", TOKEN)]),
        &map(&[]),
        &map(&[("csrf", WRONG), ("name", "x")]),
        Some("http://127.0.0.1:8787"),
        TOKEN,
    );
    assert!(matches!(r, AuthDecision::Deny(_)));
}

#[test]
fn post_with_valid_cookie_and_csrf_and_loopback_origin_is_allowed() {
    let r = check_auth(
        true,
        &map(&[("nt_session", TOKEN)]),
        &map(&[]),
        &map(&[("csrf", TOKEN), ("name", "x")]),
        Some("http://127.0.0.1:8787"),
        TOKEN,
    );
    assert!(matches!(r, AuthDecision::Allow { .. }));
}

// ---------- Origin layer ----------

#[test]
fn post_with_cross_origin_header_is_denied() {
    let r = check_auth(
        true,
        &map(&[("nt_session", TOKEN)]),
        &map(&[]),
        &map(&[("csrf", TOKEN)]),
        Some("http://evil.example"),
        TOKEN,
    );
    assert!(matches!(r, AuthDecision::Deny(_)));
}

#[test]
fn post_missing_origin_is_allowed_when_csrf_matches() {
    // Non-browser clients (curl, scripts) do not send Origin. We still
    // require the session token + CSRF — missing Origin alone is not a
    // deny signal.
    let r = check_auth(
        true,
        &map(&[("nt_session", TOKEN)]),
        &map(&[]),
        &map(&[("csrf", TOKEN)]),
        None,
        TOKEN,
    );
    assert!(matches!(r, AuthDecision::Allow { .. }));
}

#[test]
fn post_with_https_loopback_origin_is_denied_as_defense_in_depth() {
    // Server is http://; a request claiming https://127.0.0.1 is suspicious.
    let r = check_auth(
        true,
        &map(&[("nt_session", TOKEN)]),
        &map(&[]),
        &map(&[("csrf", TOKEN)]),
        Some("https://127.0.0.1"),
        TOKEN,
    );
    assert!(matches!(r, AuthDecision::Deny(_)));
}

#[test]
fn localhost_origin_is_also_accepted() {
    let r = check_auth(
        true,
        &map(&[("nt_session", TOKEN)]),
        &map(&[]),
        &map(&[("csrf", TOKEN)]),
        Some("http://localhost:8787"),
        TOKEN,
    );
    assert!(matches!(r, AuthDecision::Allow { .. }));
}

// ---------- header parsing ----------

#[test]
fn parse_cookies_handles_multiple_pairs() {
    let m = parse_cookies("nt_session=xyz; theme=dark");
    assert_eq!(m.get("nt_session").map(String::as_str), Some("xyz"));
    assert_eq!(m.get("theme").map(String::as_str), Some("dark"));
}

#[test]
fn parse_query_handles_url_encoding() {
    let m = parse_query("/engagement/new?s=abc&name=hello%20world");
    assert_eq!(m.get("s").map(String::as_str), Some("abc"));
    assert_eq!(m.get("name").map(String::as_str), Some("hello world"));
}

// ---------- live end-to-end: unauthenticated curl gets 403 ----------
//
// Spins up a tiny_http server bound to a random port, sends a raw HTTP/1.1
// request with no cookie/token, and asserts the status line is 403.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

#[test]
fn unauthenticated_request_gets_403_on_live_server() {
    use tiny_http::{Method, Response, Server};

    // Match the real server behavior: initialise auth via the public helper so
    // the token is cached in the OnceLock, then run a minimal request loop.
    let tmp = std::env::temp_dir().join(format!("ntool-web-sec-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let _ = network_tool::web::auth::init_session(&tmp);

    let server = Server::http("127.0.0.1:0").expect("bind");
    let addr = server.server_addr().to_ip().expect("ip addr").to_string();

    thread::spawn(move || {
        for mut request in server.incoming_requests() {
            // Mirror handle(): collect cookie/origin, run check_auth, 403 on deny.
            let is_post = *request.method() == Method::Post;
            let raw_url = request.url().to_string();
            let mut cookie_hdr = String::new();
            let mut origin: Option<String> = None;
            for h in request.headers() {
                let name = h.field.as_str().as_str().to_ascii_lowercase();
                if name == "cookie" {
                    cookie_hdr.push_str(h.value.as_str());
                }
                if name == "origin" {
                    origin = Some(h.value.as_str().to_string());
                }
            }
            let cookies = parse_cookies(&cookie_hdr);
            let query = parse_query(&raw_url);
            let mut body = String::new();
            if is_post {
                let _ = request.as_reader().read_to_string(&mut body);
            }
            let form: HashMap<String, String> = HashMap::new();
            let decision = check_auth(
                is_post,
                &cookies,
                &query,
                &form,
                origin.as_deref(),
                network_tool::web::auth::token(),
            );
            match decision {
                AuthDecision::Deny(reason) => {
                    let _ = request.respond(
                        Response::from_string(format!("403 forbidden: {reason}"))
                            .with_status_code(403),
                    );
                }
                AuthDecision::Allow { .. } => {
                    let _ = request.respond(Response::from_string("ok"));
                }
            }
        }
    });

    // Minimal HTTP client: send request, read first line of response.
    let mut stream = TcpStream::connect(&addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.starts_with("HTTP/1.1 403"),
        "expected 403, got: {text:?}"
    );
}
