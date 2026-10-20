//! Local web GUI (control panel). tiny_http server bound to `127.0.0.1` with
//! thread-per-request dispatch; auth is enforced by the [`auth`] middleware
//! (session token + CSRF + loopback-Origin check).

pub mod auth;

use crate::model::*;
use crate::util::*;
use crate::{content, modules, recon, report, roe, store};
use std::collections::HashMap;
use std::thread;
use tiny_http::{Header, Method, Response, Server};

use auth::AuthDecision;

enum Out {
    Html(String),
    Redirect(String),
    Markdown(String),
}

pub fn serve(port: u16, open: bool) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{port}");
    let server = match Server::http(&addr) {
        Ok(s) => s,
        Err(e) => return Err(format!("could not bind {addr}: {e}").into()),
    };
    let token = auth::init_session(&store::data_dir())?;
    let authenticated_url = format!("http://{addr}/?s={token}");
    println!("Network Tool GUI  →  {authenticated_url}");
    println!("(authorized assessments only · Ctrl-C to stop)");
    println!(
        "session token persisted in {}",
        store::data_dir().join(".session").display()
    );
    if open {
        let _ = std::process::Command::new("open")
            .arg(&authenticated_url)
            .spawn();
    }
    for request in server.incoming_requests() {
        thread::spawn(move || handle(request));
    }
    Ok(())
}

fn handle(mut request: tiny_http::Request) {
    let method = request.method().clone();
    let raw_url = request.url().to_string();

    // Collect headers before consuming the request body.
    let mut cookie_header = String::new();
    let mut origin_header: Option<String> = None;
    for h in request.headers() {
        let name = h.field.as_str().as_str().to_ascii_lowercase();
        match name.as_str() {
            "cookie" => {
                if !cookie_header.is_empty() {
                    cookie_header.push_str("; ");
                }
                cookie_header.push_str(h.value.as_str());
            }
            "origin" => origin_header = Some(h.value.as_str().to_string()),
            _ => {}
        }
    }
    let cookies = auth::parse_cookies(&cookie_header);
    let query = auth::parse_query(&raw_url);

    let mut body = String::new();
    if method == Method::Post {
        let _ = request.as_reader().read_to_string(&mut body);
    }
    let form = parse_form(&body);

    let is_post = method == Method::Post;
    let decision = auth::check_auth(
        is_post,
        &cookies,
        &query,
        &form,
        origin_header.as_deref(),
        auth::token(),
    );

    let set_cookie = match decision {
        AuthDecision::Deny(reason) => {
            let _ = request.respond(
                Response::from_string(format!("403 forbidden: {reason}"))
                    .with_status_code(403)
                    .with_header(header("Content-Type", "text/plain; charset=utf-8")),
            );
            return;
        }
        AuthDecision::Allow { set_cookie } => set_cookie,
    };

    let path = raw_url.split('?').next().unwrap_or("");
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let out = route(&method, &segs, &form);

    let mut response = match out {
        Out::Html(s) => Response::from_string(s)
            .with_header(header("Content-Type", "text/html; charset=utf-8"))
            .boxed(),
        Out::Markdown(s) => Response::from_string(s)
            .with_header(header("Content-Type", "text/plain; charset=utf-8"))
            .boxed(),
        Out::Redirect(loc) => Response::from_string("")
            .with_status_code(303)
            .with_header(header("Location", &loc))
            .boxed(),
    };
    if let Some(sc) = set_cookie {
        response.add_header(header("Set-Cookie", &sc));
    }
    let _ = request.respond(response);
}

fn route(method: &Method, segs: &[&str], form: &HashMap<String, String>) -> Out {
    match (method, segs) {
        (Method::Get, []) => index(),
        (Method::Get, ["engagement", "new"]) => Out::Html(intake_form(None)),
        (Method::Post, ["engagement", "new"]) => create_engagement(form),
        (Method::Get, ["engagement", id]) => dashboard(id),
        (Method::Get, ["engagement", id, "edit"]) => edit_page(id),
        (Method::Post, ["engagement", id, "edit"]) => update_engagement(id, form),
        (Method::Get, ["engagement", id, "recon"]) => recon_page(id),
        (Method::Post, ["engagement", id, "recon"]) => recon_import(id, form),
        (Method::Get, ["engagement", id, "modules"]) => modules_page(id),
        (Method::Post, ["engagement", id, "modules", "run"]) => modules_run(id, form),
        (Method::Get, ["engagement", id, "finding", "new"]) => finding_form(id, None),
        (Method::Post, ["engagement", id, "finding", "new"]) => finding_create(id, form),
        (Method::Get, ["engagement", id, "finding", fid]) => finding_detail(id, fid),
        (Method::Post, ["engagement", id, "finding", fid, "edit"]) => finding_update(id, fid, form),
        (Method::Post, ["engagement", id, "finding", fid, "retest"]) => {
            finding_retest(id, fid, form)
        }
        (Method::Get, ["engagement", id, "report"]) => match store::load(id) {
            Ok(e) => Out::Html(report::html(&e)),
            Err(_) => not_found(),
        },
        (Method::Get, ["engagement", id, "report.md"]) => match store::load(id) {
            Ok(e) => Out::Markdown(report::markdown(&e)),
            Err(_) => not_found(),
        },
        (Method::Get, ["engagement", id, "roe"]) => match store::load(id) {
            Ok(e) => Out::Html(roe::html(&e)),
            Err(_) => not_found(),
        },
        (Method::Get, ["engagement", id, "roe.md"]) => match store::load(id) {
            Ok(e) => Out::Markdown(roe::markdown(&e)),
            Err(_) => not_found(),
        },
        _ => not_found(),
    }
}

// ---------- pages ----------

fn index() -> Out {
    let engagements = store::list().unwrap_or_default();
    let mut rows = String::new();
    if engagements.is_empty() {
        rows.push_str("<p class=dim>No engagements yet. Create one to begin.</p>");
    } else {
        rows.push_str("<table><tr><th>Engagement</th><th>Client</th><th>Tester</th><th>Status</th><th>Auth</th><th>Findings</th><th></th></tr>");
        for e in &engagements {
            let auth = if e.active_testing_unlocked() {
                "<span class=badge-ok>unlocked</span>"
            } else {
                "<span class=badge-warn>locked</span>"
            };
            rows.push_str(&format!(
                "<tr><td><a href='/engagement/{}'>{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href='/engagement/{}'>open →</a></td></tr>",
                e.id, esc(&e.name), esc(&e.client.name), esc(&e.tester.name),
                e.status.label(), auth, e.findings.len(), e.id,
            ));
        }
        rows.push_str("</table>");
    }
    let body = format!(
        "<div class=hero><h1>Network Tool</h1><p class=sub>Authorized wireless security assessment platform · Aturc</p>\
         <a class=btn-primary href='/engagement/new'>+ New engagement</a></div>{rows}"
    );
    Out::Html(layout("Network Tool", "", &body))
}

fn intake_form(existing: Option<&Engagement>) -> String {
    let e = existing
        .cloned()
        .unwrap_or_else(|| Engagement::new(String::new()));
    let action = match existing {
        Some(x) => format!("/engagement/{}/edit", x.id),
        None => "/engagement/new".to_string(),
    };
    let title = if existing.is_some() {
        "Edit engagement"
    } else {
        "New engagement — tester & authorization intake"
    };

    let statuses: Vec<&str> = EngagementStatus::all_labels();
    let approaches = ["black-box", "grey-box", "white-box"];

    let body = format!(
        "<h1>{title}</h1>\
<form method=post action='{action}' class=form>{csrf}\
<fieldset><legend>Engagement</legend>\
{name}{status}</fieldset>\
<fieldset><legend>Tester (person performing the assessment)</legend>\
{t_name}{t_email}{t_company}{t_role}{t_certs}</fieldset>\
<fieldset><legend>Client</legend>\
{c_name}{c_contact}{c_email}{c_addr}</fieldset>\
<fieldset><legend>Scope</legend>\
{s_appr}{s_ssids}{s_bssids}{s_windows}{s_allowed}{s_prohibited}{s_out}{s_notes}</fieldset>\
<fieldset class=authbox><legend>Authorization / Rules of Engagement</legend>\
<p class=note>Active (intrusive) testing stays locked until a signed authorization is recorded here.</p>\
{a_auth}{a_name}{a_title}{a_date}{a_roe}{a_disruptive}{a_contact}</fieldset>\
<div class=actions><button class=btn-primary type=submit>Save engagement</button> <a class=btn href='/'>Cancel</a></div>\
</form>",
        title = esc(title),
        action = action,
        csrf = auth::csrf_field(),
        name = inp("name", "Engagement name", &e.name, "e.g. Evsu — Wireless Assessment 2026"),
        status = sel("status", "Status", &statuses, e.status.label()),
        t_name = inp("tester_name", "Full name", &e.tester.name, ""),
        t_email = inp("tester_email", "Email", &e.tester.email, ""),
        t_company = inp("tester_company", "Company", if e.tester.company.is_empty() { "Aturc" } else { &e.tester.company }, "Aturc"),
        t_role = inp("tester_role", "Role", &e.tester.role, "e.g. Lead pentester"),
        t_certs = inp("tester_certs", "Certifications", &e.tester.certifications, "e.g. OSWP, OSCP"),
        c_name = inp("client_name", "Client name", &e.client.name, "e.g. Evsu"),
        c_contact = inp("client_contact", "Contact name", &e.client.contact_name, ""),
        c_email = inp("client_email", "Contact email", &e.client.contact_email, ""),
        c_addr = inp("client_address", "Site address", &e.client.site_address, ""),
        s_appr = sel("scope_approach", "Approach", &approaches, &e.scope.approach),
        s_ssids = ta("scope_ssids", "In-scope SSIDs (one per line)", &vec_to_lines(&e.scope.in_scope_ssids), 3),
        s_bssids = ta("scope_bssids", "In-scope BSSIDs (one per line)", &vec_to_lines(&e.scope.in_scope_bssids), 3),
        s_windows = inp("scope_windows", "Test windows", &e.scope.test_windows, "e.g. 09:00–18:00, 3 business days"),
        s_allowed = ta("scope_allowed", "Allowed techniques (one per line)", &vec_to_lines(&e.scope.allowed_techniques), 3),
        s_prohibited = ta("scope_prohibited", "Prohibited techniques (one per line)", &vec_to_lines(&e.scope.prohibited_techniques), 3),
        s_out = ta("scope_out", "Out-of-scope notes (neighbouring networks, etc.)", &e.scope.out_of_scope_notes, 2),
        s_notes = ta("scope_notes", "Notes", &e.scope.notes, 2),
        a_auth = chk("auth_authorized", "A signed authorization letter is on file", e.authorization.authorized),
        a_name = inp("auth_name", "Authorizer name", &e.authorization.authorizer_name, ""),
        a_title = inp("auth_title", "Authorizer title", &e.authorization.authorizer_title, ""),
        a_date = inp("auth_date", "Signed date", &e.authorization.signed_date, "YYYY-MM-DD"),
        a_roe = inp("auth_roe", "RoE reference", &e.authorization.roe_reference, "document id / link"),
        a_disruptive = chk("auth_disruptive", "Disruptive techniques (deauth / rogue AP) explicitly permitted", e.authorization.disruptive_allowed),
        a_contact = inp("auth_contact", "Emergency / escalation contact", &e.authorization.emergency_contact, ""),
    );
    layout(title, "", &body)
}

fn edit_page(id: &str) -> Out {
    match store::load(id) {
        Ok(e) => Out::Html(intake_form(Some(&e))),
        Err(_) => not_found(),
    }
}

fn create_engagement(form: &HashMap<String, String>) -> Out {
    let mut e = Engagement::new(g(form, "name").to_string());
    apply_intake(&mut e, form);
    let dest = format!("/engagement/{}", e.id);
    save_then_redirect(&mut e, dest)
}

fn update_engagement(id: &str, form: &HashMap<String, String>) -> Out {
    let mut e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };
    e.name = g(form, "name").to_string();
    apply_intake(&mut e, form);
    let dest = format!("/engagement/{}", e.id);
    save_then_redirect(&mut e, dest)
}

fn apply_intake(e: &mut Engagement, form: &HashMap<String, String>) {
    e.status = EngagementStatus::from_str(g(form, "status"));
    e.tester = Tester {
        name: g(form, "tester_name").to_string(),
        email: g(form, "tester_email").to_string(),
        company: g(form, "tester_company").to_string(),
        role: g(form, "tester_role").to_string(),
        certifications: g(form, "tester_certs").to_string(),
    };
    e.client = Client {
        name: g(form, "client_name").to_string(),
        contact_name: g(form, "client_contact").to_string(),
        contact_email: g(form, "client_email").to_string(),
        site_address: g(form, "client_address").to_string(),
    };
    e.scope = Scope {
        approach: g(form, "scope_approach").to_string(),
        in_scope_ssids: lines_to_vec(g(form, "scope_ssids")),
        in_scope_bssids: lines_to_vec(g(form, "scope_bssids")),
        out_of_scope_notes: g(form, "scope_out").to_string(),
        test_windows: g(form, "scope_windows").to_string(),
        allowed_techniques: lines_to_vec(g(form, "scope_allowed")),
        prohibited_techniques: lines_to_vec(g(form, "scope_prohibited")),
        notes: g(form, "scope_notes").to_string(),
    };
    e.authorization = Authorization {
        authorized: gb(form, "auth_authorized"),
        authorizer_name: g(form, "auth_name").to_string(),
        authorizer_title: g(form, "auth_title").to_string(),
        signed_date: g(form, "auth_date").to_string(),
        roe_reference: g(form, "auth_roe").to_string(),
        disruptive_allowed: gb(form, "auth_disruptive"),
        emergency_contact: g(form, "auth_contact").to_string(),
    };
}

fn dashboard(id: &str) -> Out {
    let e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };

    // Authorization banner — the central safety gate.
    let banner = if e.active_testing_unlocked() {
        format!(
            "<div class=banner-ok><b>Active testing UNLOCKED.</b> Authorized by {} ({}) on {}. Disruptive techniques: {}.</div>",
            esc(&e.authorization.authorizer_name),
            esc(&e.authorization.authorizer_title),
            esc(&e.authorization.signed_date),
            if e.authorization.disruptive_allowed { "permitted" } else { "NOT permitted — passive/validation only" },
        )
    } else {
        "<div class=banner-warn><b>ACTIVE TESTING LOCKED.</b> No signed authorization on file. Only passive documentation and recon import are available. Record the authorization in <a href='edit'>Edit engagement</a> before any intrusive testing.</div>".to_string()
    };

    let c = e.severity_counts();
    let mut chips = String::from("<div class=sevrow>");
    let labels = Severity::all();
    for s in labels.iter().rev() {
        chips.push_str(&format!(
            "<span class=sevpill style='background:{}'>{}: {}</span>",
            s.color(),
            s.label(),
            c[s.index()]
        ));
    }
    chips.push_str("</div>");

    // Assets
    let mut assets = String::new();
    if e.assets.is_empty() {
        assets.push_str("<p class=dim>No assets yet. Use <a href='recon'>Import recon</a>.</p>");
    } else {
        assets.push_str("<table><tr><th>Type</th><th>ESSID</th><th>BSSID</th><th>Ch</th><th>Enc</th><th>Auth</th><th>Scope</th></tr>");
        for a in &e.assets {
            assets.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=mono>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                a.kind.label(), esc(&a.essid), esc(&a.bssid), esc(&a.channel),
                esc(&a.encryption), esc(&a.auth),
                if a.in_scope { "✓" } else { "" },
            ));
        }
        assets.push_str("</table>");
    }

    // Findings
    let mut findings = String::new();
    if e.findings.is_empty() {
        findings.push_str("<p class=dim>No findings yet.</p>");
    } else {
        findings.push_str("<table><tr><th>Sev</th><th>Title</th><th>Category</th><th>ATT&CK</th><th>Status</th></tr>");
        for f in &e.findings {
            let auto = if f.auto_detected {
                " <span class=auto>auto</span>"
            } else {
                ""
            };
            findings.push_str(&format!(
                "<tr><td><span class=sevtag style='background:{}'>{}</span></td><td><a href='/engagement/{}/finding/{}'>{}</a>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                f.severity.color(), f.severity.label(), e.id, f.id, esc(&f.title), auto,
                esc(&f.category), esc(&f.attack_tactic), f.status.label(),
            ));
        }
        findings.push_str("</table>");
    }

    // Action log (active-module invocations).
    let mut log = String::new();
    if e.action_log.is_empty() {
        log.push_str("<p class=dim>No module runs logged.</p>");
    } else {
        log.push_str("<table><tr><th>Time (UTC)</th><th>Module</th><th>Target</th><th>Mode</th><th>Exit</th><th>Summary</th></tr>");
        for a in e.action_log.iter().rev().take(25) {
            let mode = if a.dry_run {
                "preview".to_string()
            } else if a.disruptive {
                "<b>RUN · disruptive</b>".to_string()
            } else {
                "run".to_string()
            };
            log.push_str(&format!(
                "<tr><td class=mono>{}</td><td>{}</td><td class=mono>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                a.at.format("%Y-%m-%d %H:%M"),
                esc(&a.module_name),
                esc(&a.target),
                mode,
                a.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "—".to_string()),
                esc(&a.summary),
            ));
        }
        log.push_str("</table>");
    }

    let body = format!(
        "<div class=crumb><a href='/'>← all engagements</a></div>\
<h1>{name}</h1>\
<p class=meta>Client: <b>{client}</b> · Tester: {tester} · Status: {status}</p>\
{banner}\
<div class=toolbar>\
<a class=btn-primary href='/engagement/{id}/finding/new'>+ Add finding</a> \
<a class=btn href='/engagement/{id}/recon'>Import recon</a> \
<a class=btn href='/engagement/{id}/modules'>Active modules</a> \
<a class=btn href='/engagement/{id}/edit'>Edit engagement</a> \
<a class=btn href='/engagement/{id}/roe'>Authorization / RoE</a> \
<a class=btn href='/engagement/{id}/report'>View report</a> \
<a class=btn href='/engagement/{id}/report.md'>Download .md</a></div>\
<h2>Summary</h2>{chips}\
<h2>Wireless assets</h2>{assets}\
<h2>Findings</h2>{findings}\
<h2>Action log</h2>{log}",
        name = esc(&e.name),
        client = esc(&e.client.name),
        tester = esc(&e.tester.name),
        status = e.status.label(),
        id = e.id,
    );
    Out::Html(layout(&e.name, "", &body))
}

fn recon_page(id: &str) -> Out {
    if store::load(id).is_err() {
        return not_found();
    }
    let body = format!(
        "<div class=crumb><a href='/engagement/{id}'>← dashboard</a></div>\
<h1>Import reconnaissance</h1>\
<p class=note>Paste an <code>airodump-ng</code> CSV capture. This is a passive import — it parses a file you already captured and builds the asset inventory. No transmission is performed.</p>\
<form method=post action='/engagement/{id}/recon' class=form>{csrf}\
{ta}\
{derive}{scope}\
<div class=actions><button class=btn-primary type=submit>Import</button> <a class=btn href='/engagement/{id}'>Cancel</a></div>\
</form>",
        id = id,
        csrf = auth::csrf_field(),
        ta = ta("csv", "airodump-ng CSV", "", 14),
        derive = chk("derive", "Auto-suggest draft findings from obvious weaknesses (WEP/open/legacy WPA/PSK)", true),
        scope = chk("mark_scope", "Mark all imported access points as in-scope", false),
    );
    Out::Html(layout("Import recon", "", &body))
}

fn recon_import(id: &str, form: &HashMap<String, String>) -> Out {
    let mut e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };
    let csv = g(form, "csv");
    let mut assets = recon::parse_airodump_csv(csv);
    if gb(form, "mark_scope") {
        for a in &mut assets {
            if a.kind == AssetKind::AccessPoint {
                a.in_scope = true;
            }
        }
    }
    if gb(form, "derive") {
        let mut drafts = recon::derive_findings(&assets);
        e.findings.append(&mut drafts);
    }
    e.assets.append(&mut assets);
    let dest = format!("/engagement/{}", e.id);
    save_then_redirect(&mut e, dest)
}

fn modules_page(id: &str) -> Out {
    let e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };
    let unlocked = e.active_testing_unlocked();
    let disruptive_ok = e.authorization.disruptive_allowed;

    let banner = if unlocked {
        format!(
            "<div class=banner-ok><b>Active testing UNLOCKED.</b> Disruptive techniques: {}.</div>",
            if disruptive_ok {
                "permitted"
            } else {
                "NOT permitted — passive/validation modules only"
            }
        )
    } else {
        "<div class=banner-warn><b>ACTIVE TESTING LOCKED.</b> Record a signed authorization in <a href='edit'>Edit engagement</a>. Until then only command preview (dry-run) is available.</div>".to_string()
    };

    let mut cards = String::new();
    for m in modules::registry() {
        let tools_html: Vec<String> = m
            .tools
            .iter()
            .map(|t| {
                let ok = modules::tool_available(t);
                format!(
                    "<span class={}>{}{}</span>",
                    if ok { "badge-ok" } else { "badge-warn" },
                    esc(t),
                    if ok { "" } else { " missing" }
                )
            })
            .collect();

        let mut fields = String::new();
        for prm in &m.params {
            let label = format!("{}{}", prm.label, if prm.required { " *" } else { "" });
            fields.push_str(&inp(prm.key, &label, "", prm.placeholder));
        }

        let disr_badge = if m.disruptive {
            "<span class=badge-warn>DISRUPTIVE</span> "
        } else {
            ""
        };

        let run_controls = if m.disruptive {
            if disruptive_ok && unlocked {
                format!(
                    "{}<button class=btn-primary name=mode value=run type=submit>Run</button>",
                    chk(
                        "confirm",
                        "I confirm this disruptive action is authorized and in scope",
                        false
                    )
                )
            } else {
                "<span class=dim>Run disabled — preview only (authorization + RoE disruptive permission required)</span>".to_string()
            }
        } else if unlocked {
            "<button class=btn-primary name=mode value=run type=submit>Run</button>".to_string()
        } else {
            "<span class=dim>Run disabled — authorization required</span>".to_string()
        };

        cards.push_str(&format!(
            "<div class=finding><h3>{disr}{name}</h3>\
<p class=fmeta>{cat} · ATT&amp;CK: {tactic} {tech} · tools: {tools}</p>\
<p>{desc}</p>\
<form method=post action='/engagement/{id}/modules/run' class=form>{csrf}\
<input type=hidden name=module value='{mid}'>\
{fields}\
<label>Timeout (seconds, 0 = none)<input type=number name=timeout value='{to}' min=0></label>\
<div class=actions><button class=btn name=mode value=preview type=submit>Preview command</button> {run}</div>\
</form></div>",
            disr = disr_badge,
            name = esc(m.name),
            cat = esc(m.category),
            tactic = esc(m.tactic),
            tech = esc(m.technique),
            tools = tools_html.join(" "),
            desc = esc(m.description),
            id = id,
            csrf = auth::csrf_field(),
            mid = m.id,
            fields = fields,
            to = if m.disruptive { "30" } else { "120" },
            run = run_controls,
        ));
    }

    let body = format!(
        "<div class=crumb><a href='/engagement/{id}'>← dashboard</a></div>\
<h1>Active modules</h1>\
<p class=note>These modules run your own installed wireless tools. Authorized engagements only — every run is written to the action log.</p>\
{banner}{cards}",
        id = id,
    );
    Out::Html(layout("Active modules", "", &body))
}

fn modules_run(id: &str, form: &HashMap<String, String>) -> Out {
    let mut e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };
    let mid = g(form, "module");
    let spec = match modules::find(mid) {
        Some(s) => s,
        None => return err_page("unknown module"),
    };

    let dry_run = g(form, "mode") != "run";
    let confirm = gb(form, "confirm");

    let mut params: HashMap<String, String> = HashMap::new();
    for k in [
        "iface", "bssid", "channel", "client", "count", "wordlist", "capture", "essid", "prefix",
        "out",
    ] {
        let v = g(form, k);
        if !v.is_empty() {
            params.insert(k.to_string(), v.to_string());
        }
    }

    let warnings = match modules::gate(&e, &spec, &params, dry_run, confirm) {
        Ok(w) => w,
        Err(m) => {
            return module_result(id, &spec, "", &[format!("blocked: {m}")], None, "", "");
        }
    };

    let (program, args) = modules::build_command(&spec, &params);
    let cmdline = modules::display_command(&program, &args);

    if dry_run {
        record_action_web(
            &mut e,
            &spec,
            &params,
            &cmdline,
            true,
            None,
            false,
            "dry-run (not executed)".to_string(),
        );
        save_with_action_retry(&mut e);
        return module_result(
            id,
            &spec,
            &cmdline,
            &warnings,
            None,
            "(preview only — not executed)",
            "",
        );
    }

    if !modules::tool_available(&program) {
        return module_result(
            id,
            &spec,
            &cmdline,
            &warnings,
            None,
            "",
            &format!("required tool not found on PATH: {program}"),
        );
    }

    let timeout: u64 = g(form, "timeout").parse().unwrap_or(120);
    match modules::execute(&program, &args, timeout) {
        Ok(r) => {
            let summary = modules::summarize(&r);
            let ec = r.exit_code;
            let so = r.stdout.clone();
            let se = r.stderr.clone();
            record_action_web(
                &mut e,
                &spec,
                &params,
                &r.command,
                false,
                ec,
                r.timed_out,
                summary,
            );
            save_with_action_retry(&mut e);
            module_result(id, &spec, &cmdline, &warnings, ec, &so, &se)
        }
        Err(err) => module_result(
            id,
            &spec,
            &cmdline,
            &warnings,
            None,
            "",
            &format!("execution error: {err}"),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn module_result(
    id: &str,
    spec: &modules::ModuleSpec,
    cmd: &str,
    warnings: &[String],
    exit: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> Out {
    let mut w = String::new();
    for x in warnings {
        w.push_str(&format!("<div class=banner-warn>{}</div>", esc(x)));
    }
    let cmdblock = if cmd.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=lbl>Command</p><pre class=term>{}</pre><p class=fmeta>exit: {}</p>",
            esc(cmd),
            exit.map(|c| c.to_string())
                .unwrap_or_else(|| "—".to_string())
        )
    };
    let outblock = if stdout.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=lbl>stdout</p><pre class=term>{}</pre>",
            esc(stdout)
        )
    };
    let errblock = if stderr.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=lbl>stderr</p><pre class=term>{}</pre>",
            esc(stderr)
        )
    };
    let body = format!(
        "<div class=crumb><a href='/engagement/{id}/modules'>← modules</a> · <a href='/engagement/{id}'>dashboard</a></div>\
<h1>{name}</h1>{w}{cmdblock}{outblock}{errblock}",
        id = id,
        name = esc(spec.name),
    );
    Out::Html(layout("Module result", "", &body))
}

#[allow(clippy::too_many_arguments)]
fn record_action_web(
    e: &mut Engagement,
    spec: &modules::ModuleSpec,
    params: &HashMap<String, String>,
    command: &str,
    dry_run: bool,
    exit: Option<i32>,
    timed_out: bool,
    summary: String,
) {
    let target = params
        .get("bssid")
        .or_else(|| params.get("essid"))
        .or_else(|| params.get("iface"))
        .cloned()
        .unwrap_or_default();
    let operator = e.tester.name.clone();
    e.action_log.push(ActionRun {
        id: new_id(),
        at: chrono::Utc::now(),
        module_id: spec.id.to_string(),
        module_name: spec.name.to_string(),
        target,
        command: command.to_string(),
        disruptive: spec.disruptive,
        dry_run,
        exit_code: exit,
        timed_out,
        summary,
        operator,
    });
}

fn finding_form(id: &str, existing: Option<&Finding>) -> Out {
    let e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };
    let f = existing
        .cloned()
        .unwrap_or_else(|| Finding::new(String::new()));
    let action = match existing {
        Some(x) => format!("/engagement/{}/finding/{}/edit", id, x.id),
        None => format!("/engagement/{}/finding/new", id),
    };
    let sevs: Vec<&str> = Severity::all().iter().map(|s| s.label()).collect();
    let stats: Vec<&str> = FindingStatus::all()
        .iter()
        .map(|s| status_value(s))
        .collect();
    let cats = content::finding_categories();
    let tactics = content::attack_tactics();

    // asset datalist
    let mut dl = String::from("<datalist id=assets>");
    for a in &e.assets {
        let v = if a.essid.is_empty() {
            a.bssid.clone()
        } else {
            format!("{} ({})", a.essid, a.bssid)
        };
        dl.push_str(&format!("<option value='{}'>", esc(&v)));
    }
    dl.push_str("</datalist>");

    let body = format!(
        "<div class=crumb><a href='/engagement/{id}'>← dashboard</a></div>\
<h1>{heading}</h1>\
<form method=post action='{action}' class=form>{csrf}\
{title}\
<div class=grid3>{category}{severity}{status}</div>\
<div class=grid3>{tactic}{technique}{cvss_v}</div>\
<div class=grid3>{cvss_s}{asset}<div></div></div>{dl}\
<fieldset><legend>DREAD (0–10 each)</legend><div class=grid5>{d}{r}{ex}{a}{di}</div></fieldset>\
{desc}{ev}{imp}{rem}\
<div class=actions><button class=btn-primary type=submit>Save finding</button> <a class=btn href='/engagement/{id}'>Cancel</a></div>\
</form>",
        id = id,
        heading = if existing.is_some() { "Edit finding" } else { "Add finding" },
        action = action,
        csrf = auth::csrf_field(),
        title = inp("title", "Title", &f.title, ""),
        category = sel("category", "Category", cats, &f.category),
        severity = sel("severity", "Severity", &sevs, f.severity.label()),
        status = sel("status", "Status", &stats, status_value(&f.status)),
        tactic = sel("tactic", "ATT&CK tactic", tactics, &f.attack_tactic),
        technique = inp("technique_id", "Technique id", &f.technique_id, "e.g. T1557"),
        cvss_v = inp("cvss_vector", "CVSS vector", &f.cvss_vector, "CVSS:3.1/..."),
        cvss_s = num("cvss_score", "CVSS score", &fmtf(f.cvss_score), "0", "10"),
        asset = inp_list("affected_asset", "Affected asset", &f.affected_asset, "assets"),
        dl = dl,
        d = num("dread_d", "Damage", &f.dread.damage.to_string(), "0", "10"),
        r = num("dread_r", "Reprod.", &f.dread.reproducibility.to_string(), "0", "10"),
        ex = num("dread_e", "Exploit.", &f.dread.exploitability.to_string(), "0", "10"),
        a = num("dread_a", "Affected", &f.dread.affected_users.to_string(), "0", "10"),
        di = num("dread_di", "Discover.", &f.dread.discoverability.to_string(), "0", "10"),
        desc = ta("description", "Description (how it works)", &f.description, 3),
        ev = ta("evidence", "Evidence (timestamps, BSSID, outputs — mask secrets)", &f.evidence, 3),
        imp = ta("impact", "Business impact", &f.impact, 2),
        rem = ta("remediation", "Remediation", &f.remediation, 3),
    );
    Out::Html(layout("Finding", "", &body))
}

fn read_finding(form: &HashMap<String, String>, mut f: Finding) -> Finding {
    f.title = g(form, "title").to_string();
    f.category = g(form, "category").to_string();
    f.severity = Severity::from_str(g(form, "severity"));
    f.status = FindingStatus::from_str(g(form, "status"));
    f.attack_tactic = g(form, "tactic").to_string();
    f.technique_id = g(form, "technique_id").to_string();
    f.cvss_vector = g(form, "cvss_vector").to_string();
    f.cvss_score = g(form, "cvss_score").parse().unwrap_or(0.0);
    f.affected_asset = g(form, "affected_asset").to_string();
    f.dread = Dread {
        damage: clamp10(g(form, "dread_d")),
        reproducibility: clamp10(g(form, "dread_r")),
        exploitability: clamp10(g(form, "dread_e")),
        affected_users: clamp10(g(form, "dread_a")),
        discoverability: clamp10(g(form, "dread_di")),
    };
    f.description = g(form, "description").to_string();
    f.evidence = g(form, "evidence").to_string();
    f.impact = g(form, "impact").to_string();
    f.remediation = g(form, "remediation").to_string();
    f
}

fn finding_create(id: &str, form: &HashMap<String, String>) -> Out {
    let mut e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };
    let f = read_finding(form, Finding::new(String::new()));
    e.findings.push(f);
    let dest = format!("/engagement/{}", e.id);
    save_then_redirect(&mut e, dest)
}

fn finding_update(id: &str, fid: &str, form: &HashMap<String, String>) -> Out {
    let mut e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };
    let dest = format!("/engagement/{id}/finding/{fid}");
    if let Some(idx) = e.findings.iter().position(|f| f.id == fid) {
        let existing = e.findings[idx].clone();
        let updated = read_finding(form, existing);
        e.findings[idx] = updated;
        e.findings[idx].auto_detected = false;
        save_then_redirect(&mut e, dest)
    } else {
        Out::Redirect(dest)
    }
}

fn finding_retest(id: &str, fid: &str, form: &HashMap<String, String>) -> Out {
    let mut e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };
    let dest = format!("/engagement/{id}/finding/{fid}");
    let found = if let Some(f) = e.findings.iter_mut().find(|f| f.id == fid) {
        let result = RetestResult::from_str(g(form, "r_result"));
        f.status = match result {
            RetestResult::Mitigated => FindingStatus::Mitigated,
            RetestResult::Partial => FindingStatus::Remediating,
            RetestResult::Open => FindingStatus::Retesting,
        };
        f.retests.push(Retest {
            date: g(form, "r_date").to_string(),
            technique: g(form, "r_technique").to_string(),
            result,
            notes: g(form, "r_notes").to_string(),
        });
        true
    } else {
        false
    };
    if found {
        save_then_redirect(&mut e, dest)
    } else {
        Out::Redirect(dest)
    }
}

fn finding_detail(id: &str, fid: &str) -> Out {
    let e = match store::load(id) {
        Ok(e) => e,
        Err(_) => return not_found(),
    };
    let f = match e.finding(fid) {
        Some(f) => f.clone(),
        None => return not_found(),
    };

    let mut retests = String::new();
    if f.retests.is_empty() {
        retests.push_str("<p class=dim>No retests recorded yet.</p>");
    } else {
        retests.push_str(
            "<table><tr><th>Date</th><th>Technique</th><th>Result</th><th>Notes</th></tr>",
        );
        for r in &f.retests {
            retests.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><b>{}</b></td><td>{}</td></tr>",
                esc(&r.date),
                esc(&r.technique),
                r.result.label(),
                esc(&r.notes)
            ));
        }
        retests.push_str("</table>");
    }

    let results = ["Open", "Partial", "Mitigated"];
    let body = format!(
        "<div class=crumb><a href='/engagement/{id}'>← dashboard</a></div>\
<h1><span class=sevtag style='background:{color}'>{sev}</span> {title}</h1>\
<p class=meta>Category: {cat} · ATT&CK: {tactic} {tech} · CVSS: {cvssv} ({cvsss:.1}) · DREAD: {dread:.1}/10 · Status: {status}</p>\
<div class=card><p class=lbl>Description</p><p>{desc}</p>\
<p class=lbl>Evidence</p><p>{ev}</p>\
<p class=lbl>Impact</p><p>{imp}</p>\
<p class=lbl>Remediation</p><p>{rem}</p></div>\
<h2>Iterative retest</h2>{retests}\
<form method=post action='/engagement/{id}/finding/{fid}/retest' class=form>{csrf}\
<div class=grid3>{r_date}{r_tech}{r_result}</div>{r_notes}\
<div class=actions><button class=btn-primary type=submit>Record retest</button></div></form>\
<details class=editwrap><summary>Edit this finding</summary>{editform}</details>",
        id = id, fid = fid,
        csrf = auth::csrf_field(),
        color = f.severity.color(), sev = f.severity.label(), title = esc(&f.title),
        cat = esc(dash(&f.category)), tactic = esc(dash(&f.attack_tactic)), tech = esc(&f.technique_id),
        cvssv = esc(dash(&f.cvss_vector)), cvsss = f.cvss_score, dread = f.dread.score(), status = f.status.label(),
        desc = esc(dash(&f.description)), ev = esc(dash(&f.evidence)), imp = esc(dash(&f.impact)), rem = esc(dash(&f.remediation)),
        r_date = inp("r_date", "Date", "", "YYYY-MM-DD"),
        r_tech = inp("r_technique", "Technique retried", "", ""),
        r_result = sel("r_result", "Result", &results, ""),
        r_notes = ta("r_notes", "Notes", "", 2),
        editform = inline_edit_form(id, &f),
    );
    Out::Html(layout(&f.title, "", &body))
}

fn inline_edit_form(id: &str, f: &Finding) -> String {
    finding_form_inner(id, f)
}

fn finding_form_inner(id: &str, f: &Finding) -> String {
    let sevs: Vec<&str> = Severity::all().iter().map(|s| s.label()).collect();
    let stats: Vec<&str> = FindingStatus::all().iter().map(status_value).collect();
    let cats = content::finding_categories();
    let tactics = content::attack_tactics();
    format!(
        "<form method=post action='/engagement/{id}/finding/{fid}/edit' class=form>{csrf}\
{title}<div class=grid3>{category}{severity}{status}</div>\
<div class=grid3>{tactic}{technique}{cvss_v}</div>{cvss_s}\
<fieldset><legend>DREAD</legend><div class=grid5>{d}{r}{ex}{a}{di}</div></fieldset>\
{desc}{ev}{imp}{rem}\
<div class=actions><button class=btn-primary type=submit>Update finding</button></div></form>",
        id = id,
        fid = f.id,
        csrf = auth::csrf_field(),
        title = inp("title", "Title", &f.title, ""),
        category = sel("category", "Category", cats, &f.category),
        severity = sel("severity", "Severity", &sevs, f.severity.label()),
        status = sel("status", "Status", &stats, status_value(&f.status)),
        tactic = sel("tactic", "ATT&CK tactic", tactics, &f.attack_tactic),
        technique = inp("technique_id", "Technique id", &f.technique_id, ""),
        cvss_v = inp("cvss_vector", "CVSS vector", &f.cvss_vector, ""),
        cvss_s = num("cvss_score", "CVSS score", &fmtf(f.cvss_score), "0", "10"),
        d = num("dread_d", "Damage", &f.dread.damage.to_string(), "0", "10"),
        r = num(
            "dread_r",
            "Reprod.",
            &f.dread.reproducibility.to_string(),
            "0",
            "10"
        ),
        ex = num(
            "dread_e",
            "Exploit.",
            &f.dread.exploitability.to_string(),
            "0",
            "10"
        ),
        a = num(
            "dread_a",
            "Affected",
            &f.dread.affected_users.to_string(),
            "0",
            "10"
        ),
        di = num(
            "dread_di",
            "Discover.",
            &f.dread.discoverability.to_string(),
            "0",
            "10"
        ),
        desc = ta("description", "Description", &f.description, 3),
        ev = ta("evidence", "Evidence", &f.evidence, 3),
        imp = ta("impact", "Impact", &f.impact, 2),
        rem = ta("remediation", "Remediation", &f.remediation, 3),
    )
}

// ---------- helpers ----------

fn g<'a>(m: &'a HashMap<String, String>, k: &str) -> &'a str {
    m.get(k).map(|s| s.as_str()).unwrap_or("")
}
fn gb(m: &HashMap<String, String>, k: &str) -> bool {
    matches!(m.get(k).map(|s| s.as_str()), Some("on" | "true" | "1"))
}
fn clamp10(s: &str) -> u8 {
    s.parse::<u8>().unwrap_or(0).min(10)
}
fn fmtf(v: f32) -> String {
    if v == 0.0 {
        String::new()
    } else {
        format!("{v}")
    }
}
fn dash(s: &str) -> &str {
    if s.trim().is_empty() {
        "—"
    } else {
        s
    }
}
fn status_value(s: &FindingStatus) -> &'static str {
    match s {
        FindingStatus::Open => "Open",
        FindingStatus::Remediating => "Remediating",
        FindingStatus::Retesting => "Retesting",
        FindingStatus::Mitigated => "Mitigated",
        FindingStatus::Accepted => "Accepted",
    }
}
fn header(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap()
}
fn not_found() -> Out {
    Out::Html(layout(
        "Not found",
        "",
        "<h1>Not found</h1><p><a href='/'>← Home</a></p>",
    ))
}
fn err_page(msg: &str) -> Out {
    Out::Html(layout(
        "Error",
        "",
        &format!(
            "<h1>Error</h1><p>{}</p><p><a href='/'>← Home</a></p>",
            esc(msg)
        ),
    ))
}

/// Persist an engagement after appending an audit-log entry, retrying up to
/// four times on an optimistic-concurrency conflict. Audit-log appends are
/// append-only and idempotent in intent, so losing one to a concurrent
/// writer would silently erase evidence — the retry reloads the engagement,
/// re-appends the last action, and tries again. On persistent failure the
/// action is discarded with no further surfacing (the caller is already
/// rendering a page for the user).
fn save_with_action_retry(e: &mut Engagement) {
    let last_action = e.action_log.last().cloned();
    if store::save(e).is_ok() {
        return;
    }
    let Some(action) = last_action else {
        return;
    };
    for _ in 0..4 {
        let mut fresh = match store::load(&e.id) {
            Ok(x) => x,
            Err(_) => return,
        };
        fresh.action_log.push(action.clone());
        match store::save(&mut fresh) {
            Ok(()) => {
                *e = fresh;
                return;
            }
            Err(store::SaveError::Conflict { .. }) => continue,
            Err(_) => return,
        }
    }
}

/// Save and either redirect to `next` or render a message page explaining
/// why the save failed — including the specific "another tab wrote first,
/// please reload" wording for optimistic-concurrency conflicts.
fn save_then_redirect(e: &mut Engagement, next: String) -> Out {
    match store::save(e) {
        Ok(()) => Out::Redirect(next),
        Err(store::SaveError::Conflict { .. }) => Out::Html(layout(
            "Save conflict",
            "",
            &format!(
                "<h1>Save conflict</h1>\
<p>Another browser tab or CLI command updated this engagement after you loaded it. \
Your changes were <b>not</b> saved to avoid overwriting that work.</p>\
<p>Open the engagement again, re-apply your edits on top of the current state, then save.</p>\
<p><a class=btn href='/engagement/{id}'>← Reload engagement</a></p>",
                id = e.id,
            ),
        )),
        Err(e) => err_page(&format!("Could not save: {e}")),
    }
}

fn inp(name: &str, label: &str, value: &str, ph: &str) -> String {
    format!(
        "<label>{}<input name='{}' value='{}' placeholder='{}'></label>",
        esc(label),
        name,
        esc(value),
        esc(ph)
    )
}
fn inp_list(name: &str, label: &str, value: &str, list: &str) -> String {
    format!(
        "<label>{}<input name='{}' value='{}' list='{}'></label>",
        esc(label),
        name,
        esc(value),
        list
    )
}
fn ta(name: &str, label: &str, value: &str, rows: u32) -> String {
    format!(
        "<label>{}<textarea name='{}' rows='{}'>{}</textarea></label>",
        esc(label),
        name,
        rows,
        esc(value)
    )
}
fn num(name: &str, label: &str, value: &str, min: &str, max: &str) -> String {
    format!(
        "<label>{}<input type=number step=any min='{}' max='{}' name='{}' value='{}'></label>",
        esc(label),
        min,
        max,
        name,
        esc(value)
    )
}
fn chk(name: &str, label: &str, checked: bool) -> String {
    format!(
        "<label class=chk><input type=checkbox name='{}'{}> {}</label>",
        name,
        if checked { " checked" } else { "" },
        esc(label)
    )
}
fn sel(name: &str, label: &str, opts: &[&str], selected: &str) -> String {
    let mut o = String::new();
    for op in opts {
        let s = if *op == selected { " selected" } else { "" };
        o.push_str(&format!(
            "<option value='{}'{}>{}</option>",
            esc(op),
            s,
            esc(op)
        ));
    }
    format!(
        "<label>{}<select name='{}'>{}</select></label>",
        esc(label),
        name,
        o
    )
}

fn layout(title: &str, _sub: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
<meta name=viewport content='width=device-width,initial-scale=1'>\
<title>{} · Network Tool</title><style>{}</style></head><body><div class=wrap>{}</div></body></html>",
        esc(title),
        CSS,
        body
    )
}

const CSS: &str = "\
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--dim:#8b949e;--accent:#2f81f7;--accent2:#1f6feb}\
*{box-sizing:border-box}\
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif}\
.wrap{max-width:960px;margin:0 auto;padding:1.5rem 1rem 4rem}\
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}\
h1{font-size:1.6rem;margin:.2rem 0 .6rem}h2{font-size:1.15rem;margin:1.6rem 0 .5rem;border-bottom:1px solid var(--border);padding-bottom:.3rem}\
.hero{background:var(--panel);border:1px solid var(--border);border-radius:.7rem;padding:1.5rem;margin-bottom:1.5rem}\
.hero h1{margin:0}.sub{color:var(--dim);margin:.2rem 0 1rem}\
.meta,.crumb{color:var(--dim);font-size:.9rem;margin:.2rem 0 .8rem}\
.dim{color:var(--dim)}.note{color:var(--dim);font-size:.9rem}\
table{border-collapse:collapse;width:100%;margin:.5rem 0;font-size:.9rem}\
th,td{border:1px solid var(--border);padding:.4rem .55rem;text-align:left;vertical-align:top}\
th{background:#1c2128;color:var(--dim);font-weight:600}\
.mono{font-family:ui-monospace,Menlo,monospace;font-size:.82rem}\
.btn,.btn-primary{display:inline-block;padding:.45rem .9rem;border-radius:.45rem;font-size:.9rem;cursor:pointer;border:1px solid var(--border);margin:.15rem .1rem}\
.btn{background:var(--panel);color:var(--fg)}.btn:hover{border-color:var(--accent);text-decoration:none}\
.btn-primary{background:var(--accent2);color:#fff;border-color:var(--accent2)}.btn-primary:hover{background:var(--accent);text-decoration:none}\
.toolbar{margin:.6rem 0}\
.sevrow{display:flex;gap:.4rem;flex-wrap:wrap;margin:.4rem 0}\
.sevpill{color:#fff;padding:.25rem .7rem;border-radius:1rem;font-size:.82rem;font-weight:600}\
.sevtag{color:#fff;padding:.12rem .5rem;border-radius:.3rem;font-size:.72rem;font-weight:600}\
.badge-ok{background:#196c2e;color:#fff;padding:.1rem .5rem;border-radius:.3rem;font-size:.75rem}\
.badge-warn{background:#7d3a00;color:#fff;padding:.1rem .5rem;border-radius:.3rem;font-size:.75rem}\
.auto{background:#30363d;color:var(--dim);padding:0 .35rem;border-radius:.3rem;font-size:.7rem}\
.banner-ok{background:#0f2a16;border:1px solid #196c2e;color:#5fd47f;padding:.7rem .9rem;border-radius:.5rem;margin:.6rem 0}\
.banner-warn{background:#2a1600;border:1px solid #7d3a00;color:#f0883e;padding:.7rem .9rem;border-radius:.5rem;margin:.6rem 0}\
.form{display:flex;flex-direction:column;gap:.7rem;max-width:720px}\
fieldset{border:1px solid var(--border);border-radius:.5rem;padding:.8rem 1rem;display:flex;flex-direction:column;gap:.7rem}\
legend{color:var(--accent);font-weight:600;padding:0 .4rem}\
label{display:flex;flex-direction:column;gap:.25rem;font-size:.85rem;color:var(--dim)}\
label.chk{flex-direction:row;align-items:center;gap:.5rem;color:var(--fg);font-size:.9rem}\
input,textarea,select{background:#0b0f14;border:1px solid var(--border);color:var(--fg);border-radius:.4rem;padding:.45rem .55rem;font:inherit}\
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--accent)}\
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:.7rem}\
.grid5{display:grid;grid-template-columns:repeat(5,1fr);gap:.5rem}\
.actions{display:flex;gap:.5rem;align-items:center;margin-top:.4rem}\
.card{background:var(--panel);border:1px solid var(--border);border-radius:.5rem;padding:.3rem 1rem 1rem;margin:.6rem 0}\
.lbl{font-weight:600;color:var(--accent);margin:.8rem 0 .1rem}\
.authbox{border-color:#7d3a00}\
.editwrap{margin-top:1.5rem;border:1px solid var(--border);border-radius:.5rem;padding:.3rem .8rem}\
.editwrap summary{cursor:pointer;color:var(--accent);padding:.4rem 0}\
.term{background:#0b0f14;border:1px solid var(--border);border-radius:.4rem;padding:.6rem .7rem;overflow:auto;font-family:ui-monospace,Menlo,monospace;font-size:.8rem;white-space:pre-wrap;word-break:break-word;color:#cdd9e5}\
@media(max-width:640px){.grid3,.grid5{grid-template-columns:1fr 1fr}}\
";
