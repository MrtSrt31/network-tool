//! Authorization & Rules of Engagement document generator.
//!
//! Produces a printable, sign-ready document from the engagement data: the
//! parties, the authorization statement, the scope, permitted/prohibited
//! techniques, standard RoE clauses, and signature blocks. When the engagement
//! has no recorded authorization yet, the document is clearly marked DRAFT.
//!
//! This is a template generated from the operator's own data; both parties
//! (and legal counsel) should review it before signing.

use crate::model::Engagement;
use crate::util::esc;

fn dash(s: &str) -> &str {
    if s.trim().is_empty() {
        "—"
    } else {
        s
    }
}

fn list_items(v: &[String]) -> String {
    if v.is_empty() {
        "<li class=dim>— none specified —</li>".to_string()
    } else {
        v.iter()
            .map(|x| format!("<li>{}</li>", esc(x)))
            .collect::<String>()
    }
}

fn list_lines(v: &[String]) -> String {
    if v.is_empty() {
        "- —".to_string()
    } else {
        v.iter().map(|x| format!("- {x}\n")).collect()
    }
}

pub fn html(e: &Engagement) -> String {
    let authorized = e.active_testing_unlocked();
    let a = &e.authorization;
    let today = chrono::Utc::now().format("%Y-%m-%d");

    let status_banner = if authorized {
        String::new()
    } else {
        "<div class=draft>DRAFT — authorization not yet recorded. Not valid until signed.</div>"
            .to_string()
    };

    let company = if e.tester.company.is_empty() {
        "Aturc"
    } else {
        &e.tester.company
    };

    let disruptive_line = if a.disruptive_allowed {
        "<b>PERMITTED</b> — disruptive techniques (deauthentication, rogue AP / evil-twin) are expressly authorized within the scope and windows below."
    } else {
        "<b>NOT PERMITTED</b> — disruptive techniques (deauthentication, rogue AP / evil-twin) are prohibited. Passive and non-disruptive validation only."
    };

    let body = format!(
        "<div class=doc>\
{status_banner}\
<h1>Wireless Security Assessment<br><span class=sub>Authorization &amp; Rules of Engagement</span></h1>\
<table class=kv>\
<tr><td>Engagement</td><td>{name}</td></tr>\
<tr><td>Document date</td><td>{today}</td></tr>\
<tr><td>RoE reference</td><td>{roe}</td></tr>\
</table>\
\
<h2>1. Parties</h2>\
<div class=cols>\
<div><p class=role>Assessor (Service Provider)</p>\
<p>{company}<br>Lead: {t_name}{t_role}<br>{t_certs}{t_email}</p></div>\
<div><p class=role>Client</p>\
<p>{c_name}<br>Contact: {c_contact}<br>{c_email}{c_addr}</p></div>\
</div>\
\
<h2>2. Authorization</h2>\
<p><b>{c_name}</b> (\"the Client\") hereby authorizes <b>{company}</b> (\"the Assessor\") to perform an authorized wireless security assessment of the in-scope systems described in Section 3, strictly in accordance with these Rules of Engagement.</p>\
<p>The Client represents that it owns, or is duly authorized to permit testing of, the in-scope wireless networks, and that it has the authority to grant this authorization.</p>\
<table class=kv>\
<tr><td>Authorized by</td><td>{a_name}</td></tr>\
<tr><td>Title</td><td>{a_title}</td></tr>\
<tr><td>Signed date</td><td>{a_date}</td></tr>\
<tr><td>Status</td><td>{status_word}</td></tr>\
</table>\
\
<h2>3. Scope</h2>\
<table class=kv>\
<tr><td>Approach</td><td>{approach}</td></tr>\
<tr><td>Test windows</td><td>{windows}</td></tr>\
</table>\
<p class=role>In-scope SSIDs</p><ul>{ssids}</ul>\
<p class=role>In-scope BSSIDs</p><ul>{bssids}</ul>\
<p class=role>Out of scope</p><p>{outscope}</p>\
<p class=small>Any wireless network not expressly listed as in-scope — including neighbouring organisations' networks observed during testing — is out of scope and will not be targeted.</p>\
\
<h2>4. Permitted &amp; prohibited techniques</h2>\
<p class=role>Permitted techniques</p><ul>{allowed}</ul>\
<p class=role>Prohibited techniques</p><ul>{prohibited}</ul>\
<p class=role>Disruptive techniques</p><p>{disruptive}</p>\
\
<h2>5. Rules of Engagement</h2>\
<ol class=clauses>\
<li><b>Lawful authorization.</b> Testing is performed only against the in-scope systems during the agreed windows, under the authorization in Section 2. The Assessor will cease any activity that exceeds this authorization.</li>\
<li><b>Least impact.</b> The Assessor will prefer the least-intrusive technique that validates a finding. Disruptive techniques are used only where Section 4 permits them.</li>\
<li><b>Confidentiality.</b> All data observed or collected is treated as confidential, used solely for this engagement, and not disclosed to third parties.</li>\
<li><b>Evidence handling.</b> Captured material and findings are stored securely; secrets (keys, handshakes, credentials) are masked in reports and deleted on the Client's request after delivery.</li>\
<li><b>Stop conditions &amp; escalation.</b> On any sign of unintended disruption, out-of-scope impact, or discovery of a critical exposure, the Assessor will pause and contact the escalation contact: {emergency}.</li>\
<li><b>No warranty of completeness.</b> The assessment reflects the systems, configuration and time window tested; it does not guarantee the absence of other vulnerabilities.</li>\
<li><b>Reporting.</b> Findings are delivered with severity, evidence, and remediation guidance, followed by iterative retesting to confirm fixes.</li>\
</ol>\
<p class=small>This document is generated from engagement data and should be reviewed by both parties (and legal counsel) before signing. It does not itself constitute legal advice.</p>\
\
<h2>6. Signatures</h2>\
<div class=cols sig>\
<div class=sigbox><p class=role>For the Client</p>\
<div class=sigline></div><p>{a_name}{a_title_s}</p><div class=dateline>Date</div></div>\
<div class=sigbox><p class=role>For the Assessor</p>\
<div class=sigline></div><p>{t_name} — {company}</p><div class=dateline>Date</div></div>\
</div>\
</div>",
        status_banner = status_banner,
        name = esc(dash(&e.name)),
        today = today,
        roe = esc(dash(&a.roe_reference)),
        company = esc(company),
        t_name = esc(dash(&e.tester.name)),
        t_role = if e.tester.role.is_empty() { String::new() } else { format!(", {}", esc(&e.tester.role)) },
        t_certs = if e.tester.certifications.is_empty() { String::new() } else { format!("{}<br>", esc(&e.tester.certifications)) },
        t_email = esc(&e.tester.email),
        c_name = esc(dash(&e.client.name)),
        c_contact = esc(dash(&e.client.contact_name)),
        c_email = if e.client.contact_email.is_empty() { String::new() } else { format!("{}<br>", esc(&e.client.contact_email)) },
        c_addr = esc(&e.client.site_address),
        a_name = esc(dash(&a.authorizer_name)),
        a_title = esc(dash(&a.authorizer_title)),
        a_date = esc(dash(&a.signed_date)),
        status_word = if authorized { "AUTHORIZED" } else { "DRAFT (unsigned)" },
        approach = esc(dash(&e.scope.approach)),
        windows = esc(dash(&e.scope.test_windows)),
        ssids = list_items(&e.scope.in_scope_ssids),
        bssids = list_items(&e.scope.in_scope_bssids),
        outscope = esc(dash(&e.scope.out_of_scope_notes)),
        allowed = list_items(&e.scope.allowed_techniques),
        prohibited = list_items(&e.scope.prohibited_techniques),
        disruptive = disruptive_line,
        emergency = esc(dash(&a.emergency_contact)),
        a_title_s = if a.authorizer_title.is_empty() { String::new() } else { format!(" — {}", esc(&a.authorizer_title)) },
    );

    wrap(&e.name, &body)
}

pub fn markdown(e: &Engagement) -> String {
    let authorized = e.active_testing_unlocked();
    let a = &e.authorization;
    let company = if e.tester.company.is_empty() {
        "Aturc"
    } else {
        &e.tester.company
    };
    let mut s = String::new();
    if !authorized {
        s.push_str("> DRAFT — authorization not yet recorded. Not valid until signed.\n\n");
    }
    s.push_str("# Wireless Security Assessment — Authorization & Rules of Engagement\n\n");
    s.push_str(&format!("- Engagement: {}\n", dash(&e.name)));
    s.push_str(&format!(
        "- Document date: {}\n",
        chrono::Utc::now().format("%Y-%m-%d")
    ));
    s.push_str(&format!("- RoE reference: {}\n\n", dash(&a.roe_reference)));

    s.push_str("## 1. Parties\n\n");
    s.push_str(&format!(
        "**Assessor:** {} — Lead: {} ({}) {}\n\n",
        company,
        dash(&e.tester.name),
        dash(&e.tester.role),
        e.tester.email
    ));
    s.push_str(&format!(
        "**Client:** {} — Contact: {} {}\n\n",
        dash(&e.client.name),
        dash(&e.client.contact_name),
        e.client.contact_email
    ));

    s.push_str("## 2. Authorization\n\n");
    s.push_str(&format!(
        "{} (\"the Client\") authorizes {} (\"the Assessor\") to perform an authorized wireless security assessment of the in-scope systems, strictly per these Rules of Engagement.\n\n",
        dash(&e.client.name),
        company
    ));
    s.push_str(&format!("- Authorized by: {}\n", dash(&a.authorizer_name)));
    s.push_str(&format!("- Title: {}\n", dash(&a.authorizer_title)));
    s.push_str(&format!("- Signed date: {}\n", dash(&a.signed_date)));
    s.push_str(&format!(
        "- Status: {}\n\n",
        if authorized {
            "AUTHORIZED"
        } else {
            "DRAFT (unsigned)"
        }
    ));

    s.push_str("## 3. Scope\n\n");
    s.push_str(&format!("- Approach: {}\n", dash(&e.scope.approach)));
    s.push_str(&format!(
        "- Test windows: {}\n",
        dash(&e.scope.test_windows)
    ));
    s.push_str("\nIn-scope SSIDs:\n");
    s.push_str(&list_lines(&e.scope.in_scope_ssids));
    s.push_str("\nIn-scope BSSIDs:\n");
    s.push_str(&list_lines(&e.scope.in_scope_bssids));
    s.push_str(&format!(
        "\nOut of scope: {}\n\n",
        dash(&e.scope.out_of_scope_notes)
    ));
    s.push_str("Any network not listed as in-scope — including neighbouring organisations' networks — is out of scope.\n\n");

    s.push_str("## 4. Permitted & prohibited techniques\n\n");
    s.push_str("Permitted techniques:\n");
    s.push_str(&list_lines(&e.scope.allowed_techniques));
    s.push_str("\nProhibited techniques:\n");
    s.push_str(&list_lines(&e.scope.prohibited_techniques));
    s.push_str(&format!(
        "\nDisruptive techniques (deauth / rogue AP): {}\n\n",
        if a.disruptive_allowed {
            "PERMITTED within scope and windows"
        } else {
            "NOT PERMITTED — passive/validation only"
        }
    ));

    s.push_str("## 5. Rules of Engagement\n\n");
    for (i, c) in roe_clauses().iter().enumerate() {
        s.push_str(&format!("{}. {}\n", i + 1, c));
    }
    s.push_str(&format!(
        "\nEscalation / emergency contact: {}\n\n",
        dash(&a.emergency_contact)
    ));
    s.push_str("This document is generated from engagement data and should be reviewed by both parties (and legal counsel) before signing.\n\n");

    s.push_str("## 6. Signatures\n\n");
    s.push_str(&format!(
        "For the Client: {} ({})    ______________________    Date: __________\n\n",
        dash(&a.authorizer_name),
        dash(&a.authorizer_title)
    ));
    s.push_str(&format!(
        "For the Assessor: {} — {}    ______________________    Date: __________\n",
        dash(&e.tester.name),
        company
    ));
    s
}

fn roe_clauses() -> [&'static str; 7] {
    [
        "Lawful authorization — testing only against in-scope systems during agreed windows; activity exceeding authorization ceases immediately.",
        "Least impact — prefer the least-intrusive technique; disruptive techniques only where permitted.",
        "Confidentiality — all data treated as confidential and used solely for this engagement.",
        "Evidence handling — material stored securely; secrets masked in reports and deleted on request after delivery.",
        "Stop conditions & escalation — pause and contact the escalation contact on unintended disruption, out-of-scope impact, or a critical exposure.",
        "No warranty of completeness — reflects systems and window tested; does not guarantee absence of other vulnerabilities.",
        "Reporting — findings delivered with severity, evidence and remediation, followed by iterative retesting.",
    ]
}

fn wrap(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
<meta name=viewport content='width=device-width,initial-scale=1'>\
<title>Authorization &amp; RoE — {}</title><style>\
@page{{size:A4;margin:18mm}}\
body{{font:13px/1.6 Georgia,'Times New Roman',serif;color:#111;background:#f3f3f3;margin:0}}\
.doc{{max-width:820px;margin:1.5rem auto;background:#fff;padding:3rem;box-shadow:0 1px 6px rgba(0,0,0,.15)}}\
h1{{font-size:1.5rem;text-align:center;margin:0 0 .3rem;border-bottom:2px solid #111;padding-bottom:.6rem}}\
h1 .sub{{font-size:1rem;font-weight:normal;color:#444}}\
h2{{font-size:1.05rem;margin:1.6rem 0 .5rem;border-bottom:1px solid #bbb;padding-bottom:.2rem}}\
.kv{{border-collapse:collapse;margin:.4rem 0}}\
.kv td{{padding:.2rem .8rem .2rem 0;vertical-align:top}}\
.kv td:first-child{{color:#555;white-space:nowrap;width:140px}}\
.cols{{display:flex;gap:2rem}}.cols>div{{flex:1}}\
.role{{font-weight:bold;color:#333;margin:.6rem 0 .2rem}}\
ul,ol{{margin:.3rem 0 .3rem 1.2rem;padding:0}}li{{margin:.15rem 0}}\
.clauses li{{margin:.4rem 0}}\
.small{{font-size:.82rem;color:#666;font-style:italic}}.dim{{color:#999}}\
.draft{{background:#fde8e8;border:1px solid #c0392b;color:#8a1f16;text-align:center;font-weight:bold;letter-spacing:.05em;padding:.5rem;margin-bottom:1rem}}\
.sig{{margin-top:1.5rem}}.sigbox{{padding-top:.5rem}}\
.sigline{{border-bottom:1px solid #111;height:2.4rem;margin:.4rem 0}}\
.dateline{{border-bottom:1px solid #111;width:60%;margin-top:1.2rem;color:#555;font-size:.8rem}}\
@media print{{body{{background:#fff}}.doc{{box-shadow:none;margin:0;max-width:none;padding:0}}}}\
</style></head><body>{}</body></html>",
        esc(title),
        body
    )
}
