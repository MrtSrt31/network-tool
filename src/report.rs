//! Report generation: Markdown (portable, git-friendly) and standalone HTML
//! (printable). Both are built directly from the engagement data.

use crate::content;
use crate::model::Engagement;
use crate::util::esc;

pub fn markdown(e: &Engagement) -> String {
    let mut s = String::new();
    let created = e.created_at.format("%Y-%m-%d");
    s.push_str(&format!("# Wireless Security Assessment — {}\n\n", e.name));
    s.push_str(&format!("**Client:** {}  \n", e.client.name));
    s.push_str(&format!(
        "**Tester:** {} ({})  \n",
        e.tester.name,
        if e.tester.company.is_empty() {
            "—"
        } else {
            &e.tester.company
        }
    ));
    s.push_str(&format!("**Date:** {created}  \n"));
    s.push_str(&format!("**Status:** {}  \n\n", e.status.label()));

    // Authorization statement
    s.push_str("## Authorization\n\n");
    if e.active_testing_unlocked() {
        s.push_str(&format!(
            "Authorized by **{}** ({}) on {}. RoE reference: {}. Disruptive techniques permitted: {}.\n\n",
            e.authorization.authorizer_name,
            e.authorization.authorizer_title,
            e.authorization.signed_date,
            if e.authorization.roe_reference.is_empty() { "—" } else { &e.authorization.roe_reference },
            if e.authorization.disruptive_allowed { "yes" } else { "no" },
        ));
    } else {
        s.push_str("> No signed authorization recorded. Active testing was NOT unlocked for this engagement.\n\n");
    }

    // Executive summary
    let c = e.severity_counts();
    s.push_str("## Executive summary\n\n");
    s.push_str(&format!(
        "Findings by severity — Critical: {}, High: {}, Medium: {}, Low: {}, Info: {}. Open items: {}.\n\n",
        c[4], c[3], c[2], c[1], c[0], e.open_count()
    ));

    // Scope
    s.push_str("## Scope\n\n");
    s.push_str(&format!(
        "- Approach: {}\n",
        if e.scope.approach.is_empty() {
            "—"
        } else {
            &e.scope.approach
        }
    ));
    s.push_str(&format!(
        "- In-scope SSIDs: {}\n",
        join_or_dash(&e.scope.in_scope_ssids)
    ));
    s.push_str(&format!(
        "- In-scope BSSIDs: {}\n",
        join_or_dash(&e.scope.in_scope_bssids)
    ));
    s.push_str(&format!(
        "- Test windows: {}\n",
        dash(&e.scope.test_windows)
    ));
    s.push_str(&format!(
        "- Allowed techniques: {}\n",
        join_or_dash(&e.scope.allowed_techniques)
    ));
    s.push_str(&format!(
        "- Prohibited techniques: {}\n",
        join_or_dash(&e.scope.prohibited_techniques)
    ));
    s.push_str(&format!(
        "- Out of scope: {}\n\n",
        dash(&e.scope.out_of_scope_notes)
    ));

    // Asset inventory
    s.push_str("## Wireless asset inventory\n\n");
    if e.assets.is_empty() {
        s.push_str("_No assets recorded._\n\n");
    } else {
        s.push_str("| Type | ESSID | BSSID | Ch | Enc | Cipher | Auth | In scope |\n");
        s.push_str("|---|---|---|---|---|---|---|---|\n");
        for a in &e.assets {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                a.kind.label(),
                dash(&a.essid),
                dash(&a.bssid),
                dash(&a.channel),
                dash(&a.encryption),
                dash(&a.cipher),
                dash(&a.auth),
                if a.in_scope { "yes" } else { "no" }
            ));
        }
        s.push('\n');
    }

    // Findings
    s.push_str("## Findings\n\n");
    if e.findings.is_empty() {
        s.push_str("_No findings recorded._\n\n");
    } else {
        for (i, f) in e.findings.iter().enumerate() {
            s.push_str(&format!(
                "### {}. {} [{}]\n\n",
                i + 1,
                f.title,
                f.severity.label()
            ));
            s.push_str(&format!("- Category: {}\n", dash(&f.category)));
            let tech_md = if f.technique_id.trim().is_empty() {
                "—".to_string()
            } else {
                format!(
                    "[{}]({})",
                    f.technique_id,
                    content::attack_technique_url(f.technique_id.trim())
                )
            };
            s.push_str(&format!(
                "- ATT&CK: {} {}\n",
                dash(&f.attack_tactic),
                tech_md
            ));
            s.push_str(&format!(
                "- CVSS: {} ({:.1})\n",
                dash(&f.cvss_vector),
                f.cvss_score
            ));
            s.push_str(&format!("- DREAD score: {:.1}/10\n", f.dread.score()));
            s.push_str(&format!("- Affected asset: {}\n", dash(&f.affected_asset)));
            s.push_str(&format!("- Status: {}\n\n", f.status.label()));
            if !f.description.is_empty() {
                s.push_str(&format!("**Description.** {}\n\n", f.description));
            }
            if !f.evidence.is_empty() {
                s.push_str(&format!("**Evidence.** {}\n\n", f.evidence));
            }
            if !f.impact.is_empty() {
                s.push_str(&format!("**Impact.** {}\n\n", f.impact));
            }
            if !f.remediation.is_empty() {
                s.push_str(&format!("**Remediation.** {}\n\n", f.remediation));
            }
            if !f.evidence_action_runs.is_empty() {
                s.push_str("**Linked actions (audit chain evidence).**\n\n");
                for aid in &f.evidence_action_runs {
                    if let Some(a) = e.action_log.iter().find(|a| &a.id == aid) {
                        s.push_str(&format!(
                            "- `{}` — {} — `{}` — {}\n",
                            a.at.format("%Y-%m-%dT%H:%MZ"),
                            a.module_name,
                            a.command,
                            a.summary
                        ));
                    }
                }
                s.push('\n');
            }
            if !f.retests.is_empty() {
                s.push_str("**Retest history.**\n\n");
                for r in &f.retests {
                    s.push_str(&format!(
                        "- {} — {} — {}: {}\n",
                        r.date,
                        r.technique,
                        r.result.label(),
                        r.notes
                    ));
                }
                s.push('\n');
            }
        }
    }

    // Appendices
    s.push_str("## Appendix A — Methodology (PTES-aligned)\n\n");
    for (phase, items) in content::methodology_phases() {
        s.push_str(&format!("### {phase}\n\n"));
        for it in items {
            s.push_str(&format!("- {it}\n"));
        }
        s.push('\n');
    }

    s.push_str("## Appendix B — Hardening / remediation matrix\n\n");
    s.push_str("| Finding class | Layered hardening |\n|---|---|\n");
    for (k, v) in content::hardening_matrix() {
        s.push_str(&format!("| {k} | {v} |\n"));
    }
    s.push('\n');

    s.push_str("---\n\n");
    s.push_str(&format!(
        "_Audit chain head: `{}` ({} entries). Verify with `networktool audit verify {}`._\n",
        crate::audit::chain_head(e),
        e.action_log.len(),
        e.id,
    ));

    s
}

pub fn html(e: &Engagement) -> String {
    let c = e.severity_counts();
    let mut body = String::new();

    body.push_str(&format!(
        "<h1>Wireless Security Assessment — {}</h1>",
        esc(&e.name)
    ));
    body.push_str(&format!(
        "<p class=meta><b>Client:</b> {} &nbsp;·&nbsp; <b>Tester:</b> {} ({}) &nbsp;·&nbsp; <b>Date:</b> {} &nbsp;·&nbsp; <b>Status:</b> {}</p>",
        esc(&e.client.name),
        esc(&e.tester.name),
        esc(if e.tester.company.is_empty() { "—" } else { &e.tester.company }),
        e.created_at.format("%Y-%m-%d"),
        e.status.label(),
    ));

    // Authorization
    body.push_str("<h2>Authorization</h2>");
    if e.active_testing_unlocked() {
        body.push_str(&format!(
            "<p class=ok>Authorized by <b>{}</b> ({}) on {}. RoE: {}. Disruptive techniques permitted: {}.</p>",
            esc(&e.authorization.authorizer_name),
            esc(&e.authorization.authorizer_title),
            esc(&e.authorization.signed_date),
            esc(if e.authorization.roe_reference.is_empty() { "—" } else { &e.authorization.roe_reference }),
            if e.authorization.disruptive_allowed { "yes" } else { "no" },
        ));
    } else {
        body.push_str("<p class=warn>No signed authorization recorded. Active testing was NOT unlocked for this engagement.</p>");
    }

    // Summary
    body.push_str("<h2>Executive summary</h2><div class=sevrow>");
    let labels = ["Info", "Low", "Medium", "High", "Critical"];
    let colors = ["#5b8def", "#3fb950", "#d29922", "#f0883e", "#f85149"];
    for i in (0..5).rev() {
        body.push_str(&format!(
            "<span class=sevpill style='background:{}'>{}: {}</span>",
            colors[i], labels[i], c[i]
        ));
    }
    body.push_str(&format!(
        "</div><p>Open items: <b>{}</b> of {} findings.</p>",
        e.open_count(),
        e.findings.len()
    ));

    // Scope
    body.push_str("<h2>Scope</h2><ul>");
    body.push_str(&format!(
        "<li>Approach: {}</li>",
        esc(dash(&e.scope.approach))
    ));
    body.push_str(&format!(
        "<li>In-scope SSIDs: {}</li>",
        esc(&join_or_dash(&e.scope.in_scope_ssids))
    ));
    body.push_str(&format!(
        "<li>In-scope BSSIDs: {}</li>",
        esc(&join_or_dash(&e.scope.in_scope_bssids))
    ));
    body.push_str(&format!(
        "<li>Test windows: {}</li>",
        esc(dash(&e.scope.test_windows))
    ));
    body.push_str(&format!(
        "<li>Prohibited: {}</li>",
        esc(&join_or_dash(&e.scope.prohibited_techniques))
    ));
    body.push_str(&format!(
        "<li>Out of scope: {}</li></ul>",
        esc(dash(&e.scope.out_of_scope_notes))
    ));

    // Assets
    body.push_str("<h2>Wireless asset inventory</h2>");
    if e.assets.is_empty() {
        body.push_str("<p class=dim>No assets recorded.</p>");
    } else {
        body.push_str("<table><tr><th>Type</th><th>ESSID</th><th>BSSID</th><th>Ch</th><th>Enc</th><th>Cipher</th><th>Auth</th><th>Scope</th></tr>");
        for a in &e.assets {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=mono>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                a.kind.label(),
                esc(dash(&a.essid)),
                esc(dash(&a.bssid)),
                esc(dash(&a.channel)),
                esc(dash(&a.encryption)),
                esc(dash(&a.cipher)),
                esc(dash(&a.auth)),
                if a.in_scope { "yes" } else { "no" },
            ));
        }
        body.push_str("</table>");
    }

    // Findings
    body.push_str("<h2>Findings</h2>");
    if e.findings.is_empty() {
        body.push_str("<p class=dim>No findings recorded.</p>");
    } else {
        for (i, f) in e.findings.iter().enumerate() {
            body.push_str(&format!(
                "<div class=finding><h3><span class=sevtag style='background:{}'>{}</span> {}. {}</h3>",
                f.severity.color(),
                f.severity.label(),
                i + 1,
                esc(&f.title),
            ));
            let tech_html = if f.technique_id.trim().is_empty() {
                String::new()
            } else {
                format!(
                    "<a href='{}' target='_blank' rel='noopener'>{}</a>",
                    esc(&content::attack_technique_url(f.technique_id.trim())),
                    esc(&f.technique_id)
                )
            };
            body.push_str(&format!(
                "<p class=fmeta>Category: {} · ATT&amp;CK: {} {} · CVSS: {} ({:.1}) · DREAD: {:.1}/10 · Asset: {} · Status: {}</p>",
                esc(dash(&f.category)),
                esc(dash(&f.attack_tactic)),
                tech_html,
                esc(dash(&f.cvss_vector)),
                f.cvss_score,
                f.dread.score(),
                esc(dash(&f.affected_asset)),
                f.status.label(),
            ));
            push_para(&mut body, "Description", &f.description);
            push_para(&mut body, "Evidence", &f.evidence);
            push_para(&mut body, "Impact", &f.impact);
            push_para(&mut body, "Remediation", &f.remediation);
            if !f.evidence_action_runs.is_empty() {
                body.push_str("<p class=lbl>Linked actions (audit chain evidence)</p><ul>");
                for aid in &f.evidence_action_runs {
                    if let Some(a) = e.action_log.iter().find(|a| &a.id == aid) {
                        body.push_str(&format!(
                            "<li class=mono>{} — {} — <code>{}</code> — {}</li>",
                            a.at.format("%Y-%m-%dT%H:%MZ"),
                            esc(&a.module_name),
                            esc(&a.command),
                            esc(&a.summary),
                        ));
                    }
                }
                body.push_str("</ul>");
            }
            if !f.retests.is_empty() {
                body.push_str("<p class=lbl>Retest history</p><ul>");
                for r in &f.retests {
                    body.push_str(&format!(
                        "<li>{} — {} — <b>{}</b>: {}</li>",
                        esc(&r.date),
                        esc(&r.technique),
                        r.result.label(),
                        esc(&r.notes)
                    ));
                }
                body.push_str("</ul>");
            }
            body.push_str("</div>");
        }
    }

    // Appendices
    body.push_str("<h2>Appendix A — Methodology (PTES-aligned)</h2>");
    for (phase, items) in content::methodology_phases() {
        body.push_str(&format!("<h3>{}</h3><ul>", esc(phase)));
        for it in items {
            body.push_str(&format!("<li>{}</li>", esc(it)));
        }
        body.push_str("</ul>");
    }
    body.push_str("<h2>Appendix B — Hardening / remediation matrix</h2><table><tr><th>Finding class</th><th>Layered hardening</th></tr>");
    for (k, v) in content::hardening_matrix() {
        body.push_str(&format!("<tr><td>{}</td><td>{}</td></tr>", esc(k), esc(v)));
    }
    body.push_str("</table>");

    body.push_str(&format!(
        "<hr><p class=meta><b>Audit chain head:</b> <span class=mono>{}</span> &nbsp;·&nbsp; {} entries &nbsp;·&nbsp; verify with <code>networktool audit verify {}</code></p>",
        esc(&crate::audit::chain_head(e)),
        e.action_log.len(),
        esc(&e.id),
    ));

    wrap_report_html(&e.name, &body)
}

fn push_para(body: &mut String, label: &str, text: &str) {
    if !text.is_empty() {
        body.push_str(&format!(
            "<p><span class=lbl>{}.</span> {}</p>",
            esc(label),
            esc(text)
        ));
    }
}

fn dash(s: &str) -> &str {
    if s.trim().is_empty() {
        "—"
    } else {
        s
    }
}

fn join_or_dash(v: &[String]) -> String {
    if v.is_empty() {
        "—".to_string()
    } else {
        v.join(", ")
    }
}

fn wrap_report_html(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
<meta name=viewport content='width=device-width,initial-scale=1'>\
<title>Report — {}</title><style>\
body{{font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;background:#fff}}\
h1{{font-size:1.7rem;border-bottom:3px solid #222;padding-bottom:.4rem}}\
h2{{font-size:1.25rem;margin-top:2rem;border-bottom:1px solid #ccc;padding-bottom:.2rem}}\
h3{{font-size:1.05rem;margin-top:1.3rem}}\
.meta{{color:#555}} .dim{{color:#888}}\
table{{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.9rem}}\
th,td{{border:1px solid #ccc;padding:.35rem .5rem;text-align:left;vertical-align:top}}\
th{{background:#f2f2f2}} .mono{{font-family:ui-monospace,Menlo,monospace;font-size:.85rem}}\
.sevrow{{display:flex;gap:.4rem;flex-wrap:wrap;margin:.5rem 0}}\
.sevpill{{color:#fff;padding:.2rem .6rem;border-radius:1rem;font-size:.8rem;font-weight:600}}\
.sevtag{{color:#fff;padding:.1rem .5rem;border-radius:.3rem;font-size:.75rem;vertical-align:middle;margin-right:.4rem}}\
.finding{{border:1px solid #ddd;border-radius:.5rem;padding:.3rem 1rem 1rem;margin:1rem 0;background:#fafafa}}\
.fmeta{{color:#555;font-size:.85rem}} .lbl{{font-weight:600}}\
.ok{{color:#1a7f37}} .warn{{color:#b42318;font-weight:600}}\
@media print{{body{{margin:0}} .finding{{break-inside:avoid}}}}\
</style></head><body>{}<footer style='margin-top:3rem;color:#999;font-size:.8rem'>Generated by Network Tool · Aturc</footer></body></html>",
        esc(title),
        body
    )
}
