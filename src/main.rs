//! Network Tool — authorized wireless security assessment platform.
//!
//! One binary, two front-ends:
//!   * `networktool gui`  — local web control panel (intake, findings, report)
//!   * `networktool ...`  — scriptable CLI for the same engagement store
//!
//! For authorized assessments only. Active testing is gated behind a recorded
//! authorization per engagement.

mod content;
mod model;
mod modules;
mod recon;
mod report;
mod roe;
mod store;
mod util;
mod web;

use clap::{Args, Parser, Subcommand};
use model::*;
use std::collections::HashMap;
use std::error::Error;
use std::fs;

#[derive(Parser)]
#[command(
    name = "networktool",
    version,
    about = "Network Tool — authorized wireless security assessment platform (GUI + CLI)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the local web GUI control panel.
    Gui(GuiArgs),
    /// Manage engagements.
    Engagement {
        #[command(subcommand)]
        action: EngAction,
    },
    /// Manage findings.
    Finding {
        #[command(subcommand)]
        action: FindAction,
    },
    /// Import reconnaissance output.
    Recon {
        #[command(subcommand)]
        action: ReconAction,
    },
    /// Generate a report (markdown or html) for an engagement.
    Report(ReportArgs),
    /// Generate the Authorization & Rules of Engagement document for an engagement.
    Roe(RoeArgs),
    /// Active test-execution modules (orchestrate your installed wireless tools). Authorized use only.
    Module {
        #[command(subcommand)]
        action: ModuleAction,
    },
}

#[derive(Args)]
struct GuiArgs {
    /// Port to bind on 127.0.0.1.
    #[arg(long, default_value_t = 8787)]
    port: u16,
    /// Open the GUI in the default browser.
    #[arg(long)]
    open: bool,
}

#[derive(Subcommand)]
enum EngAction {
    /// Create a new engagement (unauthorized until you record authorization in the GUI).
    New {
        #[arg(long)]
        name: String,
        #[arg(long)]
        client: Option<String>,
        #[arg(long)]
        tester_name: Option<String>,
        #[arg(long)]
        tester_email: Option<String>,
    },
    /// List all engagements.
    List,
    /// Show one engagement.
    Show {
        id: String,
    },
}

#[derive(Subcommand)]
enum FindAction {
    /// Add a finding to an engagement.
    Add {
        #[arg(long)]
        engagement: String,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "Medium")]
        severity: String,
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        tactic: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        remediation: Option<String>,
    },
    /// List findings for an engagement.
    List {
        #[arg(long)]
        engagement: String,
    },
}

#[derive(Subcommand)]
enum ReconAction {
    /// Import an airodump-ng CSV capture into an engagement's asset inventory.
    Import {
        #[arg(long)]
        engagement: String,
        #[arg(long)]
        file: String,
        /// Auto-suggest draft findings from obvious weaknesses.
        #[arg(long)]
        derive: bool,
        /// Mark all imported access points as in-scope.
        #[arg(long = "in-scope")]
        in_scope: bool,
    },
}

#[derive(Args)]
struct ReportArgs {
    /// Engagement id.
    engagement: String,
    /// Output format: md | html.
    #[arg(long, default_value = "md")]
    format: String,
    /// Write to this file instead of stdout.
    #[arg(long)]
    out: Option<String>,
}

#[derive(Args)]
struct RoeArgs {
    /// Engagement id.
    engagement: String,
    /// Output format: html | md.
    #[arg(long, default_value = "html")]
    format: String,
    /// Write to this file instead of stdout.
    #[arg(long)]
    out: Option<String>,
}

#[derive(Subcommand)]
enum ModuleAction {
    /// List available modules.
    List,
    /// Check which required external tools are installed on this host.
    Preflight,
    /// Run a module against an engagement (respects the authorization gate).
    Run(ModuleRunArgs),
}

#[derive(Args)]
struct ModuleRunArgs {
    #[arg(long)]
    engagement: String,
    #[arg(long)]
    module: String,
    #[arg(long)]
    iface: Option<String>,
    #[arg(long)]
    bssid: Option<String>,
    #[arg(long)]
    channel: Option<String>,
    #[arg(long)]
    client: Option<String>,
    #[arg(long)]
    count: Option<String>,
    #[arg(long)]
    wordlist: Option<String>,
    #[arg(long)]
    capture: Option<String>,
    #[arg(long)]
    essid: Option<String>,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long)]
    out: Option<String>,
    /// Timeout in seconds (0 = no timeout).
    #[arg(long, default_value_t = 0)]
    timeout: u64,
    /// Preview the command without executing it.
    #[arg(long = "dry-run")]
    dry_run: bool,
    /// Explicit confirmation, required for disruptive modules.
    #[arg(long)]
    confirm: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Gui(a) => web::serve(a.port, a.open)?,
        Commands::Engagement { action } => match action {
            EngAction::New {
                name,
                client,
                tester_name,
                tester_email,
            } => {
                let mut e = Engagement::new(name);
                if let Some(c) = client {
                    e.client.name = c;
                }
                if let Some(t) = tester_name {
                    e.tester.name = t;
                }
                if let Some(em) = tester_email {
                    e.tester.email = em;
                }
                e.tester.company = "Aturc".to_string();
                store::save(&e)?;
                println!("created engagement {}  ({})", e.id, e.name);
                println!("note: active testing is LOCKED until authorization is recorded (networktool gui).");
            }
            EngAction::List => {
                let list = store::list()?;
                if list.is_empty() {
                    println!("(no engagements)");
                }
                for e in list {
                    let auth = if e.active_testing_unlocked() {
                        "unlocked"
                    } else {
                        "LOCKED"
                    };
                    println!(
                        "{}  {:<30} client={:<16} status={:<11} auth={:<8} findings={}",
                        e.id,
                        truncate(&e.name, 30),
                        truncate(&e.client.name, 16),
                        e.status.label(),
                        auth,
                        e.findings.len()
                    );
                }
            }
            EngAction::Show { id } => {
                let e = store::load(&id)?;
                print_engagement(&e);
            }
        },
        Commands::Finding { action } => match action {
            FindAction::Add {
                engagement,
                title,
                severity,
                category,
                tactic,
                description,
                remediation,
            } => {
                let mut e = store::load(&engagement)?;
                let mut f = Finding::new(title);
                f.severity = Severity::from_str(&severity);
                f.category = category.unwrap_or_default();
                f.attack_tactic = tactic.unwrap_or_default();
                f.description = description.unwrap_or_default();
                f.remediation = remediation.unwrap_or_default();
                let fid = f.id.clone();
                e.findings.push(f);
                store::save(&e)?;
                println!("added finding {fid} to {}", e.id);
            }
            FindAction::List { engagement } => {
                let e = store::load(&engagement)?;
                if e.findings.is_empty() {
                    println!("(no findings)");
                }
                for f in &e.findings {
                    println!(
                        "{}  [{:<8}] {:<40} {}",
                        f.id,
                        f.severity.label(),
                        truncate(&f.title, 40),
                        f.status.label()
                    );
                }
            }
        },
        Commands::Recon { action } => match action {
            ReconAction::Import {
                engagement,
                file,
                derive,
                in_scope,
            } => {
                let mut e = store::load(&engagement)?;
                let content = fs::read_to_string(&file)?;
                let mut assets = recon::parse_airodump_csv(&content);
                if in_scope {
                    for a in &mut assets {
                        if a.kind == AssetKind::AccessPoint {
                            a.in_scope = true;
                        }
                    }
                }
                let ap = assets
                    .iter()
                    .filter(|a| a.kind == AssetKind::AccessPoint)
                    .count();
                let st = assets.len() - ap;
                if derive {
                    let mut drafts = recon::derive_findings(&assets);
                    let n = drafts.len();
                    e.findings.append(&mut drafts);
                    println!("derived {n} draft finding(s)");
                }
                e.assets.append(&mut assets);
                store::save(&e)?;
                println!("imported {ap} access point(s) and {st} station(s) into {}", e.id);
            }
        },
        Commands::Report(a) => {
            let e = store::load(&a.engagement)?;
            let output = match a.format.as_str() {
                "html" => report::html(&e),
                _ => report::markdown(&e),
            };
            match a.out {
                Some(path) => {
                    fs::write(&path, output)?;
                    println!("wrote report to {path}");
                }
                None => print!("{output}"),
            }
        }
        Commands::Roe(a) => {
            let e = store::load(&a.engagement)?;
            let output = match a.format.as_str() {
                "md" => roe::markdown(&e),
                _ => roe::html(&e),
            };
            match a.out {
                Some(path) => {
                    fs::write(&path, output)?;
                    println!("wrote authorization/RoE document to {path}");
                }
                None => print!("{output}"),
            }
        }
        Commands::Module { action } => match action {
            ModuleAction::List => {
                for m in modules::registry() {
                    let d = if m.disruptive { "DISRUPTIVE" } else { "passive   " };
                    println!(
                        "{:<12} [{}] {:<28} tools: {}",
                        m.id,
                        d,
                        m.name,
                        m.tools.join(", ")
                    );
                    println!("               {}", m.description);
                }
            }
            ModuleAction::Preflight => {
                let mut tools: Vec<&str> = modules::registry()
                    .iter()
                    .flat_map(|m| m.tools.iter().copied())
                    .collect();
                tools.sort();
                tools.dedup();
                println!("Tool preflight (this host):");
                for t in tools {
                    println!(
                        "  {:<14} {}",
                        t,
                        if modules::tool_available(t) {
                            "found"
                        } else {
                            "MISSING"
                        }
                    );
                }
            }
            ModuleAction::Run(a) => run_module(a)?,
        },
    }
    Ok(())
}

fn run_module(a: ModuleRunArgs) -> Result<(), Box<dyn Error>> {
    let mut e = store::load(&a.engagement)?;
    let spec =
        modules::find(&a.module).ok_or_else(|| format!("unknown module: {}", a.module))?;

    let mut params: HashMap<String, String> = HashMap::new();
    for (k, v) in [
        ("iface", &a.iface),
        ("bssid", &a.bssid),
        ("channel", &a.channel),
        ("client", &a.client),
        ("count", &a.count),
        ("wordlist", &a.wordlist),
        ("capture", &a.capture),
        ("essid", &a.essid),
        ("prefix", &a.prefix),
        ("out", &a.out),
    ] {
        if let Some(x) = v {
            params.insert(k.to_string(), x.clone());
        }
    }

    let warnings = modules::gate(&e, &spec, &params, a.dry_run, a.confirm)
        .map_err(|m| format!("blocked: {m}"))?;
    for w in &warnings {
        eprintln!("warning: {w}");
    }

    let (program, args) = modules::build_command(&spec, &params);
    let cmdline = modules::display_command(&program, &args);
    println!("$ {cmdline}");

    if a.dry_run {
        record_action(&mut e, &spec, &params, &cmdline, true, None, false, "dry-run (not executed)".to_string());
        store::save(&e)?;
        println!("(dry-run — not executed; logged to action trail)");
        return Ok(());
    }

    if !modules::tool_available(&program) {
        return Err(format!("required tool not found on PATH: {program}").into());
    }

    let r = modules::execute(&program, &args, a.timeout)?;
    if !r.stdout.is_empty() {
        println!("{}", r.stdout);
    }
    if !r.stderr.is_empty() {
        eprintln!("{}", r.stderr);
    }
    println!(
        "[exit {}{}]",
        r.exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string()),
        if r.timed_out { " · TIMED OUT" } else { "" }
    );

    let summary = modules::summarize(&r);
    record_action(&mut e, &spec, &params, &r.command, false, r.exit_code, r.timed_out, summary);
    store::save(&e)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn record_action(
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
        id: model::new_id(),
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

fn print_engagement(e: &Engagement) {
    println!("Engagement : {} ({})", e.name, e.id);
    println!("Client     : {}", e.client.name);
    println!("Tester     : {} <{}>", e.tester.name, e.tester.email);
    println!("Status     : {}", e.status.label());
    println!(
        "Authorized : {}",
        if e.active_testing_unlocked() {
            "yes (active testing unlocked)"
        } else {
            "NO — active testing LOCKED"
        }
    );
    let c = e.severity_counts();
    println!(
        "Findings   : C={} H={} M={} L={} I={}  (open {})",
        c[4],
        c[3],
        c[2],
        c[1],
        c[0],
        e.open_count()
    );
    println!("Assets     : {}", e.assets.len());
    for f in &e.findings {
        println!("  - {} [{}] {}", f.id, f.severity.label(), f.title);
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{t}…")
    }
}
