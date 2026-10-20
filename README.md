# Network Tool

**Authorized wireless security assessment platform — by Aturc.**

One fast Rust binary with two front-ends over a shared engagement store:

- **GUI** — a local web control panel (intake screen, dashboard, findings, reports)
- **CLI** — the same operations, scriptable

Built for the purple-team workflow: **intake → recon → findings → remediation → iterative retest → report**, reusable across clients. Active (intrusive) testing is gated behind a recorded authorization per engagement.

> For authorized engagements only. You are responsible for holding signed authorization and staying within the agreed scope and Rules of Engagement.

## Build

```bash
cargo build --release
# binary: target/release/networktool
```

No system dependencies; standard crates only (serde, clap, tiny_http, chrono, uuid).

## GUI

```bash
networktool gui --port 8787 --open
```

Opens `http://127.0.0.1:8787` (bound to localhost only). The first screen you hit for a new job is the **tester & authorization intake** — it captures who is testing, the client, the scope, and the signed-authorization record. Until authorization is recorded, the engagement dashboard shows **ACTIVE TESTING LOCKED** and only passive documentation / recon import are available.

## CLI

```bash
# create an engagement (starts LOCKED until authorization is recorded in the GUI)
networktool engagement new --name "Evsu — Wireless Assessment 2026" \
    --client "Evsu" --tester-name "..." --tester-email "..."

networktool engagement list
networktool engagement show <id>

# import a passive airodump-ng CSV capture into the asset inventory
networktool recon import --engagement <id> --file scan-01.csv --derive --in-scope

networktool finding add --engagement <id> --title "..." --severity High \
    --category "WPS" --tactic "Initial Access"
networktool finding list --engagement <id>

# report to stdout or a file
networktool report <id> --format md
networktool report <id> --format html --out report.html

# authorization & Rules of Engagement document (printable; marked DRAFT until authorized)
networktool roe <id> --format html --out authorization-roe.html
```

In the GUI, the dashboard's **Authorization / RoE** button opens the same document,
ready to print and sign. It is generated from the engagement data and should be
reviewed by both parties (and legal counsel) before signing.

## Data & confidentiality

- Engagements are stored as one JSON file each under `~/.networktool/engagements/`.
- Override the location with `NETWORKTOOL_DATA=/path/to/dir`.
- This data is **client-confidential** — keep it out of version control (see `.gitignore`).

## Methodology baked in

Reports and the on-screen guidance follow a PTES-aligned flow and map findings to
MITRE ATT&CK, with CVSS + DREAD scoring and a layered hardening/remediation matrix
(Appendix B). The wireless attack-surface taxonomy drives the finding categories:
encryption & authentication, WPS, rogue/evil-twin & client-side, management-frame
protection, segmentation, management interface & infrastructure, monitoring & detection.

## Recon import format

`recon import` parses the two-section `airodump-ng` CSV (access points, then
associated stations). `--derive` turns obvious weaknesses (WEP, open networks,
legacy WPA, PSK) into **draft** findings flagged `auto` for the tester to review
and confirm.

## Active test-execution modules

Modules **orchestrate your own installed wireless tooling** (aircrack-ng suite,
`wash`/`reaver`, `hcxdumptool`, `airbase-ng`) — the platform builds the command,
runs it with a watchdog timeout, captures output, and writes the invocation to the
engagement's **action log**. It is not a reimplementation of those tools.

```bash
networktool module list          # the module catalogue
networktool module preflight     # which external tools are installed on this host

# preview the exact command without executing (works even while LOCKED)
networktool module run --engagement <id> --module scan --iface wlan0mon --dry-run

# real execution (requires authorization on file; disruptive modules need --confirm)
networktool module run --engagement <id> --module deauth \
    --bssid AA:BB:CC:11:22:33 --iface wlan0mon --confirm --timeout 30
```

### Safety gate (enforced on every real run)

1. The engagement must have a **signed authorization** on file (else blocked; dry-run still previews).
2. A **disruptive** module additionally requires `authorization.disruptive_allowed` **and** an explicit confirmation (`--confirm` / a checkbox).
3. A target **BSSID** is checked against the engagement's in-scope BSSID list.
4. Every invocation — preview or real — is appended to the **action log** (audit/evidence trail) with timestamp, command, operator, and result.

### Module catalogue

| Module | Disruptive | Tool | Purpose |
|---|---|---|---|
| `airmon_start` / `airmon_stop` | no | airmon-ng | Monitor-mode setup/teardown |
| `scan` | no | airodump-ng | Wide survey → CSV (import afterwards) |
| `scan_target` | no | airodump-ng | Targeted handshake capture |
| `deauth` | **yes** | aireplay-ng | Force reconnect / test 802.11w (PMF) |
| `wpa_crack` | no | aircrack-ng | Offline PSK resilience (no transmission) |
| `wps_scan` | no | wash | List WPS-enabled APs |
| `wps_attack` | **yes** | reaver | WPS PIN exposure assessment |
| `pmkid` | **yes** | hcxdumptool | PMKID capture |
| `evil_twin` | **yes** | airbase-ng | Rogue-AP / client auto-join test |

> The host that runs the modules needs the tools installed (typically a Linux
> assessment laptop). On macOS, `preflight` will report them as missing — use the
> GUI/CLI for planning, intake, documentation and reporting there.

## Status

v1 covers the full workflow end-to-end: engagement intake, authorization gating,
passive recon import, findings with ATT&CK/CVSS/DREAD, iterative retest, active
module orchestration with an audit trail, and MD/HTML reporting — in both GUI and CLI.
