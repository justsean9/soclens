# SOCLens (`soclens`)

[![Release](https://img.shields.io/github/v/release/justsean9/soclens)](https://github.com/justsean9/soclens/releases)
[![License: MIT](https://img.shields.io/github/license/justsean9/soclens)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-checked-blue.svg)](https://mypy-lang.org/)

Cross-platform SOC investigation workbench providing a unified CLI (`soclens`) and interactive Textual Terminal User Interface (`soclens tui`) integrating Recorded Future (Watchlists, Brand Monitoring, Entity Match, Connect v2, SOAR v3, Detection Rules, Playbook Alerts, Alerts v3, Cases, Sandbox v0), **16 built-in free passive OSINT feeds** (WHOIS/RDAP, DoH DNS, GeoIP, BGP/ASN, Shodan InternetDB, crt.sh, URLScan, SANS DShield, Wayback Machine, AlienVault OTX, GreyNoise, CIRCL NSRL, MITRE CVE + FIRST EPSS + CISA KEV, plus optional free-key VirusTotal, AbuseIPDB, and abuse.ch) into a single pane of glass alongside Splunk Search & Splunk Enterprise Security triage/enrichment, SentinelOne EDR, Sigma-to-Splunk conversion, Local LLM analysis, per-user settings profiles, and air-gapped offline deployment bundling.

See [docs/RF_API_REVIEW.md](docs/RF_API_REVIEW.md) for the Recorded Future API reference and [CHANGELOG.md](CHANGELOG.md) for release notes.

---

## Screenshots

Interactive Textual TUI (`soclens tui`) rendered with sanitized demo data (regenerate anytime with `python scripts/generate_screenshots.py`):

### Threat Research Workbench (`7`)
Unified single-pane-of-glass investigation combining Recorded Future risk scoring, Insikt Group notes, and detection rules with 16 built-in free passive OSINT sources (WHOIS/RDAP, DNS/SPF/DMARC, GeoIP, BGP/ASN, Shodan InternetDB, VirusTotal, AbuseIPDB, abuse.ch, OTX, GreyNoise, DShield, URLScan, crt.sh, Wayback, CIRCL NSRL, and MITRE CVE/EPSS/CISA KEV):

![Threat Research Workbench](docs/screenshots/research.svg)

### Recorded Future Intel & Alerts (`4`)
Unified Alerts v3, Playbook Alerts, and Cases triage with multi-status filters, inline inspection, and on-demand enrichment:

![Recorded Future Intel & Alerts](docs/screenshots/rf-intel.svg)

### Splunk ES & Mission Control Triage (`F9`)
Hybrid Mission Control v2 / SPL notable triage with tenant filtering, RF enrichment, and cross-workbench pivoting:

![Splunk ES & Mission Control Triage](docs/screenshots/splunk-es.svg)

### SentinelOne EDR Workbench (`9`)
Multi-site threats, endpoints, exclusions, and blocklist triage with Admin View mutation guardrails (`F2`):

![SentinelOne EDR Workbench](docs/screenshots/sentinelone.svg)

<details>
<summary>More screenshots: Sigma Rules, Local LLM Copilot &amp; Admin Dashboard</summary>

### Sigma Rules & Splunk Export (`5`, Admin View)
Insikt Group & local Sigma rule browsing with live pySigma `savedsearches.conf` stanza preview:

![Sigma Rules & Splunk Export](docs/screenshots/sigma-rules.svg)

### Local LLM SOC Copilot (`F7`)
Ollama & OpenAI-compatible triage assistant with attached investigation context and SPL generation:

![Local LLM SOC Copilot](docs/screenshots/local-llm.svg)

### Dashboard & Diagnostics (`1`, Admin View — All 13 Tabs)
Environment, proxy/SSL, credential status, `trace_id` API error logs, and Recorded Future API surface coverage:

![Dashboard & Diagnostics](docs/screenshots/dashboard-admin.svg)

</details>

---

## Quick Download: Offline Release Bundles

Pre-packaged air-gapped deployment archives (source + installers + verified offline `wheelhouse/` for Python 3.12, 3.13, and 3.14) are published on the GitHub **Releases** tab and can also be built locally with `python scripts/build_release_bundles.py`:

- **GitHub Releases:** [Releases & Assets](https://github.com/justsean9/soclens/releases)

**Air-gapped quick install after downloading:**
```powershell
# Windows PowerShell
Expand-Archive .\soclens-v2.2.0-offline-win_amd64.zip -DestinationPath .\soclens
cd .\soclens
.\install_offline.ps1 -LaunchTui

# Subsequent launches in PowerShell:
.\soclens.ps1 tui
```
```bash
# Linux / macOS
unzip soclens-v2.2.0-offline-linux_x86_64.zip -d soclens
cd soclens
./install_offline.sh --launch-tui
```

---

## Table of Contents
1. [Screenshots](#screenshots)
2. [Quick Download: Offline Release Bundles](#quick-download-offline-release-bundles)
3. [Prerequisites & Installation](#prerequisites--installation)
4. [Authentication & Workspace Configuration](#authentication--workspace-configuration)
5. [Windows-Compatible TUI](#windows-compatible-tui)
6. [General CLI Usage](#general-cli-usage)
7. [Recorded Future Lists & Brand Logo Automation](#recorded-future-lists--brand-logo-automation)
8. [Recorded Future SOC APIs (`rf`)](#recorded-future-soc-apis-rf)
9. [Threat Research (`research` & TUI Research Tab)](#threat-research-research--tui-research-tab)
10. [Sigma Rule Searching & Splunk Conversion](#sigma-rule-searching--splunk-conversion)
11. [Splunk Saved Searches Validation](#splunk-saved-searches-validation)
12. [Packaging & Air-Gapped Deployment Bundling](#packaging--air-gapped-deployment-bundling)

---

## Prerequisites & Installation

Ensure Python 3.12+ (3.12, 3.13, or 3.14) is installed on Windows, Linux, or macOS.

### Offline / Air-Gapped Installation (Included Packages)

This repository includes a self-contained `wheelhouse/` directory containing all 31 runtime packages, platform-compiled native wheels (`win_amd64`, `manylinux*_x86_64`, `macosx_*_arm64` for Python 3.12–3.14), and PEP 517 build backend wheels (`setuptools`, `wheel`) so installation requires zero internet access.

On Windows, `install_offline.ps1` creates `.venv` and installs the PowerShell launcher shim (`.venv\Scripts\soclens.ps1` alongside the root `.\soclens.ps1` launcher) invoking `python.exe -m soclens.cli`:

```powershell
# PowerShell (Windows PowerShell 5.1, PowerShell 7+, or pwsh on Linux/macOS)
.\install_offline.ps1

# Or install offline and launch the TUI directly:
.\install_offline.ps1 -LaunchTui
```

```bash
# Linux / macOS (Bash or Zsh)
./install_offline.sh
```

Or install manually from the included `wheelhouse/` directory:

```bash
pip install --no-index --find-links wheelhouse -e .
# Or with uv offline:
uv pip install --offline --no-index --find-links wheelhouse -e .
```

### Online Installation

```bash
# Editable installation (recommended)
pip install -e .

# Or install runtime dependencies directly
pip install -r requirements.txt
```

---

## Authentication & Workspace Configuration

Every analyst can configure credentials and tool defaults directly inside the **Settings Menu** (`Settings` tab / key `0` or `F10` in the TUI, or `soclens settings` in the CLI) without setting shell environment variables. Environment variables and CLI flags continue to work seamlessly and override saved user settings.

**Configuration Precedence:** `CLI flags` > `Active TUI Session Override` > `Environment Variables` > `Per-User Saved Profile` > `Built-in Defaults`

**Per-User Settings File Locations** (encrypted at rest with **AES-256-GCM** inside an authenticated JSON envelope and saved atomically with `0600` owner-only permissions on Linux/macOS):
- **Windows**: `%APPDATA%\soclens\settings.json` (auto-unlocked via Windows DPAPI by default)
- **macOS**: `~/Library/Application Support/soclens/settings.json` (auto-unlocked via macOS Keychain by default)
- **Linux**: `$XDG_CONFIG_HOME/soclens/settings.json` (default `~/.config/soclens/settings.json`; auto-unlocked via Linux Secret Service / `secret-tool`, falling back to a separate `0600` keyfile at `$XDG_DATA_HOME/soclens/.settings.key` on headless hosts)
- **Override**: `SOCLENS_SETTINGS_FILE=/path/to/settings.json` (and `SOCLENS_PROFILE=<name>` for named profiles)

Legacy plaintext `settings.json` files (schema v1) are still read seamlessly and automatically migrated to encrypted schema v2 on the next save.

### Option 1: In-App Settings UI & CLI (`soclens settings`)
1. Launch the TUI (`soclens tui` or `.\soclens.ps1 tui`) and press `0` or `F10` (or click **Settings** on the Dashboard) to enter your Recorded Future, Splunk, SentinelOne, SSL/CA/Proxy, and Workspace defaults, test connections live, import existing env vars, manage named profiles (`default`, `prod`, `lab`), or manage encryption under **Profiles & Storage**.
2. Or configure via the CLI (never commits credentials; `settings.json` and `.settings.key` are excluded from git and offline deployment bundles):
```bash
soclens settings path
soclens settings set rf_api_token "your_api_key"
soclens settings set splunk_host "https://your-splunk-sh:8089"
soclens settings set splunk_token "your_bearer_token"
soclens settings import-env
soclens settings show

# Optional: switch to Master Passphrase encryption (Scrypt + AES-256-GCM; no key stored on disk/OS keystore)
soclens settings encrypt --passphrase
soclens settings unlock
soclens settings lock
soclens settings rekey --new-passphrase

# Switch back to OS keystore auto-unlock or rotate the data encryption key
soclens settings encrypt --mode os_keystore
soclens settings rekey --rotate-kek
```
For non-interactive automation in Master Passphrase mode, export `SOCLENS_SETTINGS_PASSPHRASE` or `SOCLENS_SETTINGS_PASSPHRASE_FILE=/path/to/0600-passphrase-file`.

### Option 2: Environment Variables (Optional Overrides / CI / Automation)
Configure credentials via environment variables if preferred (never commit tokens or `apikey.key` to git):

### Recorded Future API
```bash
# Linux / macOS
export RF_API_TOKEN="your_api_key"          # or RECORDED_FUTURE_API_KEY
export RF_SANDBOX_TOKEN="your_sandbox_key"  # optional; falls back to RF_API_TOKEN
export RF_ASI_API_KEY="your_asi_key"        # optional; Attack Surface Intelligence (or SECURITYTRAILS_API_KEY)
export RF_PFI_TOKEN="your_pfi_token"        # optional; Payment Fraud Intel (falls back to RF_API_TOKEN)
export RF_RISKRECON_TOKEN="your_rr_token"   # optional; RiskRecon (or RISKRECON_API_TOKEN)
export SOCLENS_HOME="/path/to/workspace"     # optional workspace root for caches, state & logs
export SOCLENS_AUTO_APPROVE="true"           # required to allow live list mutations without --dry-run
```

```powershell
# Windows PowerShell
$env:RF_API_TOKEN = "your_api_key"
$env:SOCLENS_HOME = "C:\opt\soclens"
$env:SOCLENS_AUTO_APPROVE = "true"
```

### Splunk Search Head (Enterprise Security)
```bash
export SPLUNK_HOST="https://your-splunk-sh:8089"
export SPLUNK_TOKEN="your_bearer_token"     # recommended (or SPLUNK_USERNAME / SPLUNK_PASSWORD)
export SPLUNK_APP="SplunkEnterpriseSecuritySuite"
```

### Free Passive OSINT API Keys (Optional — 13 Sources Require Zero Keys)
Thirteen passive OSINT feeds (WHOIS/RDAP, DoH DNS, GeoIP, BGP/ASN, Shodan InternetDB, crt.sh, URLScan, DShield, Wayback, OTX, GreyNoise, CIRCL NSRL, MITRE CVE/EPSS/CISA KEV) work immediately with no API keys. You can configure optional free-tier keys either in **Settings (`0`/`F10`) -> OSINT Free API Keys** or via environment variables:
```bash
export SOCLENS_OSINT_ENABLED="true"         # set "false" to disable passive OSINT in air-gapped environments
export VT_API_KEY="your_free_vt_key"        # VirusTotal v3 (virustotal.com/gui/join-us)
export ABUSEIPDB_API_KEY="your_free_key"    # AbuseIPDB v2 (abuseipdb.com/register)
export ABUSECH_AUTH_KEY="your_free_key"     # Single key unlocks ThreatFox, URLhaus & MalwareBazaar (auth.abuse.ch)
export OTX_API_KEY="your_free_otx_key"      # Optional higher AlienVault OTX rate limits
export URLSCAN_API_KEY="your_free_key"      # Optional higher URLScan.io search quotas
export GREYNOISE_API_KEY="your_free_key"    # Optional GreyNoise Community key
```

### Corporate / Internal SSL-Inspecting Proxy
When running behind a corporate SSL/TLS inspection proxy, you can either supply your organization's root CA bundle or temporarily bypass certificate verification:

```bash
# Linux / macOS: trust an internal proxy CA bundle or disable SSL verification
export HTTPS_PROXY="http://proxy.corp.local:8080"
export HTTP_PROXY="http://proxy.corp.local:8080"
export RF_CA_BUNDLE="/etc/ssl/certs/corp-proxy-ca.pem"  # recommended
# Or disable SSL verification across RF APIs & brand-logo scraping:
export RF_VERIFY_SSL="false"                            # or RF_INSECURE_SSL=true
```

```powershell
# Windows PowerShell
$env:HTTPS_PROXY = "http://proxy.corp.local:8080"
$env:RF_VERIFY_SSL = "false"                            # or $env:RF_CA_BUNDLE = "C:\certs\corp-proxy-ca.pem"

# Or pass CLI flags directly (works before or after any subcommand):
.\soclens.ps1 -k tui
.\soclens.ps1 watchlist sync-logos <BRAND_LIST_ID> --domains-file domains.txt --insecure
.\soclens.ps1 rf alerts --ca-bundle C:\certs\corp-proxy-ca.pem
.\scripts\soclens-brand-sync.ps1 -ListId <BRAND_LIST_ID> -SourceListId <DOMAIN_LIST_ID> -Insecure
```

In the TUI (`soclens tui`), the **Dashboard & Diagnostics** tab displays active proxy/SSL status and provides a live **Insecure SSL: OFF/ON** toggle button (also available via right-click).

All Recorded Future API errors (including `traceId` / `trace_id`) are logged thread-safely to `<workspace>/logs/rf_api_errors.jsonl`.

---

## Windows-Compatible TUI

Launch the interactive Textual TUI (works cleanly on Windows Terminal, Windows PowerShell 5.1, cross-platform PowerShell 7+ `pwsh` on Windows/Linux/macOS, `cmd.exe`, Linux, and macOS):

```powershell
# In Windows PowerShell
.\soclens.ps1 tui
# Or dry-run (read-only) mode:
.\soclens.ps1 tui --dry-run
# Launch directly in Admin view (all 13 tabs):
.\soclens.ps1 tui --admin
soclens tui --view admin

# Or after dot-sourcing the venv (uses .venv\Scripts\soclens.ps1):
. .\.venv\Scripts\Activate.ps1
soclens tui

# Or invoke Python directly:
.\.venv\Scripts\python.exe -m soclens tui
```

UI Views (default: **User View**):
- **User View (Default — 8 Tabs)**: Displays **RF Intel & Alerts** (`4`), **Research** (`7`, initial tab), **Logs** (`8`), **SentinelOne** (`9`), **Local LLM** (`F7`), **Splunk Search** (`F8`), **Splunk ES** (`F9`), and **Settings** (`0` / `F10`) for focused day-to-day analyst triage and per-user configuration.
- **Admin View (All 13 Tabs)**: Adds **Dashboard & Diagnostics** (`1`, initial tab), **Watchlists** (`2`), **Brand Logos** (`3`), **Sigma Rules** (`5`), and **Splunk & Bundle** (`6`), along with watchlist-mutation pivots.
- Toggle between **User View** and **Admin View** anytime via the top UI view selector (`User View` / `Admin View`), the `Admin: OFF/ON [F2]` toggle button, the `F2` shortcut, `--view user|admin` / `--admin`, or `SOCLENS_UI_VIEW=admin`.

Keyboard shortcuts:
- `F2`: Toggle **User View** <-> **Admin View**
- `F3`: Change display timezone (`Local` / `UTC` / IANA zone)
- `F4` / `F6`: Copy Selected List ID (**Watchlists**) / Cycle Table Sort (**Watchlists** & **Brand Logos**)
- **User View** tabs: `4` (RF Intel & Alerts), `7` (Research), `8` (Logs), `9` (SentinelOne), `0`/`F10` (Settings), `F7` (Local LLM), `F8` (Splunk Search), `F9` (Splunk ES)
- **Admin View** adds: `1` (Dashboard & Diagnostics), `2` (Watchlists), `3` (Brand Logos), `5` (Sigma Rules), `6` (Splunk & Bundle)
- `c` / `y` / `v` (in **Sigma Rules**): Copy SPL query / Copy full Splunk stanza / Open selectable **Copyable View** modal
- `o` (in **RF Intel & Alerts**): Open selected alert screenshot in OS image viewer
- `Tab` / `Shift+Tab`: Navigate controls
- `q` / `Ctrl+q`: Quit cleanly (stops any active continuous watch worker)

### Screenshot & Image Viewing (Windows-Safe & OS Viewer Default)
- **Windows Terminal Safety**: Kitty Graphics Protocol (`Kitty HD`) is automatically disabled on Windows (`win32`) and Windows Terminal / ConEmu (`WT_SESSION` / `WT_PROFILE_ID` / `ConEmuPID`) to prevent garbled placeholder rendering; inline previews use sharpened true-color half-blocks alongside native OS image viewing.
- **Toggle OS Viewer as Default**: Set the native OS image viewer as the default action for `[v]` / `Images (N)` via:
  - **Dashboard & Diagnostics**: `Image Viewer: TUI/OS` button (or right-click menu)
  - **RF Intel & Alerts**: `OS Viewer Default: OFF/ON` inside the `/` Filter & Tools drawer (or right-click menu)
  - **Screenshot Viewer Modal**: `OS Default: OFF/ON` button (or right-click menu)
  - **CLI / Environment**: `--os-image-viewer`, `--image-viewer os`, `SOCLENS_IMAGE_VIEWER=os`, or `RF_TUI_OPEN_IMAGES_IN_OS_VIEWER=true`
  - Preferences are persisted per workspace in `.soclens_tui_settings.json`.
- **Right-Click Open in Details Pane**: Right-click directly on any inline screenshot preview or anywhere inside the right-side details panel (`RF Intel & Alerts`) to **Open Screenshot in OS Image Viewer**, **Open All Screenshots**, **View in TUI Modal**, or **Save PNG** (press `o` anytime to open the selected alert's screenshot directly in the OS viewer).

---

## General CLI Usage

SOCLens exposes `soclens` on Linux/macOS, `.\soclens.ps1` (and `.venv\Scripts\soclens.ps1`) in Windows PowerShell, and `python -m soclens` / `python -m soclens.cli` everywhere:

```bash
soclens --help
soclens --version
```

Global flags:
- `--version` / `-V`: Display the installed toolkit version and exit
- `--dry-run` / `-d`: Enforce read-only mode across APIs and Splunk validation
- `--json`: Emit clean machine-readable JSON on `stdout`
- `--tui` / `-t`: Launch the interactive TUI
- `-k` / `--insecure` / `--no-verify-ssl`: Disable SSL certificate verification for HTTPS requests (for corporate/internal proxy usage; works before or after any subcommand)
- `--ca-bundle <PATH>`: Use a custom CA certificate bundle PEM file for HTTPS requests (overrides `RF_CA_BUNDLE`)

Available subcommands:
- `watchlist`: Manage all 21 Recorded Future list types, CSV delta sync, liveness checks, brand logo hash monitoring, and brand issue diagnostics (`brand-issues`)
- `rf`: Query Entity Match, Connect v2 (including fields & 3rd-party extensions), SOAR v3, Alerts v3, Playbook Alerts, Cases, and Sandbox v0
- `research`: Run multi-API dossier investigations, capability probes, Links Graph, Analyst Notes, Threat Maps/Actors, Malware Intelligence, Risk History, Identity Intelligence, Collective Insights, Fusion v3, ATO, STIX/TAXII 2.1, Sandbox v0, ASI, PFI, and RiskRecon queries
- `sigma`: Load/cache Insikt Group Sigma rules, search, and export Splunk `savedsearches.conf` stanzas
- `validate`: Validate `savedsearches.conf` stanzas concurrently against Splunk REST API (with cross-platform `--background`)
- `splunk`: Run ad-hoc Splunk SPL searches (`search`), list `indexes` / `saved-searches`, dispatch saved searches, and operate Splunk ES (`es notables`, `es update`, `es correlation-searches`, `es threat-intel`, `es enrich`, etc.)
- `s1`: Query SentinelOne Management API v2.1 endpoints, threats, exclusions, and blocklist indicators
- `llm`: Connect to Ollama or OpenAI-compatible local LLMs (`status`, `models`, `chat`, `explain-sigma`)
- `settings`: Manage per-user saved credentials, tool settings, and named profiles (`path`, `show`, `set`, `unset`, `import-env`, `profiles`, `use`, `delete-profile`, `reset`)
- `bundle`: Package the toolkit and runtime dependencies into an air-gapped ZIP bundle
- `tui`: Launch the Textual TUI (`--admin` / `--view`, `--timezone`, `--image-viewer` / `--os-image-viewer`)

---

## Recorded Future Lists & Brand Logo Automation

### Watchlist Operations
```bash
soclens watchlist list [--type brand] [--json]
soclens watchlist create "Brand Logo Hashes" --type brand
soclens watchlist info <LIST_ID>
soclens watchlist status <LIST_ID>
soclens watchlist entities <LIST_ID> [--json]
soclens watchlist add <LIST_ID> InternetDomainName example.com
soclens watchlist remove <LIST_ID> InternetDomainName example.com
soclens watchlist sync <LIST_ID> domains.csv --type InternetDomainName --dry-run
soclens watchlist export <LIST_ID> --output exported.csv --format csv
```

### Brand Logo Extraction, Hashing & Continuous Sync
The brand monitoring pipeline discovers brand logos from JSON-LD, app/touch icons, web manifests, `<img>`/`<picture>`/`srcset`, inline `<svg>`, and `data:` URIs while filtering out banners, UI icons, spacers, and third-party badges, validates magic bytes and image dimensions, computes SHA-256/SHA-1/MD5 hashes, and performs domain-scoped, grace-period-protected delta updates against Recorded Future `Hash` watchlists.

Test safely on 1–2 domains before enabling live updates:
```bash
# Dry-run validation on 1-2 domains
soclens watchlist validate-logos <BRAND_LIST_ID> --domains example.com,brand.org

# One-shot live sync (requires SOCLENS_AUTO_APPROVE=true)
soclens watchlist sync-logos <BRAND_LIST_ID> --domains-file domains.txt --ignore-hashes-file ignored_hashes.txt

# Built-in unattended continuous polling mode (lockfile + brand_sync_state.json)
soclens watchlist sync-logos <BRAND_LIST_ID> --domains-file domains.txt --watch --interval 3600
```

For Windows Task Scheduler / PowerShell and Linux `systemd` timer deployment templates, see [scripts/README_AUTOMATION.md](scripts/README_AUTOMATION.md).

---

## Recorded Future SOC APIs (`rf`)

```bash
soclens rf apis
soclens rf entity-match "Cobalt Strike" --types Malware
soclens rf lookup ip 198.51.100.10 --json
soclens rf company example.com
soclens rf enrich --ip 198.51.100.10 --domain bad.example
soclens rf triage phishing --domain lookalike.example
soclens rf alerts --limit 20 --json
soclens rf playbook-alerts --categories domain_abuse,malicious_sites
soclens rf cases --limit 20
soclens rf sandbox --query suspicious.exe
soclens rf fields ip
soclens rf extension ip 8.8.8.8 GreyNoiseIntelligence
```

---

## Threat Research (`research` & TUI Research Tab)

Investigate any IP, domain (`badsite.com`), hash, URL, CVE, malware family, threat actor, MITRE ATT&CK technique, email, ASN, company, or free-text term in **one unified pane of glass** combining Recorded Future APIs with **16 built-in, 100% passive free OSINT sources (18 live feeds)**. For domains and URLs, SOCLens automatically resolves the primary public hosting IP via DNS-over-HTTPS and chains IP intelligence (GeoIP, BGP/ASN, Shodan InternetDB, DShield, GreyNoise, AbuseIPDB) alongside domain WHOIS/RDAP, DNS, certificates, and web reputation — without ever initiating direct HTTP/TLS connections to potentially malicious targets.

### Built-In Free Passive OSINT Sources (Zero Additional Dependencies)

13 sources work immediately with **zero API keys**, and 3 additional free-tier API key integrations unlock VirusTotal, AbuseIPDB, and the entire abuse.ch suite (ThreatFox, URLhaus, MalwareBazaar) from **Settings (`0`/`F10`) -> OSINT Free API Keys**:

| Source | Category | Cost / Key | What Analysts Get |
|---|---|---|---|
| **WHOIS / RDAP** (`rdap.org`) | WHOIS | Free (No key) | Registrar, registrant, domain age & newly-registered (<= 30d) flag, abuse email, CIDR |
| **DNS & Email Auth** (Cloudflare / Google DoH) | DNS | Free (No key) | A, AAAA, NS, MX, TXT, CNAME, SOA, CAA, PTR, SPF/DMARC posture, DNSSEC |
| **IP Geolocation & ISP** (`ipwho.is`) | Network | Free (No key) | Country, city, coordinates, timezone, ASN, ISP/Org (auto-chained for domains) |
| **BGP Routing & ASN** (RIPEstat) | Network | Free (No key) | Announced BGP prefix, origin ASN(s), holder, abuse contacts (auto-chained) |
| **Shodan InternetDB** | Network | Free (No key) | Open ports + service hints, CPEs, known CVEs, hostnames, tags (auto-chained) |
| **Certificate Transparency** (`crt.sh`) | Certificates | Free (No key) | Historical TLS certs, issuers, deduplicated subdomains/SANs |
| **URLScan.io Public Search** | Web Intel | Free (Optional key) | Historical web scans, malicious/phishing verdicts, page titles, screenshot links |
| **SANS ISC / DShield** | Reputation | Free (No key) | Global sensor attack counts, distinct targets attacked, threat feeds |
| **Wayback Machine CDX** | Web Intel | Free (No key) | Historical snapshots & safe passive archive links without touching live sites |
| **AlienVault / LevelBlue OTX** | Reputation | Free (Optional key) | Community pulses, malware families, adversaries, ATT&CK IDs, passive DNS |
| **GreyNoise Community** | Reputation | Free (Optional key) | Mass-scanner Noise vs benign RIOT classification (`benign` / `malicious`) |
| **CIRCL Hashlookup (NSRL)** | File Intel | Free (No key) | Known-good software / OS file verification for MD5, SHA-1, and SHA-256 |
| **MITRE CVE + FIRST EPSS + CISA KEV** | Vulnerability | Free (No key) | CVSS score/vector, CWEs, exploit probability (EPSS), and CISA KEV active-exploit status |
| **VirusTotal v3** | Reputation | Free API Key | Multi-engine AV/URL/domain/IP/hash detections, categories, reputation (`VT_API_KEY`) |
| **AbuseIPDB v2** | Reputation | Free API Key | Abuse confidence %, report count, Tor exit flag, ISP/usage type (`ABUSEIPDB_API_KEY`) |
| **abuse.ch Suite** | Reputation | Free Auth-Key | Single `ABUSECH_AUTH_KEY` unlocks **ThreatFox** + **URLhaus** + **MalwareBazaar** |

```bash
# Unified Recorded Future + Free Passive OSINT dossier (single pane of glass)
soclens research investigate badsite.com --output report.md
soclens research investigate 198.51.100.42 --json
soclens research investigate CVE-2021-44228 --deep
soclens research investigate 8.8.8.8 --no-osint            # Recorded Future only
soclens research investigate badsite.com --osint-only      # Free OSINT only (no RF token required)

# Standalone Free Passive OSINT CLI (works even without RF_API_TOKEN)
soclens research osint --list-sources
soclens research osint 1.1.1.1
soclens research osint badsite.com --sources rdap,dns,shodan,virustotal --json

# Probe token entitlements across all 25 Recorded Future API surfaces
soclens research capabilities

# Direct API research surfaces
soclens research links ip:8.8.8.8 --timeframe -30d --scope medium
soclens research notes --title "Ransomware" --published -30d --limit 10
soclens research actors --query "APT29" --limit 10
soclens research actors --map
soclens research malware --query "Cobalt Strike" --nl --field sha256
soclens research rules --entity O7NRMb --types sigma,yara,snort
soclens research risk --history ip:8.8.8.8 --from -30d
soclens research identity --domains example.com
soclens research fusion --ls /public
soclens research taxii2 --collections --root default
soclens research sandbox --list org --limit 10
```

In the TUI (`soclens tui`, press `7`), the **Research** tab provides a unified search-first workbench with a **Source Mode selector** (`RF + OSINT`, `OSINT Only`, `RF Only`), an **OSINT Sources** modal (`s`) to toggle feeds or jump straight to **Settings -> OSINT Free API Keys**, a **Unified Intelligence Brief** combining RF risk and passive OSINT verdict/signals, a 4-column findings table (`Category | Source | Finding | Detail`) with source-group filtering inside `/`, clickable rich drill-downs for every OSINT and RF section, pivot history (`[` Back / `]` Forward), double-click entity pivoting (`p`), Raw JSON toggle (`j`), Markdown/JSON export, and right-click cross-tab pivoting to **Local LLM**, **Splunk Search**, **Watchlists**, and **RF Intel & Alerts**.

---

## Sigma Rule Searching & Splunk Conversion

Convert Recorded Future Insikt Group Sigma rules or local YAML files into Splunk Enterprise Security `savedsearches.conf` stanzas using configurable pySigma processing pipelines, custom Splunk indexes, custom `| table` columns, and field/sourcetype mappings:

```bash
# Search and export cached/API Sigma rules with default splunk_windows pipeline
soclens sigma "PowerShell" --json
soclens sigma --refresh --export --output savedsearches.conf
soclens sigma --export --days 7 --cron-schedule "0 * * * *" --earliest-time -70m --latest-time -10m

# Custom per-logsource Splunk indexes (supports multi-index) and appended table/suppress fields
soclens sigma --export \
  --pipeline splunk_windows \
  --index-map "windows:security=win_sec,windows:sysmon=edr_sysmon,aws=cloud_aws" \
  --default-index "soc_fallback" \
  --custom-table-fields "tenant_id,env,asset_criticality" \
  --custom-suppress-fields "tenant_id" \
  --field-map "CommandLine=process_cmd,User=actor_user" \
  --sourcetype-map "windows:security=WinEventLog:Security" \
  --output savedsearches.conf

# Override table fields per logsource or write all stanzas to one file (--no-split)
soclens sigma --export \
  --index sec_events \
  --table-fields-map "windows=_time host User EventCode CommandLine tenant_id;aws=_time eventName sourceIPAddress tenant_id" \
  --no-split --output combined_savedsearches.conf

# Splunk CIM data model (| tstats ... from datamodel=...) or custom YAML pipeline / profile
soclens sigma --export --pipeline splunk_cim --custom-table-fields "tenant_id" --output cim_searches.conf
soclens sigma --export --pipeline-file my_pipeline.yml --sigma-config sigma_profile.json --output savedsearches.conf

# Convert local Sigma YAML rule file(s) offline without an RF API token
soclens sigma --convert-file ./my_rule.yml --index-map "windows=win_sec" --custom-table-fields "tenant_id"
soclens sigma --convert-file ./my_rule.yml --pipeline splunk_windows_sysmon --json
```

Supported environment variables for Sigma defaults:
- `SOCLENS_SIGMA_CONFIG`: Path to a JSON/YAML conversion profile (`index_map`, `custom_table_fields`, `table_fields_map`, `field_map`, `sourcetype_map`, `pipeline`, `output_format`, etc.)
- `SOCLENS_SIGMA_PIPELINE` / `SOCLENS_SIGMA_PIPELINE_PATH` / `SOCLENS_SIGMA_OUTPUT_FORMAT`: Default pySigma pipeline (`splunk_windows`, `splunk_windows_sysmon`, `splunk_cim`, `none`), custom YAML pipeline file, and output format (`default` or `data_model`)
- `SOCLENS_INDEX` / `SOCLENS_INDEX_MAP` / `SOCLENS_DEFAULT_INDEX`: Global override, per-logsource index mapping, and fallback index
- `SOCLENS_CUSTOM_TABLE_FIELDS` / `SOCLENS_TABLE_FIELDS_MAP` / `SOCLENS_DEFAULT_TABLE_FIELDS` / `SOCLENS_TENANT_FIELD`: Append custom fields, map table fields per logsource, or override default `| table` fields
- `SOCLENS_CUSTOM_SUPPRESS_FIELDS` / `SOCLENS_SUPPRESS_FIELDS_MAP` / `SOCLENS_DEFAULT_SUPPRESS_FIELDS`: Customize `alert.suppress.fields`
- `SOCLENS_FIELD_MAP` / `SOCLENS_SOURCETYPE_MAP`: Custom Sigma-to-Splunk field renames and per-logsource `sourcetype` mappings

In the TUI (`soclens tui`, press `5`), expand **Splunk Export, Custom Indexes & Table Fields** on the **Sigma Rules** tab to configure pipelines, custom index mappings, custom `| table` / suppression fields, field renames, live index resolution in the table, and one-click stanza preview before exporting.

---

## Splunk Saved Searches Validation

```bash
# Dry-run parse check
soclens validate --input savedsearches.conf --dry-run

# Foreground concurrent validation (defaults to SplunkEnterpriseSecuritySuite)
soclens validate --input "savedsearches_*.conf" --earliest -7d --concurrency 5

# Cross-platform detached background validation
soclens validate --input "savedsearches_*.conf" --earliest -30d --background --log-file validation.log --status-file status.json
```

---

## Packaging & Air-Gapped Deployment Bundling

Create a self-contained deployment ZIP (never includes `apikey.key`, `.log`, `.git`, or `.venv`). When a local `wheelhouse/` directory is present, `--wheelhouse` packages those verified wheels completely offline without network access:

```bash
soclens bundle --output soclens_bundle.zip
soclens bundle --wheelhouse --output soclens_airgap_all.zip
soclens bundle --wheelhouse --target-platform win_amd64 --output soclens_win64.zip
soclens bundle --wheelhouse --target-platform manylinux2014_x86_64 --output soclens_linux64.zip
soclens bundle --target-platform pure --output soclens_pure.zip

# Verify bundled wheelhouse SHA-256 checksums, ZIP integrity, and lockfile completeness offline
python scripts/build_wheelhouse.py --verify

# Build and verify all pre-packaged offline release bundles (bundles/v2.2.0/)
python scripts/build_release_bundles.py
python scripts/build_release_bundles.py --verify
```

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

To report a security vulnerability or credential/exposure concern, please follow the instructions in [SECURITY.md](SECURITY.md).

## License

This project is licensed under the [MIT License](LICENSE).
