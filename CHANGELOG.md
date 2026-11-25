# Changelog

All notable changes to **SOCLens (`soclens`)** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.3.1] - 2026-11-25

### Added
- **Native Copilot Studio Direct-to-Engine (`copilot_studio`) `POST` + SSE Transport (`soclens.copilot`, `soclens.llm`, `soclens.tui.screens.llm`)**:
  - Added native `CopilotStudioD2ETransport` for Copilot Studio Native/Mobile App Connection String URLs (`https://<env>.environment.api.powerplatform.com/copilotstudio/.../bots/<schema>/conversations?api-version=...`), using `POST` + `Accept: text/event-stream` SSE streaming and automatic Power Platform token resolution (`az account get-access-token --resource https://api.powerplatform.com` via `az_cli`, or direct Bearer token — zero Entra ID App Registration required).
  - Automatically routes `/copilotstudio/.../conversations` URLs to `CopilotStudioD2ETransport` even when `copilot_directline` is selected, fixing `HTTP 404: does not match any known API routes`.

## [2.3.0] - 2026-11-25

### Added
- **Microsoft Enterprise Copilot Chat, Copilot Studio & Security Copilot Integration (`soclens.copilot`, `soclens.llm`, `soclens llm`)**:
  - Added token-first transports requiring **no Entra ID App Registration**, supporting **Enterprise M365 Copilot Chat** (`m365_copilot` via Microsoft Graph Beta `/copilot/conversations`, `/chat`, and `/chatOverStream` SSE streaming with direct Bearer token or automatic `az_cli` token refresh), **Copilot Studio custom agents** (`copilot_directline` via Mobile/Web Channel Token Endpoint or Direct Line v3 secret with watermark polling and Adaptive Card/citation rendering), and **Microsoft Security Copilot** (`security_copilot` via Graph Beta `workspaces/{id}/sessions` → `prompts` → `evaluations`).
  - Added named multi-agent preset configuration (`ms_copilot_agents_json` / `SOCLENS_MS_COPILOT_AGENTS`), PAM/Vault secret hydration support for `ms_copilot_bearer_token`, `ms_copilot_token_endpoint`, and `ms_copilot_directline_secret`, and CLI support for `--provider m365_copilot|copilot_directline|security_copilot`, `--agent`, `--conversation-id`, and `soclens llm agents`.
- **Multi-Window Concurrent AI Chat Tabs in the TUI (`soclens.tui.screens.llm`, `F7`)**:
  - Upgraded the AI Analyst pane with a **Multi-Chat Session Bar** (`+ New Chat`, `Close Chat`, session switcher) where each chat window maintains independent provider, agent/model, server-side `conversation_id`, scrollback transcript, attached Splunk/S1/RF pivot context, and background worker — enabling concurrent chats with multiple Copilot agents and local LLMs simultaneously.
- **Microsoft Copilot & Offline Install KB Guide (`docs/MICROSOFT_COPILOT_GUIDE.md`)**:
  - Added comprehensive documentation covering licensing/cost selection, obtaining Graph/Copilot tokens without Entra ID App Registration (Azure CLI `az_cli`, Graph Explorer, Azure PowerShell, Copilot Studio Token Endpoint), multi-agent JSON setup, Security Copilot readiness, PAM/Vault storage, air-gapped offline installation, and troubleshooting.

### Removed
- Removed legacy `docs/ignore/SOCLENS_MEGA_PROMPT.md`.

## [2.2.0] - 2026-11-25

### Added
- **Akeyless Vault Secret Manager / PAM Provider (`soclens.secret_stores.akeyless`)**:
  - Native `ConfiguredSession()` integration for Akeyless SaaS and self-hosted Gateway supporting `access_key` and `token` authentication modes, static/dynamic/rotated secrets, path-prefix catalog discovery, and Settings UI / dynamic vault dropdown support with zero new runtime dependencies.
- **24-Hour Local Alert Cache, Background Preloading & Human-Readable Inspectors (`soclens.alert_cache`, `soclens.tui`)**:
  - Local 24-hour alert caching and background preloading for Recorded Future alerts, full Playbook Alert details and cached screenshot images, SentinelOne MDR alert defaults, full-line row hover tooltip popups across `DoubleClickDataTable` tables, and structured table formatting for SentinelOne `mitigationStatus` action lists.
- **Global Text Selection Highlighting, Clickable Structured Fields & Right-Click RF/Splunk Search Pivot (`soclens.tui.pivot`, `soclens.tui.screens.base`)**:
  - Added `SelectableRichLog` across all 13 TUI dashboards with high-contrast word-accurate gold selection highlights, clickable cyan/blue structured field search buttons, streamlined right-click menus restricted to Recorded Future and Splunk (`index=* "KEYWORD"`) searches, and transparent/translucent modal overlays that preserve background visibility.
- **Threat Research Search-to-Initial-Thoughts Banner & Opt-in ASCII Art (`soclens.tui.research_art`)**:
  - Live Threat Research status banner that stays hidden while idle, displays search progress (`SCANNING...`) transitioning into initial threat verdict and top RF/OSINT signals, and auto-hides after 10 seconds — with ASCII art disabled by default and optionally unlockable via Settings (`soclens_ascii_art_enabled` / `SOCLENS_ASCII_ART`).

### Fixed
- **SentinelOne Full Cursor Pagination & Newest-First Default Sorting (`soclens.sentinelone`)**:
  - Traversed all cursor pages (`MAX_PAGE_SIZE=100`) with cycle and null guards and default newest-first sorting across API and client fallback.
- **TUI Text Selection & Bottom-Panel Highlighting**:
  - Fixed character offset mapping (`Strip.apply_offsets`) and cell-accurate selection highlighting so only selected words highlight cleanly across all panels.
- **CI & README Hygiene**:
  - Disabled automatic GitHub CI workflow triggers on push/PR (retaining tag-triggered releases) and removed the CI status badge from `README.md`.

## [2.1.0] - 2026-11-25

### Added
- **Unified Recorded Future + 16 Free Passive OSINT Feeds (`soclens.osint`, `soclens.research`, `soclens research osint`)**:
  - Integrated 16 passive, zero-extra-dependency free OSINT modules (18 live feeds) alongside Recorded Future in a single pane of glass across both the **Research** TUI tab (`7`) and CLI:
    - **13 zero-key public feeds**: WHOIS/RDAP (with Newly Registered Domain `<= 30d` alerting), DNS-over-HTTPS (DNS/SPF/DMARC/DNSSEC/PTR), ipwho.is GeoIP, RIPEstat BGP/ASN, Shodan InternetDB, crt.sh Certificate Transparency logs, URLScan.io, SANS DShield, Wayback Machine CDX, AlienVault OTX, GreyNoise Community, CIRCL NSRL Hashlookup, and MITRE CVE + FIRST EPSS + CISA KEV.
    - **3 optional free-tier API key integrations** configurable in **Settings** (`OSINT Free API Keys`): VirusTotal v3, AbuseIPDB v2, and abuse.ch (ThreatFox, URLhaus, MalwareBazaar).
  - Added automatic domain/URL → resolved public hosting IP chaining, Unified Verdict synthesis, Source Coverage badge strip, `OSINTSourcesModal` (`s`), `RF + OSINT` / `OSINT Only` / `RF Only` mode selector, and standalone `soclens research osint` CLI (works even without an RF API token).
- **Encrypted `settings.json` at Rest with AES-256-GCM & Hybrid Keystore (`soclens.settings_crypto`)**:
  - Added authenticated AES-256-GCM encryption (schema v2) for per-user `settings.json` with two key-management modes:
    - `os_keystore` (default, auto-unlock): Windows DPAPI (`CryptProtectData`), macOS Keychain (`/usr/bin/security`), and Linux Secret Service (`secret-tool`) with automatic `0600` keyfile fallback on headless servers/containers.
    - `passphrase` (Master Passphrase): Scrypt KDF (RFC 7914) wrapping a per-file random 256-bit DEK with zero key material stored on disk, supporting interactive TUI unlock modals, CLI prompts, and non-interactive `SOCLENS_SETTINGS_PASSPHRASE` / `SOCLENS_SETTINGS_PASSPHRASE_FILE`.
  - Added CLI encryption management commands, TUI **Settings** encryption controls and unlock modal, updated `SECURITY.md`, and bundled verified offline `cryptography`, `cffi`, and `pycparser` wheels across Python 3.12–3.14 for Windows, Linux, and macOS (75 verified offline wheels total).
- **TUI Screenshots & Headless Screenshot Generator (`scripts/generate_screenshots.py`, `docs/screenshots/`)**:
  - Added SVG screenshots for Threat Research, RF Intel & Alerts, Splunk ES, SentinelOne, Sigma Rules, Local LLM Copilot, and the Admin Dashboard in `README.md`, along with a reproducible headless screenshot generator using sanitized demo data.

### Fixed
- **ProxySG / Edge SWG Compatibility & Proxy 403 Diagnostics (`soclens.client`, `soclens.osint`)**:
  - Appended a ProxySG-safe trailing `/` to Recorded Future Connect v2 domain (`/v2/domain/{id}/`), company-by-domain (`/v2/company/by_domain/{domain}/`), and file/TLD-extension URL and Entity Match lookups (`/v2/url/.../`, `/entity-match/entity/.../`) so Broadcom/Symantec ProxySG does not misclassify `.com`/`.exe`/`.bat`/`.sh` paths as executable downloads (`HTTP 403`).
  - Normalized user-supplied trailing slashes on domain inputs so they are never double-slashed or percent-encoded as `%2F`.
  - Added HTML/ProxySG `403` detection in `classify_403_permission` (`proxy_blocked`) and `OSINTClient._request_json` to clearly distinguish proxy policy blocks from upstream API authentication errors.

## [2.0.0] - 2026-11-25

### Breaking / Behavioral Changes
- **Rebrand to SOCLens (`soclens`)**: Renamed the Python package (`soclens`), CLI (`soclens`), PowerShell launcher (`soclens.ps1`), automation scripts (`scripts/soclens-brand-sync*`), configuration directory, and environment variables (`SOCLENS_*`), removing legacy root helper scripts (`main.py`, `bundle.py`, `manage_env.py`, `manage.sh`, `manage.fish`, `scripts/spawn_splunk.*`), `RF.md`, and stale pre-rebrand `bundles/v2.0.0/` archives.
- **User vs. Admin TUI Views (`F2` / `--view` / `--admin`)**: `soclens tui` now defaults to **User View**, displaying the 8 day-to-day analyst & per-user tabs (**RF Intel & Alerts** `4`, **Research** `7` initial tab, **Logs** `8`, **SentinelOne** `9`, **Local LLM** `F7`, **Splunk Search** `F8`, **Splunk ES** `F9`, and **Settings** `0`/`F10`) while hiding admin/configuration tabs (**Dashboard & Diagnostics** `1`, **Watchlists** `2`, **Brand Logos** `3`, **Sigma Rules** `5`, **Splunk & Bundle** `6`) and admin/destructive mutations until toggled via `F2`, the top selector bar, `--view admin` / `--admin`, or `SOCLENS_UI_VIEW=admin` (automatically enabled when specifying an admin `initial_tab`).

### Added
- **Pluggable Secret Manager / PAM Integration & Dynamic TUI Dropdowns (`soclens.secret_stores`, `soclens secrets`)**:
  - Cross-platform `ConfiguredSession()` integrations for **Thycotic / Delinea Secret Server** (password, Delinea Platform client credentials, and token auth with proactive refresh & `401` retry), **HashiCorp Vault KV v2** (Token & AppRole auth), **1Password Connect Server**, and **Bitwarden (`bw serve`)** with zero new third-party runtime dependencies.
  - Strictly persists only `vault_secret_map` references to `settings.json` (`0600`), hydrating secret values in memory via `set_session_overrides(...)` while preserving environment-variable precedence and supporting `rf_llm_api_key`.
  - Added **Secret Manager (PAM / Vault)** (`cat-secrets`) in **Settings** (`0`/`F10`), dynamic `Input <-> Select` vault reference dropdown switching across RF, Splunk, and SentinelOne credential fields, non-blocking TUI startup hydration, `--no-secret-store`, and `soclens secrets` CLI (`test`, `list`, `fields`, `map`, `unmap`, `pull`).
- **Splunk ES 8.6 Mission Control Workbench & Custom Tenant Fields (`soclens.splunk_es`, `F9`)**:
  - Hybrid Mission Control v2 REST primary (`/servicesNS/nobody/missioncontrol/public/v2/...`) with automatic Splunk ES 7.x SPL / `/services/notable_update` fallback, preset and user-saved queue views, item-type pills, timeframe/auto-refresh controls, toggleable summary strip, multi-select bulk triage, 6-tab Finding Inspector (`Overview | Metadata & Custom | Src / Dest | RF Enrichment | Notes & History | Raw JSON`), Markdown notes with optional RF dual-posting, Adaptive Response invocations/dispatch, and Investigations.
  - First-class configurable tenant extraction (`splunk_es_tenant_field`, defaulting to `tenant_id` with configurable aliases), `Group by Tenant` queue rollup, `conf-incident_review` / `conf-log_review` `event_attributes` custom-field auto-discovery, `Custom / Org Fields` Inspector panel, and `splunk_es_custom_fields` pinning/create support.
- **SentinelOne Multi-Site Tier Grouping, Tenant Admin & Exclusion Cloning (`soclens.sentinelone`, `soclens s1`, `9`)**:
  - Added `Global -> Account -> Site -> Group` hierarchy, configurable case-insensitive `s1_tier_rules` (`MDR-*`, `MSSP-*`, `Other`), Tier Filter Pills, searchable multi-site selector, 4 alert grouping modes (`Flat Alert Stream`, `Service Tier`, `Site`, `Tier + File Hash (SHA1)`), and Cloud/STAR alerts.
  - Expanded `SentinelOne` (`9`) across 5 sub-workbenches (`Alerts & Threats`, `Sites Admin`, `Users & RBAC Admin`, `Exclusions & Site-to-Site Cloning`, `Agents & Blocklist`) read-only in User View and strictly gated behind Admin View (`F2`/`--admin`), `ConfirmActionModal` / exact site-name confirmation, `--yes` / `SOCLENS_AUTO_APPROVE`, and `--dry-run`, with `limit <= 100` cursor pagination, `429` backoff, non-empty mutation `filter` guardrails, `<= 15` req/s exclusion cloning with dry-run diff preview, and matching `soclens s1` CLI commands.
- **Cross-Workbench Pivot Bus & Local LLM Copilot (`soclens.tui.pivot`, `soclens.llm`, `F7`)**:
  - Added `s1_site_tenant_map` and regex tier-capture tenant mapping, auto-run scoped read-only pivots (`F9 <-> 9`, `4`, `7`), safe `F8` SPL pre-fill (`auto_run=True` only on `orig_sid`), and bundled `[ES + Tenant + S1 + RF]` attack-chain & closing-note context attached directly into **Local LLM** (`F7`).
- **Per-User Settings UI Tab & CLI (`soclens.settings`, `soclens settings`, `0` / `F10`)**:
  - Cross-platform per-user settings persistence (`settings.json` with `0600` POSIX permissions), named profiles (`default`, `prod`, `lab`, etc.), secret masking, `soclens settings import-env` / `set` / `unset` / `use` / `reset`, and live in-TUI credential/configuration reload across RF Core, Sandbox, ASI, PFI, RiskRecon, Splunk, SentinelOne, and proxy/SSL settings.
- **Splunk Enterprise Search, Splunk ES & Automated RF Enrichment (`soclens.splunk`, `soclens.splunk_es`, `soclens.splunk_rf_enrichment`)**:
  - **Splunk Search** workbench tab (`F8`) and `soclens splunk search/indexes/saved-searches/dispatch` CLI with paginated results, saved-search browser, and **Recorded Future IOC Enrichment** pivot.
  - Automated RF entity/IP/domain/hash/URL enrichment (`soclens splunk es enrich` + **Enrich Selected / All** & **Post RF Comment**).
- **Local LLM Workbench (`soclens.llm`, `soclens llm`, `F7`)**:
  - Native Ollama and OpenAI-compatible REST integration (`RF_LLM_PROVIDER`, `RF_LLM_BASE_URL`, `RF_LLM_MODEL`) with SOC prompt templates, interactive **Local LLM** chat tab (`F7`), and one-click **Explain with Local LLM** pivots from Sigma Rules and RF Intel alerts.
- **Sigma Detection Pipeline, Custom Index Maps & Table Fields (`soclens.sigma`, `5`)**:
  - Configurable pySigma processing pipelines (`splunk_windows`, `splunk_windows_sysmon`, `splunk_cim`, `none`, or `--pipeline-file`), per-logsource index mapping (`--index-map`), custom appended/mapped `| table` & `alert.suppress.fields`, field renames (`--field-map`), `--convert-file` offline conversion, and expandable UI controls in **Sigma Rules**.
- **Cross-Platform Clipboard & Selectable Copyable View (`soclens.tui.clipboard`, `CopyTextModal`)**:
  - Unified clipboard copy across Windows (`clip.exe` + PowerShell UTF-8), macOS (`pbcopy`), Linux (`wl-copy` / `xclip` / `xsel`), and SSH/OSC 52 terminals, plus copy toolbars (`Copy SPL` `c`, `Copy Stanza` `y`, `Copy YAML`, `Copyable View` `v`) across Sigma, RF Intel, Research, Watchlists, Brand Logos, Splunk & Bundle, and Logs.
- **Alerts & Playbook Auto-Enrichment (`soclens.tui.screens.rf_intel`)**:
  - Automatic SOAR/Connect enrichment and severity-sorted triage presentation across Classic Alerts, Playbook Alerts, and Cases.
- **Watchlists Drilldown & Company Entity ID Resolution (`soclens.tui.screens.watchlists`, `soclens.client`)**:
  - Full-width searchable Watchlists browse (`name` + `type`) -> Entity drilldown (`F4` Copy List ID, `Esc`/`Backspace` navigation) and ID-based removal support for non-auto-resolved Recorded Future entities (`Company` etc.).
- **Brand Logos Multi-Column Sorting & Issue Dashboards (`soclens.logos`, `soclens watchlist brand-issues`)**:
  - Interactive sorting (`F6`), right-click domain-scoped sync/validate actions, and dedicated issue filters (`missing_hashes`, `silent_zero_hashes`, `domain_errors`, `image_errors`, `failing_grace`, `duplicate_hashes`).
- **Display Timezone Selection (`soclens.timezone`, `F3`)**:
  - Consistent timestamp formatting across TUI panes with `F3` / `TimezoneModal` selector, `--timezone`, and `SOCLENS_TZ`.
- **Windows-Safe Image Rendering & Native OS Viewer Default (`soclens.tui.image_render`, `--os-image-viewer`)**:
  - Automatic Kitty TGP suppression on Windows / Windows Terminal in favor of true-color half-blocks, right-click screenshot preview actions (`o`), and persistent `OS Image Viewer` default toggle.

### Fixed & Security
- Stabilized lazy-mounted TUI worker races (`watchlists.py` `WorkerCancelled` sequence gating and `rf_intel.py` initial auto-enrichment) and added a 4-tier + Tier 5 offline E2E regression suite.
- Added `settings.json`, `.soclens_settings.json`, and `.soclens_tui_settings.json` to both `soclens.bundler.EXCLUDED_FILE_NAMES` and `scripts/build_release_bundles.py` `FORBIDDEN_EXACT_NAMES`.

## [1.0.2] - 2026-11-24

### Added & Fixed
- **Insecure SSL & Custom CA Bundle Support for Internal / Corporate Proxies**:
  - Added unified SSL configuration in `soclens.config` (`get_rf_verify_ssl`, `parse_ssl_verify`, `suppress_insecure_ssl_warnings`, `format_ssl_verify_status`, and `get_proxy_summary` with credential masking) supporting `RF_VERIFY_SSL`, `RF_INSECURE_SSL`, `SOCLENS_INSECURE_SSL`, and `RF_CA_BUNDLE` (while preserving `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`).
  - Added global and subcommand-level CLI flags `-k` / `--insecure` / `--no-verify-ssl` and `--ca-bundle <PATH>` across `tui`, `watchlist`, `rf`, `research`, `sigma`, and `validate`.
  - Updated `RecordedFutureClient`, `ExtractorConfig`, `brand_sync`, and `watchlist` to honor insecure SSL / custom CA overrides and fail fast on `SSLError` with clear proxy troubleshooting guidance logged to `logs/rf_api_errors.jsonl`.
  - Added live **Insecure SSL: OFF/ON** toggle button, context-menu action, subtitle status, and masked proxy diagnostics in the TUI **Dashboard & Diagnostics** tab (`soclens tui`).
  - Added `-Insecure` and `-CaBundle` parameters to `scripts/soclens-brand-sync.ps1` and `-k` / `--insecure` / `--ca-bundle` support to `scripts/build_wheelhouse.py`.

## [1.0.1] - 2026-11-24

### Fixed & Changed
- **Windows PowerShell Launchers (`soclens.ps1`, `install_offline.ps1`)**:
  - Added root PowerShell launcher [`soclens.ps1`](soclens.ps1) (pure ASCII, compatible with Windows PowerShell 5.1, PowerShell 7+, and `pwsh`) invoking `python -m soclens.cli`.
  - Updated `install_offline.ps1` with `Install-WindowsPowerShellShims` to install `.venv\Scripts\soclens.ps1`, dot-source `.venv\Scripts\Activate.ps1` in output hints, and launch the TUI directly via `python.exe -m soclens.cli tui`.
  - Hardened `scripts/soclens-brand-sync.ps1` with `try {} catch {}` UTF-8 console setup for non-interactive Task Scheduler sessions plus `SOCLENS_PYTHON` and Windows `py` launcher fallback resolution.
  - Added [`soclens/__main__.py`](soclens/__main__.py) so `python -m soclens` works directly everywhere alongside `python -m soclens.cli`.
  - Updated `soclens/bundler.py` and `scripts/build_release_bundles.py` with PowerShell launcher verification.

## [1.0.0] - 2026-11-24

### Added
- **Unified CLI (`soclens`)**:
  - Cross-platform entrypoints with global `--version` / `-V`, `--dry-run` / `-d`, `--json`, and `--tui` / `-t` flags.
  - Subcommands covering `watchlist`, `rf`, `research`, `sigma`, `validate`, `bundle`, and `tui`.
- **8-Tab Windows-Compatible Textual TUI (`soclens tui`)**:
  - Interactive full-viewport responsive workbench with tabs `1`–`8`: **Dashboard & Diagnostics**, **Watchlists**, **Brand Logos**, **RF Intel & Alerts**, **Sigma Rules**, **Splunk & Bundle**, **Research**, and **Logs**.
  - Centralized `TuiLoggingBridge` and `AppLogStore` capturing all logging, warnings, and print output inside the **Logs** tab without corrupting the terminal UI.
  - Right-click context menus (`ContextMenuModal`), mandatory approval prompts (`ConfirmActionModal`) for destructive operations, Kitty HD + inline terminal image preview, and cross-tab entity pivoting.
- **Recorded Future API Client & Diagnostics (`soclens.client`, `soclens.config`)**:
  - Coverage across 22 documented Recorded Future API families (Lists/Watchlists, Entity Match, Connect API v2 & 3rd-party extensions, SOAR v3, Detection Rules, Playbook Alerts, Alerts v3/v2, Cases, Sandbox v0, Links Graph, Analyst Notes, Threat Maps/Actors, Malware Intelligence, Risk History, Identity Intelligence, Collective Insights, Fusion v3, ATO, STIX/TAXII 2.1, ASI, PFI, and RiskRecon).
  - Exponential backoff retries for HTTP `429 Too Many Requests`, HTTP `403` entitlement vs. privilege classification, and persistent `traceId` diagnostics written to `logs/rf_api_errors.jsonl`.
- **Threat Research Engine & Workbench (`soclens.research`, `soclens research`)**:
  - Multi-API investigation dossiers, token capability probing (`soclens research capabilities`), pivot history navigation, and Markdown/JSON report export.
- **Brand Logo Extraction, Hashing & Continuous Sync (`soclens.logos`)**:
  - Pure-Python image validation (PNG IHDR/CRC-32, magic bytes, dimensions, aspect-ratio gating), JSON-LD/manifest/CSS/SVG/`srcset` extraction, parked/hijacked/bot-gate detection, and SHA-256 delta sync with 3-failure grace protection and lockfile overlap prevention.
  - Unattended continuous sync templates for Linux `systemd` and Windows Task Scheduler / PowerShell.
- **Sigma Rule Cache & Splunk ES Validation (`soclens.sigma`, `soclens.splunk`)**:
  - Insikt Group Sigma rule caching, search, and conversion to Splunk Enterprise Security `savedsearches.conf` stanzas.
  - Concurrent Splunk REST API validator with cross-platform background mode (`--background`).
- **Offline / Air-Gapped Packaging & v1.0.0 Release Bundles**:
  - Self-contained 62-wheel multi-platform `wheelhouse/` supporting Python 3.12, 3.13, and 3.14 on Windows x64 (`win_amd64`), Linux x64 (`manylinux*_x86_64`), and macOS ARM64 (`macosx_*_arm64`) with offline SHA-256 verification (`scripts/build_wheelhouse.py --verify`).
  - Zero-internet installers `install_offline.ps1` (Windows PowerShell 5.1 / PowerShell 7+) and `install_offline.sh` (Bash/Zsh).
  - Pre-built offline release ZIP bundles in `bundles/v1.0.0/` (`all`, `win_amd64`, `linux_x86_64`, `macosx_arm64`) with `SHA256SUMS.txt` and `scripts/build_release_bundles.py`.
