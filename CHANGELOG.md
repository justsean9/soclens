# Changelog

All notable changes to **SOCLens (`soclens`)** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Rebranded the project, Python package (`soclens`), CLI (`soclens`), PowerShell launcher (`soclens.ps1`), automation scripts (`scripts/soclens-brand-sync*`), configuration directory, and environment variables (`SOCLENS_*`) to **SOCLens**.
- Removed legacy root helper scripts (`main.py`, `bundle.py`, `manage_env.py`, `manage.sh`, `manage.fish`, `scripts/spawn_splunk.*`), `RF.md`, and stale pre-rebrand `bundles/v2.0.0/` archives.

## [2.0.0] - 2026-11-24

### Breaking / Behavioral Changes
- **User vs. Admin TUI Views (`F2` / `--view` / `--admin`)**: `soclens tui` now defaults to **User View**, displaying the 8 day-to-day analyst & per-user tabs (**RF Intel & Alerts** `4`, **Research** `7` initial tab, **Logs** `8`, **SentinelOne** `9`, **Local LLM** `F7`, **Splunk Search** `F8`, **Splunk ES** `F9`, and **Settings** `0`/`F10`) while hiding admin/configuration tabs (**Dashboard & Diagnostics** `1`, **Watchlists** `2`, **Brand Logos** `3`, **Sigma Rules** `5`, **Splunk & Bundle** `6`) and watchlist-mutation pivots until toggled via `F2`, the top selector bar, `--view admin` / `--admin`, or `SOCLENS_UI_VIEW=admin` (automatically enabled when specifying an admin `initial_tab`).

### Added
- **Per-User Settings UI Tab & CLI (`soclens.settings`, `soclens settings`, `0` / `F10`)**:
  - Cross-platform per-user settings persistence (`settings.json` with `0600` POSIX permissions), named profiles (`default`, `prod`, `lab`, etc.), secret masking, `soclens settings import-env` / `set` / `unset` / `use` / `reset`, and live in-TUI credential/configuration reload across RF Core, Sandbox, ASI, PFI, RiskRecon, Splunk, SentinelOne, and proxy/SSL settings.
- **Splunk Enterprise Search, Splunk ES & Automated RF Enrichment (`soclens.splunk`, `soclens.splunk_es`, `soclens.splunk_rf_enrichment`)**:
  - **Splunk Search** workbench tab (`F8`) and `soclens splunk search/indexes/saved-searches/dispatch` CLI with paginated results, saved-search browser, and **Recorded Future IOC Enrichment** pivot.
  - **Splunk ES** workbench tab (`F9`) and `soclens splunk es` CLI covering notable event triage/updates (`SplunkNotableTriageModal`), correlation searches, threat-intel KVStore collections, assets/identities, risk scores, and automated RF entity/IP/domain/hash/URL enrichment (`soclens splunk es enrich` + **Enrich Selected / All** & **Post RF Comment**).
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

### Security & Hygiene
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
