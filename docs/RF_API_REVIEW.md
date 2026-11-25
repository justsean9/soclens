# Recorded Future API Review & SOC Toolkit Coverage Matrix

**Document Scope**: Authoritative technical review of all Recorded Future APIs usable for production SOC operations, cross-referencing the repository snapshot (`RF.md`, `RF-DOCS-2026Q1`) against live Recorded Future LLM & OpenAPI documentation (`docs.recordedfuture.com/llms.txt`, `reference/llms.txt`, `llm-instructions.md` `RF-DOCS-2026Q4`, `get-started.md`, `api-entitlements.md`, and 119 endpoint `.md` specifications).

---

## 1. Executive Summary & Authoritative Sources

### 1.1 Purpose
This review establishes the canonical API baseline for the `soclens` (`soclens`) toolkit across watch list management, brand logo hash monitoring, Sigma detection rule synchronization, IOC enrichment/triage, playbook/classic alert handling, case management, and malware sandboxing.

### 1.2 Source Comparison: `RF.md` (`RF-DOCS-2026Q1`) vs Live `docs.recordedfuture.com` (`RF-DOCS-2026Q4`)

| Dimension | `RF.md` (`RF-DOCS-2026Q1`) | Live Docs (`RF-DOCS-2026Q4`) | Impact on `soclens` |
|---|---|---|---|
| **Catalog Scope** | 393 lines, 13 workflows, prose endpoint names | `llms.txt` (27 categories), `reference/llms.txt` (476 lines), `llm-instructions.md` (533 lines, 99 explicit `slug:` -> `.md` specs) | Direct OpenAPI 3.0/3.1 schemas eliminate guesswork in field names and pagination |
| **Error Payload Formats** | Claims *all* v2 errors share `{"error": {"status", "message", "reason"}, "traceId"}` (`RF.md:36`) | 8 distinct schemas across API families (e.g., Lists/Detection Rules use `trace_id`; Sandbox uses string `"error"`; Playbook Alerts/Cases use `status`) | `_log_api_error` safely parses all 8 schemas without `AttributeError` |
| **Playbook Alert Brand Categories** | Omits `malicious_sites`, `dark_web` / `/dark_web_brand`, and `socmed_impersonation` / `/social_media_impersonation` | Full OpenAPI specs for `domain_abuse`, `malicious_sites`, `dark_web_brand`, `social_media_impersonation`, including `DrpAsset.ImageHash` and `MaliciousSitesLogoHashChange` | Enables end-to-end verification of Brand Image Watch List matches & PNG screenshot retrieval |
| **Alerts v3 Path** | Not explicitly distinguished | Canonical path is `GET https://api.recordedfuture.com/alert/v3` (`/v3/alerts` is marked `"V3 Proxy Redirect (Legacy)"`) | `search_alerts_v3` targets `/alert/v3` directly |
| **Detection Rules Schema** | Prose mention only | `POST /detection-rule/search` uses `updated: {"after", "before"}`, returns `result` (singular) and `next_offset`, paginates with `offset` | Fixed critical schema bug in `search_detection_rules` |
| **SOAR v3 Company Key** | Not detailed | OpenAPI `EnrichRequest` uses `"companybydomain"` (prose typo in `soar-triage-batch.md` says `"company"`) | Prevents 400 validation failures in `soar_enrich` / `soar_triage` |
| **Entity ID Prefixes & Auto-Resolution** | Generic guidance | `available-entity-types.md` defines 16+ predictable prefixes (`idn:`, `ip:`, `hash:`, `asn:`, etc.); `{type, name}` auto-resolution works ONLY for `IpAddress`, `InternetDomainName`, `Hash`, `CyberVulnerability` | Fixed `_is_rf_entity_id` heuristic in `soclens.client` |
| **Additional API Families** | Limited to 13 workflows | Documents `Analyst Notes`, `Risk`, `Autonomous Threat Operations`, `Fusion v3`, `STIX/TAXII 1.x/2.1`, `Takedowns` (PhishFort), `RiskRecon` | Complete 21-surface architecture & out-of-scope integration guidance |

---

## 2. API Families, Base URLs & Authentication Schemes

### 2.1 Environment Variables (`GEMINI.md` & `soclens.config`)
- **Core API Token**: `RF_API_TOKEN` (checked first) or `RECORDED_FUTURE_API_KEY` (fallback). Never hardcode tokens.
- **Sandbox API Token**: `RF_SANDBOX_TOKEN` (optional override; falls back to Core token if unified). Note that Sandbox uses a different header scheme (`Authorization: Bearer <token>`).
- **Base URL Overrides** (optional): `RF_BASE_URL` (default `https://api.recordedfuture.com`), `RF_SANDBOX_BASE_URL` (default `https://sandbox.recordedfuture.com/api/v0`).

### 2.2 Complete 21-Surface API Directory

| # | API Family | Base URL | Auth Header / Scheme | Required Module Entitlement | Primary Use in SOC |
|---|---|---|---|---|---|
| 1 | **Lists & Watchlists** | `https://api.recordedfuture.com/list` | `X-RFToken: <token>` (or OAuth2 `idp`) | All modules | Manage 21 list types (`brand`, `domain`, `ip`, `hash`, `company`, etc.) |
| 2 | **Entity Match & Lookup** | `https://api.recordedfuture.com/entity-match` | `X-RFToken: <token>` | All modules | Resolve names (`Product`, `Company`, `CVE`, Threat Actors) to opaque RF IDs |
| 3 | **Connect API v2** | `https://api.recordedfuture.com/v2` | `X-RFToken: <token>` | Per-entity (`SecOps`/`Threat`/`Brand` for IP/Domain/URL; `Vuln Intel`; `Third Party Intel`) | Deep IOC lookup, company-by-domain attribution, search, Risk Lists & ETag `HEAD` checks |
| 4 | **SOAR API v3** | `https://api.recordedfuture.com/soar/v3` | `X-RFToken: <token>` | `SecOps`, `Threat Intel` | Batch IOC enrichment & context triage (up to 1,000 IOCs/call) |
| 5 | **Detection Rules** | `https://api.recordedfuture.com/detection-rule` & `/detection-rule-relation` | `X-RFToken: <token>` | `SecOps`, `Threat Intel` | Search & export Insikt Group Sigma, YARA, and Snort rules |
| 6 | **Playbook Alerts** | `https://api.recordedfuture.com/playbook-alert` | `X-RFToken: <token>` | All except `SecOps Intel` (category-licensed; `Brand Intel` for DRP/brand) | Triage `domain_abuse`, `malicious_sites`, `dark_web_brand`, `social_media_impersonation`, retrieve logo-hash matches & PNG screenshots |
| 7 | **Alerts v3 & v2** | `https://api.recordedfuture.com/alert` | `X-RFToken: <token>` | All except `SecOps Intel` | Classic rule alerts search (`GET /alert/v3`), hits, images, bulk status updates (`/v2/update`) |
| 8 | **Cases** | `https://api.recordedfuture.com/case` | `X-RFToken: <token>` | Alerts / Case Management | Search, lookup (`POST /case/lookup`), create, and update (`PUT /case/update`) SOC cases |
| 9 | **Recorded Future Sandbox v0** | `https://sandbox.recordedfuture.com/api/v0` (regional: `us-sandbox...`, `apj-sandbox...`) | `Authorization: Bearer <token>` | `SecOps`, `Threat Intel` | Detonate files/URLs, poll/stream tasks, pull `overview.json` & PCAP/YARA, search corpus |
| 10 | **Identity Intelligence** | `https://api.recordedfuture.com/identity` | `X-RFToken: <token>` | `Identity Intelligence` | Breached credential searches, hostname/password lookups, dump metadata |
| 11 | **Links** | `https://api.recordedfuture.com/links` | `X-RFToken: <token>` | `SecOps`, `Threat Intel` | Relationship graph pivoting across threat actors, malware, and TTPs |
| 12 | **Collective Insights** | `https://api.recordedfuture.com/collective-insights/` | `X-RFToken: <token>` | `SecOps`, `Threat Intel` | Bidirectional SIEM/EDR detection telemetry ingestion and enriched search |
| 13 | **Fusion v3** | `https://api.recordedfuture.com/fusion/v3` | `X-RFToken: <token>` | Granted by RF Support as needed | Download/upload custom Fusion datasets (percent-encode `/` as `%2F`) |
| 14 | **Analyst Notes** | `https://api.recordedfuture.com/analyst-note` | `X-RFToken: <token>` | All modules | Search, publish, and retrieve Insikt/custom intelligence notes |
| 15 | **Risk History & Rules** | `https://api.recordedfuture.com/risk` | `X-RFToken: <token>` | All modules + `RiskApiRead` privilege | Historical risk score timelines and active risk rules |
| 16 | **Threat Maps** | `https://api.recordedfuture.com/threat` | `X-RFToken: <token>` | `Threat Intel` | Organizational threat actor & malware opportunity/intent scoring |
| 17 | **Malware Intelligence** | `https://api.recordedfuture.com/malware-intelligence` | `X-RFToken: <token>` | `SecOps`, `Threat Intel` | Natural-language and IOC-driven malware report retrieval |
| 18 | **Autonomous Threat Operations (ATO)** | `https://api.recordedfuture.com/autonomous-threat-operations` | `X-RFToken: <token>` | `Threat Intel` or `SecOps Intel` + ATO add-on | Autonomous hunting and threat response workflows |
| 19 | **STIX / TAXII 1.x & 2.1** | `https://api.recordedfuture.com/taxii` & `/taxii2` | TAXII 1.x: `X-RFToken` or Basic; TAXII 2.1: Basic `""` (empty user) + `<token>` password | Integration subscription | Read-only STIX 1.1.1 XML (280 collections) and STIX 2.1 JSON (5 collections/root, max 1,000/page) |
| 20 | **ASI & PFI (External)** | ASI: `https://api.securitytrails.com/v2`; PFI: `https://pfi.regemini.com/api/v1` | ASI: `apikey: <key>`; PFI: `X-RFToken: <token>` | `Attack Surface Intelligence` / `Payment Fraud Intelligence` (+ Magecart add-on) | External attack surface inventory & exposures; async payment/card/Magecart scanning |
| 21 | **Takedowns & RiskRecon (External)** | Takedowns: PhishFort Unified API; RiskRecon: `https://api.sandbox.riskrecon.com` | Takedowns: PhishFort Auth; RiskRecon: `Authorization: Bearer <token>` | `Brand Intelligence` / `RiskRecon` | Domain/brand takedown orchestration; third-party security posture scoring |

---

## 3. Rate Limiting, Retries & Resilience

### 3.1 Core Rate Limit
- **Quota**: **1,000 requests per 60 seconds** across Core Recorded Future APIs. Exceeding this quota returns HTTP `429 Too Many Requests`.
- **Single-Entity Watch List Constraint**: Watch List `POST /list/{listId}/entity/add` and `POST /list/{listId}/entity/remove` accept **1 entity per request** (no bulk mutation endpoint). Large delta syncs therefore rely heavily on connection pooling and rate-limit resilience.

### 3.2 Mandatory Client Resilience Rules (`soclens.client.RecordedFutureClient`)
1. **Persistent `requests.Session`**: Reuse TLS connections across Watch List loops, paginated searches, and risk list polls.
2. **`Retry-After` Header Compliance**: On HTTP `429`, inspect `Retry-After` (supporting both numeric seconds, e.g., `5`, and RFC HTTP-dates via `email.utils.parsedate_to_datetime`) and honor it (capped sensibly at `60.0s`).
3. **Exponential Backoff with Jitter**: When `Retry-After` is absent on `429`, or on transient `5xx` (`500`, `502`, `503`, `504`) and `requests.exceptions.RequestException` (connection/timeout), wait `min(backoff * 2^attempt, 60.0) * uniform(0.75, 1.25)`. Never sleep after the final failed attempt.
4. **ETag / `HEAD` Polling for Bulk Feeds**: Use `HEAD /v2/{type}/risklist` (`v2_stat_risklist`) and `HEAD /fusion/v3/files/{path}` before downloading multi-megabyte feeds.
5. **Typed Exceptions (No Silent `[]` / Cache Wipes)**: `_request()` raises `RecordedFutureRateLimitError`, `RecordedFutureAuthError`, or `RecordedFutureAPIError` instead of returning `None` or `[]`, preventing downstream modules (such as `soclens.sigma` cache refresh or `soclens.logos` brand sync delta) from corrupting state on transient failures.

---

## 4. HTTP 403 Permission Boundaries & Module Entitlements

### 4.1 Two Distinct `403 Forbidden` Failure Modes (`api-entitlements.md`)
Recorded Future returns two materially different `403 Forbidden` messages that `RecordedFutureClient` classifies into `RecordedFutureAuthError.permission_type`:

1. **`"Missing API privileges"` -> `permission_type="missing_api_privileges"`**
   - **Cause**: The API token does not include the required Recorded Future module license for that endpoint, or the token was generated before a recent license upgrade and must be regenerated.
   - **Action**: Verify module entitlements below; regenerate token or contact your Recorded Future account team.
2. **`"Missing Data permissions"` -> `permission_type="missing_data_permissions"`**
   - **Cause**: The token has the required module license, but the associated user or integration account lacks ACL access to the requested data group (e.g., restricted organization, Watch List, or Alert rule scope).
   - **Action**: Contact your Recorded Future organization administrator to adjust data-group permissions.

### 4.2 Module Entitlement Matrix

| Endpoint / Capability | Required Module(s) |
|---|---|
| Lists API (`/list/*`), Entity Match (`/entity-match/*`), Analyst Notes (`/analyst-note/*`) | All modules |
| Lists Entity Tags (`POST /list/{id}/entity/tags`) | All modules, **restricted to `type="company"` lists only** (non-`company` lists return `403`) |
| Connect v2 IP / Domain / URL lookup & risk lists | `SecOps Intelligence`, `Threat Intelligence`, or `Brand Intelligence` |
| Connect v2 Hash / Malware lookup & Hash risk lists | `SecOps Intelligence` or `Threat Intelligence` |
| Connect v2 Vulnerability lookup & risk lists | `Vulnerability Intelligence` |
| Connect v2 Company lookup (`by_domain`, risk rules) | `Third Party Intelligence` |
| SOAR v3, Detection Rules, Links, Collective Insights, Malware Intel, Sandbox v0 | `SecOps Intelligence` or `Threat Intelligence` |
| Playbook Alerts (`domain_abuse`, `malicious_sites`, `dark_web_brand`, `social_media_impersonation`) | `Brand Intelligence` (DRP / Brand module) |
| Playbook Alerts (`cyber_vulnerability`, `code_repo_leakage`, `third_party_risk`, `identity_novel_exposures`) | Corresponding module (`Vulnerability`, `SecOps`/`Threat`, `Third Party`, `Identity`) |
| Alerts v3 / v2 (`/alert/*`) | All modules **except** `SecOps Intelligence` |
| Cases (`/case/*`) | Alerts / Case Management |
| Risk History (`/risk/*`) | All modules + `"Risk History Read API Access"` integration + `RiskApiRead` privilege |
| Identity Intelligence (`/identity/*`) | `Identity Intelligence` |
| ASI / PFI / Takedowns | `Attack Surface Intelligence` / `Payment Fraud Intelligence` (+ Magecart) / `Brand Intelligence` |

---

## 5. Error Payload Schemas & `traceId` Persistence

### 5.1 All 8 Error Payload Schemas

| # | API Family | Error JSON Schema | `trace_id` Source | Notes |
|---|---|---|---|---|
| 1 | **Connect API v2 (`/v2/*`)** | `{"error": {"status": int, "message": str, "reason": str}, "traceId": str}` | `traceId` | Canonical nested `error` object |
| 2 | **Lists, Entity Match, Detection Rules, Identity** | `{"message": str, "status_code": int, "trace_id": uuid_str}` | `trace_id` | Flat root fields; snake_case `trace_id` |
| 3 | **Collective Insights** | `{"message": str, "traceId": str}` | `traceId` or `trace-id` header | Always check response headers |
| 4 | **Playbook Alerts & Cases** | `{"status": {"status_code": "Ok"\|"Error", "status_message": str}}` (or root `{"status_code", "status_message"}` on `PUT /playbook-alert/common/{id}`) | `trace-id` header (if present) | May return HTTP `200` with `status_code == "Error"` |
| 5 | **Sandbox v0 (`/api/v0/*`)** | `{"error": "<ERROR_CODE_STR>", "message": "<str>"}` | `trace-id` header (if present) | **`error` is a `str`, NOT a `dict`** |
| 6 | **Links (`/links/*`)** | `{"message": str, "status_code": int}` | `trace-id` header (if present) | No body `traceId` |
| 7 | **ASI (`api.securitytrails.com/v2`)** | `{"detail": [{"loc": [...], "msg": str, "type": str}]}` | `trace-id` header (if present) | HTTP `422` validation array |
| 8 | **PFI (`pfi.regemini.com/api/v1`)** | `{"message": str}` | `trace-id` header (if present) | Minimal root message |

### 5.2 Persistent `traceId` Diagnostics (`soclens.config.record_api_error`)
`RecordedFutureClient._log_api_error()` safely handles all 8 schemas, non-dict JSON, and plain-text/HTML error bodies (without failing on string `error` fields or `MagicMock` test objects), records `self.last_trace_id`, logs the structured error via Python `logging`, and appends a thread-safe JSONL entry to `<workspace>/logs/rf_api_errors.jsonl` containing:
`timestamp`, `endpoint`, `method`, `status_code`, `trace_id`, `message`, `reason`, and `category`.

---

## 6. Brand Image Watch List & Logo Monitoring Deep Dive

### 6.1 Brand Watch List Schema (`type: "brand"`)
- **Discovery & Creation**: Search via `POST /list/search` with `{"type": "brand"}`, or create via `POST /list/create` with `{"name": "<Brand Logos>", "type": "brand"}`.
- **Supported Entity Type**: Strictly **`Hash`** ONLY (`lists-supported-entities.md`). Submitting `InternetDomainName` or `URL` entities to a `brand` list is rejected.
- **Hash Format & Absence of Perceptual Hashes**:
  - Recorded Future identifies watched brand images using cryptographic hashes with prefix `hash:` (e.g., `hash:049ed15ef970bd12ce662cffa59f7d0e0b360d47fac556ac3d36f2788a2bc5a4`).
  - Canonical format is **64-character lowercase hex SHA-256** (`available-entity-types.md`). `hash-lookup.md` also recognizes `SHA-1` and `MD5` (used locally by `soclens` for `ignored_hashes.txt` suppression).
  - **No perceptual hash (`pHash`, `dHash`, `aHash`) API, schema, or field exists anywhere in Recorded Future APIs.**

### 6.2 Entity Add / Replace / Capacity Semantics
- **Auto-Resolution**: `Hash` is one of the 4 auto-resolved entity types (`IpAddress`, `InternetDomainName`, `Hash`, `CyberVulnerability`). `POST /list/{listId}/entity/add` accepts `{"entity": {"type": "Hash", "name": "<sha256>"}, "context": {...}}` (or `{"entity": {"id": "hash:<sha256>"}}`).
- **Context & Portal UI Rendering**:
  - `context.annotation` is the **only** context property rendered in the Recorded Future Portal UI.
  - Additional metadata keys (e.g., `domain`, `image_url`, `source`, `sync_time`) are stored and returned verbatim by `GET /list/{listId}/entities`, enabling deterministic domain-scoped delta syncs.
  - Re-adding an existing hash with a modified `context` **replaces the entire `context` object** (it does not merge keys); an identical or omitted `context` returns `{"result": "unchanged"}`.
- **Capacity & Rate Constraints**:
  - Default Watch List limit is **1,000 entities** (increasable up to 15,000 via RF Support; Meta Company Impersonation lists have a limit of 1).
  - `soclens.client` warns via `logger.warning` whenever a list reaches `>= 900` entities (`WATCHLIST_WARNING_THRESHOLD`) or `>= 1000` (`WATCHLIST_DEFAULT_LIMIT`).

### 6.3 Downstream Playbook Alerts & PNG Verification Loop
When Recorded Future crawlers detect a watched logo hash on suspicious infrastructure, **Brand Intelligence** generates Playbook Alerts in `domain_abuse` and `malicious_sites`:
- **Alert Search**: `POST /playbook-alert/search` with `category: ["domain_abuse", "malicious_sites"]` (note: search filter uses `"dark_web"` and `"socmed_impersonation"`, whereas detail paths map to `/dark_web_brand/{id}` and `/social_media_impersonation/{id}`).
- **Logo Hash Evidence Panels**:
  - `DrpAsset.ImageHash`: `{"type": "image_hash", "hash_id": "hash:..."}` ("A watched image (logo) hash matched on the attacker domain.")
  - `MaliciousSitesLogoHashChange`: `{"url": "...", "scan": "uuid:...", "hashes": ["hash:..."], "brands": [...], "type": "logo_hash_change"}`
  - Complementary ML logotype detections: `DrpAsset.Logotype` (`logotype_id`) and `MaliciousSitesLogotype` (bounding `region`).
- **PNG Screenshot Retrieval**: `GET /playbook-alert/{domain_abuse|malicious_sites}/{alert_id}/image/{image_id}` returns raw `image/png` bytes (`get_playbook_alert_image`).

---

## 7. SOC Toolkit Coverage Matrix

### 7.1 Tier 1 — Implemented & Hardened in M1 (`soclens.client` & `soclens.config`)

| RF API Family | Endpoints Wrapped | `RecordedFutureClient` Methods |
|---|---|---|
| **Lists & Watchlists** | `POST /list/search`, `POST /list/create`, `GET /list/{id}/info`, `GET /list/{id}/status`, `GET /list/{id}/entities`, `POST /list/{id}/entity/add`, `POST /list/{id}/entity/remove`, `GET /list/{id}/textEntries`, `GET /list/{id}/entitiesWithTags`, `POST /list/{id}/entity/tags` | `get_watchlists`, `create_list`, `get_list_info`, `get_list_status`, `get_watchlist_entities`, `add_entity`, `remove_entity`, `get_text_entries`, `get_entities_with_tags`, `replace_entity_tags` |
| **Detection Rules** | `POST /detection-rule/search`, `GET /detection-rule-relation/entity/list`, `GET /detection-rule-relation/entity/types` | `search_detection_rules` (fixed `updated.after` / `result` / `next_offset` / `offset`), `get_detection_rule_entities`, `get_detection_rule_entity_types` |
| **Entity Match** | `POST /entity-match/match`, `GET /entity-match/entity/{id}` | `entity_match`, `entity_lookup` |
| **SOAR v3** | `POST /soar/v3/enrichment`, `GET /soar/v3/triage/contexts`, `POST /soar/v3/triage/contexts/{context}` | `soar_enrich`, `soar_get_contexts`, `soar_triage` |
| **Connect API v2** | `GET /v2/{type}/{id}`, `GET /v2/{type}/fields`, `GET /v2/{type}/{id}/extension/{ext}`, `GET /v2/company/by_domain/{domain}`, `GET /v2/{type}/risklist`, `HEAD /v2/{type}/risklist`, `GET /v2/{type}/riskrules`, `GET /v2/{type}/search` | `v2_lookup` (percent-encoded `url:`), `v2_fields`, `v2_lookup_extension`, `v2_company_by_domain`, `v2_risklist`, `v2_stat_risklist`, `v2_riskrules`, `v2_search` |
| **Playbook Alerts** | `POST /playbook-alert/search`, `GET /common/{id}`, `POST /{cat}/{id}`, `PUT /common/{id}`, `GET /{cat}/{id}/image/{img}`, `GET /metadata/common` | `search_playbook_alerts`, `get_playbook_alert_preview`, `get_playbook_alert` (maps `dark_web`->`dark_web_brand`, `socmed_impersonation`->`social_media_impersonation`), `update_playbook_alert`, `get_playbook_alert_image`, `get_playbook_alert_metadata` |
| **Alerts v3 & v2** | `GET /alert/v3`, `GET /alert/v3/{id}`, `GET /alert/v3/hits`, `GET /alert/v3/image`, `GET /alert/v2/rule`, `POST /alert/v2/update` | `search_alerts_v3`, `get_alert_v3`, `get_alert_v3_hits`, `get_alert_v3_image`, `search_alert_rules`, `update_alerts_v2` |
| **Cases** | `POST /case/search`, `POST /case/lookup`, `POST /case/create`, `PUT /case/update`, `POST /case/assignees` | `search_cases`, `lookup_cases`, `create_case`, `update_case`, `get_case_eligible_assignees` |
| **Sandbox v0** | `GET /search`, `GET /samples`, `GET /samples/{id}`, `GET /samples/{id}/{overview.json,summary,reports/static}`, `GET /samples/{id}/{task}/report_triage.json`, `GET /samples/{id}/urlscan1/{report_urlscan.json,screenshot.png}`, `GET /yara*` | `sandbox_search`, `sandbox_list_samples`, `sandbox_get_sample`, `sandbox_get_overview`, `sandbox_get_summary`, `sandbox_get_static_report`, `sandbox_get_dynamic_report`, `sandbox_get_url_scan_report`, `sandbox_get_url_scan_screenshot`, `sandbox_list_yara_rules`, `sandbox_get_yara_rule` |

### 7.2 Tier 2 — Full-API Threat Research Engine & Toolkit Surfaces (`soclens.research`, `soclens.cli`, `soclens.tui`)

| RF API Family | Endpoints Wrapped | `RecordedFutureClient` Methods & Research Integration |
|---|---|---|
| **Links Graph** | `POST /links/search`, `GET /links/metadata/{entities,events,sections}` | `links_search`, `links_metadata_entities`, `links_metadata_events`, `links_metadata_sections` |
| **Analyst Notes** | `POST /analyst-note/search`, `POST /analyst-note/lookup/{id}`, `GET /analyst-note/attachment/{id}`, `GET /analyst-note/export/{html,pdf}/{id}` | `search_analyst_notes`, `lookup_analyst_note`, `get_analyst_note_attachment`, `export_analyst_note` |
| **Threat Maps & Actors** | `GET /threat/maps`, `POST /threat/map/{actors,malware}`, `POST /threat/map/{orgId}/{actors,malware}`, `POST /threat/actor/search`, `GET /threat/{actor,malware}/categories` | `get_threat_maps`, `get_threat_actor_map`, `search_threat_actors`, `get_threat_actor_categories`, `get_malware_threat_map`, `get_malware_categories` |
| **Malware Intelligence** | `POST /malware-intelligence/v1/{query,query_nl,query_iocs,reports}` | `malware_intel_query`, `malware_intel_query_nl`, `malware_intel_query_iocs`, `malware_intel_sandbox_reports` |
| **Risk History & Active Rules** | `POST /risk/history`, `POST /risk/active/rule` | `search_risk_history`, `get_active_company_risk_rule` |
| **Identity Intelligence** | `POST /identity/{detections,credentials/search,credentials/lookup,password/lookup,hostname/lookup,ip/lookup,incident/report,metadata/dump/search}` | `identity_detections`, `identity_search`, `identity_lookup`, `identity_password_lookup`, `identity_hostname_lookup`, `identity_ip_lookup`, `identity_incident_report`, `identity_dump_metadata` |
| **Collective Insights** | `POST /collective-insights/search`, `GET /collective-insights/exclusions/{org}/all` | `search_collective_insights`, `list_collective_insights_exclusions` |
| **Fusion v3** | `GET /fusion/v3/files/directory/{path}`, `HEAD /fusion/v3/files/{path}`, `GET /fusion/v3/files/{path}` | `fusion_list_directory`, `fusion_stat_file`, `fusion_get_file` (percent-encoded `%2F`) |
| **Autonomous Threat Ops (ATO)** | `GET /autonomous-threat-operations/v1/sources`, `POST /v1/{hunting,detection,prevention}/profiles/query`, `POST /v1/{detection,prevention}/profiles/{id}/{indicators,rules}` | `ato_list_sources`, `ato_query_profiles`, `ato_get_profile_indicators`, `ato_get_profile_rules` |
| **STIX / TAXII 2.1** | `GET /taxii2/`, `GET /taxii2/{root}/collections/`, `GET /taxii2/{root}/collections/{id}/objects/` | `taxii2_discover`, `taxii2_get_collections`, `taxii2_get_objects` (HTTP Basic `""` / `<token>`) |
| **Attack Surface Intel (ASI)** | `GET /projects`, `GET /projects/{id}/assets`, `POST /projects/{id}/assets/_search`, `GET /projects/{id}/assets/{asset}`, `GET /projects/{id}/{exposures,signatures}*` | `asi_list_projects`, `asi_find_assets`, `asi_search_assets`, `asi_read_asset`, `asi_list_asset_exposures`, `asi_list_exposures`, `asi_get_exposure_assets`, `asi_list_signatures`, `asi_get_signature` (`apikey` auth) |
| **Payment Fraud Intel (PFI)** | `GET /task/list`, `GET /task/{id}`, `PUT /pipeline/*`, `POST /file/{id}` | `pfi_list_tasks`, `pfi_get_task_status`, `pfi_query_pipeline`, `pfi_pickup_data` |
| **RiskRecon** | `GET /v1/toes*`, `GET /v1/toes/{id}/ratings`, `GET /v1/findings_paginated/{id}`, `GET /v1/hosts/{id}`, `GET /v1/portfolio_data_loss_events` | `riskrecon_list_toes`, `riskrecon_lookup_by_domain`, `riskrecon_lookup_by_cve`, `riskrecon_get_ratings`, `riskrecon_get_findings`, `riskrecon_get_hosts`, `riskrecon_get_breach_events` (`Bearer` auth) |

- **`soclens.research` Engine**: Auto-classifies and resolves arbitrary targets (IP, domain, hash, URL, CVE, malware, threat actor, MITRE ATT&CK, ASN, email, company, free text), fans out across licensed APIs in parallel, gracefully degrades `401`/`403` module entitlement gaps, deduplicates pivot entities, probes token capabilities (`probe_api_capabilities`), and exports Markdown/JSON dossiers.
- **Downstream Consuming Modules**: `soclens.logos` & `soclens.watchlist` (Watchlists + Brand Monitoring), `soclens.sigma` & `soclens.splunk` & `soclens.bundler` (Sigma rules, Splunk validation, air-gapped ZIPs), `soclens.cli` (`soclens research ...`), and `soclens.tui` (`Tab 7: Research` with pivot history and cross-tab jumps).

### 7.3 Tier 3 — Documented Peripheral Surfaces
- **STIX / TAXII 1.x (`/taxii`)**: Legacy XML service (prefer TAXII 2.1 `/taxii2` above).
- **Takedowns (PhishFort Unified API)**: Separate PhishFort credentialed workflow for active takedown submission/status outside read-only SOC research.
