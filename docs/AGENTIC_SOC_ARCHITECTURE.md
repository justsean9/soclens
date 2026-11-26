# SOCLens Read-Only Agentic SOC Architecture & Review

**Scope:** Review of existing SOCLens AI/Copilot integrations and Hermes agent action, permission, and audit patterns (`/home/ubuntu/.hermes/hermes-agent`), plus the design of SOCLens's strictly read-only, LLM-controlled agentic SOC investigation architecture (Milestones M1–M4).

---

## 1. Overview & Non-Negotiable Invariants

SOCLens (`v2.3.2`, Python 3.12+, Textual TUI) integrates Recorded Future, Splunk Core, Splunk Enterprise Security (ES), SentinelOne, and 16+ passive OSINT sources. Adding an LLM-controlled investigation layer introduces prompt-injection and runaway-automation risks if the agent can ever mutate security state, mint credentials, or execute arbitrary SPL side-effect commands. Accordingly, the architecture enforces five hard invariants:

1. **Zero Write / Mutation / Token-Minting Surface:** Only explicitly allowlisted read-only wrappers (29 tools across 5 source categories) exist in `ReadOnlyToolRegistry`. All 81 verified mutating, remediation, exclusion, adaptive-response, user/RBAC, job-control, and token/secret-retrieving methods are excluded and rejected at registration.
2. **Fail-Closed Policy Gating:** `evaluate_tool_permission()` denies by default on unknown tools, non-read-only specs, unknown modes, unknown source categories, `ask_only` mode, disabled `cross_search_enabled`, disabled per-source toggles, per-tool opt-outs (`disabled_tools`), and unsafe SPL queries.
3. **Mode Separation (`ask_only` vs `full_investigation`):**
   - `ask_only`: Answers strictly from the attached event context; 0 external tools advertised or callable.
   - `full_investigation`: Enables LLM-controlled cross-source read-only querying subject to AI Control Panel policy and bounded step/repeat guardrails.
4. **Secret-Redacted Persistent Audit Trail:** Every lifecycle event (`prompt`, `llm_response`, `tool_call`, `permission_check`, `tool_result`, `decision`, `blocked_action`, `policy_change`, `error`) is recursively redacted (`redact_sensitive_data`) before atomic JSONL persistence (`ai_audit.jsonl`).
5. **Offline & Strict Project Standards:** Zero new unbundled runtime dependencies outside `wheelhouse/` / `pyproject.toml`, Python 3.12+ PEP 604 typing, `ruff check .`, and strict `mypy soclens`.

---

## 2. Review of Existing SOCLens AI & Microsoft Copilot Integrations

SOCLens already ships a multi-provider synchronous AI client (`soclens/llm.py`, `soclens/copilot.py`, `soclens/config.py`, `soclens/settings.py`) and multi-window TUI chat pane (`soclens/tui/screens/llm.py`).

### 2.1 Supported Provider Matrix (`SUPPORTED_LLM_PROVIDERS`)

| Provider | Implementation | Endpoints & Transport | Auth Mode | Streaming | Conversation Handling |
|---|---|---|---|---|---|
| `ollama` | `LocalLLMClient` (`soclens/llm.py`) | `GET /api/tags`, `POST /api/chat` | None (local) | NDJSON (`stream: true`) | Client-side `messages[]` list |
| `openai` | `LocalLLMClient` (`soclens/llm.py`) | `GET /v1/models`, `POST /v1/chat/completions` | Optional `Authorization: Bearer` | SSE (`data: {...}`, `[DONE]`) | Client-side `messages[]` list |
| `gemini` | `LocalLLMClient` (`soclens/llm.py`) | `GET /v1beta/models`, `POST /v1beta/models/{m}:generateContent`, `:streamGenerateContent?alt=sse` | `x-goog-api-key` (`GEMINI_API_KEY` / `GOOGLE_API_KEY` / `gemini_api_key`) | SSE (`alt=sse`) | Client-side `contents[]` (`user`/`model` + `functionCall`/`functionResponse`) |
| `m365_copilot` | `M365CopilotTransport` (`soclens/copilot.py`) | Graph Beta `/copilot/conversations`, `chat` / `chatOverStream` | `CopilotTokenResolver` (`token` or `az_cli`) | Real SSE (`chatOverStream`) | Server-side `conversation_id`; single-turn flattening in `LocalLLMClient.chat()` |
| `copilot_studio` | `CopilotStudioD2ETransport` (`soclens/copilot.py`) | Power Platform D2E `POST /conversations`, `POST /conversations/{id}` | `CopilotTokenResolver` (`token` or `az_cli`) | Real SSE + Adaptive Cards & citations | Server-side `conversation_id`; single-turn flattening |
| `copilot_directline` | `CopilotDirectLineTransport` (`soclens/copilot.py`) | Direct Line v3 `/tokens/generate`, `/conversations/{id}/activities` (auto-routes D2E URLs) | Direct Line secret or Token Endpoint | Simulated via watermark polling | Server-side `conversation_id`, `_dl_token`, `_watermark` |
| `security_copilot` | `SecurityCopilotTransport` (`soclens/copilot.py`) | Graph Beta `workspaces/{ws}/sessions` -> `prompts` -> `evaluations` | `CopilotTokenResolver` (`token` or `az_cli`) | Simulated via evaluation polling | Server-side `session_id`; single-turn flattening |

### 2.2 Strengths & Architectural Gaps

- **Strengths:**
  - `ConfiguredSession` inheritance for corporate proxies and custom CA bundles (`verify_ssl`), retry/backoff on transient `429`/`5xx`, and cooperative `threading.Event` cancellation (`stop_event`).
  - `CopilotTokenResolver` (`soclens/copilot.py`) supports both static Bearer tokens (with local JWT `exp` pre-flight validation via `inspect_jwt_expiry`) and live `az account get-access-token` caching.
  - `SECRET_MANAGED_SETTING_KEYS` (`soclens/settings.py`) encrypts `rf_llm_api_key`, `gemini_api_key`, `ms_copilot_bearer_token`, `ms_copilot_token_endpoint`, and `ms_copilot_directline_secret` at rest using AES-256-GCM (`soclens/settings_crypto.py`) and supports enterprise secret stores (`akeyless`, `bitwarden`, `hashicorp_vault`, `onepassword_connect`, `secret_server`).
  - `_ChatSession` (`soclens/tui/screens/llm.py`) cleanly isolates concurrent chat tabs in the TUI.

- **Gaps Addressed by This Architecture:**
  1. **No tool-calling or agent loop:** Neither `LocalLLMClient` nor any Copilot transport passes `tools` schemas, parses tool requests, or executes multi-step cross-source investigations.
  2. **Transport asymmetry:** `openai` and `ollama` accept structured `messages[]` (and OpenAI-style `tools` payloads), whereas all 4 Copilot transports expose text-only `send_turn(turn_text, conversation_id=...)` methods (`soclens/llm.py`).
  3. **No per-event AI tracking or persistence:** Alert panes (`RFIntelPane`, `SentinelOnePane`, `SplunkESPane`) lack attached per-event AI panels, right-click "Ask about event" vs "Full investigation" actions, and background triage queuing over `AlertCacheStore`.
  4. **No governance controls or audit log:** `AppLogStore` only logs coarse chat UI messages in memory; there is no AI Control Panel policy store or persistent, redacted JSONL audit trail.

---

## 3. Review of Hermes Agent Action, Permission & Audit Patterns

Inspection of `/home/ubuntu/.hermes/hermes-agent` yielded four battle-tested governance patterns adapted directly into SOCLens:

| Hermes Pattern & Source | Behavior in Hermes | SOCLens Adaptation |
|---|---|---|
| **Single-Source Registry & Dual Gate** (`tools/registry.py`, `model_tools.py`, `tools/hosted_tool_policy.py`) | `ToolRegistry` normalizes dispatch; `_select_tool_names()` subtracts `disabled_toolsets` **last** so opt-outs always win; `HOSTED_TOOL_ALLOWLIST` is enforced at both schema generation and execution. | `ReadOnlyToolRegistry` (`soclens/agent_tools.py`) registers only 29 `ReadOnlyToolSpec(readonly=True)` wrappers, rejects `FORBIDDEN_MUTATING_METHOD_NAMES`, filters `openai_schemas()`, and re-checks `evaluate_tool_permission()` on every `execute()`. |
| **Fail-Safe Side-Effect Classification & Pre-Bypass Floors** (`agent/tool_result_classification.py`, `tools/approval_floors.py`, `tools/approval.py`) | `tool_may_have_side_effect()` defaults unknown tools to unsafe (`True`); `_tool_is_read_only()` fails safe to `False`; `_match_user_deny_rule()` & `_hardline_block_result()` run **before** any bypass mode. | `evaluate_tool_permission()` (`soclens/agent_policy.py`) enforces `readonly_enforced` -> `ask_only_no_tools` / `invalid_mode` -> `cross_search_disabled` -> `source_disabled:{cat}` -> `tool_disabled` -> `spl_readonly_violation` in strict order. |
| **Bounded Tool Round & Stall Guardrails** (`agent/turn_tool_round.py`, `agent/tool_guardrails.py`) | `run_tool_round()` validates, **persists before execute**, tracks `ToolCallSignature` SHA-256 hashes (`exact_failure_counts`, `_identical_streak`, period-4 cycle detection), and enforces iteration/time caps. | `SocAgentOrchestrator` (M2) bounds runs by `max_tool_steps` (default `8`) and `max_identical_tool_calls` (default `2`), audits `tool_call` + `permission_check` **before** handler execution, and halts repeated/cycling calls. |
| **Lifecycle Hooks & Recursive Redaction** (`hermes_cli/hooks.py`, `agent/trajectory.py`, `agent/redact.py`, `hermes_cli/dashboard_auth/audit.py`) | Structured `pre_tool_call` / `post_tool_call` events; `redact_trajectory_value()` recursively strips Bearer tokens, JWTs, URL params, and secret keys while excluding metadata like `token_count` before JSONL write. | `AuditLogStore` + `redact_sensitive_data()` (`soclens/agent_audit.py`) recursively redacts headers (`Authorization`, `X-RFToken`, `x-api-key`), Bearer/ApiToken schemes, JWTs, query params, vendor prefixes (`sk-`, `ghp_`, `AKIA`), and secret keys while preserving `max_tokens` and SOC IOCs/CVEs. |

---

## 4. SOCLens Read-Only Agentic Architecture (M1–M4)

```
+-----------------------------------------------------------------------------+
| M4: Textual TUI (SocLensApp, EventAIPanelWidget, AskEventAIModal,           |
|     AIControlPanelWidget, AuditLogViewWidget)                               |
+-----------------------------+-----------------------------+-----------------+
                              |                             |
                              v                             v
+----------------------------------------+   +--------------------------------+
| M3: Event Tracking & Background Queue  |   | M1: Governance & Policy        |
| (soclens/event_tracker.py)             |   | (soclens/agent_policy.py)      |
| - Canonical event_key across 4 streams |   | - AIPolicyConfig / Store       |
| - EventAIStore (event_ai_panels.json)  |   | - evaluate_tool_permission()   |
| - BackgroundTriageQueue                |   +---------------+----------------+
+-----------------------------+----------+                   |
                              |                              v
                              v               +-------------------------------+
+----------------------------------------+    | M1: Audit & Redaction         |
| M2: Multi-Provider Orchestrator        |--->| (soclens/agent_audit.py)      |
| (soclens/agent_orchestrator.py)        |    | - redact_sensitive_data()     |
| - Native tools (openai/ollama)         |    | - AuditLogStore (JSONL)       |
| - Structured <tool_call> (4 Copilots)  |    +---------------+---------------+
| - ask_only vs full_investigation       |                    ^
+-----------------------------+----------+                    |
                              |                               |
                              v                               |
+-------------------------------------------------------------+---------------+
| M1: Strictly Read-Only Tool Registry (soclens/agent_tools.py)               |
| - ReadOnlyToolRegistry + validate_readonly_spl() lexer                      |
| - 29 allowlisted wrappers: Splunk (3), Splunk ES (7), SentinelOne (7),      |
|   Recorded Future (8), Watchlists & OSINT (4)                               |
+-----------------------------------------------------------------------------+
```

### 4.1 Layer Responsibilities

- **M1 — Governance, Policy, Audit & Read-Only Tools:**
  - `soclens/agent_policy.py`: `AIPolicyConfig` (safe default `background_triage_enabled=False`, `cross_search_enabled=True`, 5 source toggles, `disabled_tools`, `max_tool_steps=8`, `max_identical_tool_calls=2`), atomic `AIPolicyStore` (`<workspace_dir>/.soclens_cache/ai_policy.json`), and fail-closed `evaluate_tool_permission()`.
  - `soclens/agent_audit.py`: `AuditEntry` (covering all 9 `AuditEventType` / `VALID_AUDIT_EVENT_TYPES` literals: `prompt`, `llm_response`, `tool_call`, `permission_check`, `tool_result`, `decision`, `blocked_action`, `policy_change`, `error`), `redact_sensitive_data()`, and thread-safe JSONL `AuditLogStore` (`<workspace_dir>/.soclens_cache/ai_audit.jsonl`) with `query(event_key=..., run_id=..., event_type=..., blocked_only=..., limit=...)`.
  - `soclens/agent_tools.py`: `FORBIDDEN_MUTATING_METHOD_NAMES` (81 excluded write/remediation/token methods), deterministic stateful SPL lexer `validate_readonly_spl()`, `ReadOnlyToolSpec`, `ReadOnlyToolRegistry`, and `build_default_readonly_registry()` supporting both direct client instances and lazy callable factories across all 29 read-only tools.
- **M2 — Multi-Provider Agent Orchestrator (`soclens/agent_orchestrator.py`):**
  - `SocAgentOrchestrator` drives `ask_only` (0 tools), `full_investigation` (event investigation), and `chat()` (`ChatTurnResult` for freeform analyst conversations under `freeform_chat::<session_id>`) across all 7 `SUPPORTED_LLM_PROVIDERS`: native OpenAI/Ollama/Gemini `tools`/`tool_calls` (`functionDeclarations`/`functionCall`) when supported, and a strict structured `<tool_call>{"name": ..., "arguments": {...}}</tool_call>` protocol for `m365_copilot`, `copilot_studio`, `copilot_directline`, `security_copilot`, and fallback local models.
- **M3 — Unique Event Tracking & Background Triage (`soclens/event_tracker.py`):**
  - Normalizes events across `rf_alert`, `rf_playbook`, `s1_threat`, `s1_cloud_alert`, and `splunk_es` into canonical composite `event_key` strings, persists `EventAIPanelEntry` attachments (`<workspace_dir>/.soclens_cache/event_ai_panels.json`), and diffs `AlertCacheStore` / preloader updates to enqueue unseen events for async background triage only when `background_triage_enabled` is `True`.
- **M4 — Textual TUI & CLI Integration (`soclens/tui/ai_widgets.py`, `soclens/tui/screens/llm.py`, `soclens/cli.py`):**
  - Attaches `EventAIPanelWidget` to `RFIntelPane`, `SentinelOnePane`, and `SplunkESPane` detail views with right-click & toolbar triggers for `ask_only` (`AskEventAIModal`) and `full_investigation`, plus `AIControlPanelWidget` and `AuditLogViewWidget` sub-tabs in `LocalLLMPane` (`tab-llm`).
  - Freeform Chat in `LocalLLMPane` (`template="freeform"`) routes through `SocAgentOrchestrator.chat()` with a per-session `Tools: ON / OFF` toggle (`#llm-tools-toggle-btn`), live transcript tool execution/block traces, AI Control Panel enforcement, and full JSONL audit logging. CLI `soclens llm chat --tools` exposes the same read-only tool orchestration in headless/terminal workflows.

### 4.2 Read-Only Tool Surface (29 Tools)

| Source Category (`AIPolicyConfig` Toggle) | Registered Tools |
|---|---|
| `splunk_search` (`splunk_search_enabled`) | `splunk_search` (SPL lexer-gated), `splunk_list_indexes`, `splunk_list_saved_searches` |
| `splunk_es` (`splunk_es_enabled`) | `splunk_es_list_notables`, `splunk_es_get_finding`, `splunk_es_list_investigations`, `splunk_es_list_risk_events`, `splunk_es_lookup_asset`, `splunk_es_lookup_identity`, `splunk_es_query_threat_intel` |
| `sentinelone` (`sentinelone_enabled`) | `s1_list_threats`, `s1_get_threat_timeline`, `s1_list_cloud_alerts`, `s1_list_agents`, `s1_get_agent`, `s1_list_activities`, `s1_dv_query` |
| `recorded_future` (`recorded_future_enabled`) | `rf_search_alerts`, `rf_get_alert`, `rf_search_playbook_alerts`, `rf_get_playbook_alert`, `rf_lookup_ioc_or_cve`, `rf_search_analyst_notes`, `rf_soar_enrich`, `rf_links_search` |
| `watchlists_osint` (`watchlists_osint_enabled`) | `rf_get_watchlists`, `rf_get_watchlist_entities`, `osint_enrich_target`, `unified_research_target` |

---

## 5. Threat Model & Security Invariants

1. **Prompt Injection via Alert Payloads (`_raw`, logs, analyst notes):**
   - Untrusted strings inside alert JSON could instruct the LLM to run `mitigate_threat`, `update_notable`, `add_entity`, or `| outputlookup`.
   - *Mitigation:* Mutating methods are never registered in `ReadOnlyToolRegistry`; `ReadOnlyToolRegistry.register()` rejects any spec with `readonly != True` or a name/method in `FORBIDDEN_MUTATING_METHOD_NAMES`; `evaluate_tool_permission()` denies unregistered tools with `readonly_enforced`.
2. **SPL Command Smuggling & Parser Differentials:**
   - Attackers may try case-mixing (`| OutputLookup`), leading pipes (`| delete`), nested subsearches (`[ search ... | collect ]` or `[| outputcsv ]`), triple-backtick comments (` ```c``` | sendemail`), backtick macros (`` `write_macro` ``), semicolons, or unclosed quotes/brackets.
   - *Mitigation:* `validate_readonly_spl()` runs a deterministic stateful lexer (tracking `"..."` with `\` escapes, `'...'`, `` ```...``` `` comments, `[...]` bracket depth, and `|` pipe segments) and is invoked in both `evaluate_tool_permission()` and `ReadOnlyToolRegistry.execute()` as well as inside the `splunk_search` handler. Literal strings inside quotes (e.g., `index=main "outputlookup"`) remain allowed without false positives.
3. **Credential / Token Leakage into Audit Logs:**
   - API keys, `Authorization: Bearer`, `X-RFToken`, `ApiToken`, Direct Line secrets, JWTs, or URL credentials could appear in prompts, errors, or tool payloads.
   - *Mitigation:* `AuditLogStore.append()` runs `redact_sensitive_data()` recursively over `payload`, `reason`, `event_key`, and `tool_name` prior to disk serialization while keeping operational metadata (`max_tokens`, `token_count`) and SOC indicators (IPs, domains, hashes, CVEs) intact.
4. **Unconfigured Integration Crashes:**
   - `SplunkClient` and `SplunkESClient` raise `ConfigurationError` on instantiation if unconfigured, while `RecordedFutureClient` / `SentinelOneClient` expose `.api_token` / `.has_auth`.
   - *Mitigation:* `build_default_readonly_registry()` supports lazy factories and catches `ConfigurationError`, returning structured `{"ok": False, "error": ...}` envelopes instead of crashing investigations.

---

## 6. Standards & Offline Packaging

- **Runtime:** Python 3.12+ (`from __future__ import annotations`, PEP 604 union types).
- **Static Analysis:** `.venv/bin/ruff check .` (`E, F, W, I, UP`, `line-length = 100`) and `.venv/bin/mypy soclens` (strict typing).
- **Dependencies:** Zero additions to `pyproject.toml` or `wheelhouse/`; implemented exclusively with Python stdlib and existing SOCLens modules.
