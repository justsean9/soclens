"""Unit and governance tests for SOCLens Milestone M1 (agent_governance)."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from soclens import splunk_es, splunk_rf_enrichment
from soclens.agent_audit import AuditEntry, AuditLogStore, redact_sensitive_data
from soclens.agent_policy import (
    SOURCE_CATEGORY_OSINT,
    SOURCE_CATEGORY_RF,
    SOURCE_CATEGORY_S1,
    SOURCE_CATEGORY_SPLUNK,
    SOURCE_CATEGORY_SPLUNK_ES,
    AIPolicyConfig,
    AIPolicyStore,
    evaluate_tool_permission,
)
from soclens.agent_tools import (
    FORBIDDEN_MUTATING_METHOD_NAMES,
    READONLY_TOOL_NAMES,
    ReadOnlyToolRegistry,
    ReadOnlyToolSpec,
    _opt_str_list,
    _opt_str_list_or_str,
    build_default_readonly_registry,
    validate_readonly_spl,
)
from soclens.client import RecordedFutureClient
from soclens.config import ConfigurationError
from soclens.osint import OSINTSectionOutcome
from soclens.sentinelone import SentinelOneClient
from soclens.splunk import SplunkClient
from soclens.splunk_es import SplunkESClient
from soclens.splunk_rf_enrichment import SplunkRFEnricher


def _full_enabled_policy(**overrides: Any) -> AIPolicyConfig:
    return AIPolicyConfig(**overrides)


# ---------------------------------------------------------------------------
# 1. Policy Persistence, Defaults & Fail-Closed Permission Gating
# ---------------------------------------------------------------------------


def test_policy_defaults_and_atomic_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    default_store = AIPolicyStore()
    assert default_store.path == (tmp_path.resolve() / ".soclens_cache" / "ai_policy.json")

    loaded_default = default_store.load()
    assert loaded_default.background_triage_enabled is False
    assert loaded_default.cross_search_enabled is True
    assert loaded_default.splunk_search_enabled is True
    assert loaded_default.splunk_es_enabled is True
    assert loaded_default.sentinelone_enabled is True
    assert loaded_default.recorded_future_enabled is True
    assert loaded_default.watchlists_osint_enabled is True
    assert loaded_default.disabled_tools == []
    assert loaded_default.max_tool_steps == 50
    assert loaded_default.max_identical_tool_calls == 2
    assert loaded_default.max_same_tool_failures == 10
    assert loaded_default.ai_kill_switch_active is False
    assert loaded_default.kill_switch_visible is True
    assert loaded_default.kill_switch_label == "KILL AI"
    assert loaded_default.kill_switch_hotkey == "f12"

    updated = default_store.update(
        background_triage_enabled=True,
        splunk_search_enabled=False,
        disabled_tools=[" rf_links_search ", "rf_links_search", "s1_dv_query"],
        max_tool_steps=12,
        max_identical_tool_calls=4,
    )
    assert updated.background_triage_enabled is True
    assert updated.splunk_search_enabled is False
    assert updated.disabled_tools == ["rf_links_search", "s1_dv_query"]
    assert updated.max_tool_steps == 12
    assert updated.max_identical_tool_calls == 4

    # Simulated restart: fresh store reads persisted values
    restarted_store = AIPolicyStore(default_store.path)
    reloaded = restarted_store.load()
    assert reloaded == updated


def test_policy_resilience_clamping_and_unknown_field_rejection(tmp_path: Path) -> None:
    policy_path = tmp_path / "ai_policy.json"
    store = AIPolicyStore(policy_path)

    # Corrupt JSON -> defaults
    policy_path.write_text("{not valid json", encoding="utf-8")
    assert store.load() == AIPolicyConfig()

    # Non-dict JSON -> defaults
    policy_path.write_text('["unexpected", "list"]', encoding="utf-8")
    assert store.load() == AIPolicyConfig()

    # Bad field types + out-of-range ints + extra keys -> safe fallback & clamping
    policy_path.write_text(
        json.dumps(
            {
                "background_triage_enabled": "yes",
                "cross_search_enabled": "invalid-bool",
                "max_tool_steps": 999,
                "max_identical_tool_calls": 0,
                "unknown_future_field": "ignored",
            }
        ),
        encoding="utf-8",
    )
    loaded = store.load()
    assert loaded.background_triage_enabled is True
    assert loaded.cross_search_enabled is True
    assert loaded.max_tool_steps == 500
    assert loaded.max_identical_tool_calls == 1

    with pytest.raises(ValueError, match="Unknown AI policy field"):
        store.update(nonexistent_toggle=True)


def test_evaluate_tool_permission_fail_closed_rules() -> None:
    policy = _full_enabled_policy()

    # Rule 1: is_readonly=False or unregistered tool -> readonly_enforced
    d_mut = evaluate_tool_permission(
        "splunk_search",
        SOURCE_CATEGORY_SPLUNK,
        False,
        "full_investigation",
        policy,
    )
    assert d_mut.allowed is False
    assert d_mut.rule == "readonly_enforced"

    d_unknown = evaluate_tool_permission(
        "mitigate_threat",
        SOURCE_CATEGORY_S1,
        True,
        "full_investigation",
        policy,
    )
    assert d_unknown.allowed is False
    assert d_unknown.rule == "readonly_enforced"

    # Rule 2: ask_only and invalid mode
    d_ask = evaluate_tool_permission(
        "splunk_search",
        SOURCE_CATEGORY_SPLUNK,
        True,
        "ask_only",
        policy,
    )
    assert d_ask.allowed is False
    assert d_ask.rule == "ask_only_no_tools"

    d_bad_mode = evaluate_tool_permission(
        "splunk_search",
        SOURCE_CATEGORY_SPLUNK,
        True,
        "autonomous_yolo",
        policy,
    )
    assert d_bad_mode.allowed is False
    assert d_bad_mode.rule == "invalid_mode"

    # Rule 3: cross_search_enabled=False
    d_cross = evaluate_tool_permission(
        "splunk_search",
        SOURCE_CATEGORY_SPLUNK,
        True,
        "full_investigation",
        _full_enabled_policy(cross_search_enabled=False),
    )
    assert d_cross.allowed is False
    assert d_cross.rule == "cross_search_disabled"

    # Rule 4: per-source category toggles + unknown category
    for cat, attr in [
        (SOURCE_CATEGORY_SPLUNK, "splunk_search_enabled"),
        (SOURCE_CATEGORY_SPLUNK_ES, "splunk_es_enabled"),
        (SOURCE_CATEGORY_S1, "sentinelone_enabled"),
        (SOURCE_CATEGORY_RF, "recorded_future_enabled"),
        (SOURCE_CATEGORY_OSINT, "watchlists_osint_enabled"),
    ]:
        tool = {
            SOURCE_CATEGORY_SPLUNK: "splunk_search",
            SOURCE_CATEGORY_SPLUNK_ES: "splunk_es_list_notables",
            SOURCE_CATEGORY_S1: "s1_list_threats",
            SOURCE_CATEGORY_RF: "rf_search_alerts",
            SOURCE_CATEGORY_OSINT: "osint_enrich_target",
        }[cat]
        d_src = evaluate_tool_permission(
            tool,
            cat,
            True,
            "full_investigation",
            _full_enabled_policy(**{attr: False}),
        )
        assert d_src.allowed is False
        assert d_src.rule == f"source_disabled:{cat}"

    d_bad_cat = evaluate_tool_permission(
        "splunk_search",
        "unknown_category",
        True,
        "full_investigation",
        policy,
    )
    assert d_bad_cat.allowed is False
    assert d_bad_cat.rule == "source_disabled:unknown_category"

    # Rule 5: per-tool opt-out
    d_tool = evaluate_tool_permission(
        "splunk_search",
        SOURCE_CATEGORY_SPLUNK,
        True,
        "full_investigation",
        _full_enabled_policy(disabled_tools=["splunk_search"]),
    )
    assert d_tool.allowed is False
    assert d_tool.rule == "tool_disabled"

    # Rule 6: SPL validation on splunk_search when arguments include "spl"
    d_bad_spl = evaluate_tool_permission(
        "splunk_search",
        SOURCE_CATEGORY_SPLUNK,
        True,
        "full_investigation",
        policy,
        arguments={"spl": "index=main | outputlookup evil.csv"},
    )
    assert d_bad_spl.allowed is False
    assert d_bad_spl.rule == "spl_readonly_violation"

    # Allowed when valid
    d_ok = evaluate_tool_permission(
        "splunk_search",
        SOURCE_CATEGORY_SPLUNK,
        True,
        "full_investigation",
        policy,
        arguments={"spl": "index=main error | stats count by host"},
    )
    assert d_ok.allowed is True
    assert d_ok.rule == "allowed"


# ---------------------------------------------------------------------------
# 2. Redaction & Persistent AuditLogStore
# ---------------------------------------------------------------------------


def test_redact_sensitive_data_masks_secrets_and_preserves_ioc_metadata() -> None:
    sample = {
        "headers": {
            "Authorization": "Bearer super.secret.token-123",
            "X-RFToken": "rf-secret-999",
            "x-api-key": "openai-abc",
            "Content-Type": "application/json",
        },
        "config": {
            "api_key": "my-api-key-val",
            "token": "raw-token-val",
            "secret": "top-secret-val",
            "password": "hunter2-password",
            "client_secret": "cs-xyz-123",
            "directline_secret": "dl-secret-456",
            "max_tokens": 512,
            "token_count": 120,
            "empty_token": "",
            "unset_secret": None,
        },
        "nested_list": [
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.sig12345",
            "https://alice:mypassword@splunk.local:8089/search?api_key=abc&token=def&sig=ghi",
            "vendor key sk-proj-1234567890abcdef and ghp_abcdefghij123456 and AKIAIOSFODNN7EXAMPLE",
            '{"client_secret": "inline-cs", "max_tokens": 256}',
        ],
        "ioc_context": {
            "ip": "203.0.113.42",
            "cve": "CVE-2024-3094",
            "domain": "malicious.example.com",
            "hash": "44d88612fea8a8f36de82e1278abb02f",
        },
    }

    redacted = redact_sensitive_data(sample)
    serialized = json.dumps(redacted)

    for secret in (
        "super.secret.token-123",
        "rf-secret-999",
        "openai-abc",
        "my-api-key-val",
        "raw-token-val",
        "top-secret-val",
        "hunter2-password",
        "cs-xyz-123",
        "dl-secret-456",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "mypassword",
        "sk-proj-1234567890abcdef",
        "ghp_abcdefghij123456",
        "AKIAIOSFODNN7EXAMPLE",
        "inline-cs",
    ):
        assert secret not in serialized

    assert redacted["config"]["max_tokens"] == 512
    assert redacted["config"]["token_count"] == 120
    assert redacted["config"]["empty_token"] == ""
    assert redacted["config"]["unset_secret"] is None
    assert redacted["headers"]["Content-Type"] == "application/json"
    assert '"max_tokens": 256' in redacted["nested_list"][3]
    assert redacted["ioc_context"] == sample["ioc_context"]


def test_audit_log_store_redacts_persists_across_restarts_and_survives_corruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    store = AuditLogStore()
    assert store.path == (tmp_path.resolve() / ".soclens_cache" / "ai_audit.jsonl")

    e1 = store.append(
        AuditEntry(
            entry_id="",
            timestamp="",
            run_id="run-1",
            event_key="rf_alert::a1",
            provider="openai",
            mode="full_investigation",
            event_type="prompt",
            reason="Authorization: Bearer raw-secret-token-xyz",
            payload={"prompt": "Check 1.2.3.4", "api_key": "secret-key-99"},
        )
    )
    assert e1.entry_id
    assert e1.timestamp.endswith("Z")

    store.append(
        AuditEntry(
            entry_id="id-2",
            timestamp="2026-11-25T21:00:00Z",
            run_id="run-1",
            event_key="rf_alert::a1",
            provider="openai",
            mode="ask_only",
            event_type="blocked_action",
            tool_name="splunk_search",
            allowed=False,
            reason="External investigation tools are disabled in ask_only mode.",
            payload={"spl": "index=main"},
        )
    )
    store.append(
        AuditEntry(
            entry_id="id-3",
            timestamp="2026-11-25T21:01:00Z",
            run_id="run-2",
            event_key="s1_threat::t9",
            provider="m365_copilot",
            mode="full_investigation",
            event_type="decision",
            allowed=True,
            reason="Benign telemetry",
        )
    )

    raw_disk = store.path.read_text(encoding="utf-8")
    assert "raw-secret-token-xyz" not in raw_disk
    assert "secret-key-99" not in raw_disk
    assert "1.2.3.4" in raw_disk

    # Inject a corrupted JSONL line to verify resilience
    with store.path.open("a", encoding="utf-8") as fh:
        fh.write("{corrupt truncated line\n")

    restarted = AuditLogStore(store.path)
    all_entries = restarted.query()
    assert len(all_entries) == 3
    assert len(restarted.query(event_key="rf_alert::a1")) == 2
    assert len(restarted.query(run_id="run-2")) == 1
    assert len(restarted.query(event_type="decision")) == 1
    blocked = restarted.query(blocked_only=True)
    assert len(blocked) == 1
    assert blocked[0].tool_name == "splunk_search"
    assert len(restarted.query(limit=2)) == 2
    assert restarted.query(limit=0) == []


def test_audit_log_store_thread_safe_concurrent_appends(tmp_path: Path) -> None:
    store = AuditLogStore(tmp_path / "ai_audit.jsonl")

    def _write_one(idx: int) -> None:
        store.append(
            AuditEntry(
                entry_id="",
                timestamp="",
                run_id=f"run-{idx % 4}",
                event_key=f"splunk_es::default::ev-{idx}",
                provider="ollama",
                mode="full_investigation",
                event_type="tool_result",
                tool_name="splunk_es_list_notables",
                allowed=True,
                payload={"idx": idx},
            )
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_write_one, range(60)))

    entries = store.query(limit=100)
    assert len(entries) == 60


# ---------------------------------------------------------------------------
# 3. SPL Lexer Validator (Valid + Adversarial Bypass Attempts)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "spl",
    [
        "index=main error | stats count by host",
        "search index=wineventlog EventCode=4688 | table _time, host, user",
        "| tstats count where index=_internal by sourcetype",
        "| inputlookup asset_lookup_by_str | head 20",
        'index=main "outputlookup"',
        'index=main msg="pipe | delete | sendemail"',
        r'search raw="foo \" | outputlookup bar.csv" | stats count',
        'index=main [ search index=auth status="failed" | stats count by src_ip ]',
        "index=main [| inputlookup trusted_hosts.csv | fields host ] | head 10",
        'index=main action=delete | where status="update" | stats count',
        "index=main | eval 'my field'=1 | stats count",
        "index=main ```harmless analyst note``` | stats count by src_ip",
        'index=main | eval x="a\'b" | stats count',
        "index=main | eval 'a\"b'=1 | stats count",
        "index=main | eval x='a\"b' | eval y=\"c'd\" | stats count",
        'index=main | eval x="a|b" | stats count',
        "index=main [search index=auth | stats count by src_ip] | head 10",
        "index=main [search index=auth | fields src_ip] status=failed | stats count",
        'index=main ([search index=auth | fields user] OR user="admin") | stats count',
        "index=main | where host IN ([search index=assets | fields host]) | stats count",
        "index=main | eval x = [search index=auth | stats count | return $count] + 1",
    ],
)
def test_validate_readonly_spl_allows_valid_queries(spl: str) -> None:
    ok, reason = validate_readonly_spl(spl)
    assert ok is True, f"Expected valid SPL to pass, got: {reason}"


@pytest.mark.parametrize(
    "spl",
    [
        "",
        "   \n\t ",
        "index=main\x00 | stats count",
        "index=main | outputlookup evil.csv",
        "index=main | OUTPUTCSV out.csv",
        "index=main\n  |\tOutputLookup foo.csv",
        "| collect index=summary",
        "| tscollect namespace=x",
        "| mcollect index=metrics",
        "| meventcollect index=metrics",
        '| sendemail to="attacker@example.com"',
        "| sendalert my_alert",
        "index=main | sendmodalert foo=1",
        "| run my_script",
        "| script python evil",
        "| delete",
        "delete index=main",
        '| map search="outputlookup evil.csv"',
        "| dbxoutput connection=prod",
        "| dump basefilename=exfil",
        "| savedsearch trigger_webhook",
        "| rest /services/authentication/users",
        "| curl https://evil.example.com",
        "index=main [ search index=other | outputlookup evil.csv ]",
        "index=main [| delete ]",
        "index=main [ outputcsv foo.csv ]",
        "index=main ```comment``` | outputlookup evil.csv",
        "index=main `malicious_macro`",
        "index=main ```unclosed comment",
        'index=main "unclosed quote',
        "index=main 'unclosed single quote",
        "index=main 'foo | outputlookup evil.csv'",
        r"index=main 'a\' | outputlookup evil.csv'",
        "index=main msg='| outputcsv foo.csv'",
        "index=main 'foo' 'bar | outputlookup evil.csv | head 1'",
        "index=main 'foo ; outputlookup evil.csv'",
        "index=main 'foo `evil_macro`'",
        "index=main | eval x='a\"b' | outputlookup evil.csv | eval y='c\"d'",
        "index=main 'a\"b' | delete 'c\"d'",
        "index=main 'a\"b' ; outputcsv evil.csv 'c\"d'",
        "index=main 'a\"b' `evil_macro` 'c\"d'",
        "index=main 'a\"b' [search index=sec | sendemail to=x] 'c\"d'",
        "index=main 'a\"b | outputlookup evil.csv c\"d'",
        "index=main | eval x='a```b' | outputlookup evil.csv | eval y='c```d'",
        'index=main \\" | outputlookup evil.csv "foo"',
        "index=main [search index=sec] outputlookup evil.csv",
        "index=main [search index=sec] delete",
        "index=main [search index=sec] sendemail to=x",
        "index=main [search index=sec] unknown_cmd arg=1",
        "index=main [search index=sec] AND outputlookup evil.csv",
        "index=main [search index=sec [search index=third] outputlookup evil.csv]",
        "index=main [ search index=other",
        "index=main ]",
        "index=main [ ]",
        "index=main | ",
        "index=main; outputlookup evil.csv",
        r'search raw="foo \\" | outputlookup bar.csv',
        'index=main | "outputlookup" evil.csv',
    ],
)
def test_validate_readonly_spl_blocks_bypass_and_mutating_queries(spl: str) -> None:
    ok, reason = validate_readonly_spl(spl)
    assert ok is False, f"Expected unsafe SPL to be blocked: {spl!r}"
    assert reason


def test_spl_quote_desync_and_continuation_blocked_at_policy_and_registry(
    tmp_path: Path,
) -> None:
    mock_splunk = MagicMock()
    registry = build_default_readonly_registry(splunk_client=mock_splunk)
    audit = AuditLogStore(tmp_path / "audit.jsonl")
    policy = _full_enabled_policy()

    bypasses = [
        "index=main | eval x='a\"b' | outputlookup evil.csv | eval y='c\"d'",
        "index=main 'a\"b' | delete 'c\"d'",
        "index=main 'a\"b' ; outputcsv evil.csv 'c\"d'",
        "index=main 'a\"b' `evil_macro` 'c\"d'",
        "index=main 'a\"b' [search index=sec | sendemail to=x] 'c\"d'",
        "index=main [search index=sec] outputlookup evil.csv",
        "index=main [search index=sec] unknown_cmd arg=1",
    ]
    for spl in bypasses:
        dec = evaluate_tool_permission(
            "splunk_search",
            SOURCE_CATEGORY_SPLUNK,
            True,
            "full_investigation",
            policy,
            arguments={"spl": spl},
        )
        assert dec.allowed is False
        assert dec.rule == "spl_readonly_violation"

        res = registry.execute(
            "splunk_search",
            {"spl": spl},
            mode="full_investigation",
            policy=policy,
            audit=audit,
            run_id="run-spl-desync",
            event_key="rf_alert::a1",
            provider="openai",
        )
        assert res["ok"] is False
        assert res["blocked"] is True
        assert res["rule"] == "spl_readonly_violation"

    mock_splunk.run_search.assert_not_called()
    assert (
        len(
            audit.query(
                run_id="run-spl-desync",
                event_type="blocked_action",
                blocked_only=True,
            )
        )
        == len(bypasses)
    )


# ---------------------------------------------------------------------------
# 4. Zero Write/Mutation Surface & Registry Guardrails
# ---------------------------------------------------------------------------


def test_forbidden_mutating_method_inventory_matches_codebase() -> None:
    discovered_symbols: set[str] = set()
    for target in (
        RecordedFutureClient,
        SentinelOneClient,
        SplunkClient,
        SplunkESClient,
        splunk_es,
        SplunkRFEnricher,
        splunk_rf_enrichment,
    ):
        discovered_symbols.update(dir(target))

    missing = FORBIDDEN_MUTATING_METHOD_NAMES - discovered_symbols
    assert not missing, f"Stale entries in FORBIDDEN_MUTATING_METHOD_NAMES: {missing}"
    assert len(FORBIDDEN_MUTATING_METHOD_NAMES) >= 81


def test_default_registry_has_exact_29_readonly_tools_and_zero_write_overlap() -> None:
    registry = build_default_readonly_registry()
    specs = registry.list_tools()
    names = {spec.name for spec in specs}

    assert len(specs) == 29
    assert names == READONLY_TOOL_NAMES
    assert names.isdisjoint(FORBIDDEN_MUTATING_METHOD_NAMES)

    for spec in specs:
        assert spec.readonly is True
        assert set(spec.underlying_methods).isdisjoint(FORBIDDEN_MUTATING_METHOD_NAMES)

    schemas = registry.openai_schemas()
    assert len(schemas) == 29
    filtered = registry.openai_schemas(allowed_names={"splunk_search", "rf_get_alert"})
    assert {item["function"]["name"] for item in filtered} == {"splunk_search", "rf_get_alert"}


def test_registry_rejects_non_readonly_and_forbidden_tool_registrations() -> None:
    registry = ReadOnlyToolRegistry()

    @dataclass(frozen=True)
    class _MutableFakeSpec:
        name: str = "fake_tool"
        source_category: str = SOURCE_CATEGORY_RF
        description: str = "bad"
        parameters_schema: dict[str, Any] = None  # type: ignore[assignment]
        handler: Any = lambda _args: {}
        readonly: bool = False
        underlying_methods: tuple[str, ...] = ()

    with pytest.raises(ValueError, match="readonly=True"):
        registry.register(_MutableFakeSpec())  # type: ignore[arg-type]

    for forbidden_name in (
        "mitigate_threat",
        "update_notable",
        "get_site_token",
        "generate_service_user_token",
        "dispatch_saved_search",
        "write_enrichment_to_notable",
        "add_entity",
    ):
        with pytest.raises(ValueError, match="Forbidden mutating"):
            registry.register(
                ReadOnlyToolSpec(
                    name=forbidden_name,
                    source_category=SOURCE_CATEGORY_S1,
                    description="forbidden",
                    parameters_schema={"type": "object", "properties": {}},
                    handler=lambda _args: {},
                )
            )

    with pytest.raises(ValueError, match="forbidden mutating method"):
        registry.register(
            ReadOnlyToolSpec(
                name="sneaky_wrapper",
                source_category=SOURCE_CATEGORY_S1,
                description="forbidden underlying",
                parameters_schema={"type": "object", "properties": {}},
                handler=lambda _args: {},
                underlying_methods=("mitigate_threat",),
            )
        )


def test_registry_execute_blocks_and_audits_policy_and_spl_violations(tmp_path: Path) -> None:
    mock_splunk = MagicMock()
    registry = build_default_readonly_registry(splunk_client=mock_splunk)
    audit = AuditLogStore(tmp_path / "audit.jsonl")

    # 1. ask_only blocks without invoking handler
    res_ask = registry.execute(
        "splunk_search",
        {"spl": "index=main | head 5"},
        mode="ask_only",
        policy=_full_enabled_policy(),
        audit=audit,
        run_id="r1",
        event_key="rf_alert::1",
        provider="openai",
    )
    assert res_ask["ok"] is False
    assert res_ask["blocked"] is True
    assert res_ask["rule"] == "ask_only_no_tools"
    mock_splunk.run_search.assert_not_called()

    # 2. Mutating SPL blocks and audits blocked_action
    res_spl = registry.execute(
        "splunk_search",
        {"spl": "index=main | outputlookup steal.csv"},
        mode="full_investigation",
        policy=_full_enabled_policy(),
        audit=audit,
        run_id="r2",
        event_key="rf_alert::1",
        provider="ollama",
    )
    assert res_spl["ok"] is False
    assert res_spl["blocked"] is True
    assert res_spl["rule"] == "spl_readonly_violation"
    mock_splunk.run_search.assert_not_called()

    blocked_entries = audit.query(blocked_only=True)
    assert [entry.event_type for entry in blocked_entries].count("blocked_action") == 2


def test_unconfigured_clients_fail_gracefully_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for env_key in (
        "RF_API_TOKEN",
        "SPLUNK_TOKEN",
        "SPLUNK_USERNAME",
        "SPLUNK_PASSWORD",
        "S1_CONSOLE_URL",
        "S1_API_TOKEN",
        "SENTINELONE_URL",
        "SENTINELONE_API_TOKEN",
    ):
        monkeypatch.delenv(env_key, raising=False)

    registry = build_default_readonly_registry(
        rf_client=RecordedFutureClient(api_token=""),
        s1_client=SentinelOneClient(console_url="", api_token=""),
        splunk_client=lambda: None,
        splunk_es_client=lambda: None,
        osint_client=lambda: None,
    )
    policy = _full_enabled_policy()

    for tool_name, args in [
        ("splunk_search", {"spl": "index=main | head 1"}),
        ("splunk_es_list_notables", {}),
        ("s1_list_threats", {}),
        ("rf_search_alerts", {}),
        ("rf_get_watchlists", {}),
        ("osint_enrich_target", {"target": "1.2.3.4"}),
        ("unified_research_target", {"query": "1.2.3.4"}),
    ]:
        res = registry.execute(tool_name, args, mode="full_investigation", policy=policy)
        assert res["ok"] is False
        assert "configured" in res["error"].lower()


# ---------------------------------------------------------------------------
# 5. All 29 Read-Only Tool Wrappers (Mocked Clients & Lazy Factories)
# ---------------------------------------------------------------------------


def test_all_29_readonly_tool_wrappers_with_mocked_clients_and_lazy_factories(
    tmp_path: Path,
) -> None:
    mock_splunk = MagicMock()
    mock_splunk.run_search.return_value = {"status": "success", "results": [{"host": "web-01"}]}
    mock_splunk.list_indexes.return_value = [{"name": "main"}]
    mock_splunk.list_saved_searches.return_value = [{"name": "Brute Force"}]

    mock_es = MagicMock()
    mock_es.list_notables.return_value = [{"event_id": "es-1"}]
    mock_es.get_finding.return_value = {"finding_id": "f-1"}
    mock_es.list_investigations.return_value = [{"id": "inv-1"}]
    mock_es.list_risk_events.return_value = [{"risk_object": "alice"}]
    mock_es.lookup_asset.return_value = [{"ip": "10.0.0.5"}]
    mock_es.lookup_identity.return_value = [{"identity": "alice"}]
    mock_es.query_threat_intel.return_value = [{"ip": "198.51.100.7"}]

    mock_s1 = MagicMock()
    mock_s1.list_threats.return_value = [{"id": "t-1"}]
    mock_s1.get_threat_timeline.return_value = [{"activityType": 1}]
    mock_s1.list_cloud_alerts.return_value = [{"id": "ca-1"}]
    mock_s1.list_agents.return_value = [{"id": "ag-1"}]
    mock_s1.get_agent.return_value = {"id": "ag-1", "computerName": "srv-01"}
    mock_s1.list_activities.return_value = [{"id": "act-1"}]
    mock_s1.create_dv_query.return_value = {"data": {"queryId": "dvq-1"}}
    mock_s1.get_dv_query_status.return_value = {"data": {"responseState": "FINISHED"}}
    mock_s1.get_dv_events.return_value = [{"eventType": "Process Creation"}]

    mock_rf = MagicMock()
    mock_rf.search_alerts_v3.return_value = {"data": [{"id": "rfa-1"}]}
    mock_rf.get_alert_v3.return_value = {"data": {"id": "rfa-1"}}
    mock_rf.search_playbook_alerts.return_value = {"data": [{"playbook_alert_id": "pb-1"}]}
    mock_rf.get_playbook_alert.return_value = {"data": {"panel_status": "ok"}}
    mock_rf.get_playbook_alert_preview.return_value = {"data": {"title": "preview"}}
    mock_rf.v2_lookup.return_value = {"data": {"risk": {"score": 89}}}
    mock_rf.search_analyst_notes.return_value = {"data": [{"id": "note-1"}]}
    mock_rf.soar_enrich.return_value = {"data": {"results": []}}
    mock_rf.links_search.return_value = {"data": {"counts": {}}}
    mock_rf.get_watchlists.return_value = [{"id": "wl-1", "name": "Brand"}]
    mock_rf.get_watchlist_entities.return_value = [
        {"entity": {"id": "idn:evil.com", "name": "evil.com"}},
        {"entity": {"id": "idn:good.com", "name": "good.com"}},
    ]

    mock_osint = MagicMock()
    mock_osint.enrich_target.return_value = {
        "cisa_kev": OSINTSectionOutcome(
            key="cisa_kev",
            title="CISA KEV",
            status="ok",
            count=1,
            data={"cve": "CVE-2024-1234"},
        )
    }

    fake_dossier = MagicMock()
    fake_dossier.to_dict.return_value = {"query": "CVE-2024-1234", "sections": {"rf": {}}}
    mock_research_fn = MagicMock(return_value=fake_dossier)

    # Use lazy callable factories to verify dynamic resolution works identically
    registry = build_default_readonly_registry(
        rf_client=lambda: mock_rf,
        s1_client=lambda: mock_s1,
        splunk_client=lambda: mock_splunk,
        splunk_es_client=lambda: mock_es,
        osint_client=lambda: mock_osint,
        research_fn=mock_research_fn,
    )
    policy = _full_enabled_policy()
    audit = AuditLogStore(tmp_path / "all29.jsonl")

    calls: list[tuple[str, dict[str, Any]]] = [
        ("splunk_search", {"spl": "index=main | stats count"}),
        ("splunk_list_indexes", {}),
        ("splunk_list_saved_searches", {"app": "search"}),
        ("splunk_es_list_notables", {"urgency": "high"}),
        ("splunk_es_get_finding", {"finding_id": "f-1"}),
        ("splunk_es_list_investigations", {"status": "new"}),
        ("splunk_es_list_risk_events", {"risk_object": "alice"}),
        ("splunk_es_lookup_asset", {"query": "10.0.0.5"}),
        ("splunk_es_lookup_identity", {"query": "alice"}),
        ("splunk_es_query_threat_intel", {"collection": "ip_intel", "query": {"ip": "1.2.3.4"}}),
        ("s1_list_threats", {"query": "mimikatz"}),
        ("s1_get_threat_timeline", {"threat_id": "t-1"}),
        ("s1_list_cloud_alerts", {"sha1": "abc"}),
        ("s1_list_agents", {"computer_name": "srv-01"}),
        ("s1_get_agent", {"agent_id": "ag-1"}),
        ("s1_list_activities", {"agent_ids": ["ag-1"]}),
        ("s1_dv_query", {"query": "SrcProcName = 'cmd.exe'", "from_date": "2026-11-24T00:00:00Z", "to_date": "2026-11-25T00:00:00Z", "poll_interval_seconds": 0.0}),
        ("rf_search_alerts", {"freetext": "ransomware"}),
        ("rf_get_alert", {"alert_id": "rfa-1"}),
        ("rf_search_playbook_alerts", {"categories": ["domain_abuse"]}),
        ("rf_get_playbook_alert", {"alert_id": "pb-1", "category": "domain_abuse"}),
        ("rf_lookup_ioc_or_cve", {"value": "CVE-2024-1234"}),
        ("rf_search_analyst_notes", {"entity": "CVE-2024-1234"}),
        ("rf_soar_enrich", {"iocs": {"ip": ["1.2.3.4"]}}),
        ("rf_links_search", {"entities": ["ip:1.2.3.4"]}),
        ("rf_get_watchlists", {"name": "Brand"}),
        ("rf_get_watchlist_entities", {"list_id": "wl-1", "query": "evil.com"}),
        ("osint_enrich_target", {"target": "CVE-2024-1234"}),
        ("unified_research_target", {"query": "CVE-2024-1234"}),
    ]
    assert {name for name, _ in calls} == READONLY_TOOL_NAMES

    for tool_name, args in calls:
        res = registry.execute(
            tool_name,
            args,
            mode="full_investigation",
            policy=policy,
            audit=audit,
            run_id="run-29",
            event_key="rf_alert::rfa-1",
            provider="openai",
        )
        assert res["ok"] is True, f"{tool_name} failed: {res}"
        assert res["tool"] == tool_name
        # Output must be strictly JSON-serializable for LLM tool responses
        json.dumps(res)

    mock_splunk.run_search.assert_called_once()
    mock_es.query_threat_intel.assert_called_once_with("ip_intel", query={"ip": "1.2.3.4"}, limit=50)
    mock_s1.create_dv_query.assert_called_once()
    mock_s1.get_dv_events.assert_called_once_with("dvq-1", limit=100)
    mock_rf.get_playbook_alert.assert_called_once_with("domain_abuse", "pb-1", panels=None)
    mock_rf.v2_lookup.assert_called_once_with("vulnerability", "CVE-2024-1234", fields=None, metadata=False)
    mock_osint.enrich_target.assert_called_once()
    mock_research_fn.assert_called_once()

    # Check watchlist query filter & preview fallback & DV failure/empty branches
    wl_res = registry.execute(
        "rf_get_watchlist_entities",
        {"list_id": "wl-1", "query": "evil.com"},
        mode="full_investigation",
        policy=policy,
    )
    assert len(wl_res["result"]) == 1

    pb_preview = registry.execute(
        "rf_get_playbook_alert",
        {"alert_id": "pb-1"},
        mode="full_investigation",
        policy=policy,
    )
    assert pb_preview["ok"] is True
    mock_rf.get_playbook_alert_preview.assert_called_once_with("pb-1")

    mock_s1.get_dv_query_status.return_value = {"data": {"responseState": "EMPTY_RESULTS"}}
    dv_empty = registry.execute(
        "s1_dv_query",
        {
            "query": "EventType = 'DNS'",
            "from_date": "2026-11-24T00:00:00Z",
            "to_date": "2026-11-25T00:00:00Z",
            "poll_interval_seconds": 0.0,
        },
        mode="full_investigation",
        policy=policy,
    )
    assert dv_empty["ok"] is True
    assert dv_empty["result"]["events"] == []

    mock_s1.get_dv_query_status.return_value = {"data": {"responseState": "FAILED"}}
    dv_failed = registry.execute(
        "s1_dv_query",
        {
            "query": "EventType = 'DNS'",
            "from_date": "2026-11-24T00:00:00Z",
            "to_date": "2026-11-25T00:00:00Z",
            "poll_interval_seconds": 0.0,
        },
        mode="full_investigation",
        policy=policy,
    )
    assert dv_failed["ok"] is False
    assert "FAILED" in dv_failed["error"]


# ---------------------------------------------------------------------------
# 6. Iteration 2 Regression Tests (Redaction, Non-Mapping Args, Hardening)
# ---------------------------------------------------------------------------


def test_redact_sensitive_data_prefixed_strings_escaped_json_and_basic_auth() -> None:
    prefixed_cases = [
        ("ms_bearer_token=ms_secret_abc123", "ms_secret_abc123"),
        ("ms_copilot_bearer_token=msc_secret_abc123", "msc_secret_abc123"),
        ("ms_copilot_directline_secret=dl_secret_abc123", "dl_secret_abc123"),
        ("ms_directline_secret=ms_dl_abc123", "ms_dl_abc123"),
        ("rf_api_token=rf_secret_abc123", "rf_secret_abc123"),
        ("s1_api_token=s1_secret_abc123", "s1_secret_abc123"),
        ("splunk_token=sp_tok_abc123", "sp_tok_abc123"),
        ("splunk_password=sp_pwd_abc123", "sp_pwd_abc123"),
        ("rf_llm_api_key=rf_llm_abc123", "rf_llm_abc123"),
        ("custom_service_token: custom_tok_xyz", "custom_tok_xyz"),
        ('{"ms_bearer_token": "ms_json_abc123", "max_tokens": 50}', "ms_json_abc123"),
        ('{"splunk_password": "sp_json_abc123"}', "sp_json_abc123"),
        (r'{\"api_key\": \"esc_abc123\"}', "esc_abc123"),
        (
            r'{\"ms_copilot_directline_secret\": \"dl_esc_999\", \"max_tokens\": \"50\", \"token_type\": \"bearer\"}',
            "dl_esc_999",
        ),
    ]
    for raw_text, secret in prefixed_cases:
        redacted = redact_sensitive_data(raw_text)
        assert secret not in redacted, f"Secret {secret!r} leaked in {redacted!r}"
        assert "<REDACTED>" in redacted

    # Metadata and IOCs remain intact inside strings and escaped JSON
    meta_str = (
        "max_tokens=512 token_count=120 prompt_tokens=10 completion_tokens=20 "
        "total_tokens=30 token_type=Bearer ms_auth_mode=delegated auth_mode=cli "
        "ip=203.0.113.5 cve=CVE-2024-3094 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert redact_sensitive_data(meta_str) == meta_str

    esc_with_meta = (
        r'{\"ms_bearer_token\": \"ms_json_abc123\", \"max_tokens\": \"50\", \"token_type\": \"bearer\"}'
    )
    esc_redacted = redact_sensitive_data(esc_with_meta)
    assert "ms_json_abc123" not in esc_redacted
    assert r'\"max_tokens\": \"50\"' in esc_redacted
    assert r'\"token_type\": \"bearer\"' in esc_redacted

    # Authorization: Basic preserves scheme and masks base64 credentials, idempotently
    basic_redacted = redact_sensitive_data("Authorization: Basic dXNlcjpwYXNz")
    assert basic_redacted == "Authorization: Basic <REDACTED>"
    assert "dXNlcjpwYXNz" not in basic_redacted
    assert redact_sensitive_data(basic_redacted) == "Authorization: Basic <REDACTED>"


@pytest.mark.parametrize(
    ("bad_args", "expected_type"),
    [
        (["bad_list", "api_key=leak_me_123"], "list"),
        ("Authorization: Basic dXNlcjpwYXNz", "str"),
        (123, "int"),
    ],
)
def test_registry_execute_fails_closed_on_non_mapping_arguments(
    tmp_path: Path, bad_args: Any, expected_type: str
) -> None:
    mock_splunk = MagicMock()
    registry = build_default_readonly_registry(splunk_client=mock_splunk)
    audit = AuditLogStore(tmp_path / "non_mapping_audit.jsonl")

    res = registry.execute(
        "splunk_list_indexes",
        bad_args,
        mode="full_investigation",
        policy=_full_enabled_policy(),
        audit=audit,
        run_id="run-bad-args",
        event_key="rf_alert::bad-args",
        provider="openai",
    )
    assert res == {
        "ok": False,
        "blocked": False,
        "tool": "splunk_list_indexes",
        "error": f"Invalid tool arguments: expected mapping, got {expected_type}.",
    }
    mock_splunk.list_indexes.assert_not_called()

    entries = audit.query(run_id="run-bad-args")
    assert [e.event_type for e in entries] == ["tool_call", "permission_check", "error"]
    assert entries[1].allowed is False
    assert entries[2].allowed is False
    raw_disk = audit.path.read_text(encoding="utf-8")
    assert "leak_me_123" not in raw_disk
    assert "dXNlcjpwYXNz" not in raw_disk


def test_bytes_ignored_in_opt_str_list_helpers_and_s1_tool() -> None:
    assert _opt_str_list({"x": b"unresolved"}, "x") is None
    assert _opt_str_list({"x": bytearray(b"unresolved")}, "x") is None
    assert _opt_str_list_or_str({"x": b"unresolved"}, "x") is None
    assert _opt_str_list_or_str({"x": bytearray(b"unresolved")}, "x") is None

    mock_s1 = MagicMock()
    mock_s1.list_threats.return_value = []
    registry = build_default_readonly_registry(s1_client=mock_s1)
    res = registry.execute(
        "s1_list_threats",
        {"incident_statuses": b"unresolved"},
        mode="full_investigation",
        policy=_full_enabled_policy(),
    )
    assert res["ok"] is True
    mock_s1.list_threats.assert_called_once()
    assert mock_s1.list_threats.call_args.kwargs["incident_statuses"] is None


def test_resolve_client_direct_magicmock_factory_and_configuration_error() -> None:
    # Direct MagicMock instance must NOT be invoked as a factory
    direct_mock = MagicMock()
    direct_mock.list_indexes.return_value = [{"name": "main"}]
    direct_reg = build_default_readonly_registry(splunk_client=direct_mock)
    res_direct = direct_reg.execute(
        "splunk_list_indexes",
        {},
        mode="full_investigation",
        policy=_full_enabled_policy(),
    )
    assert res_direct["ok"] is True
    assert direct_mock.called is False
    direct_mock.list_indexes.assert_called_once()

    # Genuine callable factory MUST still be called
    factory_target = MagicMock()
    factory_target.list_indexes.return_value = [{"name": "security"}]
    factory_reg = build_default_readonly_registry(splunk_client=lambda: factory_target)
    res_factory = factory_reg.execute(
        "splunk_list_indexes",
        {},
        mode="full_investigation",
        policy=_full_enabled_policy(),
    )
    assert res_factory["ok"] is True
    assert res_factory["result"] == [{"name": "security"}]
    factory_target.list_indexes.assert_called_once()

    # Caller-provided factory raising ConfigurationError must fail gracefully as unconfigured
    def _raising_factory() -> Any:
        raise ConfigurationError("Splunk credentials missing")

    err_reg = build_default_readonly_registry(splunk_client=_raising_factory)
    res_err = err_reg.execute(
        "splunk_list_indexes",
        {},
        mode="full_investigation",
        policy=_full_enabled_policy(),
    )
    assert res_err["ok"] is False
    assert "configured" in res_err["error"].lower()


# ---------------------------------------------------------------------------
# 7. Iteration 3 Regression Tests (Quoted Assignments, Multi-Escaped JSON,
#    Inner Escaped Quotes, Hyphenated *-token, Bare token=, Bearer with =)
# ---------------------------------------------------------------------------


def test_redact_sensitive_data_iteration3_quoted_multiescaped_hyphen_bare_and_bearer() -> None:
    # 1. Quoted key="value" / key='value' / key: "value" (including spaces & inner \")
    quoted_assignment_cases = [
        ('splunk_password="my secret pass"', "my secret pass", 'splunk_password="<REDACTED>"'),
        ("ms_bearer_token='my_secret_tok'", "my_secret_tok", "ms_bearer_token='<REDACTED>'"),
        ('api_key="quoted_api_key_val"', "quoted_api_key_val", 'api_key="<REDACTED>"'),
        ('api_key: "quoted val"', "quoted val", 'api_key: "<REDACTED>"'),
        ('splunk_password="part1\\"part2_leak"', "part2_leak", 'splunk_password="<REDACTED>"'),
        (r'splunk_password=\"my secret pass\"', "my secret pass", r'splunk_password=\"<REDACTED>\"'),
    ]
    for raw, secret, expected in quoted_assignment_cases:
        out = redact_sensitive_data(raw)
        assert secret not in out
        assert out == expected
        assert redact_sensitive_data(out) == out

    # 2. Multi-level escaped JSON quotes AND inner escaped quotes inside JSON values
    json_escape_cases = [
        (r'{\\"api_key\\": \\"double_esc_secret\\"}', "double_esc_secret", r'{\\"api_key\\": \\"<REDACTED>\\"}'),
        (
            r'{\\"ms_bearer_token\\": \\"double_esc_ms\\"}',
            "double_esc_ms",
            r'{\\"ms_bearer_token\\": \\"<REDACTED>\\"}',
        ),
        (r'{"api_key": "part1\"part2_leak"}', "part2_leak", '{"api_key": "<REDACTED>"}'),
        (r'{"api_key": "part1\\"}', "part1", '{"api_key": "<REDACTED>"}'),
        (
            r'{\"api_key\": \"part1\\\"part2_leak\", \"splunk_password\": \"part3\\\"part4_leak\"}',
            "part2_leak",
            r'{\"api_key\": \"<REDACTED>\", \"splunk_password\": \"<REDACTED>\"}',
        ),
        (
            json.dumps(json.dumps({"api_key": 'part1"part2_leak'})),
            "part2_leak",
            None,
        ),
    ]
    for raw, secret, expected in json_escape_cases:
        out = redact_sensitive_data(raw)
        assert secret not in out
        assert "<REDACTED>" in out
        if expected is not None:
            assert out == expected
        assert redact_sensitive_data(out) == out

    # 3. Hyphenated *-token keys in headers, quoted assignments, URLs, and JSON strings
    hyphen_cases = [
        ("x-custom-token: hyp_tok_123", "hyp_tok_123", "x-custom-token: <REDACTED>"),
        ('x-custom-token="hyp_quoted_123"', "hyp_quoted_123", 'x-custom-token="<REDACTED>"'),
        ('{"x-custom-token": "hyp_json_123"}', "hyp_json_123", '{"x-custom-token": "<REDACTED>"}'),
        (
            "https://example.test/api?x-custom-token=hyp_qs_123",
            "hyp_qs_123",
            "https://example.test/api?x-custom-token=<REDACTED>",
        ),
    ]
    for raw, secret, expected in hyphen_cases:
        out = redact_sensitive_data(raw)
        assert secret not in out
        assert out == expected
        assert redact_sensitive_data(out) == out

    # 4. Bare token= / token: / token="..." in strings
    bare_token_cases = [
        ("token=bare_tok_secret", "bare_tok_secret", "token=<REDACTED>"),
        ("token: bare_tok_secret2", "bare_tok_secret2", "token: <REDACTED>"),
        ('token="bare_quoted_secret"', "bare_quoted_secret", 'token="<REDACTED>"'),
    ]
    for raw, secret, expected in bare_token_cases:
        out = redact_sensitive_data(raw)
        assert secret not in out
        assert out == expected
        assert redact_sensitive_data(out) == out

    # 5. Bearer tokens containing '=' (base64 padding / key-value-like opaque tokens)
    bearer_eq_cases = [
        ("Bearer abc123=def456", "abc123=def456", "Bearer <REDACTED>"),
        ("Bearer dXNlcjpwYXNz==", "dXNlcjpwYXNz==", "Bearer <REDACTED>"),
        ("Authorization: Bearer abc123=def456", "abc123=def456", "Authorization: Bearer <REDACTED>"),
        ('Bearer token="my_secret"', "my_secret", 'Bearer token="<REDACTED>"'),
        (
            "token_type=Bearer access_token=secret123",
            "secret123",
            "token_type=Bearer access_token=<REDACTED>",
        ),
    ]
    for raw, secret, expected in bearer_eq_cases:
        out = redact_sensitive_data(raw)
        assert secret not in out
        assert out == expected
        assert redact_sensitive_data(out) == out

    # Preservation of non-secret metadata across plain, quoted, and escaped JSON forms
    preserved_inputs = [
        "token_type=Bearer ms_auth_mode=delegated",
        'max_tokens="50" token_type="Bearer" ms_auth_mode="delegated"',
        r'{\"max_tokens\": \"50\", \"token_type\": \"bearer\"}',
        r'{\\"max_tokens\\": \\"50\\"}',
        '{"api_key": "", "max_tokens": "50"}',
    ]
    for raw in preserved_inputs:
        assert redact_sensitive_data(raw) == raw


# ---------------------------------------------------------------------------
# 8. Iteration 4 Regression Tests (O(N) ReDoS, 16KB Boundary, PEM, Auth, k=2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("hyphen_repeat_100kb", "a-" * 50000),
        ("hyphen_repeat_plus_benign_kv", ("a-" * 50000) + "notasecret=val"),
        ("double_hyphen_repeat_75kb", "a--" * 25000),
        ("mixed_case_underscore_100kb", "AbCd-EfGh_" * 10000),
        ("backslash_run_50kb", ("\\" * 50000) + '"a": "b"'),
        ("unclosed_multiline_5k", 'api_key="sec\n' * 5000),
        ("url_query_211kb", "https://example.test/?" + "&".join(f"p{i}=v{i}" for i in range(17000))),
        ("amp_kv_100kb", "a=1&" * 25000),
        ("slash_kv_100kb", "k=v/" * 25000),
        ("colon_slash_100kb", "k:v/" * 25000),
        ("auth_digest_90kb", "Authorization: Digest " + ("a=1, " * 18000)),
        ("pipe_kv_40kb", "k=v|" * 10000),
        ("a_eq_50kb", "a=" * 25000),
        ("a_colon_50kb", "a:" * 25000),
        ("q_a_1_50kb", "?a=1" * 12500),
        ("bearer_a_eq_50kb", "Bearer " + ("a=" * 25000)),
        ("foo_bar_50kb", "foo=bar&" * 6250),
        ("api_key_amp_40kb", "api_key=1&" * 4000),
        ("repeated_unclosed_pem_4k", ('"api_key": "-----BEGIN PRIVATE KEY-----\n' * 4000) + ("X" * 10000)),
    ],
)
def test_redact_sensitive_data_linear_time_redos_resistant(label: str, payload: str) -> None:
    t0 = time.process_time()
    out = redact_sensitive_data(payload)
    elapsed = time.process_time() - t0
    assert elapsed < 0.50, f"{label} took {elapsed:.4f}s CPU time (expected < 0.50s linear time)"
    if label == "unclosed_multiline_5k":
        assert "sec" not in out
    elif label in {"auth_digest_90kb", "bearer_a_eq_50kb", "api_key_amp_40kb", "repeated_unclosed_pem_4k"}:
        assert "<REDACTED>" in out
        assert "PRIVATE KEY" not in out
    else:
        assert out == payload


def test_registry_execute_redacts_before_16kb_truncation_and_returns_unredacted(
    tmp_path: Path,
) -> None:
    audit = AuditLogStore(tmp_path / "boundary_audit.jsonl")
    registry = ReadOnlyToolRegistry()

    secret_val = "BOUNDARY_SECRET_999_LONG_VALUE"
    bearer_val = "sk-1234567890abcdef_boundary"
    jwt_val = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig123456789"
    arg_secret = "ARG_BOUNDARY_SECRET_XYZ_999"

    registry.register(
        ReadOnlyToolSpec(
            name="splunk_list_indexes",
            source_category=SOURCE_CATEGORY_SPLUNK,
            description="boundary test",
            parameters_schema={"type": "object", "properties": {}},
            handler=lambda _args: {
                "padding": "A" * 15950,
                "api_key": secret_val,
                "auth": f"Bearer {bearer_val}",
                "jwt_blob": jwt_val,
            },
        )
    )

    res = registry.execute(
        "splunk_list_indexes",
        {"padding": "B" * 15950, "api_key": arg_secret},
        mode="full_investigation",
        policy=_full_enabled_policy(),
        audit=audit,
        run_id="run-boundary",
        event_key="rf_alert::boundary",
        provider="openai",
    )

    # Caller continues to receive the full, unredacted tool output
    assert res["ok"] is True
    assert res["result"]["api_key"] == secret_val
    assert bearer_val in res["result"]["auth"]
    assert res["result"]["jwt_blob"] == jwt_val

    # Persisted audit JSONL on disk must never contain any secret fragments
    raw_disk = audit.path.read_text(encoding="utf-8")
    for leaked_fragment in (
        "BOUNDARY_SEC",
        secret_val,
        "sk-12345",
        bearer_val,
        "eyJhbGciOiJIUz",
        jwt_val,
        "ARG_BOUNDARY",
        arg_secret,
    ):
        assert leaked_fragment not in raw_disk


def test_redact_sensitive_data_unclosed_multiline_pem_and_k2_escapes() -> None:
    cases = [
        # Unclosed single-line quotes
        ('{"api_key": "unclosed_secret_val', '{"api_key": "<REDACTED>', ("unclosed_secret_val",)),
        ('splunk_password="unclosed_secret_val', 'splunk_password="<REDACTED>', ("unclosed_secret_val",)),
        # Unclosed multiline non-PEM must NOT swallow subsequent lines
        (
            'api_key="unclosed_s1\nhost="web-01" user="alice"',
            'api_key="<REDACTED>\nhost="web-01" user="alice"',
            ("unclosed_s1",),
        ),
        (
            '{"api_key": "unclosed_s2\n"host": "web-01"}',
            '{"api_key": "<REDACTED>\n"host": "web-01"}',
            ("unclosed_s2",),
        ),
        # Multiline PEM private keys (JSON, quoted assignment, truncated, unquoted)
        (
            '{"private_key": "-----BEGIN PRIVATE KEY-----\nMIIE\nSECRET_KEY_BODY\n-----END PRIVATE KEY-----"}',
            '{"private_key": "<REDACTED>"}',
            ("SECRET_KEY_BODY",),
        ),
        (
            'private_key="-----BEGIN PRIVATE KEY-----\nSECRET_BODY\n-----END PRIVATE KEY-----"',
            'private_key="<REDACTED>"',
            ("SECRET_BODY",),
        ),
        (
            '{"private_key": "-----BEGIN PRIVATE KEY-----\nSECRET_TRUNCATED',
            '{"private_key": "<REDACTED>',
            ("SECRET_TRUNCATED",),
        ),
        (
            "log:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\nUNQUOTED_PEM_SECRET\n-----END RSA PRIVATE KEY-----\nhost=web1",
            "log:\n<REDACTED>\nhost=web1",
            ("UNQUOTED_PEM_SECRET",),
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nUNQUOTED_TRUNCATED_PEM",
            "<REDACTED>",
            ("UNQUOTED_TRUNCATED_PEM",),
        ),
        # k=2 double-escaped trailing backslashes (bs=4, bs=6) and inner escaped quote
        (r'{\\"api_key\\": \\"part1\\\\"}', r'{\\"api_key\\": \\"<REDACTED>\\"}', ("part1",)),
        (r'{\\"api_key\\": \\"abc\\\\\\"}', r'{\\"api_key\\": \\"<REDACTED>\\"}', ("abc",)),
        (
            r'{\\"api_key\\": \\"part1\\\\\\"part2_leak\\"}',
            r'{\\"api_key\\": \\"<REDACTED>\\"}',
            ("part1", "part2_leak"),
        ),
    ]
    for raw, expected, forbidden in cases:
        out = redact_sensitive_data(raw)
        assert out == expected
        for secret in forbidden:
            assert secret not in out
        assert redact_sensitive_data(out) == out

    # Non-secret public certificate remains intact
    cert = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEF\n-----END CERTIFICATE-----"
    assert redact_sensitive_data(cert) == cert


def test_redact_sensitive_data_auth_schemes_key_parity_url_order_and_token_type() -> None:
    cases = [
        ("Authorization: Splunk splunk_session_key_123", "Authorization: Splunk <REDACTED>", ("splunk_session_key_123",)),
        ("Authorization: Token tok_abc_123", "Authorization: Token <REDACTED>", ("tok_abc_123",)),
        ('Authorization: Token token="tok_nested_123"', 'Authorization: Token token="<REDACTED>"', ("tok_nested_123",)),
        (
            'Authorization: Digest username="alice", realm="prod", response="6629fae4"',
            "Authorization: Digest <REDACTED>",
            ("6629fae4",),
        ),
        (
            "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261125/us-east-1/s3/aws4_request, Signature=deadbeef",
            "Authorization: AWS4-HMAC-SHA256 <REDACTED>",
            ("deadbeef",),
        ),
        ("Proxy-Authorization: Basic dXNlcjpwYXNz", "Proxy-Authorization: Basic <REDACTED>", ("dXNlcjpwYXNz",)),
        ("proxy_authorization=Basic dXNlcjpwYXNz", "proxy_authorization=Basic <REDACTED>", ("dXNlcjpwYXNz",)),
        (
            "x_rftoken=rf_val_1 proxy_authorization=pa_val_2 bearer=b_val_3 sig=sig_val_4",
            "x_rftoken=<REDACTED> proxy_authorization=<REDACTED> bearer=<REDACTED> sig=<REDACTED>",
            ("rf_val_1", "pa_val_2", "b_val_3", "sig_val_4"),
        ),
        (
            '{"x_rftoken": "rf_j", "proxy_authorization": "pa_j", "bearer": "b_j", "sig": "s_j"}',
            '{"x_rftoken": "<REDACTED>", "proxy_authorization": "<REDACTED>", "bearer": "<REDACTED>", "sig": "<REDACTED>"}',
            ("rf_j", "pa_j", "b_j", "s_j"),
        ),
        (
            "https://example.test/api?token=secret_tok&page=2",
            "https://example.test/api?token=<REDACTED>&page=2",
            ("secret_tok",),
        ),
        (
            "https://example.test/api?x-api-key=secret_key&host=web1",
            "https://example.test/api?x-api-key=<REDACTED>&host=web1",
            ("secret_key",),
        ),
        ("msg=password:leak123", "msg=password: <REDACTED>", ("leak123",)),
    ]
    for raw, expected, forbidden in cases:
        out = redact_sensitive_data(raw)
        assert out == expected
        for secret in forbidden:
            assert secret not in out
        assert redact_sensitive_data(out) == out

    # Non-secret token_type with arbitrary whitespace around '=' / ':' must be preserved
    for preserved in (
        "token_type = Bearer expires_in=3600",
        "token_type:  Bearer expires_in=3600",
    ):
        assert redact_sensitive_data(preserved) == preserved
        assert redact_sensitive_data(redact_sensitive_data(preserved)) == preserved


# ---------------------------------------------------------------------------
# 9. Iteration 5 Regression Tests (Auth Quoted/Unknown, Form &, PEM, k=2 Space)
# ---------------------------------------------------------------------------


def test_redact_sensitive_data_iteration5_auth_form_pem_and_k2_space() -> None:
    cases = [
        # All 5 Challenger auth-scheme leaks + unknown & multiparam schemes
        (
            'Authorization: Splunk "my_splunk_quoted_secret"',
            'Authorization: Splunk "<REDACTED>"',
            ("my_splunk_quoted_secret",),
        ),
        (
            'Authorization: Bearer "my_bearer_quoted_secret"',
            'Authorization: Bearer "<REDACTED>"',
            ("my_bearer_quoted_secret",),
        ),
        (
            'Authorization: Token "my_token_quoted_secret"',
            'Authorization: Token "<REDACTED>"',
            ("my_token_quoted_secret",),
        ),
        (
            'Authorization: Token key="my_non_sens_kv_secret"',
            'Authorization: Token key="<REDACTED>"',
            ("my_non_sens_kv_secret",),
        ),
        (
            "Authorization: ApiKey my_es_apikey_secret_999",
            "Authorization: ApiKey <REDACTED>",
            ("my_es_apikey_secret_999",),
        ),
        (
            'Authorization: Signature keyId="k1", signature="sig_secret_123"',
            "Authorization: Signature <REDACTED>",
            ("sig_secret_123",),
        ),
        (
            'Authorization: Hawk id="dh37", mac="hawk_mac_secret"',
            "Authorization: Hawk <REDACTED>",
            ("hawk_mac_secret",),
        ),
        (
            "Authorization: VAPID t=eyJ.abc.def, k=vapid_key_secret",
            "Authorization: VAPID <REDACTED>",
            ("vapid_key_secret",),
        ),
        (
            "Authorization: UnknownScheme unk_secret_123",
            "Authorization: UnknownScheme <REDACTED>",
            ("unk_secret_123",),
        ),
        (
            'Authorization: UnknownScheme "unk_quoted_123"',
            'Authorization: UnknownScheme "<REDACTED>"',
            ("unk_quoted_123",),
        ),
        (
            'Authorization: UnknownScheme key="unk_kv_123"',
            'Authorization: UnknownScheme key="<REDACTED>"',
            ("unk_kv_123",),
        ),
        (
            'Bearer "my_bearer_quoted_secret"',
            'Bearer "<REDACTED>"',
            ("my_bearer_quoted_secret",),
        ),
        # Form-urlencoded '&' boundary vs '&' inside secret value
        (
            "api_key=sec123&page=2&host=web1",
            "api_key=<REDACTED>&page=2&host=web1",
            ("sec123",),
        ),
        (
            "password=p@ss&word123",
            "password=<REDACTED>",
            ("p@ss", "word123"),
        ),
        # Truncated PEM followed by CERTIFICATE (must NOT swallow host or cert)
        (
            '{"private_key": "-----BEGIN PRIVATE KEY-----\nSECRET_KEY_TRUNCATED", "host": "web-01", "cert": "-----BEGIN CERTIFICATE-----\nCERT_DATA\n-----END CERTIFICATE-----"}',
            '{"private_key": "<REDACTED>", "host": "web-01", "cert": "-----BEGIN CERTIFICATE-----\nCERT_DATA\n-----END CERTIFICATE-----"}',
            ("SECRET_KEY_TRUNCATED",),
        ),
        (
            'private_key="-----BEGIN PRIVATE KEY-----\nSECRET_KEY_TRUNCATED" host="web-01" cert="-----BEGIN CERTIFICATE-----\nCERT_DATA\n-----END CERTIFICATE-----"',
            'private_key="<REDACTED>" host="web-01" cert="-----BEGIN CERTIFICATE-----\nCERT_DATA\n-----END CERTIFICATE-----"',
            ("SECRET_KEY_TRUNCATED",),
        ),
        # Truncated PRIVATE KEY followed by a complete PRIVATE KEY
        (
            '{"private_key": "-----BEGIN PRIVATE KEY-----\nSECRET_KEY_TRUNCATED", "host": "web-01", "backup": "-----BEGIN PRIVATE KEY-----\nBACKUP_SECRET\n-----END PRIVATE KEY-----"}',
            '{"private_key": "<REDACTED>", "host": "web-01", "backup": "<REDACTED>"}',
            ("SECRET_KEY_TRUNCATED", "BACKUP_SECRET"),
        ),
        # Unclosed non-PEM line 1 before CERTIFICATE
        (
            '{"api_key": "unclosed_s2\n"cert": "-----BEGIN CERTIFICATE-----\nCERT_DATA\n-----END CERTIFICATE-----"}',
            '{"api_key": "<REDACTED>\n"cert": "-----BEGIN CERTIFICATE-----\nCERT_DATA\n-----END CERTIFICATE-----"}',
            ("unclosed_s2",),
        ),
        # k=2 double-escaped inner quote followed by space inside JSON vs non-JSON
        (
            r'{\\"api_key\\": \\"part1\\\\\\" part2_space_leak\\"}',
            r'{\\"api_key\\": \\"<REDACTED>\\"}',
            ("part1", "part2_space_leak"),
        ),
        (
            r'{\\"api_key\\": \\"abc\\\\\\" , \\"host\\": \\"web1\\"}',
            r'{\\"api_key\\": \\"<REDACTED>\\" , \\"host\\": \\"web1\\"}',
            ("abc",),
        ),
        (
            r'api_key=\\"abc\\\\\\" host=web1',
            r'api_key=\\"<REDACTED>\\" host=web1',
            ("abc",),
        ),
    ]
    for raw, expected, forbidden in cases:
        out = redact_sensitive_data(raw)
        assert out == expected
        for secret in forbidden:
            assert secret not in out
        assert redact_sensitive_data(out) == out

    # Preserved placeholders & non-secret metadata
    for preserved in (
        "Authorization: Bearer <REDACTED>",
        'Authorization: Token token="<REDACTED>"',
        "Authorization: UnknownScheme <REDACTED>",
        'token_type="Bearer" max_tokens=50',
        '{"msg": "Token type is Bearer "}',
    ):
        assert redact_sensitive_data(preserved) == preserved
        assert redact_sensitive_data(redact_sensitive_data(preserved)) == preserved


# ---------------------------------------------------------------------------
# 10. Iteration 6 Regression Tests (Bearer Closing-Quote, Unclosed Bearer,
#     Unknown Scheme Collisions, Space-Separated Multi-Param, Scheme Prefixes)
# ---------------------------------------------------------------------------


def test_redact_sensitive_data_iteration6_bearer_quote_unknown_multiparam_and_schemes() -> None:
    # 1. Multi-field JSON, escaped JSON, and KV strings ending with "Bearer " must stay intact
    for preserved in (
        '{"msg": "Token type is Bearer ", "host": "web-01"}',
        'msg="Token type is Bearer " host="web-01"',
        r'{\"msg\": \"Token type is Bearer \", \"host\": \"web-01\"}',
        'msg="Authorization: Bearer " host="web-01"',
        '{"msg": "Authorization: Bearer ", "host": "web-01"}',
        "Authorization: Token token=\"<REDACTED>\"",
        "Authorization: Bearer <REDACTED>",
    ):
        assert redact_sensitive_data(preserved) == preserved
        assert redact_sensitive_data(redact_sensitive_data(preserved)) == preserved

    cases: list[tuple[str, str, tuple[str, ...]]] = [
        # Closing quote preserved while sibling secret field is redacted
        (
            '{"msg": "Token type is Bearer ", "api_key": "sec123"}',
            '{"msg": "Token type is Bearer ", "api_key": "<REDACTED>"}',
            ("sec123",),
        ),
        # Unclosed standalone Bearer "..."
        (
            'Bearer "unclosed_sec\nhost=web1',
            'Bearer "<REDACTED>\nhost=web1',
            ("unclosed_sec",),
        ),
        (
            'Bearer "unclosed_bearer_secret_999',
            'Bearer "<REDACTED>',
            ("unclosed_bearer_secret_999",),
        ),
        # Rule A (sep == "=") & Rule B (sep == ":") unknown-scheme collision fixes
        (
            'authorization=secretval1 host="web-01"',
            'authorization=<REDACTED> host="web-01"',
            ("secretval1",),
        ),
        (
            'proxy_authorization=paval2 bearer="b_val_3"',
            'proxy_authorization=<REDACTED> bearer="<REDACTED>"',
            ("paval2", "b_val_3"),
        ),
        (
            'Authorization: secretval1 host="web-01"',
            'Authorization: <REDACTED> host="web-01"',
            ("secretval1",),
        ),
        (
            'Authorization: paval2 token="tok_val_3"',
            'Authorization: <REDACTED> token="<REDACTED>"',
            ("paval2", "tok_val_3"),
        ),
        (
            "Authorization: my-raw-secret-tok host=web1",
            "Authorization: <REDACTED> host=web1",
            ("my-raw-secret-tok",),
        ),
        # Unlisted auth schemes with unquoted & comma-separated k=v params
        (
            "Authorization: UnknownScheme key=unquoted_secret_999",
            "Authorization: UnknownScheme <REDACTED>",
            ("unquoted_secret_999",),
        ),
        (
            "Authorization: UnknownScheme key=unk_val_sec, other=val2",
            "Authorization: UnknownScheme <REDACTED>",
            ("unk_val_sec", "val2"),
        ),
        (
            "Authorization: CustomAuth user=alice, key=secret_xyz_999",
            "Authorization: CustomAuth <REDACTED>",
            ("secret_xyz_999",),
        ),
        # Space-separated multi-parameter auth headers (preserving trailing non-auth host="web-01")
        (
            'Authorization: Token key="sec1_999" other="sec2_999"',
            "Authorization: Token <REDACTED>",
            ("sec1_999", "sec2_999"),
        ),
        (
            'Authorization: CustomScheme a="sec1_999" b="sec2_999"',
            "Authorization: CustomScheme <REDACTED>",
            ("sec1_999", "sec2_999"),
        ),
        (
            'Authorization: Bearer "part1_secret" extra="part2_secret"',
            "Authorization: Bearer <REDACTED>",
            ("part1_secret", "part2_secret"),
        ),
        (
            "Authorization: CustomAuth sk-abc1234567890 secret_part2",
            "Authorization: CustomAuth <REDACTED>",
            ("sk-abc1234567890", "secret_part2"),
        ),
        (
            'Authorization: CustomAuth sk-abc1234567890 host="web-01"',
            'Authorization: CustomAuth <REDACTED> host="web-01"',
            ("sk-abc1234567890",),
        ),
        (
            'Authorization: Bearer "part1_secret" host="web-01"',
            'Authorization: Bearer "<REDACTED>" host="web-01"',
            ("part1_secret",),
        ),
        # Non-auth sensitive keys carrying single-token schemes
        (
            "token=Splunk my_splunk_secret_999",
            "token=Splunk <REDACTED>",
            ("my_splunk_secret_999",),
        ),
        (
            "api_key=Token my_s1_secret_999",
            "api_key=Token <REDACTED>",
            ("my_s1_secret_999",),
        ),
        (
            "proxy_authorization=pa_val_2 bearer=b_val_3",
            "proxy_authorization=<REDACTED> bearer=<REDACTED>",
            ("pa_val_2", "b_val_3"),
        ),
        (
            "Authorization: Bearer abc123=def456",
            "Authorization: Bearer <REDACTED>",
            ("abc123=def456",),
        ),
    ]
    for raw, expected, forbidden in cases:
        out = redact_sensitive_data(raw)
        assert out == expected
        for secret in forbidden:
            assert secret not in out
        assert redact_sensitive_data(out) == out


def test_redact_sensitive_data_iteration6_unknown_multiparam_linear_time() -> None:
    for label, payload in (
        ("unknown_kv_space_90kb", "Authorization: UnknownScheme " + ("a=1 " * 18000)),
        ("unknown_kv_comma_90kb", "Authorization: UnknownScheme " + ("nonce=1, " * 18000)),
    ):
        t0 = time.process_time()
        out = redact_sensitive_data(payload)
        elapsed = time.process_time() - t0
        assert elapsed < 0.50, f"{label} took {elapsed:.4f}s CPU time (expected < 0.50s)"
        assert "Authorization: UnknownScheme <REDACTED>" in out

    t0 = time.process_time()
    non_auth_out = redact_sensitive_data("Authorization: rawsecretval6 " + ("a=1, " * 18000))
    assert (time.process_time() - t0) < 0.50
    assert non_auth_out.startswith("Authorization: <REDACTED> a=1, ")


# ---------------------------------------------------------------------------
# 11. Iteration 7 Regression Tests (PEM sv_m O(N), Non-Header Multiparam,
#     Unknown Scheme Log Keys, Escaped JSON \, Line Quote Parity)
# ---------------------------------------------------------------------------


def test_redact_sensitive_data_iteration7_multiparam_log_keys_escaped_json_and_quote_parity() -> None:
    # 1. Prose/concatenations ending with "Bearer " must stay intact without swallowing next quotes
    for preserved in (
        'Note: "Token type is Bearer " is used with "my_app"',
        'msg="Bearer " + "non_secret_suffix"',
        'Note: \'Token type is Bearer \' is used with \'my_app\'',
        r'{"msg": "{\"inner\": \"Token type is Bearer \"}", "host": "web-01"}',
    ):
        assert redact_sensitive_data(preserved) == preserved
        assert redact_sensitive_data(redact_sensitive_data(preserved)) == preserved

    cases: list[tuple[str, str, tuple[str, ...]]] = [
        # 2. Multi-parameter HTTP auth schemes under non-_AUTH_HEADER_KEYS (token=, api_key=)
        (
            'token=Digest username="alice", response="secret_resp_999"',
            "token=Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            "api_key=AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/2026/us-east-1/s3/aws4_request, Signature=secret_sig_999",
            "api_key=AWS4-HMAC-SHA256 <REDACTED>",
            ("secret_sig_999",),
        ),
        (
            'api_key=Hawk id="dh37fgj492je", mac="secret_mac_999"',
            "api_key=Hawk <REDACTED>",
            ("secret_mac_999",),
        ),
        # 3. Unlisted trailing log keys after raw Authorization secret (must redact secret, keep metadata)
        (
            'Authorization: rawsecretval1 region="us-east-1"',
            'Authorization: <REDACTED> region="us-east-1"',
            ("rawsecretval1",),
        ),
        (
            'Authorization: rawsecretval2 tenant="acme"',
            'Authorization: <REDACTED> tenant="acme"',
            ("rawsecretval2",),
        ),
        (
            'Authorization: rawsecretval3 user="alice"',
            'Authorization: <REDACTED> user="alice"',
            ("rawsecretval3",),
        ),
        (
            'Authorization: paval2 token="tok_val_3"',
            'Authorization: <REDACTED> token="<REDACTED>"',
            ("paval2", "tok_val_3"),
        ),
        (
            'Authorization: UnknownScheme key="unk_kv_123"',
            'Authorization: UnknownScheme key="<REDACTED>"',
            ("unk_kv_123",),
        ),
        (
            'Authorization: CustomScheme a="sec1_999" b="sec2_999"',
            "Authorization: CustomScheme <REDACTED>",
            ("sec1_999", "sec2_999"),
        ),
        (
            "Authorization: CustomAuth user=alice, key=secret_xyz_999",
            "Authorization: CustomAuth <REDACTED>",
            ("secret_xyz_999",),
        ),
        # 4. Escaped JSON must not lose trailing '\' before '\"'
        (
            r'{\"msg\": \"Authorization: Bearer my_sec_999\", \"host\": \"web-01\"}',
            r'{\"msg\": \"Authorization: Bearer <REDACTED>\", \"host\": \"web-01\"}',
            ("my_sec_999",),
        ),
        (
            r'{\"msg\": \"api_key=my_sec_999\", \"host\": \"web-01\"}',
            r'{\"msg\": \"api_key=<REDACTED>\", \"host\": \"web-01\"}',
            ("my_sec_999",),
        ),
        (
            r'{\"msg\": \"Authorization: CustomAuth user=alice, key=sec_999\", \"host\": \"web-01\"}',
            r'{\"msg\": \"Authorization: CustomAuth <REDACTED>\", \"host\": \"web-01\"}',
            ("sec_999",),
        ),
        (
            r'{\"msg\": \"api_key=Hawk id=\\\"dh37fgj492je\\\", mac=\\\"secret_mac_999\\\"\", \"host\": \"web-01\"}',
            r'{\"msg\": \"api_key=Hawk <REDACTED>\", \"host\": \"web-01\"}',
            ("secret_mac_999",),
        ),
        # 5. Quote parity: enclosing string stops before trailing " and ", while real quoted secrets starting with , or key= redact
        (
            'msg="Authorization: CustomAuth tok1_sec " and "more_text"',
            'msg="Authorization: CustomAuth <REDACTED> " and "more_text"',
            ("tok1_sec",),
        ),
        (
            'Bearer ",secret_starts_comma"',
            'Bearer "<REDACTED>"',
            ("secret_starts_comma",),
        ),
        (
            'Bearer " foo=secret_inside_quote"',
            'Bearer "<REDACTED>"',
            ("secret_inside_quote",),
        ),
        (
            'Authorization: Bearer ",secret_starts_comma"',
            'Authorization: Bearer "<REDACTED>"',
            ("secret_starts_comma",),
        ),
        (
            'Authorization: Bearer " foo=secret_inside_quote"',
            'Authorization: Bearer "<REDACTED>"',
            ("secret_inside_quote",),
        ),
    ]
    for raw, expected, forbidden in cases:
        out = redact_sensitive_data(raw)
        assert out == expected
        for secret in forbidden:
            assert secret not in out
        assert redact_sensitive_data(out) == out


def test_redact_sensitive_data_iteration7_cert_more_params_sv_linear_time() -> None:
    unit = 'Authorization: CustomScheme tok key="-----BEGIN CERTIFICATE-----\n' + ("A" * 20) + "\n"
    for suffix in ("", "-----END CERTIFICATE-----"):
        payload_small = (unit * 500) + suffix
        t0 = time.process_time()
        out_small = redact_sensitive_data(payload_small)
        dt_small = time.process_time() - t0
        assert "Authorization: CustomScheme <REDACTED>" in out_small

        payload_860kb = (unit * 10000) + suffix
        t1 = time.process_time()
        out_860kb = redact_sensitive_data(payload_860kb)
        dt_860kb = time.process_time() - t1
        assert "Authorization: CustomScheme <REDACTED>" in out_860kb
        assert dt_860kb < 0.75, f"860KB cert_more_params_sv took {dt_860kb:.4f}s CPU time (expected O(N) < 0.75s)"
        assert dt_860kb < max(0.15, dt_small * 40), (
            f"Non-linear scaling: 43KB={dt_small:.4f}s vs 860KB={dt_860kb:.4f}s"
        )

    # Also verify O(N) on long backslash runs before quotes in _SINGLE_VAL_RE
    for label, bs_payload in (
        ("bs_quote_50k", "api_key=" + ("\\" * 50000) + '"'),
        ("bs_nonquote_50k", "api_key=" + ("\\" * 50000) + "x"),
    ):
        t0 = time.process_time()
        out = redact_sensitive_data(bs_payload)
        elapsed = time.process_time() - t0
        assert elapsed < 0.25, f"{label} took {elapsed:.4f}s CPU time"
        assert redact_sensitive_data(out) == out


# ---------------------------------------------------------------------------
# 12. Iteration 8 Regression Tests (Bounded multi_m encl_close_idx O(N),
#     Unknown/Log Auth Key Disambiguation, Leading Log Key in multi_m,
#     Trailing Metadata Preservation, Escaped-Backslash Quote Parity)
# ---------------------------------------------------------------------------


def test_redact_sensitive_data_iteration8_multi_encl_linear_time() -> None:
    generators = [
        ("bs0_closed", lambda n: '"' + (r"token=Digest a=\1} " * n) + '"'),
        ("bs1_open", lambda n: r"\"" + (r"token=Digest a=\1} " * n)),
        ("no_brace", lambda n: '"' + (r"token=Digest a=1 host=x " * n) + '"'),
    ]
    for label, gen in generators:
        small = gen(500)
        t0 = time.process_time()
        out_small = redact_sensitive_data(small)
        dt_small = time.process_time() - t0
        assert "token=Digest <REDACTED>" in out_small

        large = gen(5000)
        t1 = time.process_time()
        out_large = redact_sensitive_data(large)
        dt_large = time.process_time() - t1
        assert "token=Digest <REDACTED>" in out_large
        assert dt_large < 0.50, f"{label} n=5000 took {dt_large:.4f}s CPU time (expected O(N) < 0.50s)"
        assert dt_large < max(0.15, dt_small * 40), (
            f"Non-linear scaling for {label}: n=500 {dt_small:.4f}s vs n=5000 {dt_large:.4f}s"
        )
        assert redact_sensitive_data(out_large) == out_large


def test_redact_sensitive_data_iteration8_auth_log_keys_multiparam_and_quote_parity() -> None:
    cases: list[tuple[str, str, tuple[str, ...]]] = [
        # Finding 2: raw secret before generic log keys & non-auth comma metadata must redact secret
        (
            'Authorization: rawsecretval7 id="req-123"',
            'Authorization: <REDACTED> id="req-123"',
            ("rawsecretval7",),
        ),
        (
            'Authorization: rawsecretval8 ts="2026-11-25"',
            'Authorization: <REDACTED> ts="2026-11-25"',
            ("rawsecretval8",),
        ),
        (
            'Authorization: rawsecretval6 cluster="prod", zone="us-east-1"',
            'Authorization: <REDACTED> cluster="prod", zone="us-east-1"',
            ("rawsecretval6",),
        ),
        (
            'Authorization: rawsecretval6 foo="1", bar="2"',
            'Authorization: <REDACTED> foo="1", bar="2"',
            ("rawsecretval6",),
        ),
        (
            'Authorization: rawsecretval10 id="req-123" ts="2026-11-25"',
            'Authorization: <REDACTED> id="req-123" ts="2026-11-25"',
            ("rawsecretval10",),
        ),
        (
            'Authorization: rawsecretval12 id="req-123" token="tok_val_3"',
            'Authorization: <REDACTED> id="req-123" token="<REDACTED>"',
            ("rawsecretval12", "tok_val_3"),
        ),
        # Unambiguous custom/standard multi-param schemes still redact cleanly
        (
            "Authorization: MyScheme custom_param=v1, auth_sig=secret_sig_123",
            "Authorization: MyScheme <REDACTED>",
            ("secret_sig_123",),
        ),
        (
            'Authorization: CustomHawk id="dh37", ts="1234", mac="secret_mac_999"',
            "Authorization: CustomHawk <REDACTED>",
            ("secret_mac_999",),
        ),
        (
            "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/2026/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=secret_sig_999",
            "Authorization: AWS4-HMAC-SHA256 <REDACTED>",
            ("secret_sig_999",),
        ),
        # Finding 3: leading log keys in multi_m & trailing metadata preservation
        (
            'token=Digest host="web-01", response="secret_resp_999"',
            "token=Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            'token=Digest time="1234", response="secret_resp_999"',
            "token=Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            'api_key=Hawk host="web-01", mac="secret_mac_999"',
            "api_key=Hawk <REDACTED>",
            ("secret_mac_999",),
        ),
        (
            'token=Digest username="alice", response="secret_resp_999" host="web-01"',
            'token=Digest <REDACTED> host="web-01"',
            ("secret_resp_999",),
        ),
        (
            'token=Digest host="web-01", response="secret_resp_999" region="us-east-1"',
            'token=Digest <REDACTED> region="us-east-1"',
            ("secret_resp_999",),
        ),
        (
            'token=Digest host="web-01"',
            'token=<REDACTED> host="web-01"',
            (),
        ),
        (
            'token=Digest host="web-01", user_agent="curl"',
            'token=<REDACTED> host="web-01", user_agent="curl"',
            (),
        ),
        # Finding 4: escaped-backslash closing quote parity (\\\\\" closes \")
        (
            r'{\"a\": \"hello\\\\\" + \"Bearer \" + \"world\", \"b\": \"Bearer real_sec_999\"}',
            r'{\"a\": \"hello\\\\\" + \"Bearer \" + \"world\", \"b\": \"Bearer <REDACTED>\"}',
            ("real_sec_999",),
        ),
        # Optional Reviewer R7 idempotency note
        (
            "api_key=&sk-1234567890abcdef=1",
            "api_key=&<REDACTED>=1",
            ("sk-1234567890abcdef",),
        ),
    ]
    for raw, expected, forbidden in cases:
        out = redact_sensitive_data(raw)
        assert out == expected
        for secret in forbidden:
            assert secret not in out
        assert redact_sensitive_data(out) == out

    for preserved in (
        r'{\"a\": \"hello\\\\\" + \"Bearer \" + \"world\"}',
        r'{\"a\": \"hello\\\\\" + \"Authorization: Bearer \" + \"world\"}',
        r'{\"a\": \"hello\\\\\\\\\" + \"Bearer \" + \"world\"}',
    ):
        assert redact_sensitive_data(preserved) == preserved
        assert redact_sensitive_data(redact_sensitive_data(preserved)) == preserved


# ---------------------------------------------------------------------------
# 13. Iteration 9 Regression Tests (RFC Digest/Hawk/Signature/OAuth Params,
#     Space/Sensitive Auth Disambiguation, Quote Tracker Rollback & bs=2/6/10)
# ---------------------------------------------------------------------------


def test_redact_sensitive_data_iteration9_rfc_auth_params_rollback_and_quote_parity() -> None:
    cases: list[tuple[str, str, tuple[str, ...]]] = [
        # 1. RFC 7616 Digest (uri=, host=), Hawk (app=, ts=), Signature (expires_in=, method=, path=), OAuth
        (
            'Authorization: Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b71", uri="/dir/index.html", qop=auth, nc=00000001, cnonce="0a4f113b", response="secret_resp_999", opaque="5ccc069c"',
            "Authorization: Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            'token=Digest username="alice", uri="/api/secret", response="secret_resp_999"',
            "token=Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            'token=Digest host="web-01", uri="/api/secret", response="secret_resp_999"',
            "token=Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            'Authorization: Digest username="alice", host="web-01", response="secret_resp_999"',
            "Authorization: Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            'Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", app="my-app", mac="secret_mac_999"',
            "Authorization: Hawk <REDACTED>",
            ("secret_mac_999",),
        ),
        (
            'token=Hawk id="dh37fgj492je", ts="1353832234", app="my-app", mac="secret_mac_999"',
            "token=Hawk <REDACTED>",
            ("secret_mac_999",),
        ),
        (
            'Authorization: Signature keyId="k1", expires_in="60", signature="secret_sig_999"',
            "Authorization: Signature <REDACTED>",
            ("secret_sig_999",),
        ),
        (
            'Authorization: Signature keyId="k1", method="POST", path="/v1", signature="secret_sig_999"',
            "Authorization: Signature <REDACTED>",
            ("secret_sig_999",),
        ),
        (
            'token=OAuth realm="Example", oauth_consumer_key="k1", oauth_signature="secret_oauth_sig_999"',
            "token=OAuth <REDACTED>",
            ("secret_oauth_sig_999",),
        ),
        (
            "token=OAuth oauth_consumer_key=k1, oauth_signature=secret_oauth_sig_999",
            "token=OAuth <REDACTED>",
            ("secret_oauth_sig_999",),
        ),
        (
            'Authorization: CustomAuth id="1", app="my-app", mac="secret_mac_999"',
            "Authorization: CustomAuth <REDACTED>",
            ("secret_mac_999",),
        ),
        (
            'Authorization: CustomAuth realm="Example", host="web-01", mac="secret_mac_999"',
            "Authorization: CustomAuth <REDACTED>",
            ("secret_mac_999",),
        ),
        # Reviewer R8 Minor note: comma-less space-separated Hawk with ts= / app= before mac=
        (
            'Authorization: Hawk id="dh37" ts="1234" mac="secret_mac_999"',
            "Authorization: Hawk <REDACTED>",
            ("secret_mac_999",),
        ),
        (
            'Authorization: Hawk id="dh37" ts="1234" app="my-app" mac="secret_mac_999"',
            "Authorization: Hawk <REDACTED>",
            ("secret_mac_999",),
        ),
        # Trailing space-separated metadata & non-auth Digest still preserve metadata
        (
            'token=Digest username="alice", response="secret_resp_999" uri="/api/public"',
            'token=Digest <REDACTED> uri="/api/public"',
            ("secret_resp_999",),
        ),
        (
            'token=Digest username="alice", response="secret_resp_999" app="soclens"',
            'token=Digest <REDACTED> app="soclens"',
            ("secret_resp_999",),
        ),
        (
            'Authorization: Hawk id="dh37" ts="1234"',
            'Authorization: Hawk <REDACTED> ts="1234"',
            ("dh37",),
        ),
        (
            'token=Digest host="web-01", user_agent="curl"',
            'token=<REDACTED> host="web-01", user_agent="curl"',
            (),
        ),
        (
            'token=Digest host="web-01", uri="/api/public"',
            'token=<REDACTED> host="web-01", uri="/api/public"',
            (),
        ),
        # 2. Raw Authorization secret before space/comma log keys + sensitive keys must redact secret
        (
            'Authorization: rawsecretval11 id="req-123" nonce="abc"',
            'Authorization: <REDACTED> id="req-123" nonce="abc"',
            ("rawsecretval11",),
        ),
        (
            'Authorization: rawsecretval12 ts="2026-11-25" key="my_secret"',
            'Authorization: <REDACTED> ts="2026-11-25" key="my_secret"',
            ("rawsecretval12",),
        ),
        (
            'Authorization: rawsecretval13 account="acme" realm="corp"',
            'Authorization: <REDACTED> account="acme" realm="corp"',
            ("rawsecretval13",),
        ),
        (
            'Authorization: rawsecretval14 namespace="prod" mac="macval"',
            'Authorization: <REDACTED> namespace="prod" mac="macval"',
            ("rawsecretval14",),
        ),
        (
            'Authorization: rawsecretval15 id="req-123", token="tok_val_3"',
            'Authorization: <REDACTED> id="req-123", token="<REDACTED>"',
            ("rawsecretval15", "tok_val_3"),
        ),
        (
            'Authorization: rawsecretval16 host="web-01", api_key="sec_123"',
            'Authorization: <REDACTED> host="web-01", api_key="<REDACTED>"',
            ("rawsecretval16", "sec_123"),
        ),
        (
            'Authorization: rawsecretval17 ts="2026-11-25", secret="sec_456"',
            'Authorization: <REDACTED> ts="2026-11-25", secret="<REDACTED>"',
            ("rawsecretval17", "sec_456"),
        ),
        (
            'Authorization: rawsecretval18 cluster="prod", credential="cred_789"',
            'Authorization: <REDACTED> cluster="prod", credential="<REDACTED>"',
            ("rawsecretval18", "cred_789"),
        ),
        (
            'Authorization: rawsecretval8 ts="2026-11-25"',
            'Authorization: <REDACTED> ts="2026-11-25"',
            ("rawsecretval8",),
        ),
        # 3. _LineQuoteTracker speculative lookahead rollback on False
        (
            'token=Digest host="Authorization: Bearer ", foo="1", bar="2"',
            'token=<REDACTED> host="Authorization: Bearer ", foo="1", bar="2"',
            (),
        ),
        (
            'Authorization: rawsecretval6 host="Authorization: Bearer ", foo="1", bar="2"',
            'Authorization: <REDACTED> host="Authorization: Bearer ", foo="1", bar="2"',
            ("rawsecretval6",),
        ),
        # 4. Balanced bs=2/bs=6 JSON field with space followed by Bearer secret
        (
            r'{\\"a\\": \\"hello\\\\\\" world\\", \\"b\\": \\"Bearer secret_999\\"}',
            r'{\\"a\\": \\"hello\\\\\\" world\\", \\"b\\": \\"Bearer <REDACTED>\\"}',
            ("secret_999",),
        ),
        # 5. Multiline unclosed quote idempotency when next line also gets redacted
        (
            'Authorization: \\\\"nonce=id=response=ts=\'abc123}uri=\ntoken=uri=oauth_signature=\\\\"',
            'Authorization: \\\\"<REDACTED>\ntoken=<REDACTED>\\\\"',
            ("oauth_signature",),
        ),
    ]
    for raw, expected, forbidden in cases:
        out = redact_sensitive_data(raw)
        assert out == expected, f"Mismatch for {raw!r}:\n  OUT: {out!r}\n  EXP: {expected!r}"
        for secret in forbidden:
            assert secret not in out
        assert redact_sensitive_data(out) == out

    # Balanced bs=2/bs=6/bs=10 JSON & non-JSON & single-quote parity preservation
    for preserved in (
        r'a=\\"hello\\\\\\"world\\" + \\"Bearer \\" + \\"y\\"',
        r'a=\\"hello\\\\\\"world\\" + "Bearer " + "y"',
        r'a=\\"h\\\\\\"w\\\\\\" + \\"Bearer \\" + \\"y\\"',
        r'{\\"a\\": \\"hello\\\\\\"world\\" + \\"Bearer \\" + \\"y\\"}',
        r'{\\"a\\": \\"hello\\\\\\" world\\", \\"b\\": \\"Bearer \\" + \\"y\\"}',
        r'{\\"a\\": \\"hello\\\\\\" , \\"b\\": \\"Bearer \\"}',
        r"a=\\'hello\\\\\\'world\\' + \\'Bearer \\' + \\'y\\'",
        r'a=\\"hello\\\\\\\\\\\\\\"world\\" + \\"Bearer \\" + \\"y\\"',
    ):
        assert redact_sensitive_data(preserved) == preserved
        assert redact_sensitive_data(redact_sensitive_data(preserved)) == preserved


def test_redact_sensitive_data_iteration9_bs2_bs6_and_multiparam_lookahead_linear_time() -> None:
    bs_small = r'a=\\"' + (r'hello\\\\\\"world' * 1000) + r'\\" + \\"Bearer \\" + \\"y\\"'
    t0 = time.process_time()
    assert redact_sensitive_data(bs_small) == bs_small
    dt_small = time.process_time() - t0

    bs_large = r'a=\\"' + (r'hello\\\\\\"world' * 10000) + r'\\" + \\"Bearer \\" + \\"y\\"'
    t1 = time.process_time()
    assert redact_sensitive_data(bs_large) == bs_large
    dt_large = time.process_time() - t1
    assert dt_large < 0.50, f"170KB bs=2/bs=6 payload took {dt_large:.4f}s CPU time (expected < 0.50s)"
    assert dt_large < max(0.15, dt_small * 40), (
        f"Non-linear bs=2/bs=6 scaling: 17KB={dt_small:.4f}s vs 170KB={dt_large:.4f}s"
    )

    uri_chain = "Authorization: Digest a=1 " + ("uri=1 " * 20000)
    t2 = time.process_time()
    uri_out = redact_sensitive_data(uri_chain)
    dt_uri = time.process_time() - t2
    assert dt_uri < 0.50, f"120KB space optional uri chain took {dt_uri:.4f}s CPU time"
    assert uri_out.startswith("Authorization: Digest <REDACTED> uri=1 ")
    assert redact_sensitive_data(uri_out) == uri_out


# ---------------------------------------------------------------------------
# 14. Iteration 10 Regression Tests (OAuth Multi-Param & host/oauth_token First,
#     32-Step Space/Comma Lookahead Caps, encl_close_idx Cursor Sync & JSON
#     encl_is_json, JSON Array bs=2/bs=6 Parity, Lazy Single-Line Quote Scan)
# ---------------------------------------------------------------------------


def test_redact_sensitive_data_iteration10_oauth_lookahead_caps_rollback_and_json_arrays() -> None:
    exact_cases: list[tuple[str, str, tuple[str, ...]]] = [
        # Finding 2: OAuth multi-param with log keys, host=/oauth_token=-first, quoted-first
        (
            'Authorization: OAuth realm="Example", method="POST", oauth_signature="secret_oauth_sig_999"',
            "Authorization: OAuth <REDACTED>",
            ("secret_oauth_sig_999",),
        ),
        (
            'Authorization: OAuth realm="Example", host="api.example.com", oauth_signature="secret_oauth_sig_999"',
            "Authorization: OAuth <REDACTED>",
            ("secret_oauth_sig_999",),
        ),
        (
            'Authorization: OAuth oauth_consumer_key="k1", timestamp="12345", oauth_signature="secret_oauth_sig_999"',
            "Authorization: OAuth <REDACTED>",
            ("secret_oauth_sig_999",),
        ),
        (
            'token=OAuth realm="Example", host="api.example.com", oauth_signature="secret_oauth_sig_999"',
            "token=OAuth <REDACTED>",
            ("secret_oauth_sig_999",),
        ),
        (
            "Authorization: OAuth oauth_consumer_key=k1, host=api.example.com, oauth_signature=secret_oauth_sig_999",
            "Authorization: OAuth <REDACTED>",
            ("secret_oauth_sig_999",),
        ),
        (
            'token=OAuth host="api.example.com", oauth_token="tok_123", oauth_signature="secret_oauth_sig_999"',
            "token=OAuth <REDACTED>",
            ("tok_123", "secret_oauth_sig_999"),
        ),
        (
            'Authorization: OAuth host="api.example.com", oauth_token="tok_123", oauth_signature="secret_oauth_sig_999"',
            "Authorization: OAuth <REDACTED>",
            ("tok_123", "secret_oauth_sig_999"),
        ),
        (
            'Authorization: OAuth oauth_token="tok_123", host="api.example.com", oauth_signature="secret_oauth_sig_999"',
            "Authorization: OAuth <REDACTED>",
            ("tok_123", "secret_oauth_sig_999"),
        ),
        (
            'token=OAuth oauth_token="tok_123", host="api.example.com", oauth_signature="secret_oauth_sig_999"',
            "token=OAuth <REDACTED>",
            ("tok_123", "secret_oauth_sig_999"),
        ),
        (
            'Authorization: OAuth "tok", host="api.example.com", oauth_signature="secret_oauth_sig_999"',
            "Authorization: OAuth <REDACTED>",
            ("secret_oauth_sig_999",),
        ),
        (
            'token=OAuth host="web-01"',
            'token=<REDACTED> host="web-01"',
            (),
        ),
        (
            "Authorization: OAuth raw_token_123",
            "Authorization: OAuth <REDACTED>",
            ("raw_token_123",),
        ),
        # Finding 4: _has_multiparam_space_auth_ahead 32-step cap & comma-host= support
        (
            'Authorization: Hawk id="dh37" ts="1234" headers="host" uri="/v1" app="my-app" mac="secret_mac_999"',
            "Authorization: Hawk <REDACTED>",
            ("secret_mac_999",),
        ),
        (
            'Authorization: Hawk id="dh37" ts="1234" ext="info" dlg="app2" app="my-app" mac="secret_mac_999"',
            "Authorization: Hawk <REDACTED>",
            ("secret_mac_999",),
        ),
        (
            'Authorization: Digest uri="/dir/index.html" id="1" ts="2" headers="h" app="a" response="secret_resp_999"',
            "Authorization: Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            'Authorization: Digest username="alice" uri="/api/secret", host="web-01", response="secret_resp_999"',
            "Authorization: Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            'Authorization: Hawk id="dh37" ts="1234" host="web-01" mac="00:11:22:33:44:55"',
            'Authorization: Hawk <REDACTED> ts="1234" host="web-01" mac="00:11:22:33:44:55"',
            ("dh37",),
        ),
        # Finding 5: _has_comma_auth_param 32-step cap
        (
            'token=Digest host="1", ip="2", port="3", method="4", path="5", url="6", status="7", env="8", region="9", response="secret_resp_999"',
            "token=Digest <REDACTED>",
            ("secret_resp_999",),
        ),
        (
            'Authorization: CustomAuth id="1", host="2", ip="3", port="4", path="5", url="6", env="7", region="8", cluster="9", mac="secret_mac_999"',
            "Authorization: CustomAuth <REDACTED>",
            ("secret_mac_999",),
        ),
        # Finding 3 & Explorer 1: JSON bs=2/bs=6 encl_is_json & comma disambiguation
        (
            r'{\\"k\\": \\"Authorization: Digest a=1, b=\\\\\\"1 \\\\\\" , response=secret_resp_999\\", \\"other\\": \\"x\\"}',
            r'{\\"k\\": \\"Authorization: Digest <REDACTED>\\", \\"other\\": \\"x\\"}',
            ("secret_resp_999",),
        ),
        (
            r'{\\"k\\": \\"Authorization: Digest a=1, b=\\\\\\"1 \\\\\\" response=secret_resp_999\\", \\"other\\": \\"x\\"}',
            r'{\\"k\\": \\"Authorization: Digest <REDACTED>\\", \\"other\\": \\"x\\"}',
            ("secret_resp_999",),
        ),
        # Finding 6: Non-JSON semicolon prose still redacts Bearer after bs=6
        (
            r'a=1, \\"hello\\\\\\"; Bearer secret_999',
            r'a=1, \\"hello\\\\\\"; Bearer <REDACTED>',
            ("secret_999",),
        ),
    ]
    for raw, expected, forbidden in exact_cases:
        out1 = redact_sensitive_data(raw)
        assert out1 == expected, f"Mismatch for {raw!r}:\n  OUT: {out1!r}\n  EXP: {expected!r}"
        for secret in forbidden:
            assert secret not in out1
        assert redact_sensitive_data(out1) == out1

    # Finding 3 & Explorer 1 Caveat #1: encl_close_idx rollback sync & idempotency
    rollback_cases: list[tuple[str, str]] = [
        (
            "'Authorization: Digest a=\"1' Authorization: Basic 'secret_999' ' \" , b=\"2\"",
            "secret_999",
        ),
        (
            "'Authorization: Digest a=\"1' Authorization: Splunk 'secret_999' ' \" , b=\"2\"",
            "secret_999",
        ),
        (
            "'Authorization: Digest a=\"1' Authorization: Basic 'non_secret' ' \" , b=\"2\"",
            "non_secret",
        ),
        (
            "'Authorization: OAuth a=\"1' Authorization: Basic 'secret_999' ' \" , b=\"2\"",
            "secret_999",
        ),
        (
            "'Authorization: Digest \"1' Authorization: Basic 'secret_999' \"",
            "secret_999",
        ),
    ]
    for raw, leak in rollback_cases:
        out1 = redact_sensitive_data(raw)
        out2 = redact_sensitive_data(out1)
        assert leak not in out1, f"Leaked {leak!r} in {out1!r}"
        assert out1 == out2, f"Non-idempotent for {raw!r}: {out1!r} != {out2!r}"

    # Finding 6: JSON array bs=2/bs=6 parity preservation (single-line & multiline)
    for preserved in (
        r'{\\"items\\": [\\"hello\\\\\\" world\\", \\"Bearer \\" + \\"y\\"]}',
        r'{\\"items\\": [1, \\"hello\\\\\\" world\\", \\"Bearer \\" + \\"y\\"]}',
        r'{\\"items\\": [true, \\"hello\\\\\\" world\\", \\"Bearer \\" + \\"y\\"]}',
        r'{\\"items\\": [false, \\"hello\\\\\\" world\\", \\"Bearer \\" + \\"y\\"]}',
        r'{\\"items\\": [null, \\"hello\\\\\\" world\\", \\"Bearer \\" + \\"y\\"]}',
        r'{\\"items\\": ['
        + "\n  1,\n"
        + r'  \\"hello\\\\\\" world\\", \\"Bearer \\" + \\"y\\"'
        + "\n]}",
    ):
        assert redact_sensitive_data(preserved) == preserved
        assert redact_sensitive_data(redact_sensitive_data(preserved)) == preserved


def test_redact_sensitive_data_iteration10_linear_scaling() -> None:
    scaling_generators = [
        (
            "unk_space",
            lambda n: 'Authorization: tok1 foo="' + ('Authorization: tok2 bar=\\"x\\" ' * n) + '"',
        ),
        (
            "unk_comma",
            lambda n: 'Authorization: tok1 foo="'
            + ('Authorization: tok2 bar=\\"x\\", host=\\"y\\" ' * n)
            + '"',
        ),
        (
            "oauth_id",
            lambda n: 'Authorization: tok1 foo="' + ('Authorization: OAuth a=1 id="x" ' * n) + '"',
        ),
    ]
    for label, gen in scaling_generators:
        small = gen(250)
        t0 = time.process_time()
        redact_sensitive_data(small)
        dt_small = time.process_time() - t0

        large = gen(5000)
        t1 = time.process_time()
        out_large = redact_sensitive_data(large)
        dt_large = time.process_time() - t1
        assert dt_large < 0.50, f"{label} n=5000 took {dt_large:.4f}s CPU time (expected < 0.50s)"
        assert dt_large < max(0.15, dt_small * 40), (
            f"Non-linear scaling for {label}: n=250 {dt_small:.4f}s vs n=5000 {dt_large:.4f}s"
        )
        assert redact_sensitive_data(out_large) == out_large

    large_payloads = [
        (
            "hawk_ts_30_mac_490k",
            ('Authorization: Hawk id="1" ' + ('ts="1" ' * 30) + 'mac="s" ') * 2000,
        ),
        (
            "hawk_bs1_618k",
            '"' + ('Authorization: Hawk id=\\"1\\" ' + ('ts=\\"1\\" ' * 30) + 'mac=\\"s\\" ') * 2000 + '"',
        ),
        (
            "customauth_comma_30_668k",
            ('Authorization: CustomAuth id="1", ' + ('host="2", ' * 30)) * 2000,
        ),
        (
            "cert_more_params_sv_860k",
            ('Authorization: CustomAuth id="1", ' + ('cert="abc", ' * 38)) * 2000,
        ),
    ]
    for label, payload in large_payloads:
        t0 = time.process_time()
        out = redact_sensitive_data(payload)
        dt = time.process_time() - t0
        assert dt < 2.50, f"{label} ({len(payload)} B) took {dt:.4f}s CPU time (expected < 2.50s)"
        assert redact_sensitive_data(out) == out


def test_redact_sensitive_data_auth_and_auth_key_regression() -> None:
    samples: list[tuple[Any, tuple[str, ...]]] = [
        ("auth=secret-val-1", ("secret-val-1",)),
        ("Check 198.51.100.10 (auth=canary-secret-123)", ("canary-secret-123",)),
        ("auth: secret-val-2", ("secret-val-2",)),
        ('auth="secret-val-3"', ("secret-val-3",)),
        ('{"auth": "secret-val-4", "auth_mode": "token"}', ("secret-val-4",)),
        ("Auth-Key: abusech-key-5", ("abusech-key-5",)),
        ("auth_key=abusech-key-6 auth-key=abusech-key-7", ("abusech-key-6", "abusech-key-7")),
    ]
    for raw, leaks in samples:
        out1 = redact_sensitive_data(raw)
        out2 = redact_sensitive_data(out1)
        assert isinstance(out1, str)
        assert "<REDACTED>" in out1
        for leak in leaks:
            assert leak not in out1, f"Leaked {leak!r} in {out1!r}"
        assert out1 == out2, f"Non-idempotent for {raw!r}: {out1!r} != {out2!r}"

    dict_redacted = redact_sensitive_data(
        {
            "auth": "secret-val-8",
            "auth_key": "abusech-key-9",
            "auth-key": "abusech-key-10",
            "auth_mode": "token",
            "ms_auth_mode": "delegated",
            "auth_method": "az_cli",
        }
    )
    assert dict_redacted == {
        "auth": "<REDACTED>",
        "auth_key": "<REDACTED>",
        "auth-key": "<REDACTED>",
        "auth_mode": "token",
        "ms_auth_mode": "delegated",
        "auth_method": "az_cli",
    }
    assert redact_sensitive_data(dict_redacted) == dict_redacted

    nested_vault = redact_sensitive_data(
        {"auth": {"client_token": "vault-tok-123", "lease_duration": 3600}}
    )
    assert nested_vault == {"auth": {"client_token": "<REDACTED>", "lease_duration": 3600}}
    assert redact_sensitive_data(nested_vault) == nested_vault

    preserved_meta = (
        "auth_mode=cli ms_auth_mode=delegated auth_method=az_cli "
        "oauth=false auth_status=ok qop=auth"
    )
    assert redact_sensitive_data(preserved_meta) == preserved_meta

    digest_hdr = 'Authorization: Digest username="alice", qop=auth, response="sec-digest-val"'
    digest_out = redact_sensitive_data(digest_hdr)
    assert digest_out == "Authorization: Digest <REDACTED>"
    assert redact_sensitive_data(digest_out) == digest_out


def test_audit_log_store_redacts_provider_while_preserving_valid_providers(
    tmp_path: Path,
) -> None:
    store = AuditLogStore(tmp_path / "ai_audit.jsonl")
    valid_providers = (
        "m365_copilot",
        "copilot_studio",
        "copilot_directline",
        "security_copilot",
        "ollama",
        "openai",
    )
    for idx, prov in enumerate(valid_providers):
        store.append(
            AuditEntry(
                entry_id=f"prov-{idx}",
                timestamp="2026-11-26T02:00:00Z",
                run_id="run-prov",
                event_key="rf_alert::p1",
                provider=prov,
                mode="full_investigation",
                event_type="prompt",
            )
        )

    store.append(
        AuditEntry(
            entry_id="prov-secret",
            timestamp="2026-11-26T02:00:01Z",
            run_id="run-prov",
            event_key="rf_alert::p1",
            provider="openai auth=prov-secret-123 Bearer prov-bearer-456 Auth-Key: prov-ak-789",
            mode="full_investigation",
            event_type="prompt",
        )
    )

    raw_disk = store.path.read_text(encoding="utf-8")
    assert "prov-secret-123" not in raw_disk
    assert "prov-bearer-456" not in raw_disk
    assert "prov-ak-789" not in raw_disk

    entries = store.query(limit=20)
    assert [e.provider for e in entries[: len(valid_providers)]] == list(valid_providers)
    assert "<REDACTED>" in entries[-1].provider


def test_redact_sensitive_data_auth_linear_scaling() -> None:
    payloads = [
        ("auth_query_25k", "auth=secret123&" * 25000, "secret123"),
        ("auth_paren_5k", "Check 1.2.3.4 (auth=tok123) " * 5000, "tok123"),
    ]
    for label, payload, secret in payloads:
        t0 = time.process_time()
        out = redact_sensitive_data(payload)
        dt = time.process_time() - t0
        assert dt < 0.75, f"{label} ({len(payload)} B) took {dt:.4f}s CPU time (expected < 0.75s)"
        assert secret not in out
        assert redact_sensitive_data(out) == out


def test_redact_sensitive_data_redacted_prefix_bypass_regression() -> None:
    bypass_cases: list[tuple[str, str, str]] = [
        ("auth=<REDACTED>supersecret123", "supersecret123", "auth=<REDACTED>"),
        ("auth=<REDACTED_JWT>supersecret123", "supersecret123", "auth=<REDACTED>"),
        ("Auth-Key: <REDACTED>secret_ak_666", "secret_ak_666", "Auth-Key: <REDACTED>"),
        ("Auth-Key: <REDACTED_JWT>secret_ak_666", "secret_ak_666", "Auth-Key: <REDACTED>"),
        (
            "Authorization: Bearer <REDACTED>supersecret123",
            "supersecret123",
            "Authorization: Bearer <REDACTED>",
        ),
        (
            "Authorization: Bearer <REDACTED_JWT>supersecret123",
            "supersecret123",
            "Authorization: Bearer <REDACTED>",
        ),
        (
            "Authorization: Digest <REDACTED>supersecret123",
            "supersecret123",
            "Authorization: Digest <REDACTED>",
        ),
        (
            "Authorization: Digest <REDACTED_JWT>supersecret123",
            "supersecret123",
            "Authorization: Digest <REDACTED>",
        ),
        (
            'Authorization: Digest <REDACTED>, response="secret_resp_123"',
            "secret_resp_123",
            "Authorization: Digest <REDACTED>",
        ),
        ("Bearer <REDACTED>secret_br_888", "secret_br_888", "Bearer <REDACTED>"),
        ("Bearer <REDACTED_JWT>secret_br_888", "secret_br_888", "Bearer <REDACTED>"),
        (
            "token is Bearer <REDACTED>secret_br_888 in header",
            "secret_br_888",
            "token is Bearer <REDACTED> in header",
        ),
        ("ApiToken <REDACTED>secret_at_777", "secret_at_777", "ApiToken <REDACTED>"),
        ("ApiToken <REDACTED_JWT>secret_at_777", "secret_at_777", "ApiToken <REDACTED>"),
        (
            "https://example.com/cb?auth=<REDACTED>secret_qry_999&mode=1",
            "secret_qry_999",
            "https://example.com/cb?auth=<REDACTED>&mode=1",
        ),
        (
            "https://example.com/cb?auth=<REDACTED_JWT>secret_qry_999&mode=1",
            "secret_qry_999",
            "https://example.com/cb?auth=<REDACTED>&mode=1",
        ),
        (
            "https://example.com/cb?signature=<REDACTED>secret_sig_999&mode=1",
            "secret_sig_999",
            "https://example.com/cb?signature=<REDACTED>&mode=1",
        ),
        (
            "Authorization: CustomAuth qop=auth, auth=<REDACTED>secret, nc=1",
            "secret",
            "Authorization: CustomAuth <REDACTED>",
        ),
        (
            "Authorization: CustomAuth <REDACTED>secret, nc=1",
            "secret",
            "Authorization: CustomAuth <REDACTED>",
        ),
        (
            "Authorization: CustomAuth auth=<REDACTED>secret, nc=1",
            "secret",
            "Authorization: <REDACTED> auth=<REDACTED>, nc=1",
        ),
        ("Authorization: <REDACTED>supersecret123", "supersecret123", "Authorization: <REDACTED>"),
        ("Bearer custom_param=<REDACTED>secret_cp", "secret_cp", "Bearer <REDACTED>"),
        ("Bearer <REDACTED>s", "<REDACTED>s", "Bearer <REDACTED>"),
    ]
    for raw, secret, expected in bypass_cases:
        out = redact_sensitive_data(raw)
        assert secret not in out, f"Leaked {secret!r} in {out!r}"
        assert out == expected, f"Mismatch for {raw!r}: {out!r} != {expected!r}"
        assert redact_sensitive_data(out) == out, f"Non-idempotent output: {out!r}"

    clean_preserved: list[tuple[str, str]] = [
        ("auth=<REDACTED>", "auth=<REDACTED>"),
        ("auth=<REDACTED>&mode=1", "auth=<REDACTED>&mode=1"),
        ("auth=<REDACTED_JWT>&mode=1", "auth=<REDACTED_JWT>&mode=1"),
        ("Bearer <REDACTED>", "Bearer <REDACTED>"),
        ("Bearer <REDACTED_JWT>", "Bearer <REDACTED_JWT>"),
        ("token is Bearer <REDACTED> in header", "token is Bearer <REDACTED> in header"),
        ("<td>Bearer <REDACTED></td>", "<td>Bearer <REDACTED></td>"),
        ("Auth-Key: <REDACTED>", "Auth-Key: <REDACTED>"),
        ("Authorization: Bearer <REDACTED>", "Authorization: Bearer <REDACTED>"),
        ("Authorization: Bearer <REDACTED_JWT>", "Authorization: Bearer <REDACTED_JWT>"),
        ("Authorization: Digest <REDACTED>", "Authorization: Digest <REDACTED>"),
        ('Authorization: Hawk <REDACTED> ts="1234"', 'Authorization: Hawk <REDACTED> ts="1234"'),
        (
            "Authorization: CustomAuth qop=auth, auth=<REDACTED>, nc=1",
            "Authorization: CustomAuth <REDACTED>",
        ),
        ("https://example.com/cb?auth=<REDACTED>&mode=1", "https://example.com/cb?auth=<REDACTED>&mode=1"),
        (
            "https://example.com/cb?auth=<REDACTED_JWT>&mode=1",
            "https://example.com/cb?auth=<REDACTED_JWT>&mode=1",
        ),
        ("Bearer custom_param=<REDACTED>", "Bearer custom_param=<REDACTED>"),
        ('Bearer token="<REDACTED>"', 'Bearer token="<REDACTED>"'),
    ]
    for raw, expected in clean_preserved:
        out = redact_sensitive_data(raw)
        assert out == expected
        assert redact_sensitive_data(out) == out


def test_audit_log_store_redacts_redacted_prefix_bypass_end_to_end(tmp_path: Path) -> None:
    audit_path = tmp_path / "ai_audit.jsonl"
    store = AuditLogStore(audit_path)
    canaries = (
        "e2e_prefix_canary_777",
        "e2e_bearer_prefix_888",
        "e2e_ak_prefix_666",
        "e2e_qry_prefix_999",
        "e2e_jwt_prefix_555",
        "e2e_prov_prefix_444",
    )
    store.append(
        AuditEntry(
            entry_id="prefix-e2e-1",
            timestamp="2026-11-26T02:15:00Z",
            run_id="run-prefix",
            event_key="rf_alert::prefix-1",
            provider="m365_copilot auth=<REDACTED>e2e_prov_prefix_444",
            mode="full_investigation",
            event_type="prompt",
            reason="Auth-Key: <REDACTED>e2e_ak_prefix_666",
            payload={
                "event_context_preview": (
                    "auth=<REDACTED>e2e_prefix_canary_777 "
                    "Authorization: Bearer <REDACTED>e2e_bearer_prefix_888 "
                    "https://example.com/cb?auth=<REDACTED_JWT>e2e_qry_prefix_999&mode=1 "
                    "ApiToken <REDACTED_JWT>e2e_jwt_prefix_555"
                )
            },
        )
    )
    raw_disk = audit_path.read_text(encoding="utf-8")
    for canary in canaries:
        assert canary not in raw_disk

    reloaded = AuditLogStore(audit_path).query(limit=10)
    assert len(reloaded) == 1
    assert "<REDACTED>" in reloaded[0].provider
    assert "<REDACTED>" in reloaded[0].reason
    assert "<REDACTED>" in reloaded[0].payload["event_context_preview"]


def test_redact_sensitive_data_redacted_prefix_linear_scaling() -> None:
    payloads = [
        ("auth_prefix_25k", "auth=<REDACTED>sec&" * 25000, "sec"),
        ("bearer_prefix_5k", "Bearer <REDACTED>sec " * 5000, "sec"),
        ("auth_clean_25k", "auth=<REDACTED>&" * 25000, None),
        ("bearer_clean_5k", "Bearer <REDACTED> " * 5000, None),
        ("url_prefix_5k", "https://example.com/cb?auth=<REDACTED>sec&mode=1 " * 5000, "sec"),
    ]
    for label, payload, secret in payloads:
        t0 = time.process_time()
        out = redact_sensitive_data(payload)
        dt = time.process_time() - t0
        assert dt < 0.75, f"{label} ({len(payload)} B) took {dt:.4f}s CPU time (expected < 0.75s)"
        if secret is not None:
            assert secret not in out
        assert redact_sensitive_data(out) == out


def test_redact_sensitive_data_nested_placeholders_html_and_metadata_regression() -> None:
    nested_and_edge_cases: list[tuple[str, str, tuple[str, ...]]] = [
        # Nested & mixed <REDACTED>, <REDACTED_JWT>, <REDACTED_MAX_DEPTH> in Bearer / ApiToken
        ("Bearer <REDACTED><REDACTED>secret", "Bearer <REDACTED>", ("secret",)),
        ("ApiToken <REDACTED_JWT><REDACTED>secret", "ApiToken <REDACTED>", ("secret",)),
        ("Bearer <REDACTED_MAX_DEPTH>secret", "Bearer <REDACTED>", ("secret",)),
        ("Bearer <REDACTED_MAX_DEPTH>x", "Bearer <REDACTED>", ("<REDACTED_MAX_DEPTH>x",)),
        ("Bearer <REDACTED>x", "Bearer <REDACTED>", ("<REDACTED>x",)),
        ("Bearer ab<REDACTED>secret", "Bearer <REDACTED>", ("secret",)),
        ("Bearer abcdef<REDACTED>secret", "Bearer <REDACTED>", ("secret",)),
        ("Bearer <REDACTED>foo<REDACTED>secret", "Bearer <REDACTED>", ("secret",)),
        (
            "Bearer <REDACTED>foo<REDACTED_JWT>bar<REDACTED_MAX_DEPTH>secret",
            "Bearer <REDACTED>",
            ("secret",),
        ),
        ("Bearer <REDACTED_MAX_DEPTH><REDACTED_JWT>secret", "Bearer <REDACTED>", ("secret",)),
        ("Bearer custom_param=<REDACTED><REDACTED>secret", "Bearer <REDACTED>", ("secret",)),
        ("Bearer custom_param=<REDACTED_MAX_DEPTH>secret", "Bearer <REDACTED>", ("secret",)),
        ("Bearer custom_param=<REDACTED>foo<REDACTED>secret", "Bearer <REDACTED>", ("secret",)),
        (
            'Bearer custom_param="<REDACTED><REDACTED>secret"',
            'Bearer custom_param="<REDACTED>"',
            ("secret",),
        ),
        (
            'Bearer custom_param="<REDACTED_MAX_DEPTH>secret"',
            'Bearer custom_param="<REDACTED>"',
            ("secret",),
        ),
        ('Bearer custom_param="my_secret"', 'Bearer custom_param="<REDACTED>"', ("my_secret",)),
        ("Bearer custom_param = <REDACTED>secret", "Bearer <REDACTED>", ("secret",)),
        ("Bearer <REDACTED>=<REDACTED>", "Bearer <REDACTED>", ("<REDACTED>=<REDACTED>",)),
        ("Bearer custom_param=x=<REDACTED>", "Bearer <REDACTED>", ("custom_param=x",)),
        ('{"msg": "Bearer abc123="}', '{"msg": "Bearer <REDACTED>"}', ("abc123=",)),
        # URL query nested, mixed, angle-bracketed, HTML-wrapped, and quoted values
        (
            "https://example.com/cb?jwt=<REDACTED><REDACTED>secret&mode=1",
            "https://example.com/cb?jwt=<REDACTED>&mode=1",
            ("secret",),
        ),
        (
            "https://example.com/cb?signature=<REDACTED_JWT><REDACTED_JWT>secret&mode=1",
            "https://example.com/cb?signature=<REDACTED>&mode=1",
            ("secret",),
        ),
        (
            "https://example.com/cb?jwt=<REDACTED>foo<REDACTED>secret&mode=1",
            "https://example.com/cb?jwt=<REDACTED>&mode=1",
            ("secret",),
        ),
        (
            "https://example.com/cb?signature=<REDACTED>foo<bar>secret_7&mode=1",
            "https://example.com/cb?signature=<REDACTED>&mode=1",
            ("secret_7",),
        ),
        (
            "https://example.com/cb?auth=<REDACTED>foo<bar><baz>secret_7&mode=1",
            "https://example.com/cb?auth=<REDACTED>&mode=1",
            ("secret_7",),
        ),
        (
            "https://example.com/cb?jwt=<REDACTED_MAX_DEPTH>secret&mode=1",
            "https://example.com/cb?jwt=<REDACTED>&mode=1",
            ("secret",),
        ),
        (
            "https://example.com/cb?auth=<REDACTED_MAX_DEPTH>secret&mode=1",
            "https://example.com/cb?auth=<REDACTED>&mode=1",
            ("secret",),
        ),
        (
            'https://example.com/cb?jwt="secret"&mode=1',
            'https://example.com/cb?jwt="<REDACTED>"&mode=1',
            ("secret",),
        ),
        ("<td>?auth=secret123</td>", "<td>?auth=<REDACTED></td>", ("secret123",)),
        ("<td>Authorization: Bearer secret123</td>", "<td>Authorization: Bearer <REDACTED></td>", ("secret123",)),
        ("<https://example.com/cb?auth=secret123>", "<https://example.com/cb?auth=<REDACTED>>", ("secret123",)),
        # Headers & KVs
        (
            "Authorization: CustomAuth foo=bar, <REDACTED><REDACTED>secret, nc=1",
            "Authorization: CustomAuth <REDACTED>",
            ("secret",),
        ),
        (
            "Authorization: CustomAuth qop=auth, foo=bar, <REDACTED><REDACTED>secret",
            "Authorization: CustomAuth <REDACTED>",
            ("secret",),
        ),
        (
            "Authorization: Digest <REDACTED><REDACTED>secret",
            "Authorization: Digest <REDACTED>",
            ("secret",),
        ),
        (
            'Authorization: Hawk <REDACTED><REDACTED>secret ts="1234"',
            'Authorization: Hawk <REDACTED> ts="1234"',
            ("secret",),
        ),
        (
            "Authorization: CustomAuth <REDACTED><REDACTED>secret",
            "Authorization: CustomAuth <REDACTED>",
            ("secret",),
        ),
        ("auth=my<secret>pass", "auth=<REDACTED>", ("secret",)),
        ("auth=<REDACTED>foo<bar>secret", "auth=<REDACTED>", ("secret",)),
        ('auth="<REDACTED><REDACTED>secret"', 'auth="<REDACTED>"', ("secret",)),
        ('{"auth": "<REDACTED><REDACTED>secret"}', '{"auth": "<REDACTED>"}', ("secret",)),
    ]
    for raw, expected, forbidden in nested_and_edge_cases:
        out = redact_sensitive_data(raw)
        assert out == expected, f"Mismatch for {raw!r}: {out!r} != {expected!r}"
        for secret in forbidden:
            assert secret not in out, f"Leaked {secret!r} in {out!r}"
        assert redact_sensitive_data(out) == out, f"Non-idempotent output: {out!r}"

    preserved_cases = [
        "<td>?auth=<REDACTED></td>",
        "<td>?signature=<REDACTED></td>",
        "<td>Bearer <REDACTED></td>",
        "<td>Authorization: Bearer <REDACTED></td>",
        "<td>Authorization: Bearer <REDACTED_MAX_DEPTH></td>",
        "<https://example.com/cb?auth=<REDACTED>>",
        "Bearer auth_mode=cli",
        "Bearer auth_mode = cli",
        "Bearer token",
        "Bearer abc",
        "Bearer a=1",
        'scheme=Bearer host="web-01"',
        'Bearer host="web-01" cluster="prod"',
        'Bearer token="<REDACTED>"',
        "Bearer custom_param=<REDACTED>",
        "Bearer custom_param=<REDACTED_MAX_DEPTH>",
        'Bearer custom_param="<REDACTED_MAX_DEPTH>"',
        "Bearer <REDACTED_MAX_DEPTH>",
        "Authorization: Bearer <REDACTED_MAX_DEPTH>",
        "https://example.com/cb?auth=<REDACTED_MAX_DEPTH>&mode=1",
        "auth=<REDACTED_MAX_DEPTH>",
        '{"url": "https://x?jwt="}',
        "auth_mode=cli ms_auth_mode=delegated auth_method=az_cli qop=auth",
        "token_type=Bearer expires_in=3600",
        "[auth=<REDACTED>]",
    ]
    for raw in preserved_cases:
        out = redact_sensitive_data(raw)
        assert out == raw, f"Preservation mismatch for {raw!r}: got {out!r}"
        assert redact_sensitive_data(out) == raw


def test_redact_sensitive_data_nested_placeholders_linear_scaling() -> None:
    def _measure_unit(label: str, unit: str, *, prefix: str = "", suffix: str = "", secret: str | None = None) -> None:
        results: list[tuple[int, float]] = []
        for target_bytes in (5000, 25000, 100000):
            reps = max(1, target_bytes // len(unit))
            payload = prefix + (unit * reps) + suffix
            t0 = time.process_time()
            out = redact_sensitive_data(payload)
            dt = time.process_time() - t0
            if secret is not None:
                assert secret not in out, f"Secret leaked in {label}"
            assert redact_sensitive_data(out) == out, f"Non-idempotent {label}"
            results.append((len(payload), dt))

        dt_5k, dt_25k, dt_100k = results[0][1], results[1][1], results[2][1]
        assert dt_100k < 0.50, f"{label} 100KB took {dt_100k:.4f}s CPU time (expected < 0.50s)"
        assert dt_100k < max(0.15, dt_5k * 40), (
            f"Non-linear scaling for {label}: 5KB={dt_5k:.4f}s, 25KB={dt_25k:.4f}s, 100KB={dt_100k:.4f}s"
        )

    _measure_unit("bearer_nested_redacted", "Bearer <REDACTED><REDACTED>secret ", secret="secret")
    _measure_unit("bearer_mixed_redacted", "Bearer <REDACTED>foo<REDACTED>secret ", secret="secret")
    _measure_unit("bearer_clean", "Bearer <REDACTED> ")
    _measure_unit(
        "url_nested_jwt",
        "https://example.com/cb?jwt=<REDACTED><REDACTED>secret&mode=1 ",
        secret="secret",
    )
    _measure_unit(
        "url_mixed_jwt",
        "https://example.com/cb?jwt=<REDACTED>foo<REDACTED>secret&mode=1 ",
        secret="secret",
    )
    _measure_unit("url_clean", "https://example.com/cb?jwt=<REDACTED>&mode=1 ")
    _measure_unit("html_td_auth", "<td>?auth=<REDACTED></td> ")
    _measure_unit(
        "url_bar_chain",
        "<bar>",
        prefix="https://example.com/cb?signature=<REDACTED>foo",
        suffix="secret_7&mode=1",
        secret="secret_7",
    )
    _measure_unit(
        "kv_bar_chain",
        "<bar>",
        prefix="auth=<REDACTED>foo",
        suffix="secret_kv_7",
        secret="secret_kv_7",
    )
    _measure_unit(
        "customauth_bare_comma",
        "Authorization: CustomAuth foo=bar, <REDACTED><REDACTED>secret, nc=1 ",
        secret="secret",
    )


def test_audit_log_store_redacts_nested_mixed_placeholders_end_to_end(tmp_path: Path) -> None:
    audit_path = tmp_path / "ai_audit.jsonl"
    store = AuditLogStore(audit_path)
    canaries = (
        "e2e_nested_bearer_101",
        "e2e_nested_apitok_102",
        "e2e_nested_maxdepth_103",
        "e2e_nested_custom_param_104",
        "e2e_nested_quoted_cp_105",
        "e2e_nested_jwt_106",
        "e2e_nested_sig_bar_107",
        "e2e_nested_quoted_jwt_108",
        "e2e_nested_customauth_109",
        "e2e_nested_hawk_110",
    )
    store.append(
        AuditEntry(
            entry_id="nested-e2e-1",
            timestamp="2026-11-26T02:30:00Z",
            run_id="run-nested",
            event_key="rf_alert::nested-1",
            provider="m365_copilot Bearer <REDACTED><REDACTED>e2e_nested_bearer_101",
            mode="full_investigation",
            event_type="prompt",
            reason="ApiToken <REDACTED_JWT><REDACTED>e2e_nested_apitok_102",
            payload={
                "event_context_preview": (
                    "Bearer <REDACTED_MAX_DEPTH>e2e_nested_maxdepth_103 "
                    "Bearer custom_param=<REDACTED><REDACTED>e2e_nested_custom_param_104 "
                    'Bearer custom_param="<REDACTED><REDACTED>e2e_nested_quoted_cp_105" '
                    "https://example.com/cb?jwt=<REDACTED><REDACTED>e2e_nested_jwt_106&mode=1 "
                    "https://example.com/cb?signature=<REDACTED>foo<bar>e2e_nested_sig_bar_107&mode=1 "
                    'https://example.com/cb?jwt="e2e_nested_quoted_jwt_108"&mode=1 '
                    "<td>?auth=<REDACTED></td>"
                ),
                "headers_raw": (
                    "Authorization: CustomAuth foo=bar, <REDACTED><REDACTED>e2e_nested_customauth_109, nc=1 | "
                    'Authorization: Hawk <REDACTED><REDACTED>e2e_nested_hawk_110 ts="1234"'
                ),
            },
        )
    )
    raw_disk = audit_path.read_text(encoding="utf-8")
    for canary in canaries:
        assert canary not in raw_disk, f"Canary {canary!r} leaked to ai_audit.jsonl!"
    assert "<td>?auth=<REDACTED></td>" in raw_disk
    assert 'ts=\\"1234\\"' in raw_disk

    reloaded = AuditLogStore(audit_path).query(limit=10)
    assert len(reloaded) == 1
    assert "<REDACTED>" in reloaded[0].provider
    assert "<REDACTED>" in reloaded[0].reason
    assert "<td>?auth=<REDACTED></td>" in reloaded[0].payload["event_context_preview"]


def test_redact_sensitive_data_github_pat_prefixes_and_url_delimiters() -> None:
    for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
        tok = f"{prefix}1234567890abcdefABCD"
        out = redact_sensitive_data(f"token leaked: {tok} done")
        assert out == "token leaked: <REDACTED> done"
        assert tok not in out
        assert redact_sensitive_data(out) == out

    fine_pat = "github_pat_11ABCDEF0123456789_xyz9876543210"
    out_pat = redact_sensitive_data(f"pat={fine_pat} raw {fine_pat}")
    assert out_pat == "pat=<REDACTED> raw <REDACTED>"
    assert fine_pat not in out_pat
    assert redact_sensitive_data(out_pat) == out_pat

    delimiter_cases = [
        ("[?auth=secret123]", "[?auth=<REDACTED>]", ("secret123",)),
        ("[?auth=<REDACTED>]", "[?auth=<REDACTED>]", ()),
        ("(https://example.com/?auth=secret123)", "(https://example.com/?auth=<REDACTED>)", ("secret123",)),
        ("(https://example.com/?auth=<REDACTED>)", "(https://example.com/?auth=<REDACTED>)", ()),
        (
            "url=https://example.com/?token=secret123, user=alice",
            "url=https://example.com/?token=<REDACTED>, user=alice",
            ("secret123",),
        ),
    ]
    for raw, expected, forbidden in delimiter_cases:
        out = redact_sensitive_data(raw)
        assert out == expected
        for sec in forbidden:
            assert sec not in out
        assert redact_sensitive_data(out) == out


def test_unified_research_target_enforces_recorded_future_disabled_policy(tmp_path: Path) -> None:
    rf_factory = MagicMock(return_value=MagicMock(api_token="rf-tok"))
    osint_mock = MagicMock()
    research_calls: list[dict[str, Any]] = []

    def _fake_research(
        rf_arg: Any,
        query: str,
        *,
        include_rf: bool,
        include_osint: bool,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        research_calls.append(
            {
                "rf_is_none": rf_arg is None,
                "query": query,
                "include_rf": include_rf,
                "include_osint": include_osint,
            }
        )
        return {"ok": True, "query": query, "include_rf": include_rf, "include_osint": include_osint}

    registry = build_default_readonly_registry(
        rf_client=rf_factory,
        osint_client=osint_mock,
        research_fn=_fake_research,
    )
    audit = AuditLogStore(tmp_path / "rf_clamp_audit.jsonl")
    policy = AIPolicyConfig(recorded_future_enabled=False, watchlists_osint_enabled=True)

    # 1. include_rf=True, include_osint=False -> denied before handler
    denied = registry.execute(
        "unified_research_target",
        {"query": "198.51.100.10", "include_rf": True, "include_osint": False},
        mode="full_investigation",
        policy=policy,
        audit=audit,
        run_id="r-deny",
    )
    assert denied["ok"] is False
    assert denied["blocked"] is True
    assert denied["rule"] == "source_disabled:recorded_future"
    assert rf_factory.call_count == 0
    assert research_calls == []

    # 2. include_rf=True, include_osint=True -> clamps include_rf=False, never invokes rf_factory
    allowed = registry.execute(
        "unified_research_target",
        {"query": "198.51.100.10", "include_rf": True, "include_osint": True},
        mode="full_investigation",
        policy=policy,
        audit=audit,
        run_id="r-clamp",
    )
    assert allowed["ok"] is True
    assert allowed["policy_clamped"]["include_rf"] is False
    assert rf_factory.call_count == 0
    assert len(research_calls) == 1
    assert research_calls[0] == {
        "rf_is_none": True,
        "query": "198.51.100.10",
        "include_rf": False,
        "include_osint": True,
    }
    assert audit.query(run_id="r-clamp", event_type="blocked_action")


def test_policy_high_budget_bounds_kill_switch_fields_and_env_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from soclens.agent_policy import format_kill_switch_hotkey_badge

    monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
    monkeypatch.delenv("SOCLENS_AI_MAX_TOOL_STEPS", raising=False)

    default_cfg = AIPolicyConfig()
    assert default_cfg.max_tool_steps == 50
    assert default_cfg.max_identical_tool_calls == 2
    assert default_cfg.max_same_tool_failures == 10
    assert default_cfg.ai_kill_switch_active is False
    assert default_cfg.kill_switch_visible is True
    assert default_cfg.kill_switch_confirm_engage is False
    assert default_cfg.kill_switch_confirm_resume is False
    assert default_cfg.kill_switch_persist_across_restarts is True
    assert default_cfg.kill_switch_label == "KILL AI"
    assert default_cfg.kill_switch_hotkey == "f12"

    clamped_low = AIPolicyConfig(
        max_tool_steps=0,
        max_identical_tool_calls=-3,
        max_same_tool_failures=0,
        kill_switch_label="   ",
        kill_switch_hotkey="bad-key",
    )
    assert clamped_low.max_tool_steps == 1
    assert clamped_low.max_identical_tool_calls == 1
    assert clamped_low.max_same_tool_failures == 1
    assert clamped_low.kill_switch_label == "KILL AI"
    assert clamped_low.kill_switch_hotkey == "f12"

    clamped_high = AIPolicyConfig(
        max_tool_steps=9999,
        max_identical_tool_calls=999,
        max_same_tool_failures=500,
        kill_switch_label="  EMERGENCY   STOP   ALL   AI   AGENTS  ",
        kill_switch_hotkey="CTRL+BACKSLASH",
    )
    assert clamped_high.max_tool_steps == 500
    assert clamped_high.max_identical_tool_calls == 50
    assert clamped_high.max_same_tool_failures == 100
    assert len(clamped_high.kill_switch_label) <= 20
    assert clamped_high.kill_switch_label == "EMERGENCY STOP ALL A"
    assert clamped_high.kill_switch_hotkey == "ctrl+backslash"
    assert format_kill_switch_hotkey_badge("f12") == "[F12]"
    assert format_kill_switch_hotkey_badge("f11") == "[F11]"
    assert format_kill_switch_hotkey_badge("ctrl+backslash") == "[Ctrl+\\]"
    assert format_kill_switch_hotkey_badge("none") == ""

    # SOCLENS_AI_MAX_TOOL_STEPS applies when policy file is absent or omits max_tool_steps
    monkeypatch.setenv("SOCLENS_AI_MAX_TOOL_STEPS", "180")
    store = AIPolicyStore(tmp_path / "ai_policy.json")
    assert store.load().max_tool_steps == 180

    store.path.write_text(json.dumps({"cross_search_enabled": True}), encoding="utf-8")
    assert store.load().max_tool_steps == 180

    # Explicit persisted max_tool_steps overrides SOCLENS_AI_MAX_TOOL_STEPS
    store.update(max_tool_steps=75)
    assert store.load().max_tool_steps == 75


def test_evaluate_tool_permission_ai_kill_switch_fail_closed() -> None:
    killed_policy = AIPolicyConfig(ai_kill_switch_active=True)
    dec_allowed_tool = evaluate_tool_permission(
        "splunk_search",
        SOURCE_CATEGORY_SPLUNK,
        True,
        "full_investigation",
        killed_policy,
        arguments={"spl": "index=main | head 1"},
    )
    assert dec_allowed_tool.allowed is False
    assert dec_allowed_tool.rule == "ai_kill_switch"

    # Non-readonly / unregistered still fails closed on readonly_enforced first
    dec_mut = evaluate_tool_permission(
        "mitigate_threat",
        SOURCE_CATEGORY_S1,
        False,
        "full_investigation",
        killed_policy,
    )
    assert dec_mut.allowed is False
    assert dec_mut.rule == "readonly_enforced"






