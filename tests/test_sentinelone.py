"""Unit tests for SentinelOne config, Management API v2.1 client, and CLI."""

from __future__ import annotations

import json
import sys
import threading
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from soclens import cli
from soclens.config import ConfigurationError, SentinelOneConfig, get_sentinelone_config
from soclens.sentinelone import (
    SentinelOneAuthError,
    SentinelOneClient,
    SentinelOneError,
    SentinelOneRateLimitError,
)


def _mock_response(
    status_code: int = 200,
    payload: Any = None,
    headers: dict[str, str] | None = None,
    text: str = "",
) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    if payload is not None:
        resp.content = json.dumps(payload).encode("utf-8")
        resp.text = json.dumps(payload)
        resp.json.return_value = payload
    else:
        resp.content = text.encode("utf-8")
        resp.text = text
        resp.json.side_effect = ValueError("No JSON")
    return resp


# ---------------------------------------------------------------------------
# Configuration tests
# ---------------------------------------------------------------------------


def test_sentinelone_config_env_and_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "S1_CONSOLE_URL",
        "SENTINELONE_URL",
        "S1_API_TOKEN",
        "SENTINELONE_API_TOKEN",
        "S1_ACCOUNT_ID",
        "S1_SITE_ID",
        "S1_VERIFY_SSL",
        "S1_TIMEOUT",
        "RF_VERIFY_SSL",
        "RF_INSECURE_SSL",
        "SOCLENS_INSECURE_SSL",
        "RF_CA_BUNDLE",
    ):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("SENTINELONE_URL", "tenant.sentinelone.net/")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "secret-s1-token")
    monkeypatch.setenv("S1_ACCOUNT_ID", "acc-1")
    monkeypatch.setenv("S1_SITE_ID", "site-2")
    monkeypatch.setenv("S1_TIMEOUT", "45.5")
    monkeypatch.setenv("RF_INSECURE_SSL", "true")

    cfg = get_sentinelone_config(required=True)
    assert isinstance(cfg, SentinelOneConfig)
    assert cfg.console_url == "https://tenant.sentinelone.net"
    assert cfg.api_token == "secret-s1-token"
    assert cfg.account_id == "acc-1"
    assert cfg.site_id == "site-2"
    assert cfg.verify_ssl is False  # fell back to get_rf_verify_ssl()
    assert cfg.timeout == 45.5
    assert cfg.has_auth is True
    assert "secret-s1-token" not in repr(cfg)


def test_sentinelone_config_primary_env_overrides_and_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("S1_CONSOLE_URL", "https://primary.s1.local/")
    monkeypatch.setenv("SENTINELONE_URL", "https://fallback.s1.local")
    monkeypatch.setenv("S1_API_TOKEN", "primary-tok")
    monkeypatch.setenv("SENTINELONE_API_TOKEN", "fallback-tok")
    monkeypatch.setenv("S1_VERIFY_SSL", "true")
    monkeypatch.setenv("RF_INSECURE_SSL", "true")

    cfg = get_sentinelone_config(required=True)
    assert cfg.console_url == "https://primary.s1.local"
    assert cfg.api_token == "primary-tok"
    assert cfg.verify_ssl is True

    monkeypatch.setenv("S1_TIMEOUT", "not-a-number")
    with pytest.raises(ConfigurationError, match="Invalid S1_TIMEOUT"):
        get_sentinelone_config()

    monkeypatch.setenv("S1_TIMEOUT", "0")
    with pytest.raises(ConfigurationError, match="must be positive"):
        get_sentinelone_config()


def test_sentinelone_config_required_raises_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("S1_CONSOLE_URL", "SENTINELONE_URL", "S1_API_TOKEN", "SENTINELONE_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    cfg = get_sentinelone_config(required=False)
    assert cfg.has_auth is False
    with pytest.raises(ConfigurationError, match="S1_CONSOLE_URL"):
        get_sentinelone_config(required=True)


# ---------------------------------------------------------------------------
# Client HTTP, Auth, Retry, Pagination, and Cancellation tests
# ---------------------------------------------------------------------------


def _make_client(session: MagicMock | None = None, **kwargs: Any) -> SentinelOneClient:
    sess = session or MagicMock(spec=requests.Session)
    sess.headers = {}
    return SentinelOneClient(
        console_url="https://usea1.sentinelone.net",
        api_token="tok-abc",
        account_id="acc-100",
        site_id="site-200",
        max_retries=2,
        backoff_base=0.01,
        session=sess,
        **kwargs,
    )


def test_client_sets_apitoken_header_and_check_connection() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    sess.request.return_value = _mock_response(200, {"data": {"build": "24.2.1"}})
    client = _make_client(sess)

    assert sess.headers["Authorization"] == "ApiToken tok-abc"
    info = client.check_connection()
    assert info["build"] == "24.2.1"
    call_kwargs = sess.request.call_args.kwargs
    assert call_kwargs["method"] == "GET"
    assert call_kwargs["url"] == "https://usea1.sentinelone.net/web/api/v2.1/system/info"


def test_client_cursor_pagination() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    sess.request.side_effect = [
        _mock_response(
            200,
            {
                "data": [{"id": "a1"}, {"id": "a2"}],
                "pagination": {"nextCursor": "cursor-page-2"},
            },
        ),
        _mock_response(
            200,
            {
                "data": [{"id": "a3"}],
                "pagination": {"nextCursor": None},
            },
        ),
    ]
    client = _make_client(sess)
    agents = client.list_agents(limit=10)
    assert [a["id"] for a in agents] == ["a1", "a2", "a3"]
    assert sess.request.call_count == 2
    assert sess.request.call_args_list[1].kwargs["params"]["cursor"] == "cursor-page-2"


def test_client_retry_429_with_retry_after_then_succeed() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    sess.request.side_effect = [
        _mock_response(
            429,
            {"errors": [{"code": 4290001, "title": "Too Many Requests", "detail": "Slow down"}]},
            headers={"Retry-After": "0.01"},
        ),
        _mock_response(200, {"data": {"build": "24.2"}}),
    ]
    client = _make_client(sess)
    info = client.check_connection()
    assert info["build"] == "24.2"
    assert sess.request.call_count == 2


def test_client_rate_limit_exhausted_raises() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    sess.request.return_value = _mock_response(
        429,
        {"errors": [{"code": 4290001, "title": "Rate Limited", "detail": "Quota exceeded"}]},
        headers={"Retry-After": "0.01"},
    )
    client = _make_client(sess)
    with pytest.raises(SentinelOneRateLimitError) as exc_info:
        client.check_connection()
    assert exc_info.value.status_code == 429
    assert exc_info.value.retry_after == 0.01
    assert sess.request.call_count == 3


def test_client_5xx_retries_and_401_raises_auth_error() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    sess.request.side_effect = [
        _mock_response(503, {"errors": [{"title": "Service Unavailable"}]}),
        _mock_response(200, {"data": []}),
    ]
    client = _make_client(sess)
    assert client.list_accounts() == []
    assert sess.request.call_count == 2

    sess.request.side_effect = None
    sess.request.return_value = _mock_response(
        401,
        {"errors": [{"code": 4010010, "title": "Authentication Failed", "detail": "Invalid token"}]},
    )
    with pytest.raises(SentinelOneAuthError) as exc_info:
        client.check_connection()
    assert exc_info.value.status_code == 401
    assert "Authentication Failed" in str(exc_info.value)


def test_client_stop_event_cancels_immediately() -> None:
    stop = threading.Event()
    stop.set()
    client = _make_client(stop_event=stop)
    with pytest.raises(SentinelOneError, match="cancelled"):
        client.check_connection()


# ---------------------------------------------------------------------------
# All SentinelOne Management API v2.1 resource methods
# ---------------------------------------------------------------------------


def test_client_scope_sites_groups_and_agents_methods() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    # list_sites supports nested data.sites shape
    sess.request.return_value = _mock_response(
        200, {"data": {"sites": [{"id": "s1", "name": "Prod Site"}]}, "pagination": {}}
    )
    sites = client.list_sites()
    assert sites == [{"id": "s1", "name": "Prod Site"}]

    sess.request.return_value = _mock_response(200, {"data": [{"id": "g1", "name": "Servers"}]})
    assert client.list_groups()[0]["id"] == "g1"

    sess.request.return_value = _mock_response(200, {"data": [{"id": "ag1", "computerName": "WKSTN-01"}]})
    assert client.get_agent("ag1")["computerName"] == "WKSTN-01"

    sess.request.return_value = _mock_response(200, {"data": {"affected": 1}})
    assert client.disconnect_agent(["ag1"])["data"]["affected"] == 1
    assert sess.request.call_args.kwargs["url"].endswith("/agents/actions/disconnect")

    client.connect_agent("ag1")
    assert sess.request.call_args.kwargs["url"].endswith("/agents/actions/connect")

    client.initiate_scan(["ag1"])
    assert sess.request.call_args.kwargs["url"].endswith("/agents/actions/initiate-scan")

    client.abort_scan(["ag1"])
    assert sess.request.call_args.kwargs["url"].endswith("/agents/actions/abort-scan")

    client.reboot_agent(["ag1"])
    assert sess.request.call_args.kwargs["url"].endswith("/agents/actions/restart-machine")

    client.move_agents_to_site(["ag1"], "site-999")
    assert sess.request.call_args.kwargs["url"].endswith("/agents/actions/move-to-site")
    assert sess.request.call_args.kwargs["json"]["data"]["targetSiteId"] == "site-999"

    client.uninstall_agent(["ag1"])
    assert sess.request.call_args.kwargs["url"].endswith("/agents/actions/uninstall")

    client.add_agent_tags(["ag1"], ["env=prod", {"key": "tier", "value": "1"}])
    assert sess.request.call_args.kwargs["url"].endswith("/agents/actions/manage-tags")
    assert sess.request.call_args.kwargs["json"]["data"]["operation"] == "add"
    assert len(sess.request.call_args.kwargs["json"]["data"]["tags"]) == 2

    client.remove_agent_tags(["ag1"], ["env=prod"])
    assert sess.request.call_args.kwargs["json"]["data"]["operation"] == "remove"


def test_client_threats_exclusions_blocklist_activities_dv() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    # Threats
    sess.request.return_value = _mock_response(200, {"data": [{"id": "th1"}]})
    assert client.list_threats(incident_statuses="unresolved")[0]["id"] == "th1"
    assert client.get_threat_timeline("th1")[0]["id"] == "th1"
    assert sess.request.call_args.kwargs["url"].endswith("/threats/th1/timeline")

    sess.request.return_value = _mock_response(200, {"data": {"affected": 1}})
    client.update_threat_verdict(["th1"], "true_positive")
    assert sess.request.call_args.kwargs["json"]["data"]["analystVerdict"] == "true_positive"

    client.update_threat_incident_status(["th1"], "resolved")
    assert sess.request.call_args.kwargs["json"]["data"]["incidentStatus"] == "resolved"

    client.mitigate_threat(["th1"], "quarantine")
    assert sess.request.call_args.kwargs["url"].endswith("/threats/mitigate/quarantine")

    with pytest.raises(ValueError, match="Invalid mitigation action"):
        client.mitigate_threat(["th1"], "nuke")

    client.add_threat_to_exclusions(["th1"], target_scope="site", mode="suppress")
    assert sess.request.call_args.kwargs["url"].endswith("/threats/add-to-exclusions")

    client.add_threat_note("th1", "Confirmed ransomware loader")
    assert sess.request.call_args.kwargs["url"].endswith("/threats/notes")
    assert sess.request.call_args.kwargs["json"]["data"]["text"] == "Confirmed ransomware loader"

    # Exclusions
    sess.request.return_value = _mock_response(200, {"data": [{"id": "ex1", "type": "path"}]})
    assert client.list_exclusions(exclusion_type="path")[0]["id"] == "ex1"

    sess.request.return_value = _mock_response(200, {"data": {"id": "ex2"}})
    client.create_exclusion(
        exclusion_type="path",
        os_type="windows",
        value=r"C:\Tools\scanner.exe",
        description="Approved tool",
    )
    assert sess.request.call_args.kwargs["method"] == "POST"
    assert sess.request.call_args.kwargs["json"]["data"]["value"] == r"C:\Tools\scanner.exe"

    client.delete_exclusions(["ex2"], exclusion_type="path")
    assert sess.request.call_args.kwargs["method"] == "DELETE"
    assert sess.request.call_args.kwargs["json"]["data"]["ids"] == ["ex2"]

    # Blocklist
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sess.request.return_value = _mock_response(200, {"data": [{"id": "bl1", "value": sha1}]})
    assert client.list_blocklist()[0]["value"] == sha1
    assert sess.request.call_args.kwargs["params"]["type"] == "black_hash"

    client.add_to_blocklist(sha1, os_type="windows", description="Known bad")
    assert sess.request.call_args.kwargs["json"]["data"]["type"] == "black_hash"
    assert sess.request.call_args.kwargs["json"]["data"]["value"] == sha1

    with pytest.raises(ValueError, match="SHA-1"):
        client.add_to_blocklist("not-a-sha1")

    client.remove_from_blocklist(["bl1"])
    assert sess.request.call_args.kwargs["method"] == "DELETE"
    assert sess.request.call_args.kwargs["json"]["data"]["type"] == "black_hash"

    # Activities & Deep Visibility
    sess.request.return_value = _mock_response(200, {"data": [{"id": "act1"}]})
    assert client.list_activities(agent_ids="ag1")[0]["id"] == "act1"

    sess.request.return_value = _mock_response(200, {"data": {"queryId": "q-123"}})
    dv_init = client.create_dv_query(
        'SrcProcName = "powershell.exe"',
        "2026-01-01T00:00:00Z",
        "2026-01-02T00:00:00Z",
    )
    assert dv_init["data"]["queryId"] == "q-123"
    assert sess.request.call_args.kwargs["url"].endswith("/dv/init-query")

    sess.request.return_value = _mock_response(200, {"data": {"responseState": "FINISHED"}})
    assert client.get_dv_query_status("q-123")["data"]["responseState"] == "FINISHED"

    sess.request.return_value = _mock_response(200, {"data": [{"eventType": "Process Creation"}]})
    assert client.get_dv_events("q-123")[0]["eventType"] == "Process Creation"


# ---------------------------------------------------------------------------
# CLI tests & approval / dry-run guardrails
# ---------------------------------------------------------------------------


def _run_cli(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(sys, "argv", ["soclens", *argv])
    try:
        cli.main()
        return 0
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 1


def test_cli_s1_active_commands_require_approval_and_respect_dry_run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("SOCLENS_AUTO_APPROVE", raising=False)

    # Without --yes or SOCLENS_AUTO_APPROVE, isolate must fail with exit code 1 and never call API
    with patch("soclens.cli._build_s1_client") as mock_build:
        rc = _run_cli(["s1", "isolate", "ag-1"], monkeypatch)
        assert rc == 1
        mock_build.assert_not_called()
    err = capsys.readouterr().err
    assert "Approval required" in err

    # With --dry-run, isolate returns 0 with dry_run JSON and never calls API
    with patch("soclens.cli._build_s1_client") as mock_build:
        rc = _run_cli(["--dry-run", "--json", "s1", "isolate", "ag-1"], monkeypatch)
        assert rc == 0
        mock_build.assert_not_called()
    out = json.loads(capsys.readouterr().out)
    assert out["dry_run"] is True
    assert out["action"] == "isolate"
    assert out["agent_ids"] == ["ag-1"]

    # With --yes, isolate executes disconnect_agent
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.disconnect_agent.return_value = {"data": {"affected": 1}}
    with patch("soclens.cli._build_s1_client", return_value=mock_client):
        rc = _run_cli(["--json", "s1", "isolate", "ag-1", "--yes"], monkeypatch)
        assert rc == 0
        mock_client.disconnect_agent.assert_called_once_with(["ag-1"])
    out = json.loads(capsys.readouterr().out)
    assert out["data"]["affected"] == 1

    # With SOCLENS_AUTO_APPROVE=true, mitigate executes without --yes
    monkeypatch.setenv("SOCLENS_AUTO_APPROVE", "true")
    mock_client.mitigate_threat.return_value = {"data": {"affected": 1}}
    with patch("soclens.cli._build_s1_client", return_value=mock_client):
        rc = _run_cli(
            ["--json", "s1", "mitigate", "th-1", "--action", "quarantine"],
            monkeypatch,
        )
        assert rc == 0
        mock_client.mitigate_threat.assert_called_once_with(["th-1"], "quarantine")


def test_cli_s1_read_commands_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.console_url = "https://tenant.sentinelone.net"
    mock_client.check_connection.return_value = {"build": "24.2.1"}
    mock_client.list_agents.return_value = [{"id": "ag-1", "computerName": "HOST-1"}]
    mock_client.list_threats.return_value = [{"id": "th-1", "threatInfo": {"threatName": "Mimikatz"}}]
    mock_client.list_sites.return_value = [{"id": "s-1", "name": "HQ"}]
    mock_client.list_activities.return_value = [{"id": "act-1", "primaryDescription": "Isolated"}]

    with patch("soclens.cli._build_s1_client", return_value=mock_client):
        assert _run_cli(["--json", "s1", "status"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)["status"] == "connected"

        assert _run_cli(["--json", "s1", "agents"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)[0]["id"] == "ag-1"

        assert _run_cli(["--json", "s1", "threats"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)[0]["id"] == "th-1"

        assert _run_cli(["--json", "s1", "sites"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)[0]["name"] == "HQ"

        assert _run_cli(["--json", "s1", "activities"], monkeypatch) == 0
        assert json.loads(capsys.readouterr().out)[0]["id"] == "act-1"


# ---------------------------------------------------------------------------
# Wave 1B / WS3: Guardrails, Tiers, Cloud Alerts, Sites, Users/RBAC, Cloning
# ---------------------------------------------------------------------------


def test_paginate_enforces_limit_le_100() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    sess.request.side_effect = [
        _mock_response(
            200,
            {
                "data": [{"id": f"a-{i}"} for i in range(100)],
                "pagination": {"nextCursor": "c2"},
            },
        ),
        _mock_response(
            200,
            {
                "data": [{"id": f"a-{i}"} for i in range(100, 200)],
                "pagination": {"nextCursor": "c3"},
            },
        ),
        _mock_response(
            200,
            {
                "data": [{"id": f"a-{i}"} for i in range(200, 250)],
                "pagination": {"nextCursor": None},
            },
        ),
    ]
    client = _make_client(sess)
    items = client.list_agents(limit=250, max_pages=5)
    assert len(items) == 250
    limits = [call.kwargs["params"]["limit"] for call in sess.request.call_args_list]
    assert limits == [100, 100, 50]
    assert all(lim <= 100 for lim in limits)


def test_mutation_guardrail_forbids_empty_or_unscoped_filter_before_network() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    for bad_body in (
        {"filter": {}, "data": {"incidentStatus": "resolved"}},
        {"filter": {"ids": []}, "data": {"incidentStatus": "resolved"}},
        {"filter": {"tenant": True}, "data": {"value": "x"}},
        {"filter": "not-a-mapping"},
    ):
        with pytest.raises(ValueError, match="empty or unscoped filter"):
            client._request("POST", "threats/incident", json_body=bad_body)

    with pytest.raises(ValueError, match="data.ids"):
        client._request("DELETE", "exclusions", json_body={"data": {"ids": []}})

    with pytest.raises(ValueError, match="data.ids"):
        client._request("DELETE", "restrictions", json_body={"data": {"ids": []}})

    with pytest.raises(ValueError, match="data.ids"):
        client._request("POST", "users/reset-2fa", json_body={"data": {"ids": []}})

    with pytest.raises(ValueError, match="data.ids"):
        client._request("POST", "users/delete-2fa", json_body={"data": {"ids": []}})

    unscoped = SentinelOneClient(
        console_url="https://usea1.sentinelone.net",
        api_token="tok-abc",
        session=sess,
    )
    with pytest.raises(ValueError, match="At least one scope"):
        unscoped.create_exclusion(
            exclusion_type="path",
            os_type="windows",
            value=r"C:\Temp\a.exe",
        )
    with pytest.raises(ValueError, match="At least one scope"):
        unscoped.add_to_blocklist("da39a3ee5e6b4b0d3255bfef95601890afd80709")

    sess.request.assert_not_called()


def test_rate_pacer_clamps_and_paces_exclusion_cloning(monkeypatch: pytest.MonkeyPatch) -> None:
    import soclens.sentinelone as s1_mod

    clock = {"now": 100.0}
    wait_calls: list[float] = []

    class _SpyEvent(threading.Event):
        def wait(self, timeout: float | None = None) -> bool:
            if timeout is not None:
                wait_calls.append(timeout)
                clock["now"] += timeout
            return self.is_set()

    monkeypatch.setattr(s1_mod.time, "monotonic", lambda: clock["now"])
    stop = _SpyEvent()
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}

    src_excls = [
        {
            "id": f"src-{i}",
            "type": "path",
            "osType": "windows",
            "value": rf"C:\Tools\app{i}.exe",
            "mode": "suppress",
            "description": "Approved",
            "scope": "site",
        }
        for i in range(4)
    ]
    sess.request.side_effect = [
        _mock_response(200, {"data": src_excls}),
        _mock_response(200, {"data": []}),
        _mock_response(200, {"data": {"id": "dst-0"}}),
        _mock_response(200, {"data": {"id": "dst-1"}}),
        _mock_response(200, {"data": {"id": "dst-2"}}),
        _mock_response(200, {"data": {"id": "dst-3"}}),
    ]
    client = _make_client(sess, stop_event=stop)
    result = client.clone_exclusions(
        "site-src",
        "site-dst",
        source_site_name="MDR-1234",
        dry_run=False,
        requests_per_second=50.0,  # must clamp to 15.0 req/s
    )
    assert result["requests_per_second"] == 15.0
    assert result["counts"]["created"] == 4
    assert len(wait_calls) == 3
    assert all(w >= (1.0 / 15.0) - 1e-9 for w in wait_calls)

    # Cancelled stop_event aborts pacing cleanly
    stop.set()
    with pytest.raises(SentinelOneError, match="cancelled"):
        client.clone_exclusions("site-src", "site-dst", dry_run=False)


def test_tier_classification_site_enrichment_and_alert_grouping() -> None:
    from soclens.config import S1TierConfig, get_s1_tier_config

    tier_cfg = get_s1_tier_config(
        site_tenant_map={"Default site": "9999", "MDR-1234": "T-1234"},
    )
    assert isinstance(tier_cfg, S1TierConfig)
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess, tier_config=tier_cfg)

    assert client.classify_site("MDR-1234") == ("MDR", "1234", "T-1234")
    assert client.classify_site("mdr_77") == ("MDR", "77", "77")
    assert client.classify_site("MSSP-8298") == ("MSSP", "8298", "8298")
    assert client.classify_site("Default site") == ("Other", None, "9999")

    enriched = client.enrich_sites_with_tiers(
        [
            {"id": "s1", "name": "MDR-1234"},
            {"id": "s2", "name": "MSSP-8298"},
            {"id": "s3", "name": "HQ"},
        ]
    )
    assert [(s["tier"], s["tenantId"]) for s in enriched] == [
        ("MDR", "T-1234"),
        ("MSSP", "8298"),
        ("Other", None),
    ]

    shared_sha1 = "a" * 40
    alerts = [
        client.normalize_alert(
            {
                "id": "th-mdr",
                "threatInfo": {"threatName": "Mimikatz", "sha1": shared_sha1},
                "agentRealtimeInfo": {"siteId": "s1", "siteName": "MDR-1234"},
            }
        ),
        client.normalize_alert(
            {
                "id": "th-mssp",
                "threatInfo": {"threatName": "Mimikatz", "sha1": shared_sha1},
                "agentRealtimeInfo": {"siteId": "s2", "siteName": "MSSP-8298"},
            }
        ),
    ]
    grouped = client.group_alerts(alerts, mode="tier_hash")
    assert set(grouped.keys()) == {f"MDR | {shared_sha1}", f"MSSP | {shared_sha1}"}
    assert len(grouped[f"MDR | {shared_sha1}"]) == 1
    assert len(grouped[f"MSSP | {shared_sha1}"]) == 1
    assert set(client.group_alerts(alerts, mode="tier").keys()) == {"MDR", "MSSP"}
    assert set(client.group_alerts(alerts, mode="site").keys()) == {"MDR-1234", "MSSP-8298"}
    assert list(client.group_alerts(alerts, mode="flat").keys()) == ["All Alerts"]


def test_cloud_alerts_unified_normalization_and_mitigation_aliases() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    cloud_item = {
        "id": "ca-1",
        "alertInfo": {
            "alertId": "ca-1",
            "incidentStatus": "UNRESOLVED",
            "analystVerdict": "UNDEFINED",
            "createdAt": "2026-11-24T11:00:00Z",
        },
        "ruleInfo": {"name": "STAR: Suspicious PowerShell", "severity": "High"},
        "agentDetectionInfo": {
            "siteId": "s-mdr",
            "siteName": "MDR-400",
            "agentComputerName": "SRV-01",
        },
        "sourceProcessInfo": {
            "fileHashSha1": "b" * 40,
            "filePath": r"C:\Windows\System32\powershell.exe",
            "user": "corp\\svc",
        },
    }
    threat_item = {
        "id": "th-1",
        "threatInfo": {
            "threatName": "Trojan.Win32",
            "incidentStatus": "unresolved",
            "analystVerdict": "undefined",
            "mitigationStatus": "active",
            "sha1": "c" * 40,
            "createdAt": "2026-11-24T12:00:00Z",
        },
        "agentRealtimeInfo": {
            "siteId": "s-mssp",
            "siteName": "MSSP-500",
            "agentComputerName": "WKSTN-02",
        },
    }

    sess.request.side_effect = [
        _mock_response(200, {"data": [cloud_item]}),
        _mock_response(200, {"data": {"affected": 1}}),
        _mock_response(200, {"data": {"affected": 1}}),
        _mock_response(200, {"data": [threat_item]}),
        _mock_response(200, {"data": [cloud_item]}),
        _mock_response(200, {"data": {"affected": 1}}),
        _mock_response(200, {"data": {"affected": 1}}),
    ]

    cloud_rows = client.list_cloud_alerts(
        incident_statuses="unresolved",
        analyst_verdicts="true_positive",
        severities="high",
    )
    assert len(cloud_rows) == 1
    first_params = sess.request.call_args_list[0].kwargs["params"]
    assert first_params["incidentStatus"] == "UNRESOLVED"
    assert first_params["analystVerdict"] == "TRUE_POSITIVE"
    assert first_params["severity"] == "High"

    client.update_cloud_alert_verdict(["ca-1"], "true_positive")
    assert sess.request.call_args_list[1].kwargs["url"].endswith(
        "/cloud-detection/alerts/analyst-verdict"
    )
    assert sess.request.call_args_list[1].kwargs["json"]["data"]["analystVerdict"] == "TRUE_POSITIVE"

    client.update_cloud_alert_incident_status(["ca-1"], "resolved")
    assert sess.request.call_args_list[2].kwargs["url"].endswith(
        "/cloud-detection/alerts/incident"
    )
    assert sess.request.call_args_list[2].kwargs["json"]["data"]["incidentStatus"] == "RESOLVED"

    unified = client.list_unified_alerts()
    assert [u["id"] for u in unified] == ["th-1", "ca-1"]
    assert unified[0]["tier"] == "MSSP"
    assert unified[0]["tenantId"] == "500"
    assert unified[1]["tier"] == "MDR"
    assert unified[1]["recordType"] == "cloud_alert"

    client.mitigate_threat(["th-1"], "rollback")
    assert sess.request.call_args_list[5].kwargs["url"].endswith(
        "/threats/mitigate/rollback-remediation"
    )
    client.mitigate_threat(["th-1"], "unquarantine")
    assert sess.request.call_args_list[6].kwargs["url"].endswith(
        "/threats/mitigate/un-quarantine"
    )


def test_sites_admin_lifecycle_and_policy_sanitization() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    sess.request.side_effect = [
        _mock_response(200, {"data": {"id": "site-10", "name": "MDR-10"}}),
        _mock_response(
            200,
            {
                "data": {
                    "antiTamperingOn": True,
                    "createdAt": "2026-01-01T00:00:00Z",
                    "updatedAt": "2026-01-02T00:00:00Z",
                    "userId": "u1",
                    "userFullName": "Admin",
                    "inheritedFrom": "account",
                    "fwForNetworkQuarantineEnabled": False,
                }
            },
        ),
        _mock_response(200, {"data": {"id": "site-20", "name": "MDR-20"}}),
        _mock_response(200, {"data": []}),  # clone source exclusions
        _mock_response(200, {"data": []}),  # clone target exclusions
        _mock_response(200, {"data": {"id": "site-30", "name": "MDR-30"}}),
        _mock_response(200, {"data": {"id": "site-20", "description": "Updated"}}),
        _mock_response(200, {"data": {"state": "expired"}}),
        _mock_response(200, {"data": {"state": "active"}}),
        _mock_response(200, {"data": {"registrationToken": "tok-new"}}),
        _mock_response(200, {"data": {"token": "tok-current"}}),
        _mock_response(200, {"data": {"antiTamperingOn": False}}),
        _mock_response(200, {"data": {"success": True}}),
        _mock_response(200, {"data": {"success": True}}),
    ]

    assert client.get_site("site-10")["name"] == "MDR-10"
    created = client.create_site(
        name="MDR-20",
        copy_policy_from_site_id="site-10",
        clone_exclusions_from_site_id="site-10",
    )
    assert created["id"] == "site-20"
    create_call = sess.request.call_args_list[2].kwargs["json"]["data"]
    assert create_call["policy"] == {"antiTamperingOn": True}
    assert create_call["inherits"] is False

    client.duplicate_site("12345", "MDR-30", copy_users=True)
    dup_body = sess.request.call_args_list[5].kwargs["json"]["data"]
    assert dup_body["sourceSiteId"] == 12345
    assert isinstance(dup_body["sourceSiteId"], int)
    assert dup_body["copyUsers"] is True

    client.update_site("site-20", description="Updated")
    client.expire_site("site-20")
    client.reactivate_site("site-20", unlimited=True)
    assert client.rotate_site_token("site-20")["data"]["registrationToken"] == "tok-new"
    assert client.get_site_token("site-20")["data"]["token"] == "tok-current"
    client.update_site_policy(
        "site-20",
        {
            "antiTamperingOn": False,
            "createdAt": "ignore",
            "inheritedFrom": "account",
        },
    )
    pol_body = sess.request.call_args_list[11].kwargs["json"]["data"]
    assert pol_body == {"antiTamperingOn": False}

    client.revert_site_policy("site-20")
    with pytest.raises(ValueError, match="mismatch"):
        client.delete_site("site-20", confirm_site_name="wrong", expected_site_name="MDR-20")
    assert client.delete_site("site-20", confirm_site_name="MDR-20", expected_site_name="MDR-20")[
        "data"
    ]["success"]


def test_users_service_users_rbac_and_clone_permissions() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    sess.request.side_effect = [
        _mock_response(200, {"data": [{"id": "u-1", "email": "a@example.com"}]}),
        _mock_response(
            200,
            {
                "data": {
                    "id": "u-1",
                    "scope": "site",
                    "scopeRoles": [
                        {
                            "id": "site-old",
                            "roleId": "role-ir",
                            "roleName": "IR Team",
                            "name": "MDR-1",
                            "accountName": "Acct",
                        }
                    ],
                }
            },
        ),
        _mock_response(200, {"data": {"id": "u-2"}}),
        _mock_response(200, {"data": {"id": "u-2"}}),
        _mock_response(200, {"data": {"success": True}}),
        _mock_response(200, {"data": {"affected": 2}}),
        _mock_response(200, {"data": {"affected": 1}}),
        _mock_response(200, {"data": {"affected": 1}}),
        _mock_response(200, {"data": {"affected": 1}}),
        _mock_response(200, {"data": {"redirectTo": "/login"}}),
        _mock_response(200, {"data": [{"id": "su-1", "name": "automation"}]}),
        _mock_response(200, {"data": {"id": "su-1", "name": "automation"}}),
        _mock_response(200, {"data": {"id": "su-2", "name": "soar"}}),
        _mock_response(200, {"data": {"id": "su-2", "description": "SOAR"}}),
        _mock_response(200, {"data": {"token": "svc-tok"}}),
        _mock_response(200, {"data": {"success": True}}),
        _mock_response(200, {"data": {"affected": 1}}),
        _mock_response(200, {"data": [{"id": "role-ir", "name": "IR Team"}]}),
    ]

    assert client.list_users(two_fa_enabled=True)[0]["id"] == "u-1"
    cloned = client.clone_user_permissions("u-1", target_site_ids=["site-new-1", "site-new-2"])
    assert cloned["scope"] == "site"
    assert cloned["scopeRoles"] == [
        {"roleId": "role-ir", "id": "site-new-1"},
        {"roleId": "role-ir", "id": "site-new-2"},
    ]

    client.create_user(
        email="b@example.com",
        full_name="Analyst B",
        scope=cloned["scope"],
        scope_roles=cloned["scopeRoles"],
        two_fa_enabled=True,
    )
    client.update_user("u-2", scope="site", scope_roles=cloned["scopeRoles"], full_name="Analyst B2")
    client.delete_user("u-2")
    client.delete_users(["u-3", "u-4"])
    client.send_reset_password_email(["u-1"])
    client.reset_2fa(["u-1"], enroll=True)
    client.delete_2fa(["u-1"])
    client.logout_user()

    assert client.list_service_users()[0]["id"] == "su-1"
    assert client.get_service_user("su-1")["name"] == "automation"
    client.create_service_user(
        name="soar",
        scope="site",
        expiration_date="2027-01-01T00:00:00Z",
        scope_roles=[{"id": "site-1", "roleId": "role-ir", "name": "Readonly"}],
    )
    su_create_body = sess.request.call_args_list[12].kwargs["json"]["data"]
    assert su_create_body["scopeRoles"] == [{"roleId": "role-ir", "id": "site-1"}]

    client.update_service_user("su-2", description="SOAR", scope="site")
    assert client.generate_service_user_token("su-2", expiration_date="2027-06-01T00:00:00Z")[
        "data"
    ]["token"] == "svc-tok"
    client.delete_service_user("su-2")
    client.delete_service_users(["su-2"])
    assert client.list_rbac_roles(predefined_role=True)[0]["id"] == "role-ir"


def test_exclusion_update_validate_and_cloning_diff() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    long_desc = "X" * 495
    src_exclusions = [
        {
            "id": "e1",
            "type": "path",
            "osType": "windows",
            "value": r"C:\Tools\scanner.exe",
            "mode": "suppress",
            "description": long_desc,
            "scope": "site",
        },
        {
            "id": "e2",
            "type": "path",
            "osType": "windows",
            "value": r"C:\Windows\Temp\dup.exe",
            "mode": "suppress",
            "description": "Already at target site",
            "scope": "site",
        },
        {
            "id": "e3",
            "type": "white_hash",
            "osType": "windows",
            "value": "AABBCC" + ("0" * 34),
            "mode": "",
            "description": "Inherited from account",
            "scope": "site",
        },
    ]
    dst_exclusions = [
        {
            "id": "t2",
            "type": "path",
            "osType": "windows",
            "value": r"c:\windows\temp\dup.exe",  # case-insensitive Windows path match
            "mode": "suppress",
            "scope": "site",
        },
        {
            "id": "t3",
            "type": "white_hash",
            "osType": "windows",
            "value": "aabbcc" + ("0" * 34),  # lowercase hash match
            "mode": "",
            "scope": "account",
        },
    ]

    sess.request.side_effect = [
        _mock_response(200, {"data": {"status": "Valid", "details": []}}),
        _mock_response(200, {"data": {"id": "e1"}}),
        _mock_response(200, {"data": src_exclusions}),
        _mock_response(200, {"data": dst_exclusions}),
        _mock_response(200, {"data": src_exclusions}),
        _mock_response(200, {"data": dst_exclusions}),
        _mock_response(200, {"data": {"id": "new-e1"}}),
    ]

    val_res = client.validate_exclusion(
        exclusion_type="white_hash",
        os_type="windows",
        value="a" * 40,
    )
    assert val_res["status"] == "Valid"
    assert sess.request.call_args_list[0].kwargs["json"]["data"]["exclusionType"] == "hash"

    client.update_exclusion(
        "e1",
        exclusion_type="path",
        os_type="windows",
        value=r"C:\Tools\scanner2.exe",
        mode="suppress_dfi_only",
        actions=["detect"],
    )
    assert sess.request.call_args_list[1].kwargs["method"] == "PUT"

    dry_plan = client.clone_exclusions(
        "site-src",
        "site-dst",
        source_site_name="MDR-1234",
        dry_run=True,
    )
    assert dry_plan["counts"]["will_create"] == 1
    assert dry_plan["counts"]["skipped_duplicate"] == 1
    assert dry_plan["counts"]["inherited_from_account"] == 1
    assert sess.request.call_args_list[2].kwargs["params"]["includeParents"] == "false"
    assert sess.request.call_args_list[3].kwargs["params"]["includeParents"] == "true"
    planned_desc = dry_plan["will_create"][0]["payload"]["description"]
    assert len(planned_desc) <= 500
    assert planned_desc.endswith("[Cloned from MDR-1234]")

    live_res = client.clone_exclusions(
        "site-src",
        "site-dst",
        source_site_name="MDR-1234",
        dry_run=False,
    )
    assert live_res["counts"]["created"] == 1
    post_call = sess.request.call_args_list[6].kwargs
    assert post_call["method"] == "POST"
    assert post_call["json"]["filter"]["siteIds"] == ["site-dst"]


def test_agents_fetch_logs_decommission_count_and_update_blocklist() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sess.request.side_effect = [
        _mock_response(200, {"data": {"affected": 1}}),
        _mock_response(200, {"data": {"affected": 1}}),
        _mock_response(200, {"data": {"total": 42}}),
        _mock_response(200, {"data": {"id": "bl-1"}}),
    ]

    assert client.fetch_logs(["ag-1"])["data"]["affected"] == 1
    assert sess.request.call_args_list[0].kwargs["url"].endswith("/agents/actions/fetch-logs")

    assert client.decommission(["ag-1"])["data"]["affected"] == 1
    assert sess.request.call_args_list[1].kwargs["url"].endswith("/agents/actions/decommission")

    assert client.count_agents(site_ids=["site-200"], infected=True) == 42
    assert sess.request.call_args_list[2].kwargs["url"].endswith("/agents/count")

    client.update_blocklist("bl-1", sha1_hash=sha1, description="Updated IOC")
    assert sess.request.call_args_list[3].kwargs["method"] == "PUT"
    assert sess.request.call_args_list[3].kwargs["json"]["data"]["id"] == "bl-1"


def test_mutation_guardrail_rejects_blank_items_trailing_slashes_and_none_body() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    for bad_body in (
        {"filter": {"ids": [""]}, "data": {"incidentStatus": "resolved"}},
        {"filter": {"ids": [None]}, "data": {"incidentStatus": "resolved"}},
        {"filter": {"siteIds": ["   "]}, "data": {"incidentStatus": "resolved"}},
    ):
        with pytest.raises(ValueError, match="empty or unscoped filter"):
            client._request("POST", "threats/mitigate/kill", json_body=bad_body)

    for method, path, body in (
        ("DELETE", "exclusions/", {"data": {"ids": []}}),
        ("DELETE", "/web/api/v2.1/exclusions/", None),
        ("DELETE", "restrictions/", {"data": {"ids": [""]}}),
        ("DELETE", "restrictions", None),
        ("POST", "users/reset-2fa/", {"data": {"ids": []}}),
        ("POST", "users/reset-2fa", None),
        ("POST", "users/delete-2fa/", {"data": {"ids": [None]}}),
        ("POST", "users/delete-2fa", None),
    ):
        with pytest.raises(ValueError, match="data.ids"):
            client._request(method, path, json_body=body)

    sess.request.assert_not_called()


def test_rate_pacer_and_clone_reject_non_finite_rps() -> None:
    import soclens.sentinelone as s1_mod

    stop = threading.Event()
    for bad_rps in (float("nan"), float("inf"), float("-inf"), 0.0, -1.0):
        with pytest.raises(ValueError, match="finite positive"):
            s1_mod._RatePacer(bad_rps, stop_event=stop)
        with pytest.raises(ValueError, match="finite positive"):
            SentinelOneClient(
                console_url="https://usea1.sentinelone.net",
                api_token="tok-abc",
                max_requests_per_second=bad_rps,
                session=MagicMock(spec=requests.Session),
            )

    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)
    for bad_rps in (float("nan"), float("inf"), 0.0):
        with pytest.raises(ValueError, match="finite positive"):
            client.clone_exclusions("site-src", "site-dst", requests_per_second=bad_rps)
    sess.request.assert_not_called()


def test_clone_user_account_scope_windows_path_dedup_and_put_exclusion_schema() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    sess.request.side_effect = [
        _mock_response(
            200,
            {
                "data": {
                    "id": "u-acct",
                    "scope": "account",
                    "scopeRoles": [{"roleId": "role-ir", "id": "acct-1"}],
                }
            },
        ),
        _mock_response(
            200,
            {
                "data": [
                    {
                        "id": "src-win",
                        "type": "path",
                        "osType": "windows",
                        "value": "C:/Tools/App/",
                        "mode": "suppress",
                        "scope": "site",
                    }
                ]
            },
        ),
        _mock_response(
            200,
            {
                "data": [
                    {
                        "id": "dst-win",
                        "type": "path",
                        "osType": "windows",
                        "value": r"c:\tools\app",
                        "mode": "suppress",
                        "scope": "site",
                    }
                ]
            },
        ),
        _mock_response(200, {"data": {"id": "e1"}}),
    ]

    cloned = client.clone_user_permissions("u-acct", target_site_ids=["site-99"])
    assert cloned["scope"] == "site"
    assert cloned["scopeRoles"] == [{"roleId": "role-ir", "id": "site-99"}]

    plan = client.plan_clone_exclusions("site-src", "site-dst", source_site_name="MDR-1")
    assert plan["counts"]["will_create"] == 0
    assert plan["counts"]["skipped_duplicate"] == 1

    client.update_exclusion(
        "e1",
        exclusion_type="path",
        os_type="windows",
        value=r"C:\Tools\Updated.exe",
        site_ids=["site-99"],
    )
    put_body = sess.request.call_args_list[3].kwargs["json"]
    assert "filter" not in put_body
    assert put_body["data"]["id"] == "e1"


def test_mutation_guardrail_requires_filter_on_filter_scoped_paths_and_strips_query() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    for bad_body in (None, {}, {"data": {}}):
        with pytest.raises(ValueError, match="empty or unscoped filter"):
            client._request("POST", "threats/mitigate/kill", json_body=bad_body)
        with pytest.raises(ValueError, match="empty or unscoped filter"):
            client._request("POST", "agents/actions/disconnect", json_body=bad_body)
        with pytest.raises(ValueError, match="empty or unscoped filter"):
            client._request("POST", "threats/add-to-exclusions", json_body=bad_body)
        with pytest.raises(ValueError, match="empty or unscoped filter"):
            client._request("POST", "cloud-detection/alerts/incident", json_body=bad_body)
        with pytest.raises(ValueError, match="empty or unscoped filter"):
            client._request("POST", "users/delete-users", json_body=bad_body)
        with pytest.raises(ValueError, match="empty or unscoped filter"):
            client._request("POST", "service-users/delete-service-users", json_body=bad_body)

    with pytest.raises(ValueError, match="data.ids"):
        client._request("DELETE", "exclusions?accountIds=1", json_body=None)
    with pytest.raises(ValueError, match="data.ids"):
        client._request("DELETE", "/web/api/v2.1/restrictions?siteIds=2", json_body=None)

    sess.request.assert_not_called()

    # Legitimate non-filter mutations remain allowed
    sess.request.side_effect = [
        _mock_response(200, {"data": {"success": True}}),
        _mock_response(200, {"data": {"id": "site-1"}}),
        _mock_response(200, {"data": {"status": "valid"}}),
        _mock_response(200, {"data": {"queryId": "q-1"}}),
    ]
    client.logout_user()
    client.expire_site("site-1")
    client.validate_exclusion(
        exclusion_type="path",
        os_type="windows",
        value=r"C:\Tools\App.exe",
    )
    client.create_dv_query(
        "src.process.name = 'cmd.exe'",
        "2026-11-24T00:00:00Z",
        "2026-11-25T00:00:00Z",
    )
    assert sess.request.call_count == 4


def test_normalize_id_list_skips_none_and_rejects_bytes() -> None:
    import soclens.sentinelone as s1_mod

    assert s1_mod._normalize_id_list([None, "  ", " th-1 ", "th-1", "th-2"]) == ["th-1", "th-2"]  # type: ignore[list-item]
    with pytest.raises(ValueError, match="At least one non-empty ID"):
        s1_mod._normalize_id_list([None, "   "])  # type: ignore[list-item]
    for bad in (b"th-1", bytearray(b"th-1"), [b"th-1"]):
        with pytest.raises(ValueError, match="Bytes"):
            s1_mod._normalize_id_list(bad)  # type: ignore[arg-type]

    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)
    with pytest.raises(ValueError, match="At least one non-empty ID"):
        client.mitigate_threat([None], "kill")  # type: ignore[list-item]
    sess.request.assert_not_called()


def test_clone_exclusions_fetches_more_than_100_items_across_pages() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    src_page_1 = [
        {
            "id": f"src-{i}",
            "type": "path",
            "osType": "windows",
            "value": rf"C:\Tools\app_{i}.exe",
            "mode": "suppress",
            "scope": "site",
        }
        for i in range(100)
    ]
    src_page_2 = [
        {
            "id": f"src-{i}",
            "type": "path",
            "osType": "windows",
            "value": rf"C:\Tools\app_{i}.exe",
            "mode": "suppress",
            "scope": "site",
        }
        for i in range(100, 130)
    ]
    dst_page_1 = [
        {
            "id": f"dst-{i}",
            "type": "path",
            "osType": "windows",
            "value": rf"C:\Other\other_{i}.exe",
            "mode": "suppress",
            "scope": "site",
        }
        for i in range(100)
    ]
    dst_page_2 = [
        {
            "id": f"dst-dup-{i}",
            "type": "path",
            "osType": "windows",
            "value": rf"C:\Tools\app_{i}.exe",
            "mode": "suppress",
            "scope": "site",
        }
        for i in range(100, 105)
    ]

    sess.request.side_effect = [
        _mock_response(200, {"data": src_page_1, "pagination": {"nextCursor": "src-p2"}}),
        _mock_response(200, {"data": src_page_2, "pagination": {"nextCursor": None}}),
        _mock_response(200, {"data": dst_page_1, "pagination": {"nextCursor": "dst-p2"}}),
        _mock_response(200, {"data": dst_page_2, "pagination": {"nextCursor": None}}),
        _mock_response(200, {"data": src_page_1, "pagination": {"nextCursor": "src-p2"}}),
        _mock_response(200, {"data": src_page_2, "pagination": {"nextCursor": None}}),
        _mock_response(200, {"data": dst_page_1, "pagination": {"nextCursor": "dst-p2"}}),
        _mock_response(200, {"data": dst_page_2, "pagination": {"nextCursor": None}}),
    ]

    plan = client.plan_clone_exclusions("site-src", "site-dst", source_site_name="MDR-130")
    assert plan["counts"]["source_total"] == 130
    assert plan["counts"]["target_total"] == 105
    assert plan["counts"]["skipped_duplicate"] == 5
    assert plan["counts"]["will_create"] == 125

    dry_plan = client.clone_exclusions("site-src", "site-dst", dry_run=True)
    assert dry_plan["counts"]["source_total"] == 130
    assert dry_plan["counts"]["will_create"] == 125
    assert all(call.kwargs["params"]["limit"] <= 100 for call in sess.request.call_args_list)


def test_scope_filter_dict_does_not_leak_default_site_or_account_on_explicit_scope() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    sess.request.return_value = _mock_response(200, {"data": {"id": "ok"}})
    client = SentinelOneClient(
        console_url="https://usea1.sentinelone.net",
        api_token="tok-abc",
        account_id="acc-default",
        site_id="site-default",
        session=sess,
    )

    client.create_exclusion(
        exclusion_type="path",
        os_type="windows",
        value=r"C:\Tools\acct.exe",
        account_ids=["acc-override"],
    )
    assert sess.request.call_args_list[0].kwargs["json"]["filter"] == {
        "accountIds": ["acc-override"]
    }

    client.create_exclusion(
        exclusion_type="path",
        os_type="windows",
        value=r"C:\Tools\site.exe",
        site_ids=["site-override"],
    )
    assert sess.request.call_args_list[1].kwargs["json"]["filter"] == {
        "siteIds": ["site-override"]
    }

    client.add_to_blocklist("a" * 40, group_ids=["grp-1"])
    assert sess.request.call_args_list[2].kwargs["json"]["filter"] == {"groupIds": ["grp-1"]}

    client.create_exclusion(
        exclusion_type="path",
        os_type="windows",
        value=r"C:\Tools\default.exe",
    )
    assert sess.request.call_args_list[3].kwargs["json"]["filter"] == {
        "accountIds": ["acc-default"],
        "siteIds": ["site-default"],
    }


def test_mutation_guardrail_collapses_slashes_and_blocks_filterless_exclusions_restrictions() -> None:
    sess = MagicMock(spec=requests.Session)
    sess.headers = {}
    client = _make_client(sess)

    for method, path, body in (
        ("POST", "exclusions", {"data": {"type": "path"}}),
        ("POST", "restrictions", {"data": {"type": "black_hash"}}),
        ("PUT", "restrictions", {"data": {"id": "r-1"}}),
        ("POST", "threats//incident", {"data": {}}),
        ("POST", "/web//api/v2.1//exclusions/?a=1#frag", {"data": {"type": "path"}}),
    ):
        with pytest.raises(ValueError, match="empty or unscoped filter"):
            client._request(method, path, json_body=body)
    sess.request.assert_not_called()



