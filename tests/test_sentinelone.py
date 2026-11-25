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
