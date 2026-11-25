"""Unit tests for SplunkESClient (notables, correlations, threat intel, assets/identities, risk) and CLI."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

import soclens.cli as cli_mod
from soclens.splunk import SplunkClient
from soclens.splunk_es import (
    NOTABLE_STATUS_LABELS,
    NOTABLE_STATUS_MAP,
    NOTABLE_URGENCIES,
    THREAT_INTEL_COLLECTIONS,
    SplunkESClient,
    SplunkESError,
    normalize_notable_status,
)


def _make_response(
    status_code: int,
    payload: object = None,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    if payload is None:
        resp.json.side_effect = ValueError("No JSON body")
        resp.text = ""
    elif isinstance(payload, str):
        resp.json.side_effect = ValueError("Invalid JSON")
        resp.text = payload
    else:
        resp.json.return_value = payload
        resp.text = json.dumps(payload)
    return resp


def _make_es_client_with_mock_splunk() -> tuple[SplunkESClient, MagicMock]:
    mock_splunk = MagicMock(spec=SplunkClient)
    mock_splunk.host = "https://splunk.local:8089"
    mock_splunk.app = "SplunkEnterpriseSecuritySuite"
    es = SplunkESClient(splunk_client=mock_splunk)
    return es, mock_splunk


class TestSplunkESClient:
    def test_constants_and_status_normalization(self) -> None:
        assert NOTABLE_STATUS_MAP == {
            "new": 1,
            "in_progress": 2,
            "pending": 3,
            "resolved": 4,
            "closed": 5,
        }
        assert NOTABLE_STATUS_LABELS[2] == "In Progress"
        assert "critical" in NOTABLE_URGENCIES
        assert "ip_intel" in THREAT_INTEL_COLLECTIONS
        assert normalize_notable_status("in_progress") == 2
        assert normalize_notable_status("In Progress") == 2
        assert normalize_notable_status("4") == 4
        assert normalize_notable_status(5) == 5
        with pytest.raises(ValueError, match="Unsupported notable status"):
            normalize_notable_status("bogus")

    def test_context_manager_defaults_to_es_app(self) -> None:
        session = MagicMock(spec=requests.Session)
        with SplunkESClient(
            host="https://splunk.local:8089",
            token="tok",
            verify_ssl=False,
            session=session,
        ) as es:
            assert es.app == "SplunkEnterpriseSecuritySuite"
            assert es.list_threat_collections() == THREAT_INTEL_COLLECTIONS

    def test_list_notables_builds_spl_and_normalizes_rows(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk.run_search.return_value = {
            "status": "success",
            "results": [
                {
                    "event_id": "abc-123@@notable@@1",
                    "rule_name": "RF High Risk IP Activity",
                    "urgency": "High",
                    "status": "2",
                    "owner": "analyst1",
                    "disposition": "true_positive",
                    "security_domain": "network",
                    "src": ["198.51.100.10", "198.51.100.11"],
                    "dest": "10.0.0.5",
                    "user": "jdoe",
                    "risk_score": "85",
                    "_time": "2026-11-24T12:00:00Z",
                    "custom_field": "extra_val",
                }
            ],
        }

        notables = es.list_notables(
            earliest="-12h",
            latest="now",
            urgency="high",
            status="in_progress",
            owner="analyst1",
            rule_name="RF High Risk",
            search_text="198.51.100",
            limit=25,
        )

        assert len(notables) == 1
        row = notables[0]
        assert row["event_id"] == "abc-123@@notable@@1"
        assert row["rule_name"] == "RF High Risk IP Activity"
        assert row["urgency"] == "high"
        assert row["status"] == 2
        assert row["status_label"] == "In Progress"
        assert row["owner"] == "analyst1"
        assert row["src"] == "198.51.100.10, 198.51.100.11"
        assert row["raw"]["custom_field"] == "extra_val"

        called_spl = mock_splunk.run_search.call_args.args[0]
        assert called_spl.startswith("`notable`")
        assert 'urgency="high"' in called_spl
        assert '(status=2 OR status_label="In Progress")' in called_spl
        assert 'owner="analyst1"' in called_spl
        assert 'rule_name="*RF High Risk*"' in called_spl
        assert '"*198.51.100*"' in called_spl
        assert "| head 25" in called_spl

    def test_list_notables_raises_on_search_failure(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk.run_search.return_value = {
            "status": "failed",
            "error_message": "Macro notable not found",
            "messages": ["Unknown macro"],
        }
        with pytest.raises(SplunkESError, match="Macro notable not found"):
            es.list_notables()

    def test_update_notable_posts_form_payload(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk._request.return_value = _make_response(
            200, {"success": True, "message": "Updated 2 notables"}
        )

        res = es.update_notable(
            ["ev-1", "ev-2"],
            status="resolved",
            urgency="critical",
            owner="soc_lead",
            disposition="true_positive",
            comment="Confirmed C2 traffic",
        )
        assert res["success"] is True
        mock_splunk._request.assert_called_once_with(
            "POST",
            "/services/notable_update?output_mode=json",
            data={
                "ruleUIDs": ["ev-1", "ev-2"],
                "status": "4",
                "urgency": "critical",
                "newOwner": "soc_lead",
                "disposition": "true_positive",
                "comment": "Confirmed C2 traffic",
            },
        )

        with pytest.raises(ValueError, match="At least one notable event_id"):
            es.update_notable([], status="closed")
        with pytest.raises(ValueError, match="At least one update field"):
            es.update_notable(["ev-1"])

    def test_list_and_toggle_correlation_searches(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk._request.return_value = _make_response(
            200,
            {
                "entry": [
                    {
                        "name": "Network - RF Malicious IP - Rule",
                        "acl": {"app": "SplunkEnterpriseSecuritySuite"},
                        "content": {
                            "action.notable": "1",
                            "action.risk": "0",
                            "action.correlationsearch.enabled": "1",
                            "action.correlationsearch.label": "RF Malicious IP",
                            "action.notable.param.security_domain": "network",
                            "action.notable.param.severity": "high",
                            "search": "index=firewall | lookup rf_ip_risklist",
                            "cron_schedule": "*/15 * * * *",
                            "disabled": False,
                            "description": "Detects RF high risk IPs",
                        },
                    },
                    {
                        "name": "Regular Non-Correlation Saved Search",
                        "acl": {"app": "SplunkEnterpriseSecuritySuite"},
                        "content": {
                            "action.notable": "0",
                            "action.risk": "0",
                            "action.correlationsearch.enabled": "0",
                            "search": "index=_internal | head 5",
                            "disabled": False,
                        },
                    },
                    {
                        "name": "Endpoint - Risk Score Rule",
                        "acl": {"app": "SplunkEnterpriseSecuritySuite"},
                        "content": {
                            "action.risk": "1",
                            "search": "index=endpoint | stats count",
                            "disabled": True,
                        },
                    },
                ]
            },
        )

        corrs = es.list_correlation_searches()
        assert len(corrs) == 2
        assert corrs[0]["name"] == "Network - RF Malicious IP - Rule"
        assert corrs[0]["enabled"] is True
        assert corrs[1]["name"] == "Endpoint - Risk Score Rule"
        assert corrs[1]["enabled"] is False

        filtered = es.list_correlation_searches(search_filter="rf malicious")
        assert len(filtered) == 1
        assert filtered[0]["name"] == "Network - RF Malicious IP - Rule"

        mock_splunk._request.return_value = _make_response(200, {"entry": []})
        toggle_res = es.set_correlation_search_enabled("Network - RF Malicious IP - Rule", False)
        assert toggle_res["enabled"] is False
        assert toggle_res["disabled"] is True
        called_url = mock_splunk._request.call_args.args[1]
        assert (
            "/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/"
            "Network%20-%20RF%20Malicious%20IP%20-%20Rule?output_mode=json"
            == called_url
        )
        assert mock_splunk._request.call_args.kwargs["data"] == {"disabled": "1"}

    def test_threat_intel_kv_store_query_and_add(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk._request.return_value = _make_response(
            200,
            [{"_key": "k1", "ip": "198.51.100.5", "description": "RF C2", "threat_key": "rf_ip"}],
        )

        entries = es.query_threat_intel("ip_intel", query={"ip": "198.51.100.5"}, limit=50)
        assert len(entries) == 1
        assert entries[0]["ip"] == "198.51.100.5"
        args, kwargs = mock_splunk._request.call_args
        assert args == (
            "GET",
            "/servicesNS/nobody/DA-ESS-ThreatIntelligence/storage/collections/data/ip_intel",
        )
        assert kwargs["params"]["limit"] == 50
        assert json.loads(kwargs["params"]["query"]) == {"ip": "198.51.100.5"}

        mock_splunk._request.return_value = _make_response(201, {"_key": "k_new"})
        added = es.add_threat_intel_entry(
            "domain_intel",
            {"domain": "bad.example", "description": "RF Malware", "threat_key": "rf_domain"},
        )
        assert added == {"_key": "k_new"}
        args, kwargs = mock_splunk._request.call_args
        assert args == (
            "POST",
            "/servicesNS/nobody/DA-ESS-ThreatIntelligence/storage/collections/data/domain_intel",
        )
        assert kwargs["json"]["domain"] == "bad.example"

        with pytest.raises(ValueError, match="Unsupported threat intelligence collection"):
            es.query_threat_intel("invalid_collection")

    def test_assets_identities_and_risk_events(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk.run_search.side_effect = [
            {"status": "success", "results": [{"ip": "10.1.2.3", "nt_host": "db01"}]},
            {"status": "success", "results": [{"identity": "jdoe", "email": "jdoe@corp.local"}]},
            {
                "status": "success",
                "results": [
                    {"risk_object": "db01", "risk_score": "65", "search_name": "RF Risk Rule"}
                ],
            },
        ]

        assets = es.lookup_asset(query="db01", limit=10)
        assert assets == [{"ip": "10.1.2.3", "nt_host": "db01"}]
        assert "| inputlookup asset_lookup_by_str" in mock_splunk.run_search.call_args_list[0].args[0]

        identities = es.lookup_identity(query="jdoe", limit=10)
        assert identities == [{"identity": "jdoe", "email": "jdoe@corp.local"}]
        assert (
            "| inputlookup identity_lookup_expanded"
            in mock_splunk.run_search.call_args_list[1].args[0]
        )

        risks = es.list_risk_events(risk_object="db01", earliest="-12h", limit=20)
        assert risks[0]["risk_score"] == "65"
        risk_spl = mock_splunk.run_search.call_args_list[2].args[0]
        assert "index=risk" in risk_spl
        assert 'risk_object="db01"' in risk_spl
        assert "| head 20" in risk_spl


class TestSplunkESCLI:
    def test_cli_splunk_es_subcommands(
        self,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("SPLUNK_HOST", "https://splunk.local:8089")
        monkeypatch.setenv("SPLUNK_TOKEN", "tok")

        fake_es = MagicMock(spec=SplunkESClient)
        fake_es.__enter__.return_value = fake_es
        fake_es.__exit__.return_value = None
        fake_es.list_notables.return_value = [
            {
                "_time": "2026-11-24T12:00:00Z",
                "event_id": "ev-100",
                "urgency": "high",
                "status": 1,
                "status_label": "New",
                "rule_name": "RF High Risk IP",
                "owner": "unassigned",
                "src": "198.51.100.1",
                "dest": "10.0.0.1",
            }
        ]
        fake_es.update_notable.return_value = {"success": True}
        fake_es.list_correlation_searches.return_value = [
            {
                "name": "RF Rule 1",
                "enabled": True,
                "severity": "high",
                "security_domain": "network",
                "cron_schedule": "*/15 * * * *",
                "action_notable": True,
                "action_risk": False,
            }
        ]
        fake_es.set_correlation_search_enabled.return_value = {
            "name": "RF Rule 1",
            "enabled": False,
            "disabled": True,
        }
        fake_es.query_threat_intel.return_value = [
            {"_key": "k1", "ip": "198.51.100.1", "description": "RF C2"}
        ]
        fake_es.lookup_asset.return_value = [{"ip": "10.0.0.1", "nt_host": "app01"}]
        fake_es.lookup_identity.return_value = [{"identity": "alice", "email": "alice@corp.local"}]
        fake_es.list_risk_events.return_value = [
            {"risk_object": "app01", "risk_score": "70", "search_name": "RBA Rule"}
        ]

        with patch.object(cli_mod, "_build_splunk_es_client_from_args", return_value=fake_es):
            # 1. notables --format json
            monkeypatch.setattr(
                "sys.argv",
                [
                    "soclens",
                    "splunk",
                    "es",
                    "notables",
                    "--earliest",
                    "-12h",
                    "--urgency",
                    "high",
                    "--format",
                    "json",
                ],
            )
            cli_mod.main()
            out = json.loads(capsys.readouterr().out)
            assert out["count"] == 1
            assert out["notables"][0]["event_id"] == "ev-100"

            # 2. update-notable --dry-run (does not call API)
            monkeypatch.setattr(
                "sys.argv",
                [
                    "soclens",
                    "splunk",
                    "es",
                    "update-notable",
                    "ev-100",
                    "--status",
                    "in_progress",
                    "--dry-run",
                ],
            )
            cli_mod.main()
            assert "DRY-RUN" in capsys.readouterr().out
            fake_es.update_notable.assert_not_called()

            # 3. update-notable live
            monkeypatch.setattr(
                "sys.argv",
                [
                    "soclens",
                    "splunk",
                    "es",
                    "update-notable",
                    "ev-100",
                    "--status",
                    "resolved",
                    "--owner",
                    "analyst1",
                    "--comment",
                    "Done",
                ],
            )
            cli_mod.main()
            assert "Updated Splunk ES notable 'ev-100'" in capsys.readouterr().out
            fake_es.update_notable.assert_called_once()

            # 4. correlations
            monkeypatch.setattr(
                "sys.argv",
                ["soclens", "splunk", "es", "correlations", "--filter", "RF"],
            )
            cli_mod.main()
            assert "RF Rule 1" in capsys.readouterr().out

            # 5. toggle-correlation --dry-run
            monkeypatch.setattr(
                "sys.argv",
                [
                    "soclens",
                    "splunk",
                    "es",
                    "toggle-correlation",
                    "RF Rule 1",
                    "--disable",
                    "--dry-run",
                ],
            )
            cli_mod.main()
            assert "DRY-RUN" in capsys.readouterr().out
            fake_es.set_correlation_search_enabled.assert_not_called()

            # 6. toggle-correlation --disable --yes
            monkeypatch.setattr(
                "sys.argv",
                [
                    "soclens",
                    "splunk",
                    "es",
                    "toggle-correlation",
                    "RF Rule 1",
                    "--disable",
                    "--yes",
                ],
            )
            cli_mod.main()
            assert "disabled" in capsys.readouterr().out
            fake_es.set_correlation_search_enabled.assert_called_once_with("RF Rule 1", False)

            # 7. threat-intel
            monkeypatch.setattr(
                "sys.argv",
                ["soclens", "splunk", "es", "threat-intel", "ip_intel", "--limit", "10", "--json"],
            )
            cli_mod.main()
            ti_out = json.loads(capsys.readouterr().out)
            assert ti_out["collection"] == "ip_intel"
            assert ti_out["count"] == 1

            # 8. assets
            monkeypatch.setattr(
                "sys.argv",
                ["soclens", "splunk", "es", "assets", "--query", "app01", "--json"],
            )
            cli_mod.main()
            assert json.loads(capsys.readouterr().out)["assets"][0]["nt_host"] == "app01"

            # 9. identities
            monkeypatch.setattr(
                "sys.argv",
                ["soclens", "splunk", "es", "identities", "--query", "alice", "--json"],
            )
            cli_mod.main()
            assert json.loads(capsys.readouterr().out)["identities"][0]["identity"] == "alice"

            # 10. risk
            monkeypatch.setattr(
                "sys.argv",
                [
                    "soclens",
                    "splunk",
                    "es",
                    "risk",
                    "--risk-object",
                    "app01",
                    "--earliest",
                    "-24h",
                    "--json",
                ],
            )
            cli_mod.main()
            assert json.loads(capsys.readouterr().out)["risk_events"][0]["risk_score"] == "70"
