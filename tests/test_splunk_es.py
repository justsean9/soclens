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


class TestSplunkESMissionControlAndTenant:
    def test_tenant_extraction_case_insensitive_and_aliases(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from soclens.splunk_es import extract_custom_fields, extract_finding_tenant

        monkeypatch.delenv("SPLUNK_ES_TENANT_FIELD", raising=False)
        monkeypatch.delenv("SPLUNK_ES_TENANT_ALIASES", raising=False)

        assert extract_finding_tenant({"Tenant_ID": "ACME-01"}) == "ACME-01"
        assert extract_finding_tenant({"raw": {"ORG_ID": "ORG-99"}}) == "ORG-99"
        assert extract_finding_tenant({"custom_fields": {"client_code": "CL-42"}}) == "CL-42"
        assert extract_finding_tenant({"fields": {"customer_id": "CUST-7"}}) == "CUST-7"

        monkeypatch.setenv("SPLUNK_ES_TENANT_FIELD", "msp_tenant")
        monkeypatch.setenv("SPLUNK_ES_CUSTOM_FIELDS", "snow_ticket,case_id")
        row = {
            "event_id": "f1",
            "_raw": "ignored",
            "_time": "2026-11-24T12:00:00Z",
            "date_hour": "12",
            "splunk_server": "idx1",
            "src": "198.51.100.1",
            "MSP_Tenant": "TENANT-X",
            "snow_ticket": "INC999",
            "org_unit": "Finance",
        }
        assert extract_finding_tenant(row) == "TENANT-X"
        cf = extract_custom_fields(row, pinned_fields=("snow_ticket", "case_id"))
        assert cf["snow_ticket"] == "INC999"
        assert cf["org_unit"] == "Finance"
        assert "_raw" not in cf
        assert "date_hour" not in cf
        assert "splunk_server" not in cf

    def test_discover_custom_fields_fallback_and_graceful_403(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        attrs = [
            {"field": "tenant_id", "label": "Tenant ID"},
            {"field": "snow_ticket", "label": "ServiceNow Ticket"},
        ]
        mock_splunk._request.side_effect = [
            _make_response(404, {"messages": [{"text": "Not found"}]}),
            _make_response(
                200,
                {
                    "entry": [
                        {
                            "content": {
                                "event_attributes": json.dumps(attrs),
                            }
                        }
                    ]
                },
            ),
        ]
        discovered = es.discover_custom_fields()
        assert discovered == attrs
        assert mock_splunk._request.call_count == 2
        assert "conf-incident_review/incident_review" in mock_splunk._request.call_args_list[0].args[1]
        assert "conf-log_review/incident_review" in mock_splunk._request.call_args_list[1].args[1]

        # Cached on subsequent call
        assert es.discover_custom_fields() == attrs
        assert mock_splunk._request.call_count == 2

        # 403 returns [] gracefully
        mock_splunk._request.reset_mock()
        mock_splunk._request.side_effect = [_make_response(403, "Forbidden")]
        assert es.discover_custom_fields(force_refresh=True) == []

    def test_mc_v2_findings_url_encoding_and_create(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        finding_id = "abc-123@@notable@@time1700000000"
        mock_splunk._request.side_effect = [
            _make_response(
                200,
                {
                    "items": [
                        {
                            "event_id": finding_id,
                            "rule_title": "Suspicious Beacon",
                            "rule_name": "net_beacon",
                            "urgency": "high",
                            "status": "1",
                            "status_label": "New",
                            "disposition": "disposition:6",
                            "disposition_label": "Undetermined",
                            "tenant_id": "ACME",
                            "orig_sid": "sid_99",
                            "orig_rid": "0",
                            "_time": "2026-11-24T12:00:00Z",
                        }
                    ],
                    "offset": 0,
                    "limit": 50,
                    "total": 1,
                },
            ),
            _make_response(
                200,
                {
                    "event_id": finding_id,
                    "rule_title": "Suspicious Beacon",
                    "tenant_id": "ACME",
                },
            ),
            _make_response(201, {"finding_id": "manual-1", "_time": "2026-11-24T12:05:00Z"}),
            _make_response(201, {"status": "success", "created": 1, "failed": 0, "findings": ["m1"]}),
        ]

        res = es.list_findings(urgency="high", limit=50)
        assert res["total"] == 1
        assert res["items"][0]["tenant_id"] == "ACME"
        assert res["items"][0]["rule_title"] == "Suspicious Beacon"

        single = es.get_finding(finding_id)
        assert single["event_id"] == finding_id
        get_url = mock_splunk._request.call_args_list[1].args[1]
        assert "abc-123%40%40notable%40%40time1700000000" in get_url

        created = es.create_finding(
            rule_title="Manual Hunt",
            security_domain="threat",
            additional_fields={"tenant_id": "ACME", "snow_ticket": "INC1"},
        )
        assert created["finding_id"] == "manual-1"
        post_json = mock_splunk._request.call_args_list[2].kwargs["json"]
        assert post_json["additional_fields"] == [
            {"name": "tenant_id", "value": "ACME"},
            {"name": "snow_ticket", "value": "INC1"},
        ]

        bulk = es.bulk_create_findings(
            [{"rule_title": "Bulk 1", "security_domain": "threat", "additional_fields": {"tenant_id": "ACME"}}]
        )
        assert bulk["created"] == 1

    def test_mc_v2_investigations_bare_list_notes_history_and_bulk_update(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        finding_id = "ev@@notable@@1"
        mock_splunk._request.side_effect = [
            _make_response(
                200,
                [
                    {
                        "investigation_guid": "inv-1",
                        "name": "C2 Incident",
                        "urgency": "critical",
                        "status_name": "In Progress",
                        "custom_fields": {"tenant_id": "ACME"},
                    }
                ],
            ),
            _make_response(201, {"investigation_guid": "inv-2"}),
            _make_response(200, {"investigation_guid": "inv-2"}),
            _make_response(200, {"investigation_guid": "inv-2"}),
            _make_response(200, [{"id": finding_id}]),
            _make_response(200, {"items": [{"id": "n1", "content": "Note 1"}], "total": 1}),
            _make_response(201, {"id": "n2", "content": "Created"}),
            _make_response(200, {"id": "n2", "content": "Updated"}),
            _make_response(200, {}),
            _make_response(200, {"items": [{"user": "alice", "message": "Changed status"}], "total": 1}),
            _make_response(200, {"queues": [{"id": "__system_default_queue__"}], "last_updated_time": 1}),
            _make_response(200, {"id": "a1", "nt_host": ["ws-01"]}),
            _make_response(200, {"id": "i1", "identity": ["jdoe"]}),
            _make_response(200, [{"entity": "ws-01", "risk_score": 80, "entity_type": "system"}]),
            _make_response(201, {"message": "Risk updated"}),
        ]

        invs = es.list_investigations()
        assert len(invs) == 1
        assert invs[0]["investigation_guid"] == "inv-1"
        assert invs[0]["tenant_id"] == "ACME"

        assert es.create_investigation("New Inv", finding_ids=[finding_id])["investigation_guid"] == "inv-2"
        assert es.update_investigation("inv-2", status="Resolved")["investigation_guid"] == "inv-2"
        assert es.add_findings_to_investigation("inv-2", [finding_id])["investigation_guid"] == "inv-2"
        assert es.bulk_update_findings(record_ids=[finding_id], status="In Progress", disposition="true_positive") == [{"id": finding_id}]
        assert es.list_notes(finding_id)["total"] == 1
        assert es.create_note(finding_id, "Created", title="T")["id"] == "n2"
        assert es.update_note(finding_id, "n2", content="Updated")["content"] == "Updated"
        assert es.delete_note(finding_id, "n2")["deleted"] is True
        assert es.get_history(finding_id)["total"] == 1
        assert len(es.list_queues()["queues"]) == 1
        assert es.get_asset("a1")["nt_host"] == ["ws-01"]
        assert es.get_identity("i1")["identity"] == ["jdoe"]
        assert es.get_risk_scores("ws-01")[0]["risk_score"] == 80
        assert es.update_risk_score("ws-01", 25, entity_type="system")["message"] == "Risk updated"

        # Verify @@ encoding on notes and history calls
        notes_url = mock_splunk._request.call_args_list[5].args[1]
        history_url = mock_splunk._request.call_args_list[9].args[1]
        assert "ev%40%40notable%40%401/notes" in notes_url
        assert "ev%40%40notable%40%401/history" in history_url

    def test_query_findings_hybrid_ignores_no_unknown_params_and_falls_back(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk._request.return_value = _make_response(
            200,
            {
                "items": [
                    {"event_id": "e1", "rule_title": "Hit 1", "tenant_id": "ACME", "urgency": "high"},
                    {"event_id": "e2", "rule_title": "Hit 2", "tenant_id": "BETA", "urgency": "high"},
                ],
                "offset": 0,
                "limit": 200,
                "total": 2,
            },
        )
        res = es.query_findings_hybrid(urgency="high", tenant_id="ACME", limit=50)
        assert res["source_backend"] == "mc_v2"
        assert [i["event_id"] for i in res["items"]] == ["e1"]
        sent_params = mock_splunk._request.call_args.kwargs["params"]
        assert "tenant_id" not in sent_params
        assert sent_params["urgency"] == "high"

        # orig_sid routes directly to SPL without calling MC v2
        mock_splunk._request.reset_mock()
        mock_splunk.run_search.return_value = {
            "status": "success",
            "results": [{"event_id": "e3", "orig_sid": "sid_123", "rule_name": "SPL Hit"}],
        }
        spl_res = es.query_findings_hybrid(orig_sid="sid_123")
        assert spl_res["source_backend"] == "spl_fallback"
        assert spl_res["items"][0]["event_id"] == "e3"
        mock_splunk._request.assert_not_called()
        assert 'orig_sid="sid_123"' in mock_splunk.run_search.call_args.args[0]

        # HTTP 404 on MC v2 falls back automatically to SPL
        mock_splunk._request.return_value = _make_response(404, "Not found")
        mock_splunk.run_search.return_value = {
            "status": "success",
            "results": [{"event_id": "e4", "tenant_id": "ACME", "rule_name": "7x Notable"}],
        }
        fb_res = es.query_findings_hybrid(tenant_id="ACME")
        assert fb_res["source_backend"] == "spl_fallback"
        assert fb_res["items"][0]["event_id"] == "e4"

    def test_triage_findings_hybrid_mc_v2_and_404_fallback(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk._request.return_value = _make_response(200, [{"id": "ev-1"}])
        res = es.triage_findings_hybrid(["ev-1"], status="resolved", disposition="true_positive")
        assert res["backend"] == "mc_v2"
        sent_json = mock_splunk._request.call_args.kwargs["json"]
        assert sent_json["disposition"] == "disposition:1"

        # 404 falls back to notable_update
        mock_splunk._request.reset_mock()
        mock_splunk._request.side_effect = [
            _make_response(404, "Not found"),
            _make_response(200, {"success": True}),
        ]
        fb = es.triage_findings_hybrid(["ev-1"], status="resolved", disposition="disposition:1", note="Done")
        assert fb["backend"] == "notable_update"
        assert mock_splunk._request.call_args_list[1].args[1] == "/services/notable_update?output_mode=json"
        assert mock_splunk._request.call_args_list[1].kwargs["data"]["disposition"] == "true_positive"

    def test_adaptive_response_and_saved_views(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        from pathlib import Path

        from soclens.splunk_es import (
            delete_splunk_es_saved_view,
            load_splunk_es_saved_views,
            save_splunk_es_saved_view,
        )

        es, mock_splunk = _make_es_client_with_mock_splunk()
        assert es.list_modaction_invocations("", "0") == []

        mock_splunk._request.side_effect = [
            _make_response(
                200,
                {"success": True, "responses": [{"action_name": "risk", "action_status": "success"}]},
            ),
            _make_response(
                200,
                {
                    "entry": [
                        {
                            "name": "risk",
                            "content": {
                                "label": "Risk Analysis",
                                "param._cam": json.dumps({"supports_adhoc": True, "required_params": ["risk_score"]}),
                                "param.risk_score": "10",
                            },
                        },
                        {
                            "name": "email",
                            "content": {"label": "Send Email", "param._cam": json.dumps({"supports_adhoc": False})},
                        },
                    ]
                },
            ),
            _make_response(200, {"success": True}),
        ]
        invs = es.list_modaction_invocations("sid_1", "0")
        assert len(invs) == 1
        actions = es.list_adaptive_response_actions(adhoc_only=True)
        assert [a["name"] for a in actions] == ["risk"]
        assert actions[0]["default_params"]["risk_score"] == "10"

        disp = es.dispatch_adaptive_response("risk", sid="sid_1", rid="0", params={"risk_score": "50"})
        assert disp["success"] is True
        assert mock_splunk._request.call_args_list[2].kwargs["data"]["param.risk_score"] == "50"

        settings_file = Path(str(tmp_path)) / "settings.json"
        save_splunk_es_saved_view({"id": "v1", "label": "ACME High"}, settings_path=settings_file)
        loaded = load_splunk_es_saved_views(settings_path=settings_file)
        assert len(loaded) == 1 and loaded[0]["label"] == "ACME High"
        delete_splunk_es_saved_view("v1", settings_path=settings_file)
        assert load_splunk_es_saved_views(settings_path=settings_file) == []

    def test_query_findings_hybrid_investigations_offset_with_client_filter(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk._request.return_value = _make_response(
            200,
            [
                {"investigation_guid": "inv-1", "name": "Inv 1", "tenant_id": "ACME"},
                {"investigation_guid": "inv-x", "name": "Inv Beta", "tenant_id": "BETA"},
                {"investigation_guid": "inv-2", "name": "Inv 2", "tenant_id": "ACME"},
                {"investigation_guid": "inv-3", "name": "Inv 3", "tenant_id": "ACME"},
            ],
        )
        res = es.query_findings_hybrid(
            item_type="investigations",
            tenant_id="ACME",
            offset=1,
            limit=1,
        )
        assert res["source_backend"] == "mc_v2"
        assert res["total"] == 3
        assert res["offset"] == 1
        assert [it["event_id"] for it in res["items"]] == ["inv-2"]
        assert mock_splunk._request.call_args.kwargs["params"]["offset"] == 0

    def test_case_insensitive_pinned_fields_dedup_and_notable_normalize(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from soclens.splunk_es import _normalize_notable_row, extract_custom_fields

        monkeypatch.setenv("SPLUNK_ES_CUSTOM_FIELDS", "snow_ticket")
        row = {"event_id": "e-1", "rule_name": "R1", "Snow_Ticket": "INC777", "raw": {"snow_ticket": "INC777"}}
        cf = extract_custom_fields(row, pinned_fields=("snow_ticket",))
        assert cf == {"snow_ticket": "INC777"}

        norm = _normalize_notable_row({"event_id": "e-1", "rule_name": "R1", "Snow_Ticket": "INC777"})
        assert norm["custom_fields"] == {"snow_ticket": "INC777"}

    def test_spl_extended_normalizes_mc_disposition(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk._request.return_value = _make_response(404, "Not found")
        mock_splunk.run_search.return_value = {
            "status": "success",
            "results": [{"event_id": "e-5", "rule_name": "Rule 5", "disposition": "true_positive"}],
        }
        res = es.query_findings_hybrid(disposition="disposition:1")
        assert res["source_backend"] == "spl_fallback"
        sent_spl = mock_splunk.run_search.call_args.args[0]
        assert 'disposition="true_positive"' in sent_spl
        assert "disposition:1" not in sent_spl

        mock_splunk.run_search.reset_mock()
        res_label = es.query_findings_hybrid(disposition="True Positive - Suspicious Activity")
        assert res_label["source_backend"] == "spl_fallback"
        sent_spl_label = mock_splunk.run_search.call_args.args[0]
        assert 'disposition="true_positive"' in sent_spl_label
        assert 'disposition_label="*True Positive - Suspicious Activity*"' in sent_spl_label

    def test_query_findings_hybrid_investigations_unfiltered_respects_small_limit(self) -> None:
        es, mock_splunk = _make_es_client_with_mock_splunk()
        mock_splunk._request.return_value = _make_response(
            200,
            [
                {"investigation_guid": "inv-2", "name": "Inv 2"},
                {"investigation_guid": "inv-3", "name": "Inv 3"},
            ],
        )
        res = es.query_findings_hybrid(
            item_type="investigations",
            offset=1,
            limit=1,
        )
        assert res["source_backend"] == "mc_v2"
        assert len(res["items"]) == 1
        assert res["items"][0]["event_id"] == "inv-2"
        assert mock_splunk._request.call_args.kwargs["params"]["limit"] == 1
        assert mock_splunk._request.call_args.kwargs["params"]["offset"] == 1
