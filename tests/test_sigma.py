import configparser
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import pytest

from soclens.client import RecordedFutureAPIError, RecordedFutureRateLimitError
from soclens.config import ConfigurationError
from soclens.sigma import (
    SigmaConfigurationError,
    SigmaConversionConfig,
    convert_sigma_rule,
    convert_sigma_rules,
    convert_to_savedsearch_stanza,
    enrich_rules_in_place,
    export_rules_to_splunk,
    extract_sigma_metadata,
    flatten_rules,
    format_spl_index_clause,
    get_split_output_path,
    get_suppress_fields_for_logsource,
    get_table_fields_for_logsource,
    interactive_loop,
    load_rules,
    load_sigma_config,
    map_logsource_to_index,
    parse_field_list,
    parse_key_value_mapping,
    search_rules,
)
from soclens.splunk import parse_savedsearches_files


class TestSigmaIntegration:
    def test_map_logsource_to_index(self) -> None:
        assert map_logsource_to_index(None) == "*"
        assert map_logsource_to_index({}) == "*"
        assert map_logsource_to_index({"service": "sysmon"}) == "*sysmon"
        assert map_logsource_to_index({"product": "windows"}) == "*wineventlog"
        assert map_logsource_to_index({"product": "macos"}) == "*mac"
        assert map_logsource_to_index({"product": "linux"}) == "*unix"
        assert map_logsource_to_index({"product": "aws"}) == "*aws"
        assert map_logsource_to_index({"product": "unknown_os"}) == "*unknown_os"

    def test_get_split_output_path(self) -> None:
        assert get_split_output_path("savedsearches.conf", "*wineventlog") == (
            "savedsearches_wineventlog.conf"
        )
        assert get_split_output_path("/path/to/rules.conf", "*") == str(
            Path("/path/to/rules_other.conf")
        )

    def test_get_table_fields_for_logsource(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SOCLENS_DEFAULT_TABLE_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_TENANT_FIELD", raising=False)
        aws_fields = get_table_fields_for_logsource({"product": "aws"})
        assert "awsRegion" in aws_fields
        assert aws_fields == (
            "_time src_ip user eventName eventSource userIdentity.arn "
            "sourceIPAddress userAgent awsRegion"
        )
        assert "ScriptBlockText" in get_table_fields_for_logsource({"service": "powershell"})
        assert "CommandLine" in get_table_fields_for_logsource({})

    def test_get_suppress_fields_for_logsource(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SOCLENS_DEFAULT_SUPPRESS_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_TENANT_FIELD", raising=False)
        assert get_suppress_fields_for_logsource({"product": "aws"}) == (
            "userIdentity.arn,eventName"
        )
        assert get_suppress_fields_for_logsource({}) == "host,User"

    def test_configurable_table_and_suppress_fields(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SOCLENS_DEFAULT_TABLE_FIELDS", "_time host custom_field")
        monkeypatch.setenv("SOCLENS_DEFAULT_SUPPRESS_FIELDS", "custom_tenant,host")
        assert get_table_fields_for_logsource({"product": "windows"}) == "_time host custom_field"
        assert get_suppress_fields_for_logsource({"product": "windows"}) == "custom_tenant,host"
        assert (
            get_table_fields_for_logsource({"product": "windows"}, default_fields="_time src")
            == "_time src"
        )
        assert (
            get_suppress_fields_for_logsource({"product": "windows"}, default_fields="src,dest")
            == "src,dest"
        )

        monkeypatch.delenv("SOCLENS_DEFAULT_TABLE_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_DEFAULT_SUPPRESS_FIELDS", raising=False)
        monkeypatch.setenv("SOCLENS_TENANT_FIELD", "tenant_id")
        assert get_table_fields_for_logsource({}).endswith(" tenant_id")
        assert get_suppress_fields_for_logsource({}) == "tenant_id,host,User"

    def test_convert_to_savedsearch_stanza(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SOCLENS_DEFAULT_TABLE_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_DEFAULT_SUPPRESS_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_TENANT_FIELD", raising=False)

        rule_content = """
title: Test Malicious Activity
description: A mock detection rule
level: high
logsource:
  product: windows
tags:
  - attack.t1053.005
"""
        stanza = convert_to_savedsearch_stanza(
            rule_id="rule_abc",
            rule_title="Test Malicious Activity",
            rule_content=rule_content,
            splunk_query="EventID=1 CommandLine=*powershell*",
            cron_schedule="*/5 * * * *",
            earliest_time="-15m",
            latest_time="-5m",
        )

        assert "[Recorded Future Sigma (Automated) - Test Malicious Activity]" in stanza
        assert "search = index=*wineventlog EventID=1 CommandLine=*powershell*" in stanza
        assert "cron_schedule = */5 * * * *" in stanza
        assert "dispatch.earliest_time = -15m" in stanza
        assert "dispatch.latest_time = -5m" in stanza
        assert (
            'action.correlationsearch.annotations = {"mitre_attack": ["T1053.005"]}' in stanza
        )
        assert "alert.suppress.fields = host,User" in stanza

    def test_convert_suppress_default_custom_and_empty_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SOCLENS_DEFAULT_SUPPRESS_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_TENANT_FIELD", raising=False)
        rule_content = "title: AWS Rule\nlogsource:\n  product: aws\n"

        stanza_default = convert_to_savedsearch_stanza(
            rule_id="aws_1",
            rule_title="AWS Rule",
            rule_content=rule_content,
            splunk_query="eventName=ConsoleLogin",
            suppress_fields=None,
        )
        assert "alert.suppress.fields = userIdentity.arn,eventName" in stanza_default

        stanza_custom = convert_to_savedsearch_stanza(
            rule_id="aws_1",
            rule_title="AWS Rule",
            rule_content=rule_content,
            splunk_query="eventName=ConsoleLogin",
            suppress_fields="tenant_id,userIdentity.arn",
        )
        assert "alert.suppress.fields = tenant_id,userIdentity.arn" in stanza_custom

        stanza_disabled = convert_to_savedsearch_stanza(
            rule_id="aws_1",
            rule_title="AWS Rule",
            rule_content=rule_content,
            splunk_query="eventName=ConsoleLogin",
            suppress_fields="",
        )
        assert "alert.suppress.fields" not in stanza_disabled

    def test_convert_flattens_multiline_ini_and_handles_yaml_nulls(self, tmp_path: Path) -> None:
        rule_content = (
            "title: null\n"
            "description: |\n"
            "  Detects Casbaneiro malware\n"
            "  using obfuscated VBS.\n"
            "level: null\n"
            "logsource:\n"
            "  product: windows\n"
        )
        casbaneiro_query = (
            'CommandLine="*wscript*" CommandLine="*//Nologo*" CommandLine="*.vbs*"\n'
            '| regex CommandLine=".*[A-Za-z0-9]{30,}.*"'
        )
        stanza = convert_to_savedsearch_stanza(
            rule_id="cas_1",
            rule_title="Casbaneiro\nMultiline Title",
            rule_content=rule_content,
            splunk_query=casbaneiro_query,
        )

        conf_file = tmp_path / "savedsearches_wineventlog.conf"
        conf_file.write_text(stanza, encoding="utf-8")

        cp = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
        cp.read(conf_file, encoding="utf-8")
        sections = cp.sections()
        assert len(sections) == 1
        assert "Casbaneiro Multiline Title" in sections[0]
        assert "\n" not in cp[sections[0]]["description"]
        assert '| regex CommandLine=".*[A-Za-z0-9]{30,}.*" | table ' in cp[sections[0]]["search"]
        assert cp[sections[0]]["action.notable.param.severity"] == "medium"

        parsed_searches = parse_savedsearches_files(conf_file)
        assert len(parsed_searches) == 1
        assert '| regex CommandLine=".*[A-Za-z0-9]{30,}.*"' in parsed_searches[0]["search"]

    def test_convert_leading_pipe_and_search_prefix_spl(self) -> None:
        rule_content = "title: Pipe Rule\nlogsource:\n  product: windows\n"

        tstats_stanza = convert_to_savedsearch_stanza(
            rule_id="pipe_1",
            rule_title="Pipe Rule",
            rule_content=rule_content,
            splunk_query="  \n| tstats count from datamodel=Endpoint.Processes by Processes.user",
        )
        assert (
            "search = | tstats count from datamodel=Endpoint.Processes by Processes.user | table "
            in tstats_stanza
        )
        assert "index=*wineventlog | tstats" not in tstats_stanza

        deferred_rex_stanza = convert_to_savedsearch_stanza(
            rule_id="pipe_2",
            rule_title="Rex Rule",
            rule_content=rule_content,
            splunk_query='\n| rex field=CommandLine "(?<arg>.*)"\n| search arg="foo"',
        )
        assert 'search = | rex field=CommandLine "(?<arg>.*)" | search arg="foo"' in (
            deferred_rex_stanza
        )
        assert "index=*wineventlog" not in deferred_rex_stanza

        search_kw_stanza = convert_to_savedsearch_stanza(
            rule_id="pipe_3",
            rule_title="Search Prefix Rule",
            rule_content=rule_content,
            splunk_query="search EventID=4688 | table _time host",
        )
        assert "search = search index=*wineventlog EventID=4688 | table _time host\n" in (
            search_kw_stanza
        )
        assert search_kw_stanza.count("| table") == 1

    def test_flatten_rules(self) -> None:
        api_results = [
            {
                "id": "set_1",
                "title": "Set 1 Rules",
                "rules": [
                    {
                        "file_name": "rule_1.yml",
                        "content": "title: Rule 1\nlevel: null\nlogsource:\n  product: windows",
                    }
                ],
            }
        ]
        flat = flatten_rules(api_results)
        assert len(flat) == 1
        assert flat[0]["title"] == "Rule 1"
        assert flat[0]["index"] == "*wineventlog"
        assert flat[0]["level"] == "N/A"

    def test_enrich_rules_in_place(self) -> None:
        rules = [{"content": "title: Rule A\nlogsource:\n  product: macos"}]
        modified = enrich_rules_in_place(rules)
        assert modified is True
        assert rules[0]["index"] == "*mac"

    def test_search_rules(self) -> None:
        rules = [
            {
                "title": "Cobalt Strike Beaconing",
                "description": "Detects beaconing",
                "content": "cobalt strike",
            },
            {
                "title": "WannaCry Ransomware",
                "description": None,
                "content": "wannacry",
            },
        ]
        matches = search_rules(rules, "cobalt")
        assert len(matches) == 1
        assert matches[0]["title"] == "Cobalt Strike Beaconing"

        matches_desc = search_rules(rules, "beaconing")
        assert len(matches_desc) == 1

    @patch("soclens.sigma.os.path.exists")
    @patch("soclens.sigma.open", new_callable=mock_open)
    def test_load_rules_cached(self, mock_file: MagicMock, mock_exists: MagicMock) -> None:
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = json.dumps(
            [
                {
                    "title": "Cached Rule",
                    "content": "title: Cached Rule\nlogsource:\n  product: windows",
                    "index": "*wineventlog",
                    "product": "windows",
                    "mitre_techniques": [],
                }
            ]
        )

        client = MagicMock()
        rules = load_rules(client, refresh=False)
        assert len(rules) == 1
        assert rules[0]["title"] == "Cached Rule"
        client.search_detection_rules.assert_not_called()

    @patch("soclens.sigma.os.path.exists")
    @patch("soclens.sigma.open", new_callable=mock_open)
    def test_load_rules_refresh(self, mock_file: MagicMock, mock_exists: MagicMock) -> None:
        mock_exists.return_value = True
        client = MagicMock()
        client.api_token = "api_key"
        client.search_detection_rules.return_value = [
            {
                "id": "set_1",
                "title": "Set Title",
                "rules": [
                    {
                        "file_name": "rule.yml",
                        "content": "title: API Rule\nlogsource:\n  product: aws",
                    }
                ],
            }
        ]

        rules = load_rules(client, refresh=True)
        assert len(rules) == 1
        assert rules[0]["title"] == "API Rule"
        client.search_detection_rules.assert_called_once()

    def test_load_rules_preserves_cache_on_api_error_or_empty_refresh(
        self, tmp_path: Path
    ) -> None:
        existing = [
            {
                "rule_id": "r1",
                "title": "Existing Cached Rule",
                "file_name": "r1.yml",
                "content": "title: Existing Cached Rule\nlogsource:\n  product: windows",
                "product": "windows",
                "category": None,
                "service": None,
                "index": "*wineventlog",
                "mitre_techniques": [],
            }
        ]
        cache_file = tmp_path / "sigma_rules_cache.json"
        cache_file.write_text(json.dumps(existing), encoding="utf-8")

        client = MagicMock()
        client.api_token = "api_key"

        client.search_detection_rules.side_effect = RecordedFutureAPIError(
            500, "Server error", trace_id="trace-500"
        )
        rules_err = load_rules(client, refresh=True, cache_dir=tmp_path)
        assert len(rules_err) == 1
        assert rules_err[0]["title"] == "Existing Cached Rule"
        assert json.loads(cache_file.read_text(encoding="utf-8"))[0]["title"] == (
            "Existing Cached Rule"
        )

        client.search_detection_rules.side_effect = RecordedFutureRateLimitError(
            429, "Rate limit", trace_id="trace-429"
        )
        assert len(load_rules(client, refresh=True, cache_dir=tmp_path)) == 1

        client.search_detection_rules.side_effect = ConfigurationError("Bad config")
        assert len(load_rules(client, refresh=True, cache_dir=tmp_path)) == 1

        client.search_detection_rules.side_effect = None
        client.search_detection_rules.return_value = []
        rules_empty = load_rules(client, refresh=True, cache_dir=tmp_path)
        assert len(rules_empty) == 1
        assert json.loads(cache_file.read_text(encoding="utf-8"))[0]["title"] == (
            "Existing Cached Rule"
        )

    def test_load_rules_raises_on_api_error_without_cache(self, tmp_path: Path) -> None:
        client = MagicMock()
        client.api_token = "api_key"
        client.search_detection_rules.side_effect = RecordedFutureAPIError(
            502, "Bad gateway", trace_id="trace-502"
        )
        with pytest.raises(RecordedFutureAPIError):
            load_rules(client, cache_dir=tmp_path)

    def test_load_rules_days_requires_token_and_default_workspace(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = MagicMock()
        client.api_token = None
        with pytest.raises(SigmaConfigurationError) as exc_info:
            load_rules(client, days=7, cache_dir=tmp_path)
        assert isinstance(exc_info.value, ConfigurationError)
        assert isinstance(exc_info.value, RuntimeError)

        cache_file = tmp_path / "sigma_rules_cache.json"
        cache_file.write_text(
            json.dumps(
                [
                    {
                        "title": "Workspace Rule",
                        "content": "title: Workspace Rule\nlogsource:\n  product: linux",
                        "product": "linux",
                        "index": "*unix",
                        "mitre_techniques": [],
                    }
                ]
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("SOCLENS_HOME", str(tmp_path))
        rules = load_rules(client)
        assert len(rules) == 1
        assert rules[0]["title"] == "Workspace Rule"

    @patch("soclens.sigma.open", new_callable=mock_open)
    @patch("soclens.sigma.SigmaCollection.from_yaml")
    @patch("soclens.sigma.NoPipelineSplunkBackend")
    def test_export_rules_to_splunk(
        self,
        mock_backend_class: MagicMock,
        mock_from_yaml: MagicMock,
        mock_file: MagicMock,
    ) -> None:
        mock_backend = MagicMock()
        mock_backend.convert.return_value = ["EventID=1"]
        mock_backend_class.return_value = mock_backend

        rules = [
            {
                "rule_id": "rule_1",
                "title": "Export Rule",
                "file_name": "export_rule.yml",
                "content": "title: Export Rule\nlogsource:\n  product: windows",
            }
        ]

        export_rules_to_splunk(rules, "savedsearches.conf", write_mode="overwrite")
        mock_file.assert_called_with(
            os.path.abspath("savedsearches_wineventlog.conf"), "w", encoding="utf-8"
        )
        mock_file().write.assert_called()

    def test_export_rules_to_splunk_creates_nested_parent_dirs(self, tmp_path: Path) -> None:
        nested_out = tmp_path / "nested" / "dir" / "savedsearches.conf"
        rules = [
            {
                "rule_id": "rule_real",
                "title": "Real Export Rule",
                "file_name": "real_export.yml",
                "content": (
                    "title: Real Export Rule\n"
                    "description: Multi\n  line desc\n"
                    "level: high\n"
                    "logsource:\n"
                    "  product: windows\n"
                    "detection:\n"
                    "  selection:\n"
                    "    EventID: 4688\n"
                    "  condition: selection\n"
                ),
            }
        ]

        export_rules_to_splunk(rules, nested_out, write_mode="overwrite")
        expected_file = tmp_path / "nested" / "dir" / "savedsearches_wineventlog.conf"
        assert expected_file.is_file()
        parsed = parse_savedsearches_files(expected_file)
        assert len(parsed) == 1
        assert "4688" in parsed[0]["search"]

    def test_interactive_loop_propagates_cache_dir_and_handles_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = MagicMock()
        inputs = iter(["--refresh", "exit"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))

        with patch("soclens.sigma.load_rules") as mock_load:
            mock_load.side_effect = RecordedFutureAPIError(503, "Unavailable", trace_id="t-1")
            interactive_loop([], client, cache_dir=tmp_path)
            mock_load.assert_called_once_with(client, refresh=True, cache_dir=tmp_path)

    def test_convert_to_savedsearch_stanza_fallback_sysmon(self) -> None:
        rule_content = "title: Sysmon Rule\nlogsource:\n  service: sysmon\n"
        stanza = convert_to_savedsearch_stanza(
            rule_id="sys_1",
            rule_title="Sysmon Rule",
            rule_content=rule_content,
            splunk_query="EventID=1",
        )
        assert "search = index=*sysmon EventID=1" in stanza

    def test_convert_to_savedsearch_stanza_fallback_cloudtrail(self) -> None:
        rule_content = "title: AWS CloudTrail Rule\nlogsource:\n  service: cloudtrail\n"
        stanza = convert_to_savedsearch_stanza(
            rule_id="aws_1",
            rule_title="AWS CloudTrail Rule",
            rule_content=rule_content,
            splunk_query="eventName=ConsoleLogin",
        )
        assert "search = index=*aws eventName=ConsoleLogin" in stanza

    def test_extract_sigma_metadata(self) -> None:
        parsed = {
            "logsource": {"product": "windows", "service": "sysmon"},
            "tags": ["attack.t1059.001", "attack.execution"],
        }
        meta = extract_sigma_metadata(parsed)
        assert meta["index"] == "*sysmon"
        assert meta["mitre_techniques"] == ["T1059.001"]

    @patch("soclens.sigma.os.path.exists")
    def test_load_rules_raises_on_missing_token_and_no_cache(
        self, mock_exists: MagicMock
    ) -> None:
        mock_exists.return_value = False
        client = MagicMock()
        client.api_token = None
        with pytest.raises(RuntimeError) as exc_info:
            load_rules(client)
        assert "Recorded Future API token is not set" in str(exc_info.value)
        assert isinstance(exc_info.value, ConfigurationError)

    def test_custom_index_mapping_specificity_aliases_and_multi_index(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SOCLENS_INDEX", raising=False)
        monkeypatch.delenv("SOCLENS_INDEX_MAP", raising=False)
        monkeypatch.delenv("SOCLENS_DEFAULT_INDEX", raising=False)

        idx_map = {
            "windows:sysmon:process_creation": "win_sysmon_proc",
            "windows:security": "win_security",
            "windows:file_event": "win_file",
            "windows": "win_generic",
            "mac": "edr_mac",
            "unix": "edr_unix",
            "default": "soc_fallback",
        }
        assert (
            map_logsource_to_index(
                {"product": "windows", "service": "sysmon", "category": "process_creation"},
                index_map=idx_map,
            )
            == "win_sysmon_proc"
        )
        assert (
            map_logsource_to_index(
                {"product": "windows", "service": "security"},
                index_map=idx_map,
            )
            == "win_security"
        )
        assert (
            map_logsource_to_index(
                {"product": "windows", "category": "file_event"},
                index_map=idx_map,
            )
            == "win_file"
        )
        assert map_logsource_to_index({"product": "windows"}, index_map=idx_map) == "win_generic"
        assert map_logsource_to_index({"product": "macos"}, index_map=idx_map) == "edr_mac"
        assert map_logsource_to_index({"product": "linux"}, index_map=idx_map) == "edr_unix"
        assert map_logsource_to_index({"product": "okta"}, index_map=idx_map) == "soc_fallback"

        # wineventlog alias when canonical windows not present
        assert (
            map_logsource_to_index({"product": "windows"}, index_map={"wineventlog": "idx_win"})
            == "idx_win"
        )

        # Unmapped without default in index_map uses default_index
        assert (
            map_logsource_to_index(
                {"category": "custom_unknown"},
                index_map={"windows": "win_sec"},
                default_index="soc_catchall",
            )
            == "soc_catchall"
        )

        # Global index_override wins over index_map and heuristics
        assert (
            map_logsource_to_index(
                {"product": "windows", "service": "security"},
                index_map=idx_map,
                index_override="forced_idx",
            )
            == "forced_idx"
        )

        # Multi-index parsing, SPL formatting, and safe split filenames
        parsed_map = parse_key_value_mapping("windows=win_sec,win_sysmon,aws=cloud_aws")
        assert parsed_map == {"windows": "win_sec,win_sysmon", "aws": "cloud_aws"}
        multi_idx = map_logsource_to_index({"product": "windows"}, index_map=parsed_map)
        assert multi_idx == "win_sec,win_sysmon"
        assert format_spl_index_clause(multi_idx) == "(index=win_sec OR index=win_sysmon)"
        assert format_spl_index_clause("index=a OR index=b") == "index=a OR index=b"
        assert get_split_output_path("savedsearches.conf", multi_idx) == (
            "savedsearches_win_sec_win_sysmon.conf"
        )

    def test_custom_table_and_suppress_fields_and_field_map(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SOCLENS_DEFAULT_TABLE_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_CUSTOM_TABLE_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_TABLE_FIELDS_MAP", raising=False)
        monkeypatch.delenv("SOCLENS_DEFAULT_SUPPRESS_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_CUSTOM_SUPPRESS_FIELDS", raising=False)
        monkeypatch.delenv("SOCLENS_SUPPRESS_FIELDS_MAP", raising=False)
        monkeypatch.delenv("SOCLENS_TENANT_FIELD", raising=False)

        logsource = {"product": "windows", "service": "sysmon"}
        tbl = get_table_fields_for_logsource(
            logsource,
            custom_fields=["tenant_id", "env", "CommandLine", "tenant_id"],
            rule_fields=["ParentImage", "Hashes"],
            field_map={"CommandLine": "proc_cmd", "User": "actor_user", "EventID": "event_id"},
        )
        tokens = parse_field_list(tbl)
        assert tokens.count("tenant_id") == 1
        assert "proc_cmd" in tokens
        assert "actor_user" in tokens
        assert "event_id" in tokens
        assert "ParentImage" in tokens
        assert "Hashes" in tokens
        assert tokens[-2:] == ["tenant_id", "env"] or {"tenant_id", "env"}.issubset(set(tokens))

        # Per-logsource table_fields_map and suppress_fields_map
        custom_tbl_map = {
            "windows:sysmon": "_time host proc_cmd",
            "aws": "_time eventName userIdentity.arn",
        }
        assert (
            get_table_fields_for_logsource(
                logsource,
                table_fields_map=custom_tbl_map,
                custom_fields="org_id",
            )
            == "_time host proc_cmd org_id"
        )

        custom_sup_map = {"windows:sysmon": "host,proc_cmd"}
        assert (
            get_suppress_fields_for_logsource(
                logsource,
                suppress_fields_map=custom_sup_map,
                custom_fields="org_id",
            )
            == "org_id,host,proc_cmd"
        )

        # Trailing | table merge vs explicit table_fields override in convert_to_savedsearch_stanza
        rule_yaml = "title: Table Merge\nlogsource:\n  product: windows\n"
        merged_stanza = convert_to_savedsearch_stanza(
            rule_id="tm_1",
            rule_title="Table Merge",
            rule_content=rule_yaml,
            splunk_query="search EventCode=4688 | table _time host",
            custom_table_fields=["tenant_id", "env"],
        )
        assert (
            "search = search index=*wineventlog EventCode=4688 | table _time host tenant_id env\n"
            in merged_stanza
        )
        assert merged_stanza.count("| table") == 1

        replaced_stanza = convert_to_savedsearch_stanza(
            rule_id="tm_2",
            rule_title="Table Replace",
            rule_content=rule_yaml,
            splunk_query="search EventCode=4688 | table _time host",
            table_fields="_time src dst",
        )
        assert (
            "search = search index=*wineventlog EventCode=4688 | table _time src dst\n"
            in replaced_stanza
        )
        assert replaced_stanza.count("| table") == 1

    def test_convert_sigma_rule_pipelines_custom_indexes_and_fields(
        self, tmp_path: Path
    ) -> None:
        # 1. splunk_windows pipeline: EventID -> EventCode, service:security -> WinEventLog:Security
        win_sec_rule = (
            "title: Security Logon Failure\n"
            "id: 11111111-1111-1111-1111-111111111111\n"
            "level: high\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  sel:\n"
            "    EventID: 4625\n"
            "    TargetUserName: admin\n"
            "  condition: sel\n"
            "fields:\n"
            "  - TargetUserName\n"
            "  - IpAddress\n"
            "tags:\n"
            "  - attack.t1110\n"
        )
        res_win = convert_sigma_rule(
            win_sec_rule,
            pipeline="splunk_windows",
            index_map={"windows:security": "win_sec"},
            sourcetype_map={"windows:security": "XmlWinEventLog:Security"},
            custom_table_fields=["tenant_id", "env"],
            custom_suppress_fields=["tenant_id"],
        )
        assert res_win["index"] == "win_sec"
        stanza_win = res_win["stanzas"][0]
        assert "index=win_sec" in stanza_win
        assert 'sourcetype="XmlWinEventLog:Security"' in stanza_win
        assert 'source="WinEventLog:Security"' in stanza_win
        assert "EventCode=4625" in stanza_win
        assert "| table _time host User CommandLine Image ParentCommandLine ParentImage TargetUserName IpAddress tenant_id env" in stanza_win
        assert "alert.suppress.fields = tenant_id,host,User" in stanza_win
        assert stanza_win.count("| table") == 1

        # 2. splunk_windows_sysmon acceleration keywords + field_map override
        sysmon_rule = (
            "title: Sysmon Proc Create\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: sysmon\n"
            "  category: process_creation\n"
            "detection:\n"
            "  sel:\n"
            "    EventID: 1\n"
            "    CommandLine|contains: whoami\n"
            "  condition: sel\n"
        )
        res_sysmon = convert_sigma_rule(
            sysmon_rule,
            pipeline="splunk_windows_sysmon",
            index_map="windows:sysmon=edr_sysmon",
            field_map={"EventID": "event_id", "CommandLine": "proc_cmd"},
            custom_table_fields="cluster",
        )
        spl_sysmon = res_sysmon["stanzas"][0]
        assert "index=edr_sysmon" in spl_sysmon
        assert '"ParentProcessGuid"' in spl_sysmon
        assert "event_id=1" in spl_sysmon
        assert 'proc_cmd="*whoami*"' in spl_sysmon
        assert "event_id" in res_sysmon["table_fields"].split()
        assert "proc_cmd" in res_sysmon["table_fields"].split()
        assert spl_sysmon.endswith("\n")

        # 3. splunk_cim (data_model) omits index= and uses CIM table columns + custom fields
        cim_rule = (
            "title: CIM Endpoint Process\n"
            "logsource:\n"
            "  product: windows\n"
            "  category: process_creation\n"
            "detection:\n"
            "  sel:\n"
            "    CommandLine|contains: mimikatz\n"
            "  condition: sel\n"
        )
        res_cim = convert_sigma_rule(
            cim_rule,
            pipeline="splunk_cim",
            custom_table_fields=["tenant_id"],
        )
        assert res_cim["output_format"] == "data_model"
        cim_stanza = res_cim["stanzas"][0]
        assert "search = | tstats " in cim_stanza
        assert "datamodel=Endpoint.Processes" in cim_stanza
        assert "index=" not in cim_stanza
        assert "| table firstTime lastTime count dest user process process_path parent_process parent_process_path tenant_id" in cim_stanza

        # 4. Regex-only & multi-index OR-regex hoist index filter before | regex / | rex
        regex_only = (
            "title: Regex Only\n"
            "logsource:\n"
            "  product: windows\n"
            "detection:\n"
            "  sel:\n"
            '    CommandLine|re: "powershell.*-enc"\n'
            "  condition: sel\n"
        )
        res_re = convert_sigma_rule(regex_only, index_override="win_re")
        assert "search = index=win_re | regex CommandLine=" in res_re["stanzas"][0]

        or_regex_multi = (
            "title: Multi Index OR Regex\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  s1:\n"
            '    CommandLine|re: "foo.*bar"\n'
            "  s2:\n"
            "    User: admin\n"
            "  condition: s1 or s2\n"
        )
        res_or = convert_sigma_rule(
            or_regex_multi,
            index_map={"windows": "win_sec,win_sysmon"},
            custom_table_fields=["tenant_id"],
        )
        assert (
            'search = (index IN ("win_sec", "win_sysmon")) | rex field=CommandLine'
            in res_or["stanzas"][0]
        )

        # 5. Custom YAML pipeline file via pipeline_path
        custom_pipe_file = tmp_path / "custom_pipe.yml"
        custom_pipe_file.write_text(
            "name: custom_org\n"
            "priority: 60\n"
            "transformations:\n"
            "  - id: map_cmd\n"
            "    type: field_name_mapping\n"
            "    mapping:\n"
            "      CommandLine: cmd_line\n",
            encoding="utf-8",
        )
        res_pipe = convert_sigma_rule(
            "title: Custom YAML Pipe\nlogsource:\n  product: windows\ndetection:\n  sel:\n    CommandLine: net.exe\n  condition: sel\n",
            pipeline="none",
            pipeline_path=custom_pipe_file,
            index_override="custom_idx",
        )
        assert 'index=custom_idx cmd_line="net.exe"' in res_pipe["stanzas"][0]

    def test_sigma_config_profiles_batch_and_no_split_export(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        json_cfg = tmp_path / "sigma_profile.json"
        json_cfg.write_text(
            json.dumps(
                {
                    "pipeline": "splunk_windows",
                    "index_map": {"windows": "win_corp", "aws": "cloud_corp"},
                    "default_index": "soc_other",
                    "custom_table_fields": ["tenant_id", "env"],
                    "custom_suppress_fields": ["tenant_id"],
                    "split_by_index": False,
                }
            ),
            encoding="utf-8",
        )
        yaml_cfg = tmp_path / "sigma_profile.yml"
        yaml_cfg.write_text(
            "pipeline: splunk_windows_sysmon\n"
            "index_map:\n"
            "  windows: win_yaml\n"
            "custom_table_fields:\n"
            "  - org_id\n",
            encoding="utf-8",
        )

        cfg_json = SigmaConversionConfig.from_file(json_cfg)
        assert cfg_json.index_map == {"windows": "win_corp", "aws": "cloud_corp"}
        assert cfg_json.custom_table_fields == ["tenant_id", "env"]
        assert cfg_json.split_by_index is False

        cfg_yaml = SigmaConversionConfig.from_file(yaml_cfg)
        assert cfg_yaml.pipeline == "splunk_windows_sysmon"
        assert cfg_yaml.index_map == {"windows": "win_yaml"}
        assert cfg_yaml.custom_table_fields == ["org_id"]

        monkeypatch.setenv("SOCLENS_SIGMA_CONFIG", str(json_cfg))
        monkeypatch.setenv("SOCLENS_CUSTOM_TABLE_FIELDS", "region")
        loaded_cfg = load_sigma_config()
        assert loaded_cfg.custom_table_fields == ["tenant_id", "env", "region"]

        rules = [
            {
                "rule_id": "r1",
                "title": "Win Rule",
                "file_name": "win.yml",
                "content": "title: Win Rule\nlogsource:\n  product: windows\ndetection:\n  sel:\n    EventID: 4688\n  condition: sel\n",
            },
            {
                "rule_id": "r2",
                "title": "AWS Rule",
                "file_name": "aws.yml",
                "content": "title: AWS Rule\nlogsource:\n  product: aws\n  service: cloudtrail\ndetection:\n  sel:\n    eventName: ConsoleLogin\n  condition: sel\n",
            },
            {
                "rule_id": "r3",
                "title": "Broken Rule",
                "file_name": "broken.yml",
                "content": "title: [broken",
            },
        ]

        batch = convert_sigma_rules(rules, config=loaded_cfg)
        assert batch["converted_count"] == 2
        assert batch["failed_count"] == 1
        assert set(batch["converted_by_index"].keys()) == {"win_corp", "cloud_corp"}

        out_single = tmp_path / "all_savedsearches.conf"
        summary = export_rules_to_splunk(rules, output_path=out_single, config=loaded_cfg)
        assert summary["converted_count"] == 2
        assert summary["failed_count"] == 1
        assert out_single.is_file()
        assert summary["files_written"] == [str(out_single.resolve())]

        parsed = parse_savedsearches_files(out_single)
        assert len(parsed) == 2
        assert any("index=win_corp" in item["search"] and "EventCode=4688" in item["search"] for item in parsed)
        assert any("index=cloud_corp" in item["search"] and "region" in item["search"] for item in parsed)
