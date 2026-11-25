import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from soclens import __version__
from soclens.cli import build_parser


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.parser = build_parser()

    def test_parser_watchlist_list(self):
        args = self.parser.parse_args(["watchlist", "list"])
        self.assertEqual(args.command, "watchlist")
        self.assertEqual(args.subcommand, "list")

    def test_parser_watchlist_entities(self):
        args = self.parser.parse_args(["watchlist", "entities", "report:wl-101"])
        self.assertEqual(args.command, "watchlist")
        self.assertEqual(args.subcommand, "entities")
        self.assertEqual(args.list_id, "report:wl-101")
        self.assertEqual(args.sort, "none")
        self.assertFalse(args.descending)
        self.assertIsNone(args.filter_query)

        args_sorted = self.parser.parse_args(
            ["watchlist", "entities", "report:wl-101", "--sort", "name", "--desc", "--filter", "irisbank"]
        )
        self.assertEqual(args_sorted.sort, "name")
        self.assertTrue(args_sorted.descending)
        self.assertEqual(args_sorted.filter_query, "irisbank")

    def test_parser_watchlist_add(self):
        args = self.parser.parse_args(["watchlist", "add", "report:wl-101", "InternetDomainName", "malicious-domain.com"])
        self.assertEqual(args.command, "watchlist")
        self.assertEqual(args.subcommand, "add")
        self.assertEqual(args.list_id, "report:wl-101")
        self.assertEqual(args.entity_type, "InternetDomainName")
        self.assertEqual(args.name, "malicious-domain.com")

    def test_parser_watchlist_remove(self):
        args = self.parser.parse_args(["watchlist", "remove", "report:wl-101", "entity_1"])
        self.assertEqual(args.command, "watchlist")
        self.assertEqual(args.subcommand, "remove")
        self.assertEqual(args.list_id, "report:wl-101")
        self.assertEqual(args.entity_id, "entity_1")

    def test_parser_watchlist_sync(self):
        args = self.parser.parse_args(["watchlist", "sync", "report:wl-101", "domains.csv", "--type", "IPAddress", "--dry-run"])
        self.assertEqual(args.command, "watchlist")
        self.assertEqual(args.subcommand, "sync")
        self.assertEqual(args.list_id, "report:wl-101")
        self.assertEqual(args.csv_path, "domains.csv")
        self.assertEqual(args.type, "IPAddress")
        self.assertTrue(args.dry_run)

    def test_parser_watchlist_validate_liveness(self):
        args = self.parser.parse_args(["watchlist", "validate-liveness", "report:wl-101", "--interactive"])
        self.assertEqual(args.command, "watchlist")
        self.assertEqual(args.subcommand, "validate-liveness")
        self.assertEqual(args.list_id, "report:wl-101")
        self.assertTrue(args.interactive)

    def test_parser_watchlist_sync_logos(self):
        args = self.parser.parse_args([
            "watchlist", "sync-logos", "report:wl-101",
            "--domains", "a.com,b.com", "--dry-run",
            "--ignore-hashes-file", "my_hashes.txt",
            "--ignore-hashes", "hash1,hash2"
        ])
        self.assertEqual(args.command, "watchlist")
        self.assertEqual(args.subcommand, "sync-logos")
        self.assertEqual(args.list_id, "report:wl-101")
        self.assertEqual(args.domains, "a.com,b.com")
        self.assertTrue(args.dry_run)
        self.assertEqual(args.ignore_hashes_file, "my_hashes.txt")
        self.assertEqual(args.ignore_hashes, "hash1,hash2")

    def test_parser_watchlist_validate_logos(self):
        args = self.parser.parse_args([
            "watchlist", "validate-logos", "report:wl-101",
            "--domains-file", "domains.txt",
            "--ignore-hashes-file", "my_hashes.txt",
            "--ignore-hashes", "hash1,hash2"
        ])
        self.assertEqual(args.command, "watchlist")
        self.assertEqual(args.subcommand, "validate-logos")
        self.assertEqual(args.list_id, "report:wl-101")
        self.assertEqual(args.domains_file, "domains.txt")
        self.assertEqual(args.ignore_hashes_file, "my_hashes.txt")
        self.assertEqual(args.ignore_hashes, "hash1,hash2")

    def test_parser_sigma(self):
        args = self.parser.parse_args(["sigma"])
        self.assertEqual(args.command, "sigma")
        self.assertIsNone(args.query)
        self.assertFalse(args.export)
        self.assertEqual(args.mode, "overwrite")

    def test_parser_sigma_with_query(self):
        args = self.parser.parse_args(["sigma", "Cobalt Strike"])
        self.assertEqual(args.command, "sigma")
        self.assertEqual(args.query, "Cobalt Strike")

    def test_parser_validate(self):
        args = self.parser.parse_args(["validate", "--concurrency", "10", "--timeout", "100"])
        self.assertEqual(args.command, "validate")
        self.assertEqual(args.concurrency, 10)
        self.assertEqual(args.timeout, 100)
        self.assertEqual(args.input, "savedsearches.conf")

    def test_parser_sandbox_removed(self):
        # The 'sandbox' subcommand should not be recognized by build_parser()
        with self.assertRaises(SystemExit):
            # argparse calls sys.exit() on error/unknown subcommand, which raises SystemExit
            with patch("sys.stderr"):  # suppress output print
                self.parser.parse_args(["sandbox", "list"])

    def test_parser_global_dry_run(self):
        args = self.parser.parse_args(["--dry-run", "watchlist", "list"])
        self.assertTrue(args.dry_run)
        self.assertEqual(args.command, "watchlist")

        args = self.parser.parse_args(["-d"])
        self.assertTrue(args.dry_run)
        self.assertIsNone(args.command)

    @patch("soclens.cli.run_unified_tui")
    @patch("soclens.cli.RecordedFutureClient")
    def test_main_tui_default(self, mock_client, mock_tui):
        with patch("sys.argv", ["main.py"]):
            from soclens.cli import main
            main()
            mock_tui.assert_called_once_with(mock_client.return_value, dry_run=False)

    @patch("soclens.cli.run_unified_tui")
    @patch("soclens.cli.RecordedFutureClient")
    def test_main_tui_dry_run(self, mock_client, mock_tui):
        with patch("sys.argv", ["main.py", "--dry-run"]):
            from soclens.cli import main
            main()
            mock_tui.assert_called_once_with(mock_client.return_value, dry_run=True)

    @patch("soclens.cli.RecordedFutureClient")
    def test_main_cli_auto_approve_missing(self, mock_client):
        # If auto-approve is not set, add/remove should execute in dry-run mode and not call API
        client_inst = mock_client.return_value
        client_inst.add_entity.return_value = True

        with patch("sys.argv", ["main.py", "watchlist", "add", "list_1", "InternetDomainName", "a.com"]):
            with patch.dict("os.environ", {}):
                # Ensure SOCLENS_AUTO_APPROVE is not present
                if "SOCLENS_AUTO_APPROVE" in os.environ:
                    del os.environ["SOCLENS_AUTO_APPROVE"]
                from soclens.cli import main
                main()
                client_inst.add_entity.assert_not_called()

    @patch("soclens.cli.RecordedFutureClient")
    def test_main_cli_auto_approve_present(self, mock_client):
        # If auto-approve is set to "1" or "true", add/remove should call API
        client_inst = mock_client.return_value
        client_inst.add_entity.return_value = True

        with patch("sys.argv", ["main.py", "watchlist", "add", "list_1", "InternetDomainName", "a.com"]):
            with patch.dict("os.environ", {"SOCLENS_AUTO_APPROVE": "true"}):
                from soclens.cli import main
                main()
                client_inst.add_entity.assert_called_once_with("list_1", "InternetDomainName", "a.com")

    def test_format_context(self):
        from soclens.cli import format_context
        self.assertEqual(format_context(None), "N/A")
        self.assertEqual(format_context({}), "N/A")
        self.assertEqual(
            format_context({"annotation": "noninternet", "source": "automated-watchlist-manager"}),
            "annotation: noninternet, source: automated-watchlist-manager"
        )

    def test_parser_watchlist_export(self):
        args = self.parser.parse_args(["watchlist", "export", "list_123", "out.csv", "--format", "json"])
        self.assertEqual(args.command, "watchlist")
        self.assertEqual(args.subcommand, "export")
        self.assertEqual(args.list_id, "list_123")
        self.assertEqual(args.output_path, "out.csv")
        self.assertEqual(args.format, "json")

    def test_load_csv_entities_header_filtering(self):
        import tempfile

        from soclens.cli import load_csv_entities
        # Create CSV file with header rows
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            tmp.write("Name,Type,Entity ID,Context\n")
            tmp.write("domain.com,InternetDomainName,ID1,N/A\n")
            tmp.write("Domain,Type,Entity ID,Context\n")
            tmp.write("another.com,InternetDomainName,ID2,N/A\n")
            tmp_path = tmp.name
        try:
            entities = load_csv_entities(tmp_path, "InternetDomainName")
            self.assertEqual(entities, [
                {"name": "ID1", "type": "InternetDomainName"},
                {"name": "ID2", "type": "InternetDomainName"}
            ])
        finally:
            os.remove(tmp_path)

    @patch("soclens.cli.load_csv_entities")
    @patch("soclens.cli.RecordedFutureClient")
    def test_execute_delta_sync_force_remove(self, mock_client, mock_load):
        from soclens.cli import execute_delta_sync
        client_inst = mock_client.return_value
        client_inst.get_watchlist_entities.return_value = [
            {"entity": {"name": "old.com", "id": "1"}, "context": {"source": "manual"}},
            {"entity": {"name": "auto.com", "id": "2"}, "context": {"source": "automated-watchlist-manager"}},
        ]
        client_inst.remove_entity.return_value = True
        client_inst.add_entity.return_value = True
        mock_load.return_value = [{"name": "new.com", "type": "InternetDomainName"}]

        # Let's run it non-dry run with force_remove = True
        client_inst.remove_entity.reset_mock()
        res = execute_delta_sync(client_inst, "list_123", "dummy.csv", "InternetDomainName", dry_run=False, force_remove=True)
        self.assertTrue(res)
        # Should remove BOTH entities since force_remove is True
        self.assertEqual(client_inst.remove_entity.call_count, 2)

    @patch("soclens.cli.execute_domain_brand_sync")
    @patch("soclens.cli.RecordedFutureClient")
    def test_main_cli_sync_logos_with_ignore_hashes(self, mock_client, mock_sync):
        from soclens.cli import main
        mock_sync.return_value = True

        test_argv = [
            "main.py", "watchlist", "sync-logos", "list_abc",
            "--domains", "domain1.com,domain2.com",
            "--dry-run",
            "--ignore-hashes-file", "noise.txt",
            "--ignore-hashes", "h1,h2"
        ]
        with patch("sys.argv", test_argv):
            main()

        mock_sync.assert_called_once()
        args, kwargs = mock_sync.call_args
        self.assertEqual(args[1], "list_abc")
        self.assertEqual(args[2], ["domain1.com", "domain2.com"])
        self.assertTrue(kwargs["dry_run"])
        self.assertEqual(kwargs["ignore_hashes_file"], "noise.txt")
        self.assertEqual(kwargs["extra_hashes"], ["h1", "h2"])

    def test_parser_rf_bundle_tui_and_watchlist_crud(self):
        args_rf = self.parser.parse_args(["rf", "lookup", "ip", "198.51.100.10", "--json"])
        self.assertEqual(args_rf.command, "rf")
        self.assertEqual(args_rf.rf_subcommand, "lookup")
        self.assertEqual(args_rf.entity_type, "ip")
        self.assertEqual(args_rf.entity_id, "198.51.100.10")
        self.assertTrue(args_rf.json)

        args_bundle = self.parser.parse_args(
            ["bundle", "--workspace", "/tmp/ws", "--target-platform", "win_amd64", "--wheelhouse"]
        )
        self.assertEqual(args_bundle.command, "bundle")
        self.assertEqual(args_bundle.target_platform, "win_amd64")
        self.assertTrue(args_bundle.wheelhouse)

        args_tui = self.parser.parse_args(["tui", "--dry-run"])
        self.assertEqual(args_tui.command, "tui")
        self.assertTrue(args_tui.dry_run)

        args_create = self.parser.parse_args(["watchlist", "create", "Brand Watch", "--type", "brand"])
        self.assertEqual(args_create.subcommand, "create")
        self.assertEqual(args_create.type, "brand")

        args_rem3 = self.parser.parse_args(["watchlist", "remove", "report:1", "Hash", "abcd"])
        self.assertEqual(args_rem3.entity_id, "Hash")
        self.assertEqual(args_rem3.entity_value, "abcd")

    def test_main_rf_apis_json_and_error_exit(self):
        import io
        import json
        from contextlib import redirect_stdout

        from soclens.cli import main

        buf = io.StringIO()
        with patch("sys.argv", ["soclens", "rf", "apis", "--json"]):
            with patch("soclens.cli.RecordedFutureClient"):
                with redirect_stdout(buf):
                    main()
        parsed = json.loads(buf.getvalue())
        self.assertIsInstance(parsed, list)
        self.assertGreaterEqual(len(parsed), 5)

        with patch("sys.argv", ["soclens", "watchlist", "sync-logos", "report:1", "--domains", "a.com", "--watch", "--interval", "-1"]):
            with patch("soclens.cli.RecordedFutureClient"):
                with patch("sys.stderr"):
                    with self.assertRaises(SystemExit) as ctx:
                        main()
        self.assertNotEqual(ctx.exception.code, 0)

    @patch("soclens.cli.create_bundle")
    def test_main_bundle_cli_json(self, mock_bundle):
        import io
        import json
        from contextlib import redirect_stdout
        from pathlib import Path

        from soclens.cli import main

        mock_bundle.return_value = Path("/tmp/out.zip")
        buf = io.StringIO()
        with patch("sys.argv", ["soclens", "bundle", "--output", "/tmp/out.zip", "--json"]):
            with redirect_stdout(buf):
                main()
        data = json.loads(buf.getvalue())
        self.assertEqual(data["output_path"], "/tmp/out.zip")

    @patch("soclens.cli.run_unified_tui")
    @patch("soclens.cli.RecordedFutureClient")
    def test_main_tui_subcommand(self, mock_client, mock_tui):
        from soclens.cli import main
        with patch("sys.argv", ["soclens", "tui", "--dry-run"]):
            main()
        mock_tui.assert_called_once_with(mock_client.return_value, dry_run=True)

    @patch("soclens.cli.RecordedFutureClient")
    def test_main_watchlist_entities_sort_and_filter(self, mock_client_cls):
        import io
        import json
        from contextlib import redirect_stdout

        from soclens.cli import main

        mock_client = mock_client_cls.return_value
        mock_client.get_watchlist_entities.return_value = [
            {
                "entity": {"id": "idn:zeta.com", "type": "InternetDomainName", "name": "zeta.com"},
                "status": "ready",
                "context": {"annotation": "other"},
            },
            {
                "entity": {"id": "idn:irisbank.com", "type": "InternetDomainName", "name": "irisbank.com"},
                "status": "ready",
                "context": {"annotation": "target bank"},
            },
            {
                "entity": {"id": "idn:alpha.com", "type": "InternetDomainName", "name": "alpha.com"},
                "status": "ready",
                "context": {"annotation": "bank"},
            },
        ]

        # JSON output sorted descending by name and filtered to "bank"
        buf_json = io.StringIO()
        with patch(
            "sys.argv",
            ["soclens", "watchlist", "entities", "report:1", "--sort", "name", "--desc", "--filter", "bank", "--json"],
        ):
            with redirect_stdout(buf_json):
                main()
        parsed = json.loads(buf_json.getvalue())
        self.assertEqual([e["entity"]["name"] for e in parsed], ["irisbank.com", "alpha.com"])

        # Table output filtered and sorted ascending by annotation
        buf_tbl = io.StringIO()
        with patch(
            "sys.argv",
            ["soclens", "watchlist", "entities", "report:1", "--sort", "annotation", "-f", "irisbank"],
        ):
            with redirect_stdout(buf_tbl):
                main()
        out_tbl = buf_tbl.getvalue()
        self.assertIn("1 of 3", out_tbl)
        self.assertIn("irisbank.com", out_tbl)
        self.assertNotIn("zeta.com", out_tbl)

        # No matches prints clear message
        buf_none = io.StringIO()
        with patch("sys.argv", ["soclens", "watchlist", "entities", "report:1", "-f", "nonexistent"]):
            with redirect_stdout(buf_none):
                main()
        self.assertIn("No entities matched filter 'nonexistent'", buf_none.getvalue())

    def test_cli_version_flag(self):
        import io
        from contextlib import redirect_stdout

        from soclens.cli import main

        for flag in ("--version", "-V"):
            buf = io.StringIO()
            with patch("sys.argv", ["soclens", flag]):
                with redirect_stdout(buf):
                    with self.assertRaises(SystemExit) as ctx:
                        main()
            self.assertEqual(ctx.exception.code, 0)
            self.assertEqual(buf.getvalue().strip(), f"soclens {__version__}")

    def test_python_dash_m_soclens_version(self):
        proc = subprocess.run(
            [sys.executable, "-m", "soclens", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertEqual(proc.stdout.strip(), f"soclens {__version__}")

    def test_parser_insecure_and_ca_bundle_global_and_subcommands(self):
        cases = [
            (["-k", "tui"], True, None),
            (["tui", "--insecure"], True, None),
            (["--no-verify-ssl", "rf", "alerts"], True, None),
            (["watchlist", "sync-logos", "report:1", "--domains", "a.com", "--insecure"], True, None),
            (["rf", "alerts", "-k"], True, None),
            (["research", "investigate", "8.8.8.8", "--ca-bundle", "/etc/ssl/corp.pem"], False, "/etc/ssl/corp.pem"),
            (["--ca-bundle", "/etc/ssl/corp.pem", "sigma", "--refresh"], False, "/etc/ssl/corp.pem"),
            (["validate", "--dry-run", "-k"], True, None),
        ]
        for argv, exp_insecure, exp_ca in cases:
            args = self.parser.parse_args(argv)
            self.assertEqual(bool(getattr(args, "insecure", False)), exp_insecure, msg=f"argv={argv}")
            self.assertEqual(getattr(args, "ca_bundle", None), exp_ca, msg=f"argv={argv}")

    @patch("soclens.cli.run_unified_tui")
    @patch("soclens.cli.RecordedFutureClient")
    def test_main_passes_insecure_and_ca_bundle_to_client(self, mock_client, mock_tui):
        from soclens.cli import main

        with patch("sys.argv", ["soclens", "-k", "tui"]):
            main()
        mock_client.assert_called_once_with(verify_ssl=False)
        mock_tui.assert_called_once_with(mock_client.return_value, dry_run=False)

        mock_client.reset_mock()
        mock_tui.reset_mock()
        with patch("sys.argv", ["soclens", "tui", "--ca-bundle", "/etc/ssl/corp.pem"]):
            main()
        mock_client.assert_called_once_with(verify_ssl="/etc/ssl/corp.pem")
        mock_tui.assert_called_once_with(mock_client.return_value, dry_run=False)

    def test_main_rejects_conflicting_ssl_flags(self):
        import io
        from contextlib import redirect_stderr

        from soclens.cli import main

        err_buf = io.StringIO()
        with patch("sys.argv", ["soclens", "--insecure", "--ca-bundle", "/etc/ssl/corp.pem", "rf", "apis"]):
            with redirect_stderr(err_buf):
                with self.assertRaises(SystemExit) as ctx:
                    main()
        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("Cannot specify both --insecure and --ca-bundle", err_buf.getvalue())

        err_val = io.StringIO()
        with patch("sys.argv", ["soclens", "validate", "--insecure", "--verify-ssl"]):
            with redirect_stderr(err_val):
                with self.assertRaises(SystemExit) as ctx_val:
                    main()
        self.assertEqual(ctx_val.exception.code, 1)
        self.assertIn("Cannot specify both --insecure and --verify-ssl", err_val.getvalue())

    def test_parser_sigma_custom_indexes_table_fields_and_pipelines(self):
        args = self.parser.parse_args(
            [
                "sigma",
                "--index",
                "forced_idx",
                "--index-map",
                "windows=win_sec",
                "--index-map",
                "aws=cloud_aws",
                "--default-index",
                "soc_fallback",
                "--custom-table-fields",
                "tenant_id,env",
                "--table-fields-map",
                "windows=_time host User",
                "--custom-suppress-fields",
                "tenant_id",
                "--suppress-fields-map",
                "windows=tenant_id,host",
                "--field-map",
                "CommandLine=proc_cmd",
                "--sourcetype-map",
                "windows:security=WinEventLog:Security",
                "--pipeline",
                "splunk_windows_sysmon",
                "--pipeline-file",
                "custom_pipe.yml",
                "--output-format",
                "default",
                "--sigma-config",
                "profile.json",
                "--no-split",
                "--no-rule-fields",
                "--convert-file",
                "rule1.yml",
            ]
        )
        self.assertEqual(args.index_override, "forced_idx")
        self.assertEqual(args.index_map, ["windows=win_sec", "aws=cloud_aws"])
        self.assertEqual(args.default_index, "soc_fallback")
        self.assertEqual(args.custom_table_fields, "tenant_id,env")
        self.assertEqual(args.table_fields_map, ["windows=_time host User"])
        self.assertEqual(args.custom_suppress_fields, "tenant_id")
        self.assertEqual(args.suppress_fields_map, ["windows=tenant_id,host"])
        self.assertEqual(args.field_map, ["CommandLine=proc_cmd"])
        self.assertEqual(args.sourcetype_map, ["windows:security=WinEventLog:Security"])
        self.assertEqual(args.pipeline, "splunk_windows_sysmon")
        self.assertEqual(args.pipeline_file, "custom_pipe.yml")
        self.assertEqual(args.output_format, "default")
        self.assertEqual(args.sigma_config, "profile.json")
        self.assertTrue(args.no_split)
        self.assertTrue(args.no_rule_fields)
        self.assertEqual(args.convert_file, ["rule1.yml"])

    def test_cli_sigma_convert_file_offline_and_export_with_custom_options(self):
        import configparser
        import io
        import json
        import tempfile
        from contextlib import redirect_stdout
        from pathlib import Path

        from soclens.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            rule_path = tmp_dir / "local_rule.yml"
            rule_path.write_text(
                "title: Local Sigma Detection\n"
                "level: high\n"
                "logsource:\n"
                "  product: windows\n"
                "  service: security\n"
                "detection:\n"
                "  selection:\n"
                "    EventID: 4688\n"
                "    CommandLine|contains: whoami\n"
                "  condition: selection\n"
                "fields:\n"
                "  - TargetUserId\n",
                encoding="utf-8",
            )
            cfg_path = tmp_dir / "sigma_profile.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "index_map": {"windows:security": "win_sec"},
                        "custom_table_fields": ["tenant_id"],
                    }
                ),
                encoding="utf-8",
            )

            # 1. Offline --convert-file --json with no RF_API_TOKEN set
            env_clean = {
                k: v
                for k, v in os.environ.items()
                if k not in ("RF_API_TOKEN", "RECORDED_FUTURE_API_KEY")
            }
            buf_json = io.StringIO()
            with (
                patch.dict(os.environ, env_clean, clear=True),
                patch(
                    "sys.argv",
                    [
                        "soclens",
                        "sigma",
                        "--convert-file",
                        str(rule_path),
                        "--sigma-config",
                        str(cfg_path),
                        "--custom-table-fields",
                        "env",
                        "--field-map",
                        "CommandLine=proc_cmd",
                        "--json",
                    ],
                ),
            ):
                with redirect_stdout(buf_json):
                    main()

            payload = json.loads(buf_json.getvalue())
            self.assertEqual(payload["index"], "win_sec")
            self.assertEqual(payload["pipeline"], "splunk_windows")
            self.assertIn("index=win_sec", payload["stanzas"][0])
            self.assertIn("EventCode=4688", payload["stanzas"][0])
            self.assertIn('proc_cmd="*whoami*"', payload["stanzas"][0])
            self.assertIn("TargetUserId", payload["table_fields"])
            self.assertIn("tenant_id", payload["table_fields"])
            self.assertIn("env", payload["table_fields"])

            # 2. Offline --convert-file --export --no-split writes valid INI file
            out_conf = tmp_dir / "custom_savedsearches.conf"
            with (
                patch.dict(os.environ, env_clean, clear=True),
                patch(
                    "sys.argv",
                    [
                        "soclens",
                        "sigma",
                        "--convert-file",
                        str(rule_path),
                        "--export",
                        "--no-split",
                        "--no-rule-fields",
                        "--index",
                        "single_idx",
                        "--custom-table-fields",
                        "soc_tier",
                        "--output",
                        str(out_conf),
                    ],
                ),
            ):
                with redirect_stdout(io.StringIO()):
                    main()

            self.assertTrue(out_conf.is_file())
            cp = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
            cp.read_string(out_conf.read_text(encoding="utf-8"))
            self.assertEqual(len(cp.sections()), 1)
            sec = cp[cp.sections()[0]]
            self.assertIn("index=single_idx", sec["search"])
            self.assertIn("soc_tier", sec["search"])
            self.assertNotIn("TargetUserId", sec["search"])

    @patch("soclens.cli.RecordedFutureClient")
    def test_watchlist_remove_company_flags_and_unchanged_output(self, mock_client):
        import io
        from contextlib import redirect_stdout

        from soclens.cli import main

        client_inst = mock_client.return_value
        client_inst.remove_entity.return_value = {"result": "removed"}

        with (
            patch.dict("os.environ", {"SOCLENS_AUTO_APPROVE": "1"}),
            patch(
                "sys.argv",
                ["soclens", "watchlist", "remove", "report:fOqHJL", "Company", "Colonial Federal Savings Bank"],
            ),
            redirect_stdout(io.StringIO()) as out1,
        ):
            main()
        client_inst.remove_entity.assert_called_once_with(
            "report:fOqHJL",
            "Colonial Federal Savings Bank",
            entity_type="Company",
        )
        self.assertIn("Successfully removed entity", out1.getvalue())

        client_inst.remove_entity.reset_mock()
        client_inst.remove_entity.return_value = {"result": "unchanged"}
        with (
            patch.dict("os.environ", {"SOCLENS_AUTO_APPROVE": "1"}),
            patch(
                "sys.argv",
                ["soclens", "watchlist", "remove", "report:fOqHJL", "iuiKOZ", "--is-id", "--no-resolve"],
            ),
            redirect_stdout(io.StringIO()) as out2,
        ):
            main()
        client_inst.remove_entity.assert_called_once_with(
            "report:fOqHJL",
            "iuiKOZ",
            is_id=True,
            resolve=False,
        )
        self.assertIn("not present in watchlist", out2.getvalue())
        self.assertIn("unchanged", out2.getvalue())

    def test_main_watchlist_brand_issues_offline_sort_and_filter(self):
        import io
        import json
        import tempfile
        from contextlib import redirect_stdout
        from pathlib import Path

        from soclens.cli import main

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            state_path = ws / "brand_sync_state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "list_id": "report:wl_hash_01",
                        "domains": {
                            "healthy.test": {
                                "consecutive_failures": 0,
                                "hashes": ["a" * 64, "b" * 64],
                                "last_error": None,
                            },
                            "silent-zero.test": {
                                "consecutive_failures": 0,
                                "hashes": [],
                                "last_error": None,
                            },
                            "conn-err.test": {
                                "consecutive_failures": 3,
                                "hashes": [],
                                "last_error": "Connection timed out",
                            },
                            "shared-peer.test": {
                                "consecutive_failures": 0,
                                "hashes": ["a" * 64],
                                "last_error": None,
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            buf_json = io.StringIO()
            with patch(
                "sys.argv",
                [
                    "soclens",
                    "watchlist",
                    "brand-issues",
                    "--state-file",
                    str(state_path),
                    "--category",
                    "missing_hashes",
                    "--sort",
                    "domain",
                    "--desc",
                    "--json",
                ],
            ):
                with redirect_stdout(buf_json):
                    main()
            payload = json.loads(buf_json.getvalue())
            self.assertEqual(payload["report"]["missing_hashes_count"], 2)
            self.assertEqual(payload["report"]["silent_zero_hashes_count"], 1)
            self.assertEqual(
                [i["domain"] for i in payload["issues"]],
                ["silent-zero.test", "conn-err.test"],
            )

            buf_txt = io.StringIO()
            with patch(
                "sys.argv",
                [
                    "soclens",
                    "watchlist",
                    "brand-issues",
                    "--state-file",
                    str(state_path),
                    "--category",
                    "silent_zero_hashes",
                ],
            ):
                with redirect_stdout(buf_txt):
                    main()
            out_txt = buf_txt.getvalue()
            self.assertIn("missing_hashes=2", out_txt)
            self.assertIn("silent-zero.test", out_txt)
            self.assertNotIn("conn-err.test", out_txt)

if __name__ == "__main__":
    unittest.main()

