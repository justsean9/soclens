"""Unit tests for soclens.settings, config precedence, ConfiguredSession, and CLI settings."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

import soclens.settings as settings_mod
from soclens.bundler import create_bundle
from soclens.cli import main as cli_main
from soclens.client import RecordedFutureClient
from soclens.config import (
    ConfiguredSession,
    get_auto_approve,
    get_proxy_summary,
    get_rf_asi_key,
    get_rf_base_url,
    get_rf_pfi_token,
    get_rf_riskrecon_token,
    get_rf_sandbox_token,
    get_rf_token,
    get_rf_verify_ssl,
    get_saved_proxies_for_url,
    get_sentinelone_config,
    get_splunk_config,
    get_workspace_dir,
    has_rf_ssl_config_override,
    has_rf_ssl_env_override,
)
from soclens.logos.extractor import load_domain_overrides
from soclens.logos.hashing import load_ignored_hashes
from soclens.sigma import get_suppress_fields_for_logsource, get_table_fields_for_logsource
from soclens.tui.image_render import detect_terminal_graphics_protocol


def test_get_settings_path_cross_platform(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings_mod, "_DEFAULT_SETTINGS_PATH_OVERRIDE", None)
    monkeypatch.delenv("SOCLENS_SETTINGS_FILE", raising=False)

    explicit = tmp_path / "custom" / "my_settings.json"
    assert settings_mod.get_settings_path(explicit) == explicit

    env_path = tmp_path / "env_cfg" / "settings.json"
    monkeypatch.setenv("SOCLENS_SETTINGS_FILE", str(env_path))
    assert settings_mod.get_settings_path() == env_path
    monkeypatch.delenv("SOCLENS_SETTINGS_FILE", raising=False)

    # Linux XDG_CONFIG_HOME and ~/.config fallback
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(sys, "platform", "linux")
    xdg_dir = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_dir))
    assert settings_mod.get_settings_path() == xdg_dir / "soclens" / "settings.json"

    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home_linux"))
    assert (
        settings_mod.get_settings_path()
        == tmp_path / "home_linux" / ".config" / "soclens" / "settings.json"
    )

    # macOS Application Support
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home_mac"))
    assert (
        settings_mod.get_settings_path()
        == tmp_path
        / "home_mac"
        / "Library"
        / "Application Support"
        / "soclens"
        / "settings.json"
    )

    # Windows APPDATA and fallback (monkeypatch sys.platform only so pathlib.Path stays valid on POSIX)
    monkeypatch.setattr(sys, "platform", "win32")
    win_appdata = tmp_path / "WinAppData"
    monkeypatch.setenv("APPDATA", str(win_appdata))
    assert settings_mod.get_settings_path() == win_appdata / "soclens" / "settings.json"

    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home_win"))
    assert (
        settings_mod.get_settings_path()
        == tmp_path / "home_win" / "AppData" / "Roaming" / "soclens" / "settings.json"
    )


def test_atomic_save_permissions_unknown_keys_and_corrupt_recovery(tmp_path: Path) -> None:
    cfg_path = tmp_path / "cfg_dir" / "settings.json"
    saved_path = settings_mod.save_profile_settings(
        {"rf_api_token": "secret-123", "splunk_app": "CustomApp"},
        settings_path=cfg_path,
    )
    assert saved_path == cfg_path
    assert cfg_path.is_file()

    if os.name != "nt":
        file_mode = stat.S_IMODE(cfg_path.stat().st_mode)
        dir_mode = stat.S_IMODE(cfg_path.parent.stat().st_mode)
        assert file_mode == 0o600
        assert (dir_mode & 0o077) == 0

    # Inject unknown top-level and profile keys and verify preservation on merge save
    raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    raw["custom_future_field"] = {"enabled": True}
    raw["profiles"]["default"]["future_setting"] = "keep-me"
    cfg_path.write_text(json.dumps(raw), encoding="utf-8")
    settings_mod.invalidate_settings_cache()

    settings_mod.save_profile_settings({"splunk_host": "https://splunk:8089"}, settings_path=cfg_path)
    updated = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert updated["custom_future_field"] == {"enabled": True}
    assert updated["profiles"]["default"]["future_setting"] == "keep-me"
    assert updated["profiles"]["default"]["rf_api_token"] == "secret-123"
    assert updated["profiles"]["default"]["splunk_host"] == "https://splunk:8089"

    # Unset a key via None
    settings_mod.save_profile_settings({"splunk_app": None}, settings_path=cfg_path)
    assert "splunk_app" not in settings_mod.get_profile_settings(settings_path=cfg_path)

    # Corrupt JSON resilience
    cfg_path.write_text("{corrupt json", encoding="utf-8")
    settings_mod.invalidate_settings_cache()
    recovered = settings_mod.load_settings_store(settings_path=cfg_path)
    assert recovered["active_profile"] == "default"
    assert recovered["profiles"] == {"default": {}}
    assert settings_mod.get_last_load_error(settings_path=cfg_path) is not None


def test_named_profiles_lifecycle_and_env_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg_path = tmp_path / "profiles" / "settings.json"
    settings_mod.save_profile_settings({"rf_api_token": "tok-default"}, settings_path=cfg_path)
    settings_mod.set_active_profile("prod", create=True, settings_path=cfg_path)
    settings_mod.save_profile_settings({"rf_api_token": "tok-prod"}, settings_path=cfg_path)

    assert settings_mod.list_profiles(settings_path=cfg_path) == ["default", "prod"]
    assert settings_mod.get_active_profile_name(settings_path=cfg_path) == "prod"
    assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_path) == "tok-prod"

    monkeypatch.setenv("SOCLENS_PROFILE", "default")
    assert settings_mod.get_active_profile_name(settings_path=cfg_path) == "default"
    assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_path) == "tok-default"
    monkeypatch.delenv("SOCLENS_PROFILE", raising=False)

    with pytest.raises(ValueError):
        settings_mod.delete_profile("default", settings_path=cfg_path)
    with pytest.raises(ValueError):
        settings_mod.validate_profile_name("bad/name")
    with pytest.raises(ValueError):
        settings_mod.validate_profile_name("..")

    settings_mod.delete_profile("prod", settings_path=cfg_path)
    assert settings_mod.get_active_profile_name(settings_path=cfg_path) == "default"
    assert settings_mod.list_profiles(settings_path=cfg_path) == ["default"]


def test_validation_and_masking() -> None:
    assert settings_mod.resolve_setting_key("RF_API_TOKEN") == "rf_api_token"
    assert settings_mod.resolve_setting_key("RECORDED_FUTURE_API_KEY") == "rf_api_token"
    assert settings_mod.resolve_setting_key("SENTINELONE_API_TOKEN") == "s1_api_token"
    assert settings_mod.resolve_setting_key("unknown_key") is None

    errors = settings_mod.validate_settings_values(
        {
            "rf_api_token": "line1\nline2",
            "rf_base_url": "not-a-url",
            "s1_timeout": "-5",
            "rf_tui_image_protocol": "invalid_proto",
            "soclens_auto_approve": "maybe",
        }
    )
    bad_keys = {k for k, _ in errors}
    assert bad_keys == {
        "rf_api_token",
        "rf_base_url",
        "s1_timeout",
        "rf_tui_image_protocol",
        "soclens_auto_approve",
    }

    for proto in ("auto", "kitty", "iterm2", "sixel", "halfblock"):
        assert settings_mod.validate_settings_values({"rf_tui_image_protocol": proto}) == []

    assert settings_mod.mask_secret("abcd") == "****"
    assert settings_mod.mask_secret("supersecrettoken") == "supe...oken"
    masked_proxy = settings_mod.format_setting_display(
        "https_proxy", "http://alice:p4ss@proxy.corp:8080", reveal=False
    )
    assert "p4ss" not in masked_proxy
    assert "proxy.corp:8080" in masked_proxy


def test_precedence_across_rf_splunk_s1_ssl_workspace_sigma_logos_and_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ws_dir = tmp_path / "saved_ws"
    ws_dir.mkdir()
    overrides_file = tmp_path / "overrides.json"
    overrides_file.write_text('{"example.com": {"include": ["/logo.png"]}}', encoding="utf-8")
    ignored_file = tmp_path / "ignored.txt"
    ignored_file.write_text(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # test\n",
        encoding="utf-8",
    )

    with patch.dict(os.environ, {}, clear=True):
        settings_mod.save_profile_settings(
            {
                "rf_api_token": "saved-rf",
                "rf_sandbox_token": "saved-sb",
                "rf_asi_api_key": "saved-asi",
                "rf_pfi_token": "saved-pfi",
                "rf_riskrecon_token": "saved-rr",
                "rf_base_url": "https://rf.saved.local",
                "rf_sandbox_base_url": "https://sb.saved.local",
                "rf_verify_ssl": "false",
                "https_proxy": "http://user:pw@proxy.saved.local:8443",
                "no_proxy": "127.0.0.1,localhost",
                "splunk_host": "https://splunk.saved.local:8089",
                "splunk_token": "saved-splunk-tok",
                "splunk_app": "CustomES",
                "splunk_verify_ssl": "true",
                "s1_console_url": "https://s1.saved.local",
                "s1_api_token": "saved-s1-tok",
                "s1_account_id": "acct-1",
                "s1_site_id": "site-1",
                "s1_timeout": "45.5",
                "soclens_home": str(ws_dir),
                "rf_tui_image_protocol": "kitty",
                "soclens_default_table_fields": "_time host custom_field",
                "soclens_default_suppress_fields": "host,custom_suppress",
                "soclens_tenant_field": "tenant_id",
                "rf_logo_overrides_file": str(overrides_file),
                "rf_ignored_hashes_file": str(ignored_file),
                "rf_ignored_hashes": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "soclens_auto_approve": "true",
            }
        )

        assert get_workspace_dir() == ws_dir.resolve()
        assert get_rf_token() == "saved-rf"
        assert get_rf_sandbox_token() == "saved-sb"
        assert get_rf_asi_key() == "saved-asi"
        assert get_rf_pfi_token() == "saved-pfi"
        assert get_rf_riskrecon_token() == "saved-rr"
        assert get_rf_base_url("core") == "https://rf.saved.local"
        assert get_rf_base_url("sandbox") == "https://sb.saved.local"
        assert get_rf_verify_ssl() is False
        assert has_rf_ssl_env_override() is False
        assert has_rf_ssl_config_override() is True
        assert "proxy.saved.local:8443" in get_proxy_summary()
        assert "pw" not in get_proxy_summary()
        assert get_saved_proxies_for_url("https://api.recordedfuture.com/v2") == {
            "https": "http://user:pw@proxy.saved.local:8443"
        }
        assert get_saved_proxies_for_url("https://127.0.0.1:8089/services") == {}

        sp = get_splunk_config(required=True)
        assert sp.host == "https://splunk.saved.local:8089"
        assert sp.token == "saved-splunk-tok"
        assert sp.app == "CustomES"
        assert sp.verify_ssl is True

        s1 = get_sentinelone_config(required=True)
        assert s1.console_url == "https://s1.saved.local"
        assert s1.api_token == "saved-s1-tok"
        assert s1.account_id == "acct-1"
        assert s1.site_id == "site-1"
        assert s1.timeout == 45.5
        assert s1.verify_ssl is False

        assert get_auto_approve() is True
        assert get_table_fields_for_logsource({}) == "_time host custom_field"
        assert get_suppress_fields_for_logsource({}) == "host,custom_suppress"
        settings_mod.save_profile_settings(
            {"soclens_default_table_fields": None, "soclens_default_suppress_fields": None}
        )
        assert get_table_fields_for_logsource({}).endswith(" tenant_id")
        assert get_suppress_fields_for_logsource({}).startswith("tenant_id,")
        assert load_domain_overrides() == {"example.com": {"include": ["/logo.png"]}}
        loaded_hashes = load_ignored_hashes()
        assert "a" * 64 in loaded_hashes
        assert "b" * 32 in loaded_hashes
        assert detect_terminal_graphics_protocol(is_headless=False) == "kitty"

        # Client uses ConfiguredSession & reloads live
        client = RecordedFutureClient()
        assert isinstance(client.session, ConfiguredSession)
        assert client.api_token == "saved-rf"
        assert client.core_base_url == "https://rf.saved.local"
        assert client.verify_ssl is False

        settings_mod.save_profile_settings(
            {"rf_api_token": "reloaded-rf", "rf_verify_ssl": "true"}
        )
        client.reload_from_config()
        assert client.api_token == "reloaded-rf"
        assert client.verify_ssl is True

        # check_connection calls single read-only watchlist search
        mock_sess = MagicMock(spec=requests.Session)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.json.return_value = [{"id": "report:1"}]
        mock_sess.request.return_value = mock_resp
        mock_sess.verify = True
        client_with_mock = RecordedFutureClient(session=mock_sess)
        conn_info = client_with_mock.check_connection()
        assert conn_info["connected"] is True
        assert conn_info["sample_lists"] == 1

        # Env beats saved; session override beats env
        os.environ["RF_API_TOKEN"] = "env-rf"
        assert get_rf_token() == "env-rf"
        assert get_rf_token(explicit="explicit-rf") == "explicit-rf"

        settings_mod.set_session_overrides({"rf_api_token": "session-rf"})
        assert get_rf_token() == "session-rf"
        assert get_rf_token(explicit="explicit-rf") == "explicit-rf"
        settings_mod.clear_session_overrides()
        assert get_rf_token() == "env-rf"


def test_configured_session_merges_saved_proxies_and_no_proxy() -> None:
    with patch.dict(os.environ, {}, clear=True):
        settings_mod.save_profile_settings(
            {
                "https_proxy": "http://saved-proxy:8080",
                "http_proxy": "http://saved-http:3128",
                "no_proxy": "127.0.0.1,internal.local",
            }
        )
        sess = ConfiguredSession()
        remote = sess.merge_environment_settings(
            "https://api.recordedfuture.com/list/search",
            proxies=None,
            stream=None,
            verify=True,
            cert=None,
        )
        assert remote["proxies"]["https"] == "http://saved-proxy:8080"

        bypassed = sess.merge_environment_settings(
            "https://127.0.0.1:8089/services/server/info",
            proxies=None,
            stream=None,
            verify=True,
            cert=None,
        )
        assert bypassed["proxies"] == {}

        # Explicit request proxy wins even when no_proxy matches
        explicit = sess.merge_environment_settings(
            "https://127.0.0.1:8089/services",
            proxies={"https": "http://explicit-proxy:9999"},
            stream=None,
            verify=True,
            cert=None,
        )
        assert explicit["proxies"]["https"] == "http://explicit-proxy:9999"


def test_cli_settings_commands_and_json_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def _run_cli_args(argv: list[str]) -> tuple[str, str]:
        monkeypatch.setattr(sys, "argv", ["soclens", *argv])
        cli_main()
        captured = capsys.readouterr()
        return captured.out, captured.err

    out, _ = _run_cli_args(["settings", "path", "--json"])
    path_payload = json.loads(out)
    assert Path(path_payload["path"]).name == "settings.json"
    assert path_payload["exists"] is False

    # Set via env alias; secret value must NOT appear raw in stdout
    out, _ = _run_cli_args(["settings", "set", "RF_API_TOKEN", "supersecret-token-9999"])
    assert "supersecret-token-9999" not in out
    assert "rf_api_token" in out

    # Show masked vs revealed
    out, _ = _run_cli_args(["settings", "show", "--json"])
    show_masked = json.loads(out)
    rf_item = next(i for i in show_masked["settings"] if i["key"] == "rf_api_token")
    assert rf_item["source"] == "settings"
    assert rf_item["value"] != "supersecret-token-9999"
    assert "..." in rf_item["value"]

    out, _ = _run_cli_args(["settings", "show", "--reveal", "--json"])
    show_rev = json.loads(out)
    rf_rev = next(i for i in show_rev["settings"] if i["key"] == "rf_api_token")
    assert rf_rev["value"] == "supersecret-token-9999"

    # Profiles & import-env
    monkeypatch.setenv("SPLUNK_HOST", "https://splunk-from-env:8089")
    out, _ = _run_cli_args(["settings", "use", "lab", "--json"])
    assert json.loads(out)["active_profile"] == "lab"

    out, _ = _run_cli_args(["settings", "import-env", "--json"])
    imp_payload = json.loads(out)
    assert "splunk_host" in imp_payload["imported"]

    out, _ = _run_cli_args(["settings", "profiles", "--json"])
    profs = json.loads(out)
    assert profs["active_profile"] == "lab"
    assert "default" in profs["profiles"] and "lab" in profs["profiles"]

    # Reset requires --yes or auto-approve; --dry-run exits 0 safely
    out, _ = _run_cli_args(["settings", "reset", "--dry-run", "--json"])
    assert json.loads(out)["dry_run"] is True
    assert settings_mod.get_saved_setting("splunk_host", profile="lab") == "https://splunk-from-env:8089"

    with pytest.raises(SystemExit) as exc_info:
        _run_cli_args(["settings", "reset"])
    assert exc_info.value.code == 1

    out, _ = _run_cli_args(["settings", "reset", "--yes", "--json"])
    assert json.loads(out)["reset"] is True
    assert settings_mod.get_profile_settings(profile="lab") == {}

    out, _ = _run_cli_args(["settings", "unset", "rf_api_token", "--profile", "default", "--json"])
    assert json.loads(out)["unset"] is True

    out, _ = _run_cli_args(["settings", "delete-profile", "lab", "--json"])
    assert json.loads(out)["deleted"] == "lab"


def test_bundler_excludes_settings_files(tmp_path: Path) -> None:
    ws = tmp_path / "bundle_ws"
    ws.mkdir()
    (ws / "soclens").mkdir()
    (ws / "soclens" / "__init__.py").write_text('__version__ = "1.0.2"\n', encoding="utf-8")
    (ws / "README.md").write_text("# SOCLens\n", encoding="utf-8")
    (ws / "settings.json").write_text('{"profiles":{"default":{"rf_api_token":"leak"}}}', encoding="utf-8")
    (ws / ".soclens_settings.json").write_text('{"secret":"leak"}', encoding="utf-8")
    (ws / ".soclens_tui_settings.json").write_text('{"secret":"leak"}', encoding="utf-8")

    out_zip = tmp_path / "out.zip"
    create_bundle(ws, output_path=out_zip, wheelhouse=False, target_platform="pure")

    import zipfile

    with zipfile.ZipFile(out_zip, "r") as zf:
        names = set(zf.namelist())
    assert "README.md" in names
    assert "settings.json" not in names
    assert ".soclens_settings.json" not in names
    assert ".soclens_tui_settings.json" not in names
