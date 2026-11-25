"""Comprehensive unit, CLI, and TUI tests for encrypted settings.json storage."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from textual.widgets import Button, Input, OptionList, Static

import soclens.settings as settings_mod
import soclens.settings_crypto as crypto_mod
from soclens.cli import main as cli_main
from soclens.tui import (
    ConfirmActionModal,
    SettingsPassphraseModal,
    SettingsUnlockModal,
    create_app,
)


def _run_cli(
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "argv", ["soclens", *argv])
    try:
        cli_main()
        rc = 0
    except SystemExit as exc:
        rc = int(exc.code) if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_default_save_encrypts_full_payload_and_hides_all_fields(tmp_path: Path) -> None:
    cfg_path = tmp_path / "enc_default" / "settings.json"
    settings_mod.save_profile_settings(
        {
            "rf_api_token": "rf-super-secret-token-999",
            "splunk_host": "https://internal-splunk.corp.local:8089",
            "splunk_username": "soc_analyst_alice",
            "splunk_password": "splunk-ultra-password!",
            "s1_console_url": "https://tenant-secret.sentinelone.net",
            "s1_api_token": "s1-edr-secret-888",
            "s1_site_tenant_map": '{"MDR-ACME":"acme-prod"}',
        },
        profile="prod_soc",
        settings_path=cfg_path,
    )

    raw_disk = cfg_path.read_text(encoding="utf-8")
    envelope = json.loads(raw_disk)
    assert envelope["schema_version"] == 2
    assert envelope["encrypted"] is True
    assert envelope["format"] == crypto_mod.ENCRYPTED_SETTINGS_FORMAT
    assert envelope["cipher"] == "AES-256-GCM"
    assert envelope["mode"] == "os_keystore"
    assert "nonce" in envelope and "ciphertext" in envelope

    # Full-file confidentiality: none of the secrets, URLs, usernames, or profile names appear on disk
    for sensitive in (
        "rf-super-secret-token-999",
        "internal-splunk.corp.local",
        "soc_analyst_alice",
        "splunk-ultra-password!",
        "tenant-secret.sentinelone.net",
        "s1-edr-secret-888",
        "MDR-ACME",
        "prod_soc",
        "profiles",
    ):
        assert sensitive not in raw_disk

    if os.name != "nt":
        assert stat.S_IMODE(cfg_path.stat().st_mode) == 0o600
        keyfile = crypto_mod.get_local_keyfile_path()
        assert keyfile.is_file()
        assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600

    # Cold reload from disk after clearing both settings cache and unlocked key cache
    settings_mod.invalidate_settings_cache()
    crypto_mod.clear_unlocked_keys()
    loaded = settings_mod.get_profile_settings(profile="prod_soc", settings_path=cfg_path)
    assert loaded["rf_api_token"] == "rf-super-secret-token-999"
    assert loaded["splunk_host"] == "https://internal-splunk.corp.local:8089"
    assert loaded["splunk_username"] == "soc_analyst_alice"
    assert loaded["s1_site_tenant_map"] == '{"MDR-ACME":"acme-prod"}'


def test_fresh_nonce_every_write_and_aad_tamper_detection(tmp_path: Path) -> None:
    cfg_path = tmp_path / "tamper" / "settings.json"
    settings_mod.save_profile_settings({"rf_api_token": "tok-1"}, settings_path=cfg_path)
    env1 = json.loads(cfg_path.read_text(encoding="utf-8"))

    settings_mod.save_profile_settings({"rf_api_token": "tok-1"}, settings_path=cfg_path)
    env2 = json.loads(cfg_path.read_text(encoding="utf-8"))
    assert env1["nonce"] != env2["nonce"]
    assert env1["ciphertext"] != env2["ciphertext"]

    # 1. Tamper with ciphertext -> decryption must fail AND writes must refuse to overwrite
    bad_ct_env = dict(env2)
    ct_bytes = bytearray(base64.b64decode(env2["ciphertext"]))
    ct_bytes[0] ^= 0xFF
    bad_ct_env["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode("ascii")
    cfg_path.write_text(json.dumps(bad_ct_env), encoding="utf-8")
    settings_mod.invalidate_settings_cache()
    crypto_mod.clear_unlocked_keys()

    recovered = settings_mod.load_settings_store(settings_path=cfg_path)
    assert recovered["profiles"] == {"default": {}}
    err = settings_mod.get_last_load_error(settings_path=cfg_path)
    assert err is not None and "decrypt" in err.lower()

    with pytest.raises(settings_mod.SettingsDecryptionError):
        settings_mod.save_profile_settings({"splunk_app": "ShouldNotOverwrite"}, settings_path=cfg_path)

    # 2. Tamper with AAD header metadata (e.g., downgrade/modify mode) -> authentication must fail
    bad_aad_env = dict(env2)
    bad_aad_env["mode"] = "passphrase"
    cfg_path.write_text(json.dumps(bad_aad_env), encoding="utf-8")
    settings_mod.invalidate_settings_cache()
    crypto_mod.clear_unlocked_keys()
    with pytest.raises(settings_mod.SettingsDecryptionError):
        settings_mod.unlock_settings(settings_path=cfg_path)


def test_legacy_plaintext_v1_migration_preserves_profiles_and_unknown_keys(tmp_path: Path) -> None:
    cfg_path = tmp_path / "legacy" / "settings.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    legacy = {
        "schema_version": 1,
        "active_profile": "prod",
        "future_root_meta": {"version": 99},
        "profiles": {
            "default": {"rf_api_token": "legacy-default-tok"},
            "prod": {"rf_api_token": "legacy-prod-tok", "custom_key": "preserve-me"},
        },
    }
    cfg_path.write_text(json.dumps(legacy), encoding="utf-8")

    info_before = settings_mod.get_settings_storage_info(cfg_path)
    assert info_before["encrypted"] is False
    assert info_before["legacy_plaintext"] is True
    assert info_before["active_profile"] == "prod"
    assert settings_mod.get_saved_setting("rf_api_token", profile="prod", settings_path=cfg_path) == "legacy-prod-tok"

    # Auto-migrate on save
    settings_mod.save_profile_settings({"splunk_app": "MigratedES"}, profile="prod", settings_path=cfg_path)
    raw_after = cfg_path.read_text(encoding="utf-8")
    assert json.loads(raw_after)["encrypted"] is True
    assert "legacy-prod-tok" not in raw_after
    assert "legacy-default-tok" not in raw_after
    assert "preserve-me" not in raw_after

    settings_mod.invalidate_settings_cache()
    crypto_mod.clear_unlocked_keys()
    migrated = settings_mod.load_settings_store(cfg_path)
    assert migrated["future_root_meta"] == {"version": 99}
    assert migrated["profiles"]["default"]["rf_api_token"] == "legacy-default-tok"
    assert migrated["profiles"]["prod"]["rf_api_token"] == "legacy-prod-tok"
    assert migrated["profiles"]["prod"]["custom_key"] == "preserve-me"
    assert migrated["profiles"]["prod"]["splunk_app"] == "MigratedES"


def test_master_passphrase_lifecycle_lock_unlock_no_clobber_and_mode_switch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Speed up Scrypt in unit test while keeping valid RFC 7914 bounds
    monkeypatch.setattr(crypto_mod, "DEFAULT_SCRYPT_N", 2**12)
    cfg_path = tmp_path / "passphrase" / "settings.json"
    settings_mod.save_profile_settings(
        {"rf_api_token": "vault-rf-tok", "splunk_token": "vault-sp-tok"},
        settings_path=cfg_path,
    )

    with pytest.raises(ValueError, match="at least 8 characters"):
        settings_mod.encrypt_settings_store(mode="passphrase", passphrase="short", settings_path=cfg_path)

    info = settings_mod.encrypt_settings_store(
        mode="passphrase",
        passphrase="correct-horse-battery-staple",
        settings_path=cfg_path,
    )
    assert info["encrypted"] is True
    assert info["encryption_mode"] == "passphrase"
    assert info["key_backend"] == crypto_mod.KEY_PROTECTION_SCRYPT_PASSPHRASE
    assert info["locked"] is False

    # Saving while unlocked succeeds immediately without re-prompting
    settings_mod.save_profile_settings({"splunk_app": "UnlockedSave"}, settings_path=cfg_path)
    assert settings_mod.get_saved_setting("splunk_app", settings_path=cfg_path) == "UnlockedSave"

    # Lock -> memory purged, reads return empty default + error, writes REFUSE to clobber disk
    disk_before_lock = cfg_path.read_text(encoding="utf-8")
    assert settings_mod.lock_settings(cfg_path) is True
    assert settings_mod.is_settings_locked(cfg_path) is True
    assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_path) is None
    assert settings_mod.get_last_load_error(cfg_path) is not None

    with pytest.raises(settings_mod.SettingsLockedError):
        settings_mod.save_profile_settings({"rf_api_token": "clobber"}, settings_path=cfg_path)
    with pytest.raises(settings_mod.SettingsLockedError):
        settings_mod.set_active_profile("newprof", settings_path=cfg_path)
    assert cfg_path.read_text(encoding="utf-8") == disk_before_lock

    # Wrong passphrase fails cleanly and keeps file locked
    with pytest.raises(settings_mod.SettingsDecryptionError):
        settings_mod.unlock_settings("wrong-passphrase-123", settings_path=cfg_path)
    assert settings_mod.is_settings_locked(cfg_path) is True

    # Correct passphrase unlocks everything
    unlocked = settings_mod.unlock_settings("correct-horse-battery-staple", settings_path=cfg_path)
    assert settings_mod.is_settings_locked(cfg_path) is False
    assert unlocked["profiles"]["default"]["rf_api_token"] == "vault-rf-tok"
    assert unlocked["profiles"]["default"]["splunk_app"] == "UnlockedSave"

    # Rotate passphrase
    settings_mod.rotate_settings_key(
        passphrase="correct-horse-battery-staple",
        new_passphrase="new-master-passphrase-2026!",
        settings_path=cfg_path,
    )
    settings_mod.lock_settings(cfg_path)
    with pytest.raises(settings_mod.SettingsDecryptionError):
        settings_mod.unlock_settings("correct-horse-battery-staple", settings_path=cfg_path)
    settings_mod.unlock_settings("new-master-passphrase-2026!", settings_path=cfg_path)
    assert settings_mod.get_saved_setting("splunk_token", settings_path=cfg_path) == "vault-sp-tok"

    # Switch back to OS keystore auto-unlock preserving all settings
    sw_info = settings_mod.encrypt_settings_store(mode="os_keystore", settings_path=cfg_path)
    assert sw_info["encryption_mode"] == "os_keystore"
    assert sw_info["locked"] is False
    settings_mod.invalidate_settings_cache()
    crypto_mod.clear_unlocked_keys()
    assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_path) == "vault-rf-tok"


def test_passphrase_env_var_file_and_explicit_lock_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(crypto_mod, "DEFAULT_SCRYPT_N", 2**12)
    cfg_path = tmp_path / "env_pw" / "settings.json"
    pw_file = tmp_path / "pw.txt"
    pw_file.write_text("file-passphrase-9876\r\n", encoding="utf-8")

    settings_mod.save_profile_settings({"rf_api_token": "env-unlocked-tok"}, settings_path=cfg_path)
    settings_mod.encrypt_settings_store(
        mode="passphrase",
        passphrase="file-passphrase-9876",
        settings_path=cfg_path,
    )
    crypto_mod.clear_unlocked_keys(mark_locked=False)
    settings_mod.invalidate_settings_cache()

    monkeypatch.setenv("SOCLENS_SETTINGS_PASSPHRASE_FILE", str(pw_file))
    assert settings_mod.is_settings_locked(cfg_path) is False
    assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_path) == "env-unlocked-tok"

    # Explicit lock overrides env auto-unlock until explicitly unlocked
    assert settings_mod.lock_settings(cfg_path) is True
    assert settings_mod.is_settings_locked(cfg_path) is True
    assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_path) is None

    # Explicit unlock succeeds using env file when passphrase=None
    settings_mod.unlock_settings(settings_path=cfg_path)
    assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_path) == "env-unlocked-tok"


def test_platform_keystore_backends_dpapi_macos_keychain_and_linux_secret_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1. Mocked Windows DPAPI backend
    cfg_dpapi = tmp_path / "dpapi" / "settings.json"
    dpapi_secret = b"DPAPI-MOCK-HEADER:"

    def _fake_protect(plaintext: bytes, *, entropy: bytes) -> bytes:
        return dpapi_secret + entropy + b"::" + plaintext

    def _fake_unprotect(ciphertext: bytes, *, entropy: bytes) -> bytes:
        prefix = dpapi_secret + entropy + b"::"
        if not ciphertext.startswith(prefix):
            raise crypto_mod.SettingsDecryptionError("DPAPI entropy mismatch")
        return ciphertext[len(prefix) :]

    monkeypatch.setenv("SOCLENS_SETTINGS_KEYSTORE", crypto_mod.KEY_PROTECTION_WINDOWS_DPAPI)
    with (
        patch.object(crypto_mod, "_dpapi_protect", side_effect=_fake_protect),
        patch.object(crypto_mod, "_dpapi_unprotect", side_effect=_fake_unprotect),
    ):
        settings_mod.save_profile_settings({"rf_api_token": "win-dpapi-secret"}, settings_path=cfg_dpapi)
        env_dpapi = json.loads(cfg_dpapi.read_text(encoding="utf-8"))
        assert env_dpapi["key_protection"]["type"] == crypto_mod.KEY_PROTECTION_WINDOWS_DPAPI
        assert "win-dpapi-secret" not in cfg_dpapi.read_text(encoding="utf-8")

        settings_mod.invalidate_settings_cache()
        crypto_mod.clear_unlocked_keys()
        assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_dpapi) == "win-dpapi-secret"

    # 2. Mocked macOS Keychain backend: verify KEK is sent via stdin (-i) and NEVER in argv
    cfg_mac = tmp_path / "mac" / "settings.json"
    mac_store: dict[tuple[str, str], str] = {}
    mac_calls: list[tuple[list[str], str | None]] = []

    def _fake_mac_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        stdin_val = kwargs.get("input")
        mac_calls.append((list(cmd), str(stdin_val) if stdin_val is not None else None))
        if "-i" in cmd:
            assert isinstance(stdin_val, str) and "add-generic-password" in stdin_val
            parts = stdin_val.strip().split('"')
            svc, acct, hex_val = parts[1], parts[3], parts[7]
            mac_store[(svc, acct)] = hex_val
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "find-generic-password" in cmd:
            svc = cmd[cmd.index("-s") + 1]
            acct = cmd[cmd.index("-a") + 1]
            val = mac_store.get((svc, acct))
            if val is None:
                return subprocess.CompletedProcess(cmd, 44, stdout="", stderr="could not be found")
            return subprocess.CompletedProcess(cmd, 0, stdout=val + "\n", stderr="")
        raise AssertionError(f"Unexpected security command: {cmd}")

    monkeypatch.setenv("SOCLENS_SETTINGS_KEYSTORE", crypto_mod.KEY_PROTECTION_MACOS_KEYCHAIN)
    with (
        patch.object(crypto_mod, "_find_macos_security_bin", return_value="/usr/bin/security"),
        patch.object(crypto_mod.subprocess, "run", side_effect=_fake_mac_run),
    ):
        settings_mod.save_profile_settings({"rf_api_token": "macos-keychain-tok"}, settings_path=cfg_mac)
        env_mac = json.loads(cfg_mac.read_text(encoding="utf-8"))
        assert env_mac["key_protection"]["type"] == crypto_mod.KEY_PROTECTION_MACOS_KEYCHAIN
        stored_hex = next(iter(mac_store.values()))
        # Confirm KEK hex never appeared in any subprocess argv
        for argv, _stdin in mac_calls:
            assert all(stored_hex not in arg for arg in argv)

        settings_mod.invalidate_settings_cache()
        crypto_mod.clear_unlocked_keys()
        assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_mac) == "macos-keychain-tok"

        # Rotate KEK generates a new keychain account
        settings_mod.rotate_settings_key(rotate_kek=True, settings_path=cfg_mac)
        assert len(mac_store) == 2

    # 3. Mocked Linux Secret Service backend + fallback to local_keyfile when daemon fails
    cfg_linux = tmp_path / "linux" / "settings.json"
    linux_store: dict[tuple[str, str], str] = {}
    linux_calls: list[tuple[list[str], str | None]] = []

    def _fake_linux_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        stdin_val = kwargs.get("input")
        linux_calls.append((list(cmd), str(stdin_val) if stdin_val is not None else None))
        svc = cmd[cmd.index("service") + 1]
        acct = cmd[cmd.index("account") + 1]
        if "store" in cmd:
            assert isinstance(stdin_val, str) and len(stdin_val) == 64
            linux_store[(svc, acct)] = stdin_val
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if "lookup" in cmd:
            val = linux_store.get((svc, acct))
            if val is None:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout=val + "\n", stderr="")
        raise AssertionError(f"Unexpected secret-tool command: {cmd}")

    monkeypatch.setenv("SOCLENS_SETTINGS_KEYSTORE", crypto_mod.KEY_PROTECTION_LINUX_SECRET_SERVICE)
    with (
        patch.object(crypto_mod, "_find_linux_secret_tool", return_value="/usr/bin/secret-tool"),
        patch.object(crypto_mod.subprocess, "run", side_effect=_fake_linux_run),
    ):
        settings_mod.save_profile_settings({"rf_api_token": "linux-ss-tok"}, settings_path=cfg_linux)
        env_linux = json.loads(cfg_linux.read_text(encoding="utf-8"))
        assert env_linux["key_protection"]["type"] == crypto_mod.KEY_PROTECTION_LINUX_SECRET_SERVICE
        stored_linux_hex = next(iter(linux_store.values()))
        for argv, _stdin in linux_calls:
            assert all(stored_linux_hex not in arg for arg in argv)

        settings_mod.invalidate_settings_cache()
        crypto_mod.clear_unlocked_keys()
        assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_linux) == "linux-ss-tok"

    # Headless Linux fallback when secret-tool errors and SOCLENS_SETTINGS_KEYSTORE is not pinned
    cfg_fallback = tmp_path / "linux_fallback" / "settings.json"
    monkeypatch.delenv("SOCLENS_SETTINGS_KEYSTORE", raising=False)
    monkeypatch.delenv("SOCLENS_SETTINGS_KEY_FILE", raising=False)
    monkeypatch.setattr(crypto_mod, "_DEFAULT_KEYFILE_PATH_OVERRIDE", None)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg_data"))
    with (
        patch.object(crypto_mod, "_dpapi_available", return_value=False),
        patch.object(crypto_mod, "_find_macos_security_bin", return_value=None),
        patch.object(crypto_mod, "_find_linux_secret_tool", return_value="/usr/bin/secret-tool"),
        patch.object(
            crypto_mod,
            "_linux_secret_service_get_kek",
            side_effect=crypto_mod.SettingsKeystoreError("D-Bus secret service unavailable"),
        ),
    ):
        settings_mod.save_profile_settings({"rf_api_token": "fallback-tok"}, settings_path=cfg_fallback)
        env_fb = json.loads(cfg_fallback.read_text(encoding="utf-8"))
        assert env_fb["key_protection"]["type"] == crypto_mod.KEY_PROTECTION_LOCAL_KEYFILE
        assert (tmp_path / "xdg_data" / "soclens" / ".settings.key").is_file()
        settings_mod.invalidate_settings_cache()
        crypto_mod.clear_unlocked_keys()
        assert settings_mod.get_saved_setting("rf_api_token", settings_path=cfg_fallback) == "fallback-tok"


def test_cli_settings_encryption_commands_and_locked_error_handling(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(crypto_mod, "DEFAULT_SCRYPT_N", 2**12)

    rc, out, err = _run_cli(["settings", "set", "rf_api_token", "cli-secret-tok-777", "--json"], monkeypatch, capsys)
    assert rc == 0, err
    assert "cli-secret-tok-777" not in settings_mod.get_settings_path().read_text(encoding="utf-8")

    # Path reports encrypted status
    rc, out, err = _run_cli(["settings", "path", "--json"], monkeypatch, capsys)
    assert rc == 0, err
    path_info = json.loads(out)
    assert path_info["encrypted"] is True
    assert path_info["cipher"] == "AES-256-GCM"

    # Dry-run encrypt
    rc, out, err = _run_cli(["settings", "encrypt", "--passphrase", "--dry-run", "--json"], monkeypatch, capsys)
    assert rc == 0, err
    assert json.loads(out)["dry_run"] is True

    # Encrypt with Master Passphrase via --passphrase-env
    monkeypatch.setenv("TEST_NEW_PW", "cli-master-pass-123")
    rc, out, err = _run_cli(
        ["settings", "encrypt", "--passphrase", "--passphrase-env", "TEST_NEW_PW", "--json"],
        monkeypatch,
        capsys,
    )
    assert rc == 0, err
    enc_res = json.loads(out)
    assert enc_res["encrypted"] is True
    assert enc_res["storage"]["encryption_mode"] == "passphrase"

    # Lock via CLI
    rc, out, err = _run_cli(["settings", "lock", "--json"], monkeypatch, capsys)
    assert rc == 0, err
    assert json.loads(out)["locked"] is True

    # Non-interactive settings show while locked exits 1 with clean JSON error
    with patch.object(sys.stdin, "isatty", return_value=False):
        rc, out, err = _run_cli(["settings", "show", "--json"], monkeypatch, capsys)
    assert rc == 1
    err_payload = json.loads(err)
    assert err_payload["locked"] is True
    assert "SOCLENS_SETTINGS_PASSPHRASE" in err_payload["hint"]

    # Unlock via CLI --passphrase-env
    rc, out, err = _run_cli(["settings", "unlock", "--passphrase-env", "TEST_NEW_PW", "--json"], monkeypatch, capsys)
    assert rc == 0, err
    assert json.loads(out)["unlocked"] is True

    # Show now works and reveals secret when asked
    rc, out, err = _run_cli(["settings", "show", "--reveal", "--json"], monkeypatch, capsys)
    assert rc == 0, err
    rf_item = next(i for i in json.loads(out)["settings"] if i["key"] == "rf_api_token")
    assert rf_item["value"] == "cli-secret-tok-777"

    # Rekey with new passphrase via env vars
    monkeypatch.setenv("TEST_ROTATED_PW", "cli-rotated-pass-456")
    rc, out, err = _run_cli(
        [
            "settings",
            "rekey",
            "--new-passphrase",
            "--passphrase-env",
            "TEST_NEW_PW",
            "--new-passphrase-env",
            "TEST_ROTATED_PW",
            "--json",
        ],
        monkeypatch,
        capsys,
    )
    assert rc == 0, err
    assert json.loads(out)["rekeyed"] is True

    # Lock and switch back to OS keystore using --current-passphrase-env
    rc, _, _ = _run_cli(["settings", "lock", "--json"], monkeypatch, capsys)
    assert rc == 0
    rc, out, err = _run_cli(
        [
            "settings",
            "encrypt",
            "--mode",
            "os_keystore",
            "--current-passphrase-env",
            "TEST_ROTATED_PW",
            "--json",
        ],
        monkeypatch,
        capsys,
    )
    assert rc == 0, err
    assert json.loads(out)["storage"]["encryption_mode"] == "os_keystore"
    assert settings_mod.get_saved_setting("rf_api_token") == "cli-secret-tok-777"

    # Interactive TTY prompt unlock path
    monkeypatch.setenv("TEST_TTY_PW", "tty-passphrase-999")
    rc, _, err = _run_cli(
        ["settings", "encrypt", "--passphrase", "--passphrase-env", "TEST_TTY_PW", "--json"],
        monkeypatch,
        capsys,
    )
    assert rc == 0, err
    settings_mod.lock_settings()
    with (
        patch.object(sys.stdin, "isatty", return_value=True),
        patch("soclens.cli.getpass.getpass", return_value="tty-passphrase-999"),
    ):
        rc, out, err = _run_cli(["settings", "show", "--reveal", "--json"], monkeypatch, capsys)
    assert rc == 0, err
    rf_tty = next(i for i in json.loads(out)["settings"] if i["key"] == "rf_api_token")
    assert rf_tty["value"] == "cli-secret-tok-777"


def test_tui_startup_unlock_modal_and_settings_encryption_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(crypto_mod, "DEFAULT_SCRYPT_N", 2**12)
    monkeypatch.delenv("RF_API_TOKEN", raising=False)
    monkeypatch.delenv("RECORDED_FUTURE_API_KEY", raising=False)

    settings_mod.save_profile_settings({"rf_api_token": "tui-encrypted-rf-tok"})
    settings_mod.encrypt_settings_store(mode="passphrase", passphrase="tui-master-pass-123")
    settings_mod.lock_settings()
    assert settings_mod.is_settings_locked() is True

    app = create_app(dry_run=True, initial_tab="tab-settings", workspace_dir=tmp_path)

    async def _run() -> None:
        async with app.run_test(size=(130, 42)) as pilot:
            await pilot.pause()
            # Locked passphrase settings automatically open SettingsUnlockModal on startup
            assert isinstance(app.screen, SettingsUnlockModal)

            # Wrong passphrase keeps modal open and shows error
            app.screen.query_one("#unlock-passphrase-input", Input).value = "wrong-pass-000"
            await pilot.click("#unlock-submit-btn")
            await pilot.pause()
            assert isinstance(app.screen, SettingsUnlockModal)
            assert "incorrect" in str(app.screen.query_one("#unlock-modal-error", Static).content).lower()

            # Correct passphrase dismisses modal and reloads live client token
            app.screen.query_one("#unlock-passphrase-input", Input).value = "tui-master-pass-123"
            await pilot.click("#unlock-submit-btn")
            await pilot.pause()
            assert not isinstance(app.screen, SettingsUnlockModal)
            assert settings_mod.is_settings_locked() is False
            assert app.client.api_token == "tui-encrypted-rf-tok"

            # Open Profiles & Storage category and test Lock -> Unlock -> Switch OS Keystore -> Rotate -> Passphrase
            app.query_one("#settings-category-list", OptionList).highlighted = 5
            await pilot.pause()
            assert "Master Passphrase" in str(
                app.query_one("#settings-encryption-status", Static).content
            )

            # Lock Now
            lock_btn = app.query_one("#settings-lock-btn", Button)
            lock_btn.scroll_visible(animate=False)
            await pilot.pause()
            lock_btn.press()
            await pilot.pause()
            assert settings_mod.is_settings_locked() is True
            assert app.query_one("#settings-unlock-btn", Button).disabled is False

            # Unlock via button
            unlock_btn = app.query_one("#settings-unlock-btn", Button)
            unlock_btn.scroll_visible(animate=False)
            await pilot.pause()
            unlock_btn.press()
            await pilot.pause()
            assert isinstance(app.screen, SettingsUnlockModal)
            app.screen.query_one("#unlock-passphrase-input", Input).value = "tui-master-pass-123"
            await pilot.click("#unlock-submit-btn")
            await pilot.pause()
            assert settings_mod.is_settings_locked() is False

            # Switch to OS Keystore (requires confirmation modal when leaving Master Passphrase)
            os_btn = app.query_one("#settings-use-os-keystore-btn", Button)
            os_btn.scroll_visible(animate=False)
            await pilot.pause()
            os_btn.press()
            await pilot.pause()
            assert isinstance(app.screen, ConfirmActionModal)
            await pilot.click("#confirm-approve-btn")
            await pilot.pause()
            assert settings_mod.inspect_settings_encryption()["encryption_mode"] == "os_keystore"

            # Rotate key in OS keystore mode produces fresh ciphertext & nonce
            before_rot = settings_mod.get_settings_path().read_text(encoding="utf-8")
            rekey_btn = app.query_one("#settings-rekey-btn", Button)
            rekey_btn.scroll_visible(animate=False)
            await pilot.pause()
            rekey_btn.press()
            await pilot.pause()
            after_rot = settings_mod.get_settings_path().read_text(encoding="utf-8")
            assert after_rot != before_rot
            assert settings_mod.get_saved_setting("rf_api_token") == "tui-encrypted-rf-tok"

            # Set Master Passphrase via SettingsPassphraseModal
            pw_btn = app.query_one("#settings-set-passphrase-btn", Button)
            pw_btn.scroll_visible(animate=False)
            await pilot.pause()
            pw_btn.press()
            await pilot.pause()
            assert isinstance(app.screen, SettingsPassphraseModal)
            app.screen.query_one("#passphrase-new-input", Input).value = "tui-new-pass-2026"
            app.screen.query_one("#passphrase-confirm-input", Input).value = "tui-new-pass-2026"
            await pilot.click("#passphrase-submit-btn")
            await pilot.pause()
            assert not isinstance(app.screen, SettingsPassphraseModal)
            assert settings_mod.inspect_settings_encryption()["encryption_mode"] == "passphrase"

        # Unmounting TUI purges in-memory unlocked keys
        assert settings_mod.is_settings_locked() is True

    asyncio.run(_run())
