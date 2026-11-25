"""Authenticated encryption (AES-256-GCM) and hybrid key management for settings.json.

Supports two encryption modes inside a single authenticated JSON envelope (schema v2):

1. ``os_keystore`` (default, auto-unlock):
   - Windows: DPAPI (``CryptProtectData`` / ``CryptUnprotectData`` via ``ctypes``)
   - macOS: Keychain (``/usr/bin/security`` using stdin ``-i`` so secrets never enter argv)
   - Linux: Secret Service (``secret-tool`` via stdin) when a D-Bus keyring daemon is available,
     with automatic fallback to a separate owner-only ``0600`` keyfile in ``$XDG_DATA_HOME/soclens/.settings.key``
     on headless servers/containers (transparently surfaced in CLI/TUI status).

2. ``passphrase`` (Master Passphrase mode):
   - Scrypt KDF (RFC 7914) derives a 256-bit KEK that wraps a per-file random 256-bit DEK
     with AES-256-GCM. No key material is stored on disk or in the OS keystore.
   - Supports interactive unlock (TUI modal / CLI ``getpass``) and non-interactive unlock
     via ``SOCLENS_SETTINGS_PASSPHRASE`` or ``SOCLENS_SETTINGS_PASSPHRASE_FILE``.
"""

from __future__ import annotations

import base64
import copy
import ctypes
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

logger = logging.getLogger("soclens.settings_crypto")

ENCRYPTED_SETTINGS_SCHEMA_VERSION = 2
ENCRYPTED_SETTINGS_FORMAT = "soclens-encrypted-settings-v1"
ENCRYPTED_SETTINGS_CIPHER = "AES-256-GCM"

ENCRYPTION_MODE_OS_KEYSTORE = "os_keystore"
ENCRYPTION_MODE_PASSPHRASE = "passphrase"
SUPPORTED_ENCRYPTION_MODES: tuple[str, ...] = (
    ENCRYPTION_MODE_OS_KEYSTORE,
    ENCRYPTION_MODE_PASSPHRASE,
)

KEY_PROTECTION_WINDOWS_DPAPI = "windows_dpapi"
KEY_PROTECTION_MACOS_KEYCHAIN = "macos_keychain"
KEY_PROTECTION_LINUX_SECRET_SERVICE = "linux_secret_service"
KEY_PROTECTION_LOCAL_KEYFILE = "local_keyfile"
KEY_PROTECTION_SCRYPT_PASSPHRASE = "scrypt_passphrase"

KEY_BACKEND_LABELS: dict[str, str] = {
    KEY_PROTECTION_WINDOWS_DPAPI: "Windows DPAPI (OS Keystore)",
    KEY_PROTECTION_MACOS_KEYCHAIN: "macOS Keychain (OS Keystore)",
    KEY_PROTECTION_LINUX_SECRET_SERVICE: "Linux Secret Service (OS Keystore)",
    KEY_PROTECTION_LOCAL_KEYFILE: "Local Keyfile (Headless Fallback — set Master Passphrase for stronger protection)",
    KEY_PROTECTION_SCRYPT_PASSPHRASE: "Master Passphrase (Scrypt + AES-256-GCM)",
    "plaintext": "Plaintext (Legacy v1 — will encrypt automatically on next save)",
    "none": "Not Created Yet (AES-256-GCM on first save)",
}

KEY_LENGTH_BYTES = 32
NONCE_LENGTH_BYTES = 12
SALT_LENGTH_BYTES = 16

DEFAULT_SCRYPT_N = 2**16
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
MIN_SCRYPT_N = 2**12
MAX_SCRYPT_N = 2**20
MIN_PASSPHRASE_LENGTH = 8

KEYCHAIN_SERVICE_NAME = "soclens.settings"
DEFAULT_KEYCHAIN_ACCOUNT = "master-kek-v1"
KEYFILE_FILENAME = ".settings.key"

_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_CRYPTPROTECT_UI_FORBIDDEN = 0x01

# Test override hook so pytest fixtures never touch a developer's real user keyfile.
_DEFAULT_KEYFILE_PATH_OVERRIDE: Path | None = None

_CRYPTO_LOCK = threading.RLock()


@dataclass
class _UnlockedKeyState:
    """In-memory unlocked DEK and envelope key-protection header for a single settings file."""

    mode: str
    dek: bytes
    key_protection: dict[str, Any]


_UNLOCKED_KEYS: dict[Path, _UnlockedKeyState] = {}
_MANUALLY_LOCKED_PATHS: set[Path] = set()


class SettingsCryptoError(RuntimeError):
    """Base error for settings encryption, decryption, and keystore failures."""


class SettingsLockedError(SettingsCryptoError):
    """Raised when passphrase-encrypted settings require unlocking before access."""


class SettingsDecryptionError(SettingsCryptoError):
    """Raised when decryption fails due to wrong passphrase, wrong key, or tampering."""


class SettingsKeystoreError(SettingsCryptoError):
    """Raised when an OS keystore or local keyfile backend fails."""


def _resolve_path_key(path: Path | str) -> Path:
    candidate = Path(path).expanduser()
    try:
        return candidate.resolve()
    except OSError:
        return candidate


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(encoded: Any, *, field_name: str, expected_len: int | None = None) -> bytes:
    if not isinstance(encoded, str) or not encoded.strip():
        raise SettingsDecryptionError(f"Encrypted settings field '{field_name}' is missing or invalid.")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise SettingsDecryptionError(
            f"Encrypted settings field '{field_name}' contains invalid base64."
        ) from exc
    if expected_len is not None and len(raw) != expected_len:
        raise SettingsDecryptionError(
            f"Encrypted settings field '{field_name}' has unexpected length {len(raw)}."
        )
    return raw


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _validate_safe_token(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _SAFE_TOKEN_RE.match(value):
        raise SettingsDecryptionError(f"Encrypted settings field '{field_name}' is invalid.")
    return value


def _key_fingerprint(key_bytes: bytes) -> str:
    return hashlib.sha256(key_bytes).hexdigest()[:16]


def get_env_passphrase() -> str | None:
    """Resolve an optional master passphrase from environment variables.

    Checks ``SOCLENS_SETTINGS_PASSPHRASE`` first, then reads ``SOCLENS_SETTINGS_PASSPHRASE_FILE``
    (stripping a single trailing newline). Empty values are treated as unset.
    """
    direct = os.environ.get("SOCLENS_SETTINGS_PASSPHRASE")
    if direct is not None and direct != "":
        return direct

    pw_file = (os.environ.get("SOCLENS_SETTINGS_PASSPHRASE_FILE") or "").strip()
    if pw_file:
        path = Path(pw_file).expanduser()
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SettingsDecryptionError(
                f"Failed to read SOCLENS_SETTINGS_PASSPHRASE_FILE '{path}': {exc}"
            ) from exc
        if content.endswith("\r\n"):
            content = content[:-2]
        elif content.endswith("\n"):
            content = content[:-1]
        if content:
            return content
    return None


def get_preferred_encryption_mode() -> str:
    """Return the preferred default encryption mode for brand-new settings files."""
    raw = (os.environ.get("SOCLENS_SETTINGS_ENCRYPTION_MODE") or "").strip().lower()
    if raw in SUPPORTED_ENCRYPTION_MODES:
        return raw
    return ENCRYPTION_MODE_OS_KEYSTORE


def get_local_keyfile_path(explicit: Path | str | None = None) -> Path:
    """Resolve the separate user-private keyfile path for headless Linux fallback."""
    if explicit is not None:
        raw = str(explicit).strip()
        if raw:
            p = Path(raw).expanduser()
            return p if p.is_absolute() else p.resolve()

    env_path = (os.environ.get("SOCLENS_SETTINGS_KEY_FILE") or "").strip()
    if env_path:
        p = Path(env_path).expanduser()
        return p if p.is_absolute() else p.resolve()

    if _DEFAULT_KEYFILE_PATH_OVERRIDE is not None:
        return _DEFAULT_KEYFILE_PATH_OVERRIDE

    if os.name == "nt" or sys.platform == "win32":
        local_appdata = (os.environ.get("LOCALAPPDATA") or "").strip()
        base_dir = (
            Path(local_appdata).expanduser()
            if local_appdata
            else Path.home() / "AppData" / "Local"
        )
        return base_dir / "soclens" / KEYFILE_FILENAME

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "soclens" / KEYFILE_FILENAME

    xdg_data = (os.environ.get("XDG_DATA_HOME") or "").strip()
    base_dir = Path(xdg_data).expanduser() if xdg_data else Path.home() / ".local" / "share"
    return base_dir / "soclens" / KEYFILE_FILENAME


def is_encrypted_envelope(raw: Any) -> bool:
    """Return True if ``raw`` is a SOCLens v2 encrypted settings envelope."""
    return (
        isinstance(raw, dict)
        and raw.get("encrypted") is True
        and raw.get("format") == ENCRYPTED_SETTINGS_FORMAT
    )


def _derive_scrypt_kek(
    passphrase: str,
    *,
    salt: bytes,
    n: int,
    r: int,
    p: int,
    dklen: int = KEY_LENGTH_BYTES,
) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise SettingsDecryptionError("Passphrase cannot be empty.")
    if n < MIN_SCRYPT_N or n > MAX_SCRYPT_N or (n & (n - 1)) != 0:
        raise SettingsDecryptionError(f"Unsupported scrypt cost parameter n={n}.")
    if r < 1 or r > 64 or p < 1 or p > 16 or dklen != KEY_LENGTH_BYTES:
        raise SettingsDecryptionError("Unsupported scrypt parameters in encrypted settings envelope.")
    kdf = Scrypt(salt=salt, length=dklen, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def _wrap_dek_with_kek(
    dek: bytes,
    kek: bytes,
    *,
    meta: dict[str, Any],
) -> tuple[bytes, bytes]:
    wrap_nonce = os.urandom(NONCE_LENGTH_BYTES)
    wrap_aad = _canonical_json_bytes({"purpose": "dek-wrap", "format": ENCRYPTED_SETTINGS_FORMAT, **meta})
    wrapped = AESGCM(kek).encrypt(wrap_nonce, dek, wrap_aad)
    return wrap_nonce, wrapped


def _unwrap_dek_with_kek(
    wrapped_dek: bytes,
    wrap_nonce: bytes,
    kek: bytes,
    *,
    meta: dict[str, Any],
    error_message: str,
) -> bytes:
    wrap_aad = _canonical_json_bytes({"purpose": "dek-wrap", "format": ENCRYPTED_SETTINGS_FORMAT, **meta})
    try:
        dek = AESGCM(kek).decrypt(wrap_nonce, wrapped_dek, wrap_aad)
    except InvalidTag as exc:
        raise SettingsDecryptionError(error_message) from exc
    if len(dek) != KEY_LENGTH_BYTES:
        raise SettingsDecryptionError("Unwrapped data encryption key has invalid length.")
    return dek


def _build_payload_aad(envelope_header: dict[str, Any]) -> bytes:
    return _canonical_json_bytes(
        {
            "format": envelope_header["format"],
            "schema_version": envelope_header["schema_version"],
            "mode": envelope_header["mode"],
            "cipher": envelope_header["cipher"],
            "key_protection": envelope_header["key_protection"],
        }
    )


# ---------------------------------------------------------------------------
# Platform OS Keystore & Local Keyfile Backends
# ---------------------------------------------------------------------------


def _dpapi_available() -> bool:
    return os.name == "nt" or sys.platform == "win32"


def _dpapi_protect(plaintext: bytes, *, entropy: bytes) -> bytes:
    """Protect ``plaintext`` using Windows DPAPI ``CryptProtectData``."""
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        raise SettingsKeystoreError("Windows DPAPI is not available on this platform.")

    class _DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_uint32),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    in_buf = ctypes.create_string_buffer(plaintext, len(plaintext))
    in_blob = _DataBlob(len(plaintext), in_buf)
    ent_buf = ctypes.create_string_buffer(entropy, len(entropy))
    ent_blob = _DataBlob(len(entropy), ent_buf)
    out_blob = _DataBlob()

    crypt32 = windll.crypt32
    kernel32 = windll.kernel32
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        "SOCLens Settings Key",
        ctypes.byref(ent_blob),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise SettingsKeystoreError("Windows DPAPI CryptProtectData failed.")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(ciphertext: bytes, *, entropy: bytes) -> bytes:
    """Unprotect a Windows DPAPI blob using ``CryptUnprotectData``."""
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        raise SettingsKeystoreError("Windows DPAPI is not available on this platform.")

    class _DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_uint32),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    in_buf = ctypes.create_string_buffer(ciphertext, len(ciphertext))
    in_blob = _DataBlob(len(ciphertext), in_buf)
    ent_buf = ctypes.create_string_buffer(entropy, len(entropy))
    ent_blob = _DataBlob(len(entropy), ent_buf)
    out_blob = _DataBlob()

    crypt32 = windll.crypt32
    kernel32 = windll.kernel32
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob),
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise SettingsDecryptionError(
            "Windows DPAPI failed to decrypt settings key (wrong Windows user account or corrupted file)."
        )
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        if out_blob.pbData:
            kernel32.LocalFree(out_blob.pbData)


def _find_macos_security_bin() -> str | None:
    if sys.platform != "darwin":
        return None
    if Path("/usr/bin/security").is_file():
        return "/usr/bin/security"
    return shutil.which("security")


def _macos_keychain_get_kek(service: str, account: str) -> bytes | None:
    sec_bin = _find_macos_security_bin()
    if not sec_bin:
        raise SettingsKeystoreError("macOS 'security' CLI is not available.")
    safe_service = _validate_safe_token(service, field_name="service")
    safe_account = _validate_safe_token(account, field_name="account")
    try:
        proc = subprocess.run(
            [sec_bin, "find-generic-password", "-s", safe_service, "-a", safe_account, "-w"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SettingsKeystoreError(f"Failed to query macOS Keychain: {exc}") from exc

    if proc.returncode == 44:
        return None
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        if "could not be found" in err.lower():
            return None
        raise SettingsKeystoreError(f"macOS Keychain lookup failed: {err or f'exit {proc.returncode}'}")

    raw_hex = proc.stdout.strip()
    if not raw_hex or not _HEX_RE.match(raw_hex):
        raise SettingsDecryptionError("macOS Keychain entry for SOCLens is corrupted.")
    key = bytes.fromhex(raw_hex)
    if len(key) != KEY_LENGTH_BYTES:
        raise SettingsDecryptionError("macOS Keychain entry for SOCLens has unexpected key length.")
    return key


def _macos_keychain_store_kek(service: str, account: str, kek: bytes) -> None:
    sec_bin = _find_macos_security_bin()
    if not sec_bin:
        raise SettingsKeystoreError("macOS 'security' CLI is not available.")
    safe_service = _validate_safe_token(service, field_name="service")
    safe_account = _validate_safe_token(account, field_name="account")
    secret_hex = kek.hex()
    # Feed add-generic-password via stdin interactive mode (-i) so the secret never appears in argv/ps.
    cmd_script = (
        f'add-generic-password -U -s "{safe_service}" -a "{safe_account}" '
        f'-l "SOCLens Settings Master Key" -w "{secret_hex}"\n'
    )
    try:
        proc = subprocess.run(
            [sec_bin, "-i"],
            input=cmd_script,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SettingsKeystoreError(f"Failed to write macOS Keychain entry: {exc}") from exc

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise SettingsKeystoreError(f"macOS Keychain store failed: {err or f'exit {proc.returncode}'}")


def _find_linux_secret_tool() -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    if not (os.environ.get("DBUS_SESSION_BUS_ADDRESS") or "").strip():
        return None
    return shutil.which("secret-tool")


def _linux_secret_service_get_kek(service: str, account: str) -> bytes | None:
    tool = _find_linux_secret_tool()
    if not tool:
        raise SettingsKeystoreError("Linux Secret Service ('secret-tool' + D-Bus) is unavailable.")
    safe_service = _validate_safe_token(service, field_name="service")
    safe_account = _validate_safe_token(account, field_name="account")
    try:
        proc = subprocess.run(
            [
                tool,
                "lookup",
                "application",
                "soclens",
                "service",
                safe_service,
                "account",
                safe_account,
            ],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SettingsKeystoreError(f"Linux Secret Service lookup failed: {exc}") from exc

    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        if not err and not (proc.stdout or "").strip():
            # secret-tool exits 1 with empty stdout/stderr when the item does not exist.
            return None
        raise SettingsKeystoreError(f"Linux Secret Service unavailable: {err or f'exit {proc.returncode}'}")

    raw_hex = proc.stdout.strip()
    if not raw_hex:
        return None
    if not _HEX_RE.match(raw_hex):
        raise SettingsDecryptionError("Linux Secret Service entry for SOCLens is corrupted.")
    key = bytes.fromhex(raw_hex)
    if len(key) != KEY_LENGTH_BYTES:
        raise SettingsDecryptionError("Linux Secret Service entry has unexpected key length.")
    return key


def _linux_secret_service_store_kek(service: str, account: str, kek: bytes) -> None:
    tool = _find_linux_secret_tool()
    if not tool:
        raise SettingsKeystoreError("Linux Secret Service ('secret-tool' + D-Bus) is unavailable.")
    safe_service = _validate_safe_token(service, field_name="service")
    safe_account = _validate_safe_token(account, field_name="account")
    try:
        proc = subprocess.run(
            [
                tool,
                "store",
                "--label=SOCLens Settings Master Key",
                "application",
                "soclens",
                "service",
                safe_service,
                "account",
                safe_account,
            ],
            input=kek.hex(),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SettingsKeystoreError(f"Linux Secret Service store failed: {exc}") from exc

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise SettingsKeystoreError(f"Linux Secret Service store failed: {err or f'exit {proc.returncode}'}")


def _load_keyfile_store(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"schema_version": 1, "active_key_id": None, "keys": {}}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SettingsKeystoreError(f"Failed to read local settings keyfile '{path}': {exc}") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("keys"), dict):
        raise SettingsKeystoreError(f"Local settings keyfile '{path}' is malformed.")
    return parsed


def _write_keyfile_store_atomic(path: Path, data: dict[str, Any]) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass

    serialized = json.dumps(data, indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".settings_key.", suffix=".tmp", dir=str(parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(serialized)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        if os.name != "nt":
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
        os.replace(tmp_path, path)
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    except BaseException:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise


def _local_keyfile_get_kek(key_id: str, *, keyfile_path: Path | None = None) -> bytes:
    path = get_local_keyfile_path(keyfile_path)
    if not path.is_file():
        raise SettingsDecryptionError(
            f"Local encryption keyfile not found at '{path}'. Cannot decrypt settings.json."
        )
    data = _load_keyfile_store(path)
    encoded = data.get("keys", {}).get(key_id)
    if not isinstance(encoded, str):
        raise SettingsDecryptionError(
            f"Encryption key ID '{key_id}' was not found in local keyfile '{path}'."
        )
    return _b64d(encoded, field_name="local_keyfile.key", expected_len=KEY_LENGTH_BYTES)


def _local_keyfile_get_or_create_kek(
    *,
    rotate: bool = False,
    keyfile_path: Path | None = None,
) -> tuple[str, bytes]:
    path = get_local_keyfile_path(keyfile_path)
    data = _load_keyfile_store(path)
    keys: dict[str, str] = dict(data.get("keys") or {})
    active_id = data.get("active_key_id")

    if not rotate and isinstance(active_id, str) and active_id in keys:
        kek = _b64d(keys[active_id], field_name="local_keyfile.key", expected_len=KEY_LENGTH_BYTES)
        return active_id, kek

    kek = os.urandom(KEY_LENGTH_BYTES)
    key_id = _key_fingerprint(kek)
    keys[key_id] = _b64e(kek)
    updated = {
        "schema_version": 1,
        "active_key_id": key_id,
        "keys": keys,
    }
    _write_keyfile_store_atomic(path, updated)
    return key_id, kek


def detect_default_os_keystore_backend() -> str:
    """Detect the active auto-unlock backend for the current OS and environment."""
    override = (os.environ.get("SOCLENS_SETTINGS_KEYSTORE") or "").strip().lower()
    if override in {
        KEY_PROTECTION_WINDOWS_DPAPI,
        KEY_PROTECTION_MACOS_KEYCHAIN,
        KEY_PROTECTION_LINUX_SECRET_SERVICE,
        KEY_PROTECTION_LOCAL_KEYFILE,
    }:
        return override

    if (os.environ.get("SOCLENS_SETTINGS_KEY_FILE") or "").strip() or _DEFAULT_KEYFILE_PATH_OVERRIDE is not None:
        return KEY_PROTECTION_LOCAL_KEYFILE

    if _dpapi_available():
        return KEY_PROTECTION_WINDOWS_DPAPI
    if _find_macos_security_bin():
        return KEY_PROTECTION_MACOS_KEYCHAIN
    if _find_linux_secret_tool():
        return KEY_PROTECTION_LINUX_SECRET_SERVICE
    return KEY_PROTECTION_LOCAL_KEYFILE


def _wrap_dek_os_keystore(
    dek: bytes,
    *,
    rotate_kek: bool = False,
) -> dict[str, Any]:
    """Wrap ``dek`` using the active OS keystore (with headless Linux keyfile fallback)."""
    backend = detect_default_os_keystore_backend()
    explicit_override = bool((os.environ.get("SOCLENS_SETTINGS_KEYSTORE") or "").strip())

    if backend == KEY_PROTECTION_WINDOWS_DPAPI:
        entropy_salt = os.urandom(SALT_LENGTH_BYTES)
        entropy = b"soclens-settings-dpapi-v1:" + entropy_salt
        wrapped = _dpapi_protect(dek, entropy=entropy)
        return {
            "type": KEY_PROTECTION_WINDOWS_DPAPI,
            "entropy_salt": _b64e(entropy_salt),
            "wrapped_dek": _b64e(wrapped),
        }

    if backend == KEY_PROTECTION_MACOS_KEYCHAIN:
        account = (
            f"master-kek-{os.urandom(4).hex()}" if rotate_kek else DEFAULT_KEYCHAIN_ACCOUNT
        )
        try:
            kek = None if rotate_kek else _macos_keychain_get_kek(KEYCHAIN_SERVICE_NAME, account)
            if kek is None:
                kek = os.urandom(KEY_LENGTH_BYTES)
                _macos_keychain_store_kek(KEYCHAIN_SERVICE_NAME, account, kek)
            meta = {
                "type": KEY_PROTECTION_MACOS_KEYCHAIN,
                "service": KEYCHAIN_SERVICE_NAME,
                "account": account,
            }
            wrap_nonce, wrapped = _wrap_dek_with_kek(dek, kek, meta=meta)
            return {
                **meta,
                "wrap_nonce": _b64e(wrap_nonce),
                "wrapped_dek": _b64e(wrapped),
            }
        except SettingsKeystoreError as exc:
            if explicit_override:
                raise
            logger.warning(
                "macOS Keychain unavailable (%s); falling back to local keyfile.",
                exc,
            )

    if backend == KEY_PROTECTION_LINUX_SECRET_SERVICE:
        account = (
            f"master-kek-{os.urandom(4).hex()}" if rotate_kek else DEFAULT_KEYCHAIN_ACCOUNT
        )
        try:
            kek = (
                None
                if rotate_kek
                else _linux_secret_service_get_kek(KEYCHAIN_SERVICE_NAME, account)
            )
            if kek is None:
                kek = os.urandom(KEY_LENGTH_BYTES)
                _linux_secret_service_store_kek(KEYCHAIN_SERVICE_NAME, account, kek)
            meta = {
                "type": KEY_PROTECTION_LINUX_SECRET_SERVICE,
                "service": KEYCHAIN_SERVICE_NAME,
                "account": account,
            }
            wrap_nonce, wrapped = _wrap_dek_with_kek(dek, kek, meta=meta)
            return {
                **meta,
                "wrap_nonce": _b64e(wrap_nonce),
                "wrapped_dek": _b64e(wrapped),
            }
        except SettingsKeystoreError as exc:
            if explicit_override:
                raise
            logger.warning(
                "Linux Secret Service unavailable (%s); falling back to local keyfile.",
                exc,
            )

    key_id, kek = _local_keyfile_get_or_create_kek(rotate=rotate_kek)
    meta = {
        "type": KEY_PROTECTION_LOCAL_KEYFILE,
        "key_id": key_id,
    }
    wrap_nonce, wrapped = _wrap_dek_with_kek(dek, kek, meta=meta)
    return {
        **meta,
        "wrap_nonce": _b64e(wrap_nonce),
        "wrapped_dek": _b64e(wrapped),
    }


def _wrap_dek_passphrase(dek: bytes, passphrase: str) -> dict[str, Any]:
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(
            f"Master passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters long."
        )
    salt = os.urandom(SALT_LENGTH_BYTES)
    kek = _derive_scrypt_kek(
        passphrase,
        salt=salt,
        n=DEFAULT_SCRYPT_N,
        r=DEFAULT_SCRYPT_R,
        p=DEFAULT_SCRYPT_P,
    )
    meta: dict[str, Any] = {
        "type": KEY_PROTECTION_SCRYPT_PASSPHRASE,
        "kdf": "scrypt",
        "salt": _b64e(salt),
        "n": DEFAULT_SCRYPT_N,
        "r": DEFAULT_SCRYPT_R,
        "p": DEFAULT_SCRYPT_P,
        "dklen": KEY_LENGTH_BYTES,
    }
    wrap_nonce, wrapped = _wrap_dek_with_kek(dek, kek, meta=meta)
    return {
        **meta,
        "wrap_nonce": _b64e(wrap_nonce),
        "wrapped_dek": _b64e(wrapped),
    }


def _unwrap_dek(
    key_protection: dict[str, Any],
    *,
    passphrase: str | None = None,
) -> bytes:
    kp_type = key_protection.get("type")
    if kp_type == KEY_PROTECTION_WINDOWS_DPAPI:
        entropy_salt = _b64d(
            key_protection.get("entropy_salt"),
            field_name="key_protection.entropy_salt",
            expected_len=SALT_LENGTH_BYTES,
        )
        wrapped = _b64d(key_protection.get("wrapped_dek"), field_name="key_protection.wrapped_dek")
        dek = _dpapi_unprotect(wrapped, entropy=b"soclens-settings-dpapi-v1:" + entropy_salt)
        if len(dek) != KEY_LENGTH_BYTES:
            raise SettingsDecryptionError("Unwrapped DPAPI settings key has unexpected length.")
        return dek

    if kp_type == KEY_PROTECTION_MACOS_KEYCHAIN:
        service = _validate_safe_token(key_protection.get("service"), field_name="key_protection.service")
        account = _validate_safe_token(key_protection.get("account"), field_name="key_protection.account")
        wrap_nonce = _b64d(
            key_protection.get("wrap_nonce"),
            field_name="key_protection.wrap_nonce",
            expected_len=NONCE_LENGTH_BYTES,
        )
        wrapped = _b64d(key_protection.get("wrapped_dek"), field_name="key_protection.wrapped_dek")
        kek = _macos_keychain_get_kek(service, account)
        if kek is None:
            raise SettingsDecryptionError(
                f"macOS Keychain key '{service}/{account}' not found; cannot decrypt settings.json."
            )
        meta = {"type": kp_type, "service": service, "account": account}
        return _unwrap_dek_with_kek(
            wrapped,
            wrap_nonce,
            kek,
            meta=meta,
            error_message="Failed to unwrap settings key with macOS Keychain master key.",
        )

    if kp_type == KEY_PROTECTION_LINUX_SECRET_SERVICE:
        service = _validate_safe_token(key_protection.get("service"), field_name="key_protection.service")
        account = _validate_safe_token(key_protection.get("account"), field_name="key_protection.account")
        wrap_nonce = _b64d(
            key_protection.get("wrap_nonce"),
            field_name="key_protection.wrap_nonce",
            expected_len=NONCE_LENGTH_BYTES,
        )
        wrapped = _b64d(key_protection.get("wrapped_dek"), field_name="key_protection.wrapped_dek")
        kek = _linux_secret_service_get_kek(service, account)
        if kek is None:
            raise SettingsDecryptionError(
                f"Linux Secret Service key '{service}/{account}' not found; cannot decrypt settings.json."
            )
        meta = {"type": kp_type, "service": service, "account": account}
        return _unwrap_dek_with_kek(
            wrapped,
            wrap_nonce,
            kek,
            meta=meta,
            error_message="Failed to unwrap settings key with Linux Secret Service master key.",
        )

    if kp_type == KEY_PROTECTION_LOCAL_KEYFILE:
        key_id = _validate_safe_token(key_protection.get("key_id"), field_name="key_protection.key_id")
        wrap_nonce = _b64d(
            key_protection.get("wrap_nonce"),
            field_name="key_protection.wrap_nonce",
            expected_len=NONCE_LENGTH_BYTES,
        )
        wrapped = _b64d(key_protection.get("wrapped_dek"), field_name="key_protection.wrapped_dek")
        kek = _local_keyfile_get_kek(key_id)
        meta = {"type": kp_type, "key_id": key_id}
        return _unwrap_dek_with_kek(
            wrapped,
            wrap_nonce,
            kek,
            meta=meta,
            error_message="Failed to unwrap settings key with local keyfile.",
        )

    if kp_type == KEY_PROTECTION_SCRYPT_PASSPHRASE:
        if not passphrase:
            raise SettingsLockedError(
                "Settings file is protected by a master passphrase and is currently locked."
            )
        if key_protection.get("kdf") != "scrypt":
            raise SettingsDecryptionError(
                f"Unsupported settings KDF: {key_protection.get('kdf')!r}."
            )
        salt = _b64d(
            key_protection.get("salt"),
            field_name="key_protection.salt",
            expected_len=SALT_LENGTH_BYTES,
        )
        try:
            n = int(key_protection["n"])
            r = int(key_protection["r"])
            p = int(key_protection["p"])
            dklen = int(key_protection.get("dklen", KEY_LENGTH_BYTES))
        except (KeyError, TypeError, ValueError) as exc:
            raise SettingsDecryptionError("Invalid scrypt parameters in encrypted settings file.") from exc
        wrap_nonce = _b64d(
            key_protection.get("wrap_nonce"),
            field_name="key_protection.wrap_nonce",
            expected_len=NONCE_LENGTH_BYTES,
        )
        wrapped = _b64d(key_protection.get("wrapped_dek"), field_name="key_protection.wrapped_dek")
        kek = _derive_scrypt_kek(passphrase, salt=salt, n=n, r=r, p=p, dklen=dklen)
        meta = {
            "type": kp_type,
            "kdf": "scrypt",
            "salt": key_protection["salt"],
            "n": n,
            "r": r,
            "p": p,
            "dklen": dklen,
        }
        return _unwrap_dek_with_kek(
            wrapped,
            wrap_nonce,
            kek,
            meta=meta,
            error_message="Incorrect master passphrase or corrupted settings file.",
        )

    raise SettingsDecryptionError(f"Unsupported key protection backend: {kp_type!r}.")


# ---------------------------------------------------------------------------
# Public Envelope Encrypt / Decrypt & Session Key Cache API
# ---------------------------------------------------------------------------


def clear_unlocked_keys(settings_path: Path | str | None = None, *, mark_locked: bool = False) -> None:
    """Clear in-memory unlocked encryption keys (all paths or a single path)."""
    with _CRYPTO_LOCK:
        if settings_path is None:
            if mark_locked:
                _MANUALLY_LOCKED_PATHS.update(_UNLOCKED_KEYS.keys())
            else:
                _MANUALLY_LOCKED_PATHS.clear()
            _UNLOCKED_KEYS.clear()
        else:
            key = _resolve_path_key(settings_path)
            _UNLOCKED_KEYS.pop(key, None)
            if mark_locked:
                _MANUALLY_LOCKED_PATHS.add(key)
            else:
                _MANUALLY_LOCKED_PATHS.discard(key)


def get_unlocked_key_state(settings_path: Path | str) -> tuple[str, bytes, dict[str, Any]] | None:
    """Return ``(mode, dek, key_protection)`` if ``settings_path`` is currently unlocked in memory."""
    key = _resolve_path_key(settings_path)
    with _CRYPTO_LOCK:
        state = _UNLOCKED_KEYS.get(key)
        if state is None:
            return None
        return state.mode, state.dek, copy.deepcopy(state.key_protection)


def _remember_unlocked_key(
    settings_path: Path | str,
    *,
    mode: str,
    dek: bytes,
    key_protection: dict[str, Any],
) -> None:
    key = _resolve_path_key(settings_path)
    with _CRYPTO_LOCK:
        _MANUALLY_LOCKED_PATHS.discard(key)
        _UNLOCKED_KEYS[key] = _UnlockedKeyState(
            mode=mode,
            dek=dek,
            key_protection=copy.deepcopy(key_protection),
        )


def encrypt_settings_payload(
    payload: dict[str, Any],
    *,
    settings_path: Path | str,
    mode: str | None = None,
    passphrase: str | None = None,
    reuse_existing_dek: bool = True,
    rotate_kek: bool = False,
) -> dict[str, Any]:
    """Encrypt a normalized settings store dict into an authenticated v2 JSON envelope.

    A fresh 96-bit random AES-GCM nonce is generated on every single write. When
    ``reuse_existing_dek=True`` and an unlocked key state for the target mode already
    exists in memory, the existing DEK + ``key_protection`` header is reused so saving
    in passphrase mode is instant and does not require re-prompting.
    """
    target_key = _resolve_path_key(settings_path)
    cached_state = get_unlocked_key_state(target_key) if reuse_existing_dek else None

    if mode is None:
        if cached_state is not None:
            resolved_mode = cached_state[0]
        else:
            resolved_mode = get_preferred_encryption_mode()
    else:
        resolved_mode = mode.strip().lower()
    if resolved_mode not in SUPPORTED_ENCRYPTION_MODES:
        raise ValueError(
            f"Unsupported encryption mode {resolved_mode!r}; expected one of {SUPPORTED_ENCRYPTION_MODES}."
        )

    dek: bytes
    key_protection: dict[str, Any]

    if (
        cached_state is not None
        and cached_state[0] == resolved_mode
        and not rotate_kek
        and passphrase is None
    ):
        dek = cached_state[1]
        key_protection = cached_state[2]
    else:
        dek = os.urandom(KEY_LENGTH_BYTES)
        if resolved_mode == ENCRYPTION_MODE_PASSPHRASE:
            eff_pass = passphrase if passphrase is not None else get_env_passphrase()
            if not eff_pass:
                raise SettingsLockedError(
                    "A master passphrase is required to encrypt settings in passphrase mode."
                )
            key_protection = _wrap_dek_passphrase(dek, eff_pass)
        else:
            key_protection = _wrap_dek_os_keystore(dek, rotate_kek=rotate_kek)

    envelope_header: dict[str, Any] = {
        "schema_version": ENCRYPTED_SETTINGS_SCHEMA_VERSION,
        "encrypted": True,
        "format": ENCRYPTED_SETTINGS_FORMAT,
        "mode": resolved_mode,
        "cipher": ENCRYPTED_SETTINGS_CIPHER,
        "key_protection": key_protection,
    }
    aad = _build_payload_aad(envelope_header)
    nonce = os.urandom(NONCE_LENGTH_BYTES)
    plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)

    envelope: dict[str, Any] = {
        **envelope_header,
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }
    _remember_unlocked_key(
        target_key,
        mode=resolved_mode,
        dek=dek,
        key_protection=key_protection,
    )
    return envelope


def decrypt_settings_envelope(
    envelope: dict[str, Any],
    *,
    settings_path: Path | str,
    passphrase: str | None = None,
    allow_env_passphrase: bool = True,
) -> dict[str, Any]:
    """Authenticate and decrypt a v2 encrypted settings envelope into a Python dict."""
    if not is_encrypted_envelope(envelope):
        raise SettingsDecryptionError("Input is not a valid SOCLens encrypted settings envelope.")

    if envelope.get("cipher") != ENCRYPTED_SETTINGS_CIPHER:
        raise SettingsDecryptionError(f"Unsupported cipher: {envelope.get('cipher')!r}.")
    if envelope.get("schema_version") != ENCRYPTED_SETTINGS_SCHEMA_VERSION:
        raise SettingsDecryptionError(
            f"Unsupported encrypted settings schema_version: {envelope.get('schema_version')!r}."
        )
    mode = envelope.get("mode")
    if mode not in SUPPORTED_ENCRYPTION_MODES:
        raise SettingsDecryptionError(f"Unsupported encryption mode: {mode!r}.")

    key_protection = envelope.get("key_protection")
    if not isinstance(key_protection, dict):
        raise SettingsDecryptionError("Encrypted settings envelope is missing key_protection metadata.")

    nonce = _b64d(envelope.get("nonce"), field_name="nonce", expected_len=NONCE_LENGTH_BYTES)
    ciphertext = _b64d(envelope.get("ciphertext"), field_name="ciphertext")
    aad = _build_payload_aad(envelope)

    target_key = _resolve_path_key(settings_path)
    dek: bytes | None = None

    with _CRYPTO_LOCK:
        cached = _UNLOCKED_KEYS.get(target_key)
        manually_locked = target_key in _MANUALLY_LOCKED_PATHS
        if (
            cached is not None
            and cached.mode == mode
            and cached.key_protection == key_protection
            and passphrase is None
        ):
            dek = cached.dek

    if dek is None:
        eff_pass = passphrase
        if (
            eff_pass is None
            and mode == ENCRYPTION_MODE_PASSPHRASE
            and allow_env_passphrase
            and not manually_locked
        ):
            eff_pass = get_env_passphrase()
        dek = _unwrap_dek(key_protection, passphrase=eff_pass)

    try:
        plaintext_bytes = AESGCM(dek).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise SettingsDecryptionError(
            "Settings file authentication failed (file was tampered with or key mismatch)."
        ) from exc

    try:
        decoded = json.loads(plaintext_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SettingsDecryptionError(f"Decrypted settings payload is not valid JSON: {exc}") from exc

    if not isinstance(decoded, dict):
        raise SettingsDecryptionError("Decrypted settings payload root must be a JSON object.")

    _remember_unlocked_key(
        target_key,
        mode=mode,
        dek=dek,
        key_protection=key_protection,
    )
    return decoded


def inspect_settings_file_encryption(settings_path: Path | str) -> dict[str, Any]:
    """Inspect a settings file's encryption state without decrypting or mutating it."""
    target = Path(settings_path).expanduser()
    resolved = _resolve_path_key(target)
    exists = target.is_file()

    if not exists:
        default_backend = detect_default_os_keystore_backend()
        default_mode = get_preferred_encryption_mode()
        pending_backend = (
            KEY_PROTECTION_SCRYPT_PASSPHRASE
            if default_mode == ENCRYPTION_MODE_PASSPHRASE
            else default_backend
        )
        return {
            "exists": False,
            "encrypted": False,
            "schema_version": ENCRYPTED_SETTINGS_SCHEMA_VERSION,
            "cipher": ENCRYPTED_SETTINGS_CIPHER,
            "encryption_mode": default_mode,
            "key_backend": pending_backend,
            "key_backend_label": KEY_BACKEND_LABELS.get(pending_backend, pending_backend),
            "locked": False,
            "legacy_plaintext": False,
            "corrupt": False,
            "encryption_summary": (
                f"Not created yet (will encrypt with {ENCRYPTED_SETTINGS_CIPHER} / "
                f"{KEY_BACKEND_LABELS.get(pending_backend, pending_backend)} on first save)"
            ),
        }

    try:
        raw_text = target.read_text(encoding="utf-8")
        parsed = json.loads(raw_text) if raw_text.strip() else {}
    except Exception as exc:
        return {
            "exists": True,
            "encrypted": False,
            "schema_version": None,
            "cipher": None,
            "encryption_mode": "corrupt",
            "key_backend": "none",
            "key_backend_label": "Unreadable / Corrupt JSON",
            "locked": False,
            "legacy_plaintext": False,
            "corrupt": True,
            "error": str(exc),
            "encryption_summary": f"Corrupt settings file ({exc})",
        }

    if is_encrypted_envelope(parsed):
        mode = str(parsed.get("mode") or ENCRYPTION_MODE_OS_KEYSTORE)
        kp = parsed.get("key_protection")
        kp_type = str(kp.get("type") if isinstance(kp, dict) else "unknown")
        label = KEY_BACKEND_LABELS.get(kp_type, kp_type)
        with _CRYPTO_LOCK:
            cached = _UNLOCKED_KEYS.get(resolved)
            is_unlocked_in_mem = (
                cached is not None
                and cached.mode == mode
                and isinstance(kp, dict)
                and cached.key_protection == kp
            )
            manually_locked = resolved in _MANUALLY_LOCKED_PATHS

        if mode == ENCRYPTION_MODE_PASSPHRASE:
            has_env_pw = False
            if not is_unlocked_in_mem and not manually_locked:
                try:
                    has_env_pw = get_env_passphrase() is not None
                except SettingsCryptoError:
                    has_env_pw = False
            locked = not is_unlocked_in_mem and not has_env_pw
            lock_state = "Locked" if locked else "Unlocked"
            summary = f"Encrypted ({ENCRYPTED_SETTINGS_CIPHER} | {label} — {lock_state})"
        else:
            locked = False
            summary = f"Encrypted ({ENCRYPTED_SETTINGS_CIPHER} | {label})"

        return {
            "exists": True,
            "encrypted": True,
            "schema_version": int(parsed.get("schema_version") or ENCRYPTED_SETTINGS_SCHEMA_VERSION),
            "cipher": str(parsed.get("cipher") or ENCRYPTED_SETTINGS_CIPHER),
            "encryption_mode": mode,
            "key_backend": kp_type,
            "key_backend_label": label,
            "locked": locked,
            "legacy_plaintext": False,
            "corrupt": False,
            "encryption_summary": summary,
        }

    return {
        "exists": True,
        "encrypted": False,
        "schema_version": int(parsed.get("schema_version") or 1) if isinstance(parsed, dict) else 1,
        "cipher": None,
        "encryption_mode": "plaintext",
        "key_backend": "plaintext",
        "key_backend_label": KEY_BACKEND_LABELS["plaintext"],
        "locked": False,
        "legacy_plaintext": True,
        "corrupt": False,
        "encryption_summary": KEY_BACKEND_LABELS["plaintext"],
    }


__all__ = [
    "DEFAULT_KEYCHAIN_ACCOUNT",
    "DEFAULT_SCRYPT_N",
    "DEFAULT_SCRYPT_P",
    "DEFAULT_SCRYPT_R",
    "ENCRYPTED_SETTINGS_CIPHER",
    "ENCRYPTED_SETTINGS_FORMAT",
    "ENCRYPTED_SETTINGS_SCHEMA_VERSION",
    "ENCRYPTION_MODE_OS_KEYSTORE",
    "ENCRYPTION_MODE_PASSPHRASE",
    "KEY_BACKEND_LABELS",
    "KEY_LENGTH_BYTES",
    "KEY_PROTECTION_LINUX_SECRET_SERVICE",
    "KEY_PROTECTION_LOCAL_KEYFILE",
    "KEY_PROTECTION_MACOS_KEYCHAIN",
    "KEY_PROTECTION_SCRYPT_PASSPHRASE",
    "KEY_PROTECTION_WINDOWS_DPAPI",
    "KEYCHAIN_SERVICE_NAME",
    "KEYFILE_FILENAME",
    "MIN_PASSPHRASE_LENGTH",
    "NONCE_LENGTH_BYTES",
    "SALT_LENGTH_BYTES",
    "SUPPORTED_ENCRYPTION_MODES",
    "SettingsCryptoError",
    "SettingsDecryptionError",
    "SettingsKeystoreError",
    "SettingsLockedError",
    "clear_unlocked_keys",
    "decrypt_settings_envelope",
    "detect_default_os_keystore_backend",
    "encrypt_settings_payload",
    "get_env_passphrase",
    "get_local_keyfile_path",
    "get_preferred_encryption_mode",
    "get_unlocked_key_state",
    "inspect_settings_file_encryption",
    "is_encrypted_envelope",
]
