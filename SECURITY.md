# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, credential leak, or unsafe behavior in this project, **please do not open a public GitHub issue**.

Instead, report it privately via GitHub Security Advisories:
- Go to **Security → Advisories → Report a vulnerability** on `justsean9/soclens`.

Please include:
- A description of the issue and potential impact
- Steps to reproduce or a minimal proof of concept
- Any suggested remediation, if known

## Security Best Practices for Users

- Per-user `settings.json` files are encrypted at rest with **AES-256-GCM** using your OS keystore (Windows DPAPI, macOS Keychain, or Linux Secret Service) by default. On headless Linux servers (which fall back to a separate `0600` local keyfile) or shared hosts, run `soclens settings encrypt --passphrase` (or use **Settings -> Profiles & Storage -> Set / Change Passphrase**) to require a Scrypt-derived Master Passphrase with zero key material stored on disk.
- Prefer an external Secret Manager / PAM integration (Delinea Secret Server, HashiCorp Vault, 1Password Connect, or Bitwarden) or environment variables (`RF_API_TOKEN`, `SPLUNK_TOKEN`, `S1_API_TOKEN`, etc.) so pulled API tokens stay strictly in process memory — never commit `apikey.key`, `settings.json`, `.settings.key`, or `.env` files.
- Keep `SOCLENS_INSECURE_SSL` disabled unless you are intentionally operating behind an internal SSL-inspecting proxy and understand the trade-offs (prefer `SOCLENS_CA_BUNDLE` with your organization's root CA when possible).
