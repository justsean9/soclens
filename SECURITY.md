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

- Store API tokens (`RF_API_TOKEN`, `SPLUNK_TOKEN`, `S1_API_TOKEN`, etc.) in environment variables or your OS secret store — never commit `apikey.key` or `.env` files.
- Keep `SOCLENS_INSECURE_SSL` disabled unless you are intentionally operating behind an internal SSL-inspecting proxy and understand the trade-offs (prefer `SOCLENS_CA_BUNDLE` with your organization's root CA when possible).
