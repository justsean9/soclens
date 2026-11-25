# Automated Brand Logo Watchlist Sync Setup

This directory provides cross-platform automation templates for unattended, idempotent brand logo synchronization using `soclens`.

## Prerequisites

1. Configure your Recorded Future API token and workspace environment variables (never commit secrets to git):
   - `RF_API_TOKEN` — Recorded Future API token with Watch List read/write permissions
   - `SOCLENS_AUTO_APPROVE=true` — Required for non-dry-run list additions/removals
   - `SOCLENS_HOME` — Workspace directory holding `domains.txt`, `ignored_hashes.txt`, `brand_sync_state.json`, and `logs/`
2. Test safely on 1–2 domains first (`--dry-run` before live sync):
   ```bash
   soclens watchlist sync-logos <LIST_ID> --domains example.com --dry-run
   ```

## Windows (PowerShell + Task Scheduler)

On Windows, SOCLens runs via PowerShell (`.\soclens.ps1` and `.\scripts\soclens-brand-sync.ps1`) invoking `.venv\Scripts\python.exe -m soclens.cli`.

1. Deploy SOCLens under `C:\opt\soclens\` (including `.venv` via `.\install_offline.ps1`, `domains.txt`, `ignored_hashes.txt`).
2. Set `RF_API_TOKEN` in the service account or system environment variables.
3. Update `YOUR_BRAND_LIST_ID` and paths in `scripts/soclens-brand-sync-task.xml`.
4. Register the hourly scheduled task (`IgnoreNew` prevents overlapping runs alongside `SyncLock`):
   ```powershell
   schtasks /Create /TN "SOCLens\BrandLogoSync" /XML "C:\opt\soclens\scripts\soclens-brand-sync-task.xml"
   ```
5. Run on demand or test in dry-run mode:
   ```powershell
   .\scripts\soclens-brand-sync.ps1 -ListId "<LIST_ID>" -DomainsFile ".\domains.txt" -DryRun
   ```

## Linux (`systemd` Service + Timer)

1. Create `/etc/soclens/soclens.env` (`chmod 600`):
   ```ini
   RF_API_TOKEN=your_token_here
   SOCLENS_AUTO_APPROVE=true
   SOCLENS_HOME=/opt/soclens
   RF_BRAND_LIST_ID=report:your_list_id
   ```
2. Copy the unit files and enable the timer:
   ```bash
   sudo cp scripts/soclens-brand-sync.service /etc/systemd/system/
   sudo cp scripts/soclens-brand-sync.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now soclens-brand-sync.timer
   ```
3. Monitor runs and logs:
   ```bash
   systemctl list-timers soclens-brand-sync.timer
   journalctl -u soclens-brand-sync.service -n 100
   ```
