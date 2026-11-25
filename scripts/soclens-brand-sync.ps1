<#
.SYNOPSIS
    Automated Windows runner for Recorded Future Brand Logo Watchlist Sync.
.DESCRIPTION
    Executes `soclens.cli watchlist sync-logos` (one-shot or continuous --watch mode)
    with UTF-8 console encoding, workspace isolation, and structured logging.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ListId,

    [string]$DomainsFile,

    [string]$SourceListId,

    [string]$Domains,

    [string]$IgnoreHashesFile,

    [string]$WorkspaceDir = $PWD.Path,

    [string]$PythonExe,

    [switch]$Watch,

    [int]$IntervalSeconds = 3600,

    [int]$MaxRuns = 0,

    [switch]$Apply,

    [switch]$DryRun,

    [switch]$Insecure,

    [string]$CaBundle
)

$ErrorActionPreference = "Stop"

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
} catch {
}
try {
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
} catch {
}
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

$OnWindows = (-not (Test-Path Variable:IsWindows)) -or $IsWindows

$ResolvedWorkspace = (Resolve-Path -Path $WorkspaceDir).Path
$env:SOCLENS_HOME = $ResolvedWorkspace

$LogDir = Join-Path $ResolvedWorkspace "logs"
if (-not (Test-Path -Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir "brand_sync.log"

if (-not $PythonExe) {
    $RequestedPy = if ($env:SOCLENS_PYTHON) { $env:SOCLENS_PYTHON.Trim() } else { "" }
    if ($RequestedPy) {
        if (Test-Path -Path $RequestedPy -PathType Leaf) {
            $PythonExe = $RequestedPy
        } else {
            $CmdReq = Get-Command $RequestedPy -ErrorAction SilentlyContinue
            if ($CmdReq -and $CmdReq.Source) {
                $PythonExe = $CmdReq.Source
            }
        }
    }
}

if (-not $PythonExe) {
    $WinVenvPython = Join-Path (Join-Path (Join-Path $ResolvedWorkspace ".venv") "Scripts") "python.exe"
    $PosixVenvPython = Join-Path (Join-Path (Join-Path $ResolvedWorkspace ".venv") "bin") "python"
    if (Test-Path -Path $WinVenvPython -PathType Leaf) {
        $PythonExe = $WinVenvPython
    } elseif (Test-Path -Path $PosixVenvPython -PathType Leaf) {
        $PythonExe = $PosixVenvPython
    }
}

if (-not $PythonExe) {
    $ProbeCandidates = @()
    if ($OnWindows -and (Get-Command py -ErrorAction SilentlyContinue)) {
        $ProbeCandidates += ,@("py", @("-3.12"))
        $ProbeCandidates += ,@("py", @("-3.13"))
        $ProbeCandidates += ,@("py", @("-3.14"))
        $ProbeCandidates += ,@("py", @("-3"))
    }
    foreach ($CmdName in @("python3.12", "python3.13", "python3.14", "python3", "python")) {
        $CmdInfo = Get-Command $CmdName -ErrorAction SilentlyContinue
        if ($CmdInfo -and $CmdInfo.Source) {
            $ProbeCandidates += ,@($CmdInfo.Source, @())
        }
    }

    $PrevProbeErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        foreach ($Candidate in $ProbeCandidates) {
            $Exe = $Candidate[0]
            $ExtraArgs = $Candidate[1]
            try {
                $CheckArgs = @()
                if ($ExtraArgs.Count -gt 0) {
                    $CheckArgs += $ExtraArgs
                }
                $CheckArgs += @("-c", "import sys; print(sys.executable); sys.exit(0 if sys.version_info >= (3, 12) else 1)")
                $OutLines = @(& $Exe @CheckArgs 2>$null)
                if ($LASTEXITCODE -eq 0 -and $OutLines.Count -gt 0) {
                    $Resolved = ($OutLines[-1]).Trim()
                    if ($Resolved) {
                        $PythonExe = $Resolved
                        break
                    }
                }
            } catch {
                continue
            }
        }
    } finally {
        $ErrorActionPreference = $PrevProbeErr
    }
}

if (-not $PythonExe) {
    if (Get-Command python3 -ErrorAction SilentlyContinue) {
        $PythonExe = "python3"
    } else {
        $PythonExe = "python"
    }
}

if ($Apply -and -not $DryRun) {
    $env:SOCLENS_AUTO_APPROVE = "true"
} else {
    Remove-Item Env:SOCLENS_AUTO_APPROVE -ErrorAction SilentlyContinue
}

if ($Insecure -and $CaBundle) {
    [Console]::Error.WriteLine("[-] Error: Cannot specify both -Insecure and -CaBundle.")
    exit 1
}
if ($Insecure) {
    $env:RF_VERIFY_SSL = "false"
} elseif ($CaBundle) {
    $env:RF_CA_BUNDLE = $CaBundle
}

$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Add-Content -Path $LogFile -Value "[$Timestamp] Starting brand logo sync for list '$ListId' (Workspace: $ResolvedWorkspace)"

if ($Watch) {
    $PyCode = @"
import json, os, sys
from soclens.client import RecordedFutureClient
from soclens.logos.brand_sync import run_continuous_brand_sync

client = RecordedFutureClient()
domains_arg = os.environ.get('RF_SYNC_DOMAINS', '').strip()
domains = [d.strip() for d in domains_arg.split(',') if d.strip()] if domains_arg else None
domains_file = os.environ.get('RF_SYNC_DOMAINS_FILE', '').strip() or None
source_list = os.environ.get('RF_SYNC_SOURCE_LIST_ID', '').strip() or None
ignore_file = os.environ.get('RF_SYNC_IGNORE_FILE', '').strip() or None
dry_run = os.environ.get('SOCLENS_AUTO_APPROVE', '').lower() not in ('1', 'true', 'yes')
interval = float(os.environ.get('RF_SYNC_INTERVAL', '3600'))
max_runs_raw = int(os.environ.get('RF_SYNC_MAX_RUNS', '0'))
max_runs = max_runs_raw if max_runs_raw > 0 else None

summary = run_continuous_brand_sync(
    client,
    os.environ['RF_SYNC_LIST_ID'],
    domains=domains,
    source_list_id=source_list,
    domains_file=domains_file,
    dry_run=dry_run,
    ignore_hashes_file=ignore_file,
    interval_seconds=interval,
    max_runs=max_runs,
    workspace_dir=os.environ.get('SOCLENS_HOME'),
)
print(json.dumps(summary, indent=2))
sys.exit(0 if summary.get('runs_failed', 0) == 0 else 1)
"@
    $env:RF_SYNC_LIST_ID = $ListId
    $env:RF_SYNC_DOMAINS = $Domains
    $env:RF_SYNC_DOMAINS_FILE = $DomainsFile
    $env:RF_SYNC_SOURCE_LIST_ID = $SourceListId
    $env:RF_SYNC_IGNORE_FILE = $IgnoreHashesFile
    $env:RF_SYNC_INTERVAL = "$IntervalSeconds"
    $env:RF_SYNC_MAX_RUNS = "$MaxRuns"

    $PrevErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $PythonExe -c $PyCode 2>&1 | Tee-Object -FilePath $LogFile -Append
        $ExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PrevErrorAction
    }
    exit $ExitCode
}

$CliArgs = @("-m", "soclens.cli", "watchlist", "sync-logos", $ListId)
if ($Domains) {
    $CliArgs += @("--domains", $Domains)
}
if ($DomainsFile) {
    $CliArgs += @("--domains-file", $DomainsFile)
}
if ($SourceListId) {
    $CliArgs += @("--source-list-id", $SourceListId)
}
if ($IgnoreHashesFile) {
    $CliArgs += @("--ignore-hashes-file", $IgnoreHashesFile)
}
if ($DryRun -or -not $Apply) {
    $CliArgs += "--dry-run"
}
if ($Insecure) {
    $CliArgs += "--insecure"
} elseif ($CaBundle) {
    $CliArgs += @("--ca-bundle", $CaBundle)
}

$PrevErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & $PythonExe @CliArgs 2>&1 | Tee-Object -FilePath $LogFile -Append
    $ExitCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $PrevErrorAction
}
exit $ExitCode
