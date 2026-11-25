<#
.SYNOPSIS
    PowerShell launcher for SOCLens.
.DESCRIPTION
    Resolves an installed Python 3.12+ interpreter (preferring the local .venv)
    and invokes `python -m soclens.cli`. Compatible with Windows PowerShell 5.1,
    PowerShell 7+ on Windows, and pwsh on Linux/macOS.
#>

# Intentionally omit [CmdletBinding()] and param(...) so CLI flags (-V, -h, -d,
# -t, --help, -70m, etc.) pass straight through $args to Python unmodified.

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

$RepoRoot = (Resolve-Path -Path $PSScriptRoot).Path
$OnWindows = (-not (Test-Path Variable:IsWindows)) -or $IsWindows

function Get-VenvPythonCandidate {
    param([string]$VenvPath)

    if (-not $VenvPath) {
        return ""
    }
    $WinPy = Join-Path (Join-Path $VenvPath "Scripts") "python.exe"
    $PosixPy = Join-Path (Join-Path $VenvPath "bin") "python"
    if ($OnWindows) {
        $Order = @($WinPy, $PosixPy)
    } else {
        $Order = @($PosixPy, $WinPy)
    }
    foreach ($Candidate in $Order) {
        if (Test-Path -Path $Candidate -PathType Leaf) {
            return $Candidate
        }
    }
    return ""
}

function Resolve-FallbackPython312Plus {
    $Candidates = @()
    if ($OnWindows -and (Get-Command py -ErrorAction SilentlyContinue)) {
        $Candidates += ,@("py", @("-3.12"))
        $Candidates += ,@("py", @("-3.13"))
        $Candidates += ,@("py", @("-3.14"))
        $Candidates += ,@("py", @("-3"))
    }
    foreach ($CmdName in @("python3.12", "python3.13", "python3.14", "python3", "python")) {
        $CmdInfo = Get-Command $CmdName -ErrorAction SilentlyContinue
        if ($CmdInfo -and $CmdInfo.Source) {
            $Candidates += ,@($CmdInfo.Source, @())
        }
    }

    $PrevErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        foreach ($Candidate in $Candidates) {
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
                        return $Resolved
                    }
                }
            } catch {
                continue
            }
        }
    } finally {
        $ErrorActionPreference = $PrevErr
    }
    return ""
}

$PythonExe = ""
$UsingRepoVenv = $false

$RequestedPy = if ($env:SOCLENS_PYTHON) { $env:SOCLENS_PYTHON.Trim() } else { "" }
if ($RequestedPy) {
    if (Test-Path -Path $RequestedPy -PathType Leaf) {
        $PythonExe = $RequestedPy
    } else {
        $CmdPy = Get-Command $RequestedPy -ErrorAction SilentlyContinue
        if ($CmdPy -and $CmdPy.Source) {
            $PythonExe = $CmdPy.Source
        } else {
            [Console]::Error.WriteLine("[-] Error: SOCLENS_PYTHON points to missing interpreter '$RequestedPy'.")
            exit 1
        }
    }
}

if (-not $PythonExe) {
    $RequestedVenv = if ($env:SOCLENS_VENV) { $env:SOCLENS_VENV.Trim() } else { "" }
    if ($RequestedVenv) {
        $PythonExe = Get-VenvPythonCandidate -VenvPath $RequestedVenv
        if (-not $PythonExe) {
            [Console]::Error.WriteLine("[-] Error: SOCLENS_VENV virtual environment at '$RequestedVenv' has no Python interpreter.")
            exit 1
        }
    }
}

if (-not $PythonExe) {
    $LocalVenvDir = Join-Path $RepoRoot ".venv"
    $LocalPy = Get-VenvPythonCandidate -VenvPath $LocalVenvDir
    if ($LocalPy) {
        $PythonExe = $LocalPy
        $UsingRepoVenv = $true
    }
}

if (-not $PythonExe) {
    $ActiveVenv = if ($env:VIRTUAL_ENV) { $env:VIRTUAL_ENV.Trim() } else { "" }
    if ($ActiveVenv) {
        $PythonExe = Get-VenvPythonCandidate -VenvPath $ActiveVenv
    }
}

if (-not $PythonExe) {
    $PythonExe = Resolve-FallbackPython312Plus
}

if (-not $PythonExe) {
    [Console]::Error.WriteLine("[-] Error: Python 3.12+ interpreter not found. Run '.\install_offline.ps1' or set SOCLENS_PYTHON.")
    exit 1
}

$ForwardArgs = @()
foreach ($Item in $args) {
    if ($null -eq $Item) {
        continue
    }
    if ($Item -is [System.Array]) {
        $Joined = (@($Item | ForEach-Object { if ($null -ne $_) { "$_" } }) -join ",")
        $ForwardArgs += $Joined
    } else {
        $ForwardArgs += "$Item"
    }
}

$HadPythonPath = Test-Path Env:PYTHONPATH
$OrigPythonPath = $env:PYTHONPATH
$PrevErr = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$ExitCode = 0

try {
    if (-not $UsingRepoVenv) {
        if ($HadPythonPath -and $OrigPythonPath) {
            $env:PYTHONPATH = $RepoRoot + [System.IO.Path]::PathSeparator + $OrigPythonPath
        } else {
            $env:PYTHONPATH = $RepoRoot
        }
    }

    if ($ForwardArgs.Count -gt 0) {
        & $PythonExe -m soclens.cli @ForwardArgs
    } else {
        & $PythonExe -m soclens.cli
    }
    $ExitCode = $LASTEXITCODE
    if ($null -eq $ExitCode) {
        $ExitCode = 0
    }
} finally {
    $ErrorActionPreference = $PrevErr
    if (-not $UsingRepoVenv) {
        if ($HadPythonPath) {
            $env:PYTHONPATH = $OrigPythonPath
        } else {
            Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        }
    }
}

exit $ExitCode
