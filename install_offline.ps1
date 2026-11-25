<#
.SYNOPSIS
    Offline / air-gapped installer for SOCLens.
.DESCRIPTION
    Creates an isolated Python virtual environment and installs soclens
    plus all runtime and build dependencies strictly from the bundled wheelhouse/
    directory with zero internet access. On Windows, installs the PowerShell
    CLI launcher shim invoking Python directly. Compatible with Windows
    PowerShell 5.1, PowerShell 7+ on Windows, and pwsh on Linux/macOS.
#>
[CmdletBinding()]
param(
    [string]$VenvDir = "",

    [string]$PythonExe = "",

    [switch]$NoEditable,

    [switch]$ForceRecreate,

    [switch]$SkipVerify,

    [switch]$LaunchTui,

    [switch]$DryRun
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

$RepoRoot = (Resolve-Path -Path $PSScriptRoot).Path
if (-not $VenvDir) {
    $VenvDir = Join-Path $RepoRoot ".venv"
} elseif (-not [System.IO.Path]::IsPathRooted($VenvDir)) {
    $VenvDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $VenvDir))
}

$WheelhouseDir = Join-Path $RepoRoot "wheelhouse"
if (-not (Test-Path -Path $WheelhouseDir -PathType Container)) {
    throw "Offline wheelhouse directory not found at '$WheelhouseDir'."
}
$WheelFiles = @(Get-ChildItem -Path $WheelhouseDir -Filter "*.whl" -File)
if ($WheelFiles.Count -eq 0) {
    throw "No .whl packages found inside '$WheelhouseDir'."
}

# Strictly disable PyPI index lookups across pip and uv
$env:PIP_NO_INDEX = "1"
$env:PIP_FIND_LINKS = $WheelhouseDir
$env:PIP_DISABLE_PIP_VERSION_CHECK = "1"
$env:UV_OFFLINE = "1"

function Resolve-Python312Plus {
    param([string]$RequestedExe)

    $Candidates = @()
    if ($RequestedExe) {
        $Candidates += ,@($RequestedExe, @())
    } else {
        if ($OnWindows -and (Get-Command py -ErrorAction SilentlyContinue)) {
            $Candidates += ,@("py", @("-3.12"))
            $Candidates += ,@("py", @("-3.13"))
            $Candidates += ,@("py", @("-3.14"))
            $Candidates += ,@("py", @("-3"))
        }
        foreach ($CmdName in @("python3.12", "python3.13", "python3.14", "python3", "python")) {
            $CmdInfo = Get-Command $CmdName -ErrorAction SilentlyContinue
            if ($CmdInfo) {
                $Candidates += ,@($CmdInfo.Source, @())
            }
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

    if ($RequestedExe) {
        throw "Requested Python executable '$RequestedExe' is missing or older than Python 3.12."
    }
    throw "Python 3.12+ is required, but no compatible interpreter was found on PATH."
}

function Get-VenvPythonPath {
    param([string]$TargetVenv)

    $WinPy = Join-Path (Join-Path $TargetVenv "Scripts") "python.exe"
    if (Test-Path -Path $WinPy -PathType Leaf) {
        return $WinPy
    }
    $PosixPy = Join-Path (Join-Path $TargetVenv "bin") "python"
    if (Test-Path -Path $PosixPy -PathType Leaf) {
        return $PosixPy
    }
    return ""
}

function Install-WindowsPowerShellShims {
    param([Parameter(Mandatory = $true)][string]$ScriptsDir)

    if (-not (Test-Path -Path $ScriptsDir -PathType Container)) {
        return
    }

    foreach ($WrapperExe in @("soclens.exe")) {
        $ExePath = Join-Path $ScriptsDir $WrapperExe
        if (Test-Path -Path $ExePath -PathType Leaf) {
            Remove-Item -Path $ExePath -Force
        }
    }

    $ShimContent = @'
# PowerShell CLI shim for SOCLens.
# Intentionally omits [CmdletBinding()] and param(...) to forward all flags.

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

$VenvPython = Join-Path $PSScriptRoot "python.exe"
if (-not (Test-Path -Path $VenvPython -PathType Leaf)) {
    $FallbackPy = Join-Path $PSScriptRoot "python"
    if (Test-Path -Path $FallbackPy -PathType Leaf) {
        $VenvPython = $FallbackPy
    } else {
        $CmdPy = Get-Command python -ErrorAction SilentlyContinue
        if ($CmdPy -and $CmdPy.Source) {
            $VenvPython = $CmdPy.Source
        } else {
            [Console]::Error.WriteLine("[-] Error: Python interpreter not found in '$PSScriptRoot'.")
            exit 1
        }
    }
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

$PrevErr = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$ExitCode = 0
try {
    if ($ForwardArgs.Count -gt 0) {
        & $VenvPython -m soclens.cli @ForwardArgs
    } else {
        & $VenvPython -m soclens.cli
    }
    $ExitCode = $LASTEXITCODE
    if ($null -eq $ExitCode) {
        $ExitCode = 0
    }
} finally {
    $ErrorActionPreference = $PrevErr
}

exit $ExitCode
'@

    foreach ($ShimName in @("soclens.ps1")) {
        $ShimPath = Join-Path $ScriptsDir $ShimName
        Set-Content -Path $ShimPath -Value $ShimContent -Encoding Ascii
    }
}

$ResolvedPython = Resolve-Python312Plus -RequestedExe $PythonExe
Write-Host "[*] Using Python: $ResolvedPython"
Write-Host "[*] Using offline wheelhouse: $WheelhouseDir ($($WheelFiles.Count) wheels)"

if ($ForceRecreate -and (Test-Path -Path $VenvDir)) {
    Write-Host "[*] Removing existing virtual environment at '$VenvDir'..."
    Remove-Item -Path $VenvDir -Recurse -Force
}

$UvCmd = Get-Command uv -ErrorAction SilentlyContinue
$VenvPython = Get-VenvPythonPath -TargetVenv $VenvDir

if (-not $VenvPython) {
    Write-Host "[*] Creating virtual environment at '$VenvDir'..."
    if ($UvCmd) {
        & $UvCmd.Source venv --offline --no-python-downloads --python $ResolvedPython $VenvDir
        if ($LASTEXITCODE -ne 0) {
            throw "uv venv failed with exit code $LASTEXITCODE"
        }
    } else {
        & $ResolvedPython -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) {
            throw "python -m venv failed with exit code $LASTEXITCODE"
        }
    }
    $VenvPython = Get-VenvPythonPath -TargetVenv $VenvDir
    if (-not $VenvPython) {
        throw "Virtual environment was created at '$VenvDir', but no Python binary was found inside."
    }
} else {
    Write-Host "[*] Reusing existing virtual environment at '$VenvDir'."
}

$TargetSpec = @()
if (-not $NoEditable) {
    $TargetSpec += "-e"
}
$TargetSpec += $RepoRoot

Write-Host "[*] Installing soclens offline..."
if ($UvCmd) {
    & $UvCmd.Source pip install --offline --no-index --find-links $WheelhouseDir --python $VenvPython @TargetSpec
    if ($LASTEXITCODE -ne 0) {
        throw "uv offline install failed with exit code $LASTEXITCODE"
    }
} else {
    $PrevErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $VenvPython -m pip --version 2>$null | Out-Null
        $HasPip = ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $PrevErr
    }
    if (-not $HasPip) {
        Write-Host "[*] Bootstrapping pip offline via ensurepip..."
        & $VenvPython -m ensurepip --default-pip
        if ($LASTEXITCODE -ne 0) {
            throw "ensurepip failed with exit code $LASTEXITCODE"
        }
    }
    & $VenvPython -m pip install --no-index --find-links $WheelhouseDir @TargetSpec
    if ($LASTEXITCODE -ne 0) {
        throw "pip offline install failed with exit code $LASTEXITCODE"
    }
}

$WinScriptsDir = Join-Path $VenvDir "Scripts"
if ($OnWindows -and (Test-Path -Path $WinScriptsDir -PathType Container)) {
    Write-Host "[*] Installing Windows PowerShell CLI launcher shim..."
    Install-WindowsPowerShellShims -ScriptsDir $WinScriptsDir
    if (Get-Command Unblock-File -ErrorAction SilentlyContinue) {
        foreach ($UnblockTarget in @(
            (Join-Path $RepoRoot "soclens.ps1"),
            (Join-Path (Join-Path $RepoRoot "scripts") "soclens-brand-sync.ps1"),
            (Join-Path $WinScriptsDir "soclens.ps1")
        )) {
            if (Test-Path -Path $UnblockTarget -PathType Leaf) {
                Unblock-File -Path $UnblockTarget -ErrorAction SilentlyContinue
            }
        }
    }
}

if (-not $SkipVerify) {
    Write-Host "[*] Verifying offline module imports and native extensions..."
    $VerifyCode = "import soclens, soclens.cli, soclens.tui, soclens.sigma, soclens.splunk, soclens.bundler, soclens.logos, soclens.research, soclens.tui.logging_bridge, yaml, re2, jq, textual, linkify_it; assert hasattr(yaml, 'CSafeLoader'); print('OK:', soclens.__version__)"
    & $VenvPython -c $VerifyCode
    if ($LASTEXITCODE -ne 0) {
        throw "Post-install verification failed with exit code $LASTEXITCODE"
    }
}

$RootLauncher = Join-Path $RepoRoot "soclens.ps1"
$WinActivate = Join-Path $WinScriptsDir "Activate.ps1"
$PosixActivate = Join-Path (Join-Path $VenvDir "bin") "Activate.ps1"
$PosixCli = Join-Path (Join-Path $VenvDir "bin") "soclens"

Write-Host ""
Write-Host "[+] Offline installation complete!"
if (Test-Path -Path $WinActivate -PathType Leaf) {
    Write-Host "    Activate venv:  . `"$WinActivate`""
    if (Test-Path -Path $RootLauncher -PathType Leaf) {
        if ($VenvDir -eq (Join-Path $RepoRoot ".venv")) {
            Write-Host "    Launch TUI:     .\soclens.ps1 tui"
        } else {
            Write-Host "    Launch TUI:     `$env:SOCLENS_VENV = `"$VenvDir`"; & `"$RootLauncher`" tui"
        }
    }
    Write-Host "    After activate: soclens tui"
    Write-Host "    Or via Python:  & `"$VenvPython`" -m soclens.cli tui"
} elseif (Test-Path -Path $PosixActivate -PathType Leaf) {
    Write-Host "    Activate venv:  . `"$PosixActivate`""
    if (Test-Path -Path $PosixCli -PathType Leaf) {
        Write-Host "    Launch TUI:     `"$PosixCli`" tui"
    }
    if (Test-Path -Path $RootLauncher -PathType Leaf) {
        Write-Host "    Via PowerShell: pwsh -NoProfile -File `"$RootLauncher`" tui"
    }
    Write-Host "    Or via Python:  `"$VenvPython`" -m soclens.cli tui"
} else {
    Write-Host "    Launch TUI:     & `"$VenvPython`" -m soclens.cli tui"
}

if ($LaunchTui) {
    $TuiArgs = @("tui")
    if ($DryRun) {
        $TuiArgs += "--dry-run"
    }
    $PrevErr = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $ExitCode = 0
    try {
        & $VenvPython -m soclens.cli @TuiArgs
        $ExitCode = $LASTEXITCODE
        if ($null -eq $ExitCode) {
            $ExitCode = 0
        }
    } finally {
        $ErrorActionPreference = $PrevErr
    }
    exit $ExitCode
}
