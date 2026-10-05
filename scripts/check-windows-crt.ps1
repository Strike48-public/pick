# Fail if a Windows exe imports the dynamic MSVC C/C++ runtime.
#
# The release ships bare exes in a zip with no installer, so a VCRUNTIME140*.dll
# or MSVCP140*.dll import makes the exe fail to start on a host without the
# Visual C++ Redistributable (pick#533). .cargo/config.toml links the CRT
# statically; this guards that it stays that way.
#
# Usage: pwsh scripts/check-windows-crt.ps1 <exe> [<exe> ...]

param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]] $Exes
)

$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found at $vswhere; cannot locate dumpbin"
}
$dumpbin = & $vswhere -latest -products * -find '**\Hostx64\x64\dumpbin.exe' | Select-Object -First 1
if (-not $dumpbin) {
    throw 'dumpbin.exe not found; install the MSVC build tools'
}

$failed = $false
foreach ($exe in $Exes) {
    if (-not (Test-Path $exe)) {
        throw "No such file: $exe"
    }
    $output = & $dumpbin /nologo /dependents $exe
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin failed on ${exe}: $output"
    }
    # Without this header the import list was not read, and an empty match
    # below would pass the check without having looked at anything.
    if (-not ($output -match 'has the following dependencies')) {
        throw "dumpbin printed no dependency list for ${exe}: $output"
    }
    $runtime = $output | Where-Object { $_ -match '(?i)^\s*(vcruntime|msvcp)\d+.*\.dll\s*$' }
    if ($runtime) {
        Write-Host "FAIL: $exe imports the dynamic MSVC runtime:"
        $runtime | ForEach-Object { Write-Host "  $($_.Trim())" }
        $failed = $true
    } else {
        Write-Host "OK: $exe does not import the dynamic MSVC runtime"
    }
}

if ($failed) {
    exit 1
}
