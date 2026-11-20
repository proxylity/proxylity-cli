<#
.SYNOPSIS
  Scans the repository (files, file names, full git history, commit messages) for
  denied patterns.

.DESCRIPTION
  Pattern sources:
    1. eng/gate/denylist.generic.txt (public, committed)
    2. The PRIVATE_DENYLIST environment variable (newline-separated regexes). In CI
       this comes from a repository secret so the list is never published.
       A local file can be supplied with -PrivateFile instead.

  Output deliberately never prints the matched text or the pattern, only the
  location and a pattern id, because CI logs for a public repository are public.

  -Mode Check    Enforce generic and private patterns. If no private list is
                 available, warn and continue (e.g. pull requests from forks).
  -Mode Release  As Check, also enforce 'release:' patterns, and fail if no private
                 list is available.

  Exit code 0 = clean, 1 = findings, 2 = configuration error.

  Works on Windows PowerShell 5.1 and PowerShell 7+.
#>
[CmdletBinding()]
param(
    [ValidateSet('Check', 'Release')]
    [string]$Mode = 'Check',
    [string]$PrivateFile
)

$ErrorActionPreference = 'Stop'
$root = (& git rev-parse --show-toplevel).Trim()
Set-Location $root

function Read-Patterns([string[]]$lines, [string]$source) {
    $result = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($raw in $lines) {
        $i++
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { continue }
        $releaseOnly = $false
        if ($line.StartsWith('release:')) { $releaseOnly = $true; $line = $line.Substring(8) }
        try { $rx = New-Object System.Text.RegularExpressions.Regex($line, 'Compiled') }
        catch { Write-Error "Invalid regex in $source (entry $i)."; exit 2 }
        $result.Add([pscustomobject]@{ Id = "$source#$i"; Regex = $rx; ReleaseOnly = $releaseOnly })
    }
    return ,$result
}

$patterns = New-Object System.Collections.Generic.List[object]
$generic = Join-Path $PSScriptRoot 'denylist.generic.txt'
$patterns.AddRange((Read-Patterns (Get-Content $generic) 'generic'))

$privateLines = @()
if ($PrivateFile) { $privateLines = Get-Content $PrivateFile }
elseif ($env:PRIVATE_DENYLIST) { $privateLines = $env:PRIVATE_DENYLIST -split "`r?`n" }

$hasPrivate = ($privateLines | Where-Object { $_.Trim() -ne '' -and -not $_.Trim().StartsWith('#') }).Count -gt 0
if ($hasPrivate) { $patterns.AddRange((Read-Patterns $privateLines 'private')) }
elseif ($Mode -eq 'Release') {
    Write-Error 'Release mode requires a private denylist (PRIVATE_DENYLIST secret or -PrivateFile).'
    exit 2
}
else {
    Write-Warning 'No private denylist available; only generic patterns are enforced.'
}

$active = $patterns | Where-Object { $Mode -eq 'Release' -or -not $_.ReleaseOnly }
$findings = 0

function Test-Line([string]$text, [string]$where) {
    if ($text -match 'gate:allow') { return }
    foreach ($p in $active) {
        if ($p.Regex.IsMatch($text)) {
            Write-Host "FINDING: $where (pattern $($p.Id))"
            $script:findings++
        }
    }
}

# Excluded from scanning: the gate's own pattern files.
$excluded = '^eng/gate/'

# 1. Working tree: file names and contents
$files = & git ls-files
foreach ($f in $files) {
    if ($f -match $excluded) { continue }
    Test-Line $f "path $f"
    $full = Join-Path $root $f
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
    $bytes = [System.IO.File]::ReadAllBytes($full)
    if ([Array]::IndexOf($bytes, [byte]0) -ge 0) { continue } # skip binary
    $n = 0
    foreach ($line in [System.IO.File]::ReadLines($full)) {
        $n++
        Test-Line $line "${f}:${n}"
    }
}

# 2. History: commit messages, author data, and every added/removed line
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'git'
$psi.Arguments = 'log --all --no-color --format=">>COMMIT %H%n%an <%ae>%n%B" -p'
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false
$psi.WorkingDirectory = $root
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$proc = [System.Diagnostics.Process]::Start($psi)
$commit = ''
$file = ''
while (($line = $proc.StandardOutput.ReadLine()) -ne $null) {
    if ($line.StartsWith('>>COMMIT ')) { $commit = $line.Substring(9, 12); $file = '(message)'; continue }
    if ($line.StartsWith('+++ b/')) { $file = $line.Substring(6); continue }
    if ($file -match $excluded) { continue }
    if ($line.StartsWith('diff --git') -or $line.StartsWith('---') -or $line.StartsWith('index ')) { continue }
    Test-Line $line "history commit $commit $file"
}
$proc.WaitForExit()

if ($findings -gt 0) {
    Write-Host "Denylist scan failed: $findings finding(s)."
    exit 1
}
Write-Host "Denylist scan passed (mode: $Mode)."
