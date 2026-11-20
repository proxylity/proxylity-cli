<#
.SYNOPSIS
  Fails if any third-party GitHub Action in .github/workflows is not pinned to a
  full 40-character commit SHA.
  Works on Windows PowerShell 5.1 and PowerShell 7+.
#>
[CmdletBinding()]
param()

$root = (& git rev-parse --show-toplevel).Trim()
$problems = 0
foreach ($f in Get-ChildItem (Join-Path $root '.github/workflows') -Filter *.yml) {
    $n = 0
    foreach ($line in Get-Content $f.FullName) {
        $n++
        if ($line -match '^\s*-?\s*uses:\s*(?<ref>\S+)') {
            $ref = $Matches['ref']
            if ($ref.StartsWith('./')) { continue } # local reusable workflow
            if ($ref -notmatch '@[0-9a-f]{40}$') {
                Write-Host "UNPINNED  $($f.Name):${n}: $ref"
                $problems++
            }
        }
    }
}
if ($problems -gt 0) { Write-Host "Action pin check failed: $problems unpinned reference(s)."; exit 1 }
Write-Host 'Action pin check passed.'
