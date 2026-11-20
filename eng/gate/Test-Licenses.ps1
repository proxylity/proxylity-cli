<#
.SYNOPSIS
  Verifies that every NuGet package the solution depends on (including transitive
  and test dependencies) has an allowed license.

.DESCRIPTION
  Reads obj/project.assets.json for each project (run `dotnet restore` first),
  locates each package's .nuspec in the NuGet cache, and checks its SPDX license
  expression against eng/gate/licenses.allowed.txt.

  Packages whose license cannot be determined from an SPDX expression (for example,
  those that only declare a license URL) fail unless listed in
  eng/gate/license-overrides.json with a justification that a person has reviewed.

  Exit code 0 = all allowed, 1 = findings.
  Works on Windows PowerShell 5.1 and PowerShell 7+.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = (& git rev-parse --show-toplevel).Trim()
Set-Location $root

$allowed = Get-Content (Join-Path $PSScriptRoot 'licenses.allowed.txt') |
    ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and -not $_.StartsWith('#') }

$overrides = @{}
$overridePath = Join-Path $PSScriptRoot 'license-overrides.json'
if (Test-Path $overridePath) {
    $json = Get-Content $overridePath -Raw | ConvertFrom-Json
    foreach ($p in $json.PSObject.Properties) { $overrides[$p.Name.ToLowerInvariant()] = $p.Value }
}

function Test-Expression([string]$expr) {
    # Supports simple SPDX expressions: A, A OR B, A AND B, with optional parentheses.
    $e = $expr -replace '[()]', ' '
    $orParts = $e -split '\s+OR\s+'
    foreach ($or in $orParts) {
        $andParts = $or -split '\s+AND\s+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        $ok = $true
        foreach ($id in $andParts) { if ($allowed -notcontains $id) { $ok = $false } }
        if ($ok -and $andParts.Count -gt 0) { return $true }
    }
    return $false
}

$assets = Get-ChildItem -Path $root -Recurse -Filter project.assets.json -File |
    Where-Object { $_.FullName -match '[\\/]obj[\\/]' }
if (-not $assets) { Write-Error 'No project.assets.json found. Run dotnet restore first.'; exit 1 }

$seen = @{}
$problems = 0
foreach ($a in $assets) {
    $doc = Get-Content $a.FullName -Raw | ConvertFrom-Json
    $folders = @($doc.packageFolders.PSObject.Properties.Name)
    foreach ($lib in $doc.libraries.PSObject.Properties) {
        if ($lib.Value.type -ne 'package') { continue }
        $key = $lib.Name.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $id, $version = $lib.Name -split '/', 2

        if ($overrides.ContainsKey($id.ToLowerInvariant())) {
            Write-Host "OVERRIDE  $($lib.Name): $($overrides[$id.ToLowerInvariant()].license) ($($overrides[$id.ToLowerInvariant()].reason))"
            continue
        }

        $nuspec = $null
        foreach ($f in $folders) {
            $candidate = Join-Path $f (Join-Path $lib.Value.path ($id.ToLowerInvariant() + '.nuspec'))
            if (Test-Path $candidate) { $nuspec = $candidate; break }
        }
        if (-not $nuspec) {
            Write-Host "UNKNOWN   $($lib.Name): nuspec not found"
            $problems++
            continue
        }

        [xml]$xml = Get-Content $nuspec -Raw
        $licenseNode = $xml.package.metadata.license
        if ($licenseNode -and $licenseNode.type -eq 'expression') {
            $expr = $licenseNode.'#text'
            if (Test-Expression $expr) { Write-Host "OK        $($lib.Name): $expr" }
            else { Write-Host "DENIED    $($lib.Name): $expr"; $problems++ }
        }
        else {
            $url = $xml.package.metadata.licenseUrl
            Write-Host "REVIEW    $($lib.Name): no SPDX expression (licenseUrl: $url)"
            $problems++
        }
    }
}

if ($problems -gt 0) {
    Write-Host "License check failed: $problems package(s) need attention."
    exit 1
}
Write-Host "License check passed ($($seen.Count) packages)."
