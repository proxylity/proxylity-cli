<#
.SYNOPSIS
  Computes the semantic version for the current commit from git tags.

.DESCRIPTION
  Release tags are plain semver without a prefix: MAJOR.MINOR.PATCH (e.g. 1.2.3).
  Only stable X.Y.Z tags are considered when finding the previous release.

  - HEAD is exactly on a release tag:   X.Y.Z
  - Otherwise (a prerelease build):     X.Y.(Z+1)-N+SHA
      where X.Y.Z is the nearest previous release tag (0.0.0 if there is none)
      and N is the number of commits since that tag (or since the start of
      history if there is none).

  With -Tag, the given tag is validated and used as the version (release builds).

  Works on Windows PowerShell 5.1 and PowerShell 7+. Requires full git history
  (in GitHub Actions use actions/checkout with fetch-depth: 0).

.OUTPUTS
  Writes the version to stdout. When running in GitHub Actions, also writes
  'version' and 'is_release' to $GITHUB_OUTPUT.
#>
[CmdletBinding()]
param(
    [string]$Tag
)

$ErrorActionPreference = 'Stop'

$stable = '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$'
$semver = '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

function Invoke-Git {
    # Windows PowerShell 5.1 turns native stderr into terminating errors when
    # $ErrorActionPreference is 'Stop', so relax it for the call.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & git @args 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        return $out
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

if ($Tag) {
    if ($Tag -notmatch $semver) {
        throw "Tag '$Tag' is not a valid semantic version (expected MAJOR.MINOR.PATCH[-prerelease], no prefix)."
    }
    $version = $Tag
    $isRelease = $true
}
else {
    $sha = (Invoke-Git rev-parse --short=8 HEAD)
    if (-not $sha) { throw 'Not a git repository, or no commits yet.' }

    $described = Invoke-Git describe --tags --long --match '[0-9]*.[0-9]*.[0-9]*' --exclude '*-*'
    $base = $null
    if ($described -and $described -match '^(?<tag>.+)-(?<n>\d+)-g[0-9a-f]+$') {
        $candidate = $Matches['tag']
        $candidateHeight = [int]$Matches['n']
        if ($candidate -match $stable) {
            $base = $candidate
            $height = $candidateHeight
        }
    }
    if (-not $base) {
        $base = '0.0.0'
        $height = [int](Invoke-Git rev-list --count HEAD)
    }

    if ($height -eq 0 -and $base -ne '0.0.0') {
        $version = $base
        $isRelease = $true
    }
    else {
        $parts = $base.Split('.')
        $next = '{0}.{1}.{2}' -f $parts[0], $parts[1], ([int]$parts[2] + 1)
        $version = '{0}-{1}+{2}' -f $next, $height, $sha
        $isRelease = $false
    }
}

Write-Output $version

if ($env:GITHUB_OUTPUT) {
    "version=$version" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    "is_release=$($isRelease.ToString().ToLowerInvariant())" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
