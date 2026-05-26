param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [switch]$Push
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

$NormalizedVersion = $Version.Trim() -replace "^v", ""
if ($NormalizedVersion -notmatch "^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$") {
    throw "Version must be valid SemVer, for example 0.1.8."
}

$ReleaseTag = "v$NormalizedVersion"
$Dirty = git status --porcelain
if ($Dirty) {
    throw "Working tree must be clean before preparing $ReleaseTag."
}

node scripts/set-release-version.mjs $NormalizedVersion
node scripts/check-release-version.mjs --tag $ReleaseTag

git add Cargo.toml Cargo.lock app/desktop/package.json app/desktop/package-lock.json app/desktop/src-tauri/Cargo.toml app/desktop/src-tauri/tauri.conf.json services/cloudflare/package.json services/cloudflare/package-lock.json
git commit -m "release: $ReleaseTag"
git tag $ReleaseTag

if ($Push) {
    git push origin HEAD
    git push origin $ReleaseTag
    Write-Host "Pushed $ReleaseTag. GitHub Actions will build the release."
} else {
    Write-Host "Prepared $ReleaseTag locally. Push with: git push origin HEAD; git push origin $ReleaseTag"
}
