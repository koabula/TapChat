[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$resolvedRoot = (Resolve-Path $RepoRoot).Path
$rootTmpDirs = Get-ChildItem -LiteralPath $resolvedRoot -Force -Directory |
    Where-Object { $_.Name -like ".tmp*" -or $_.Name -like ".cli-smoke*" }
$rootTmpFiles = Get-ChildItem -LiteralPath $resolvedRoot -Force -File |
    Where-Object { $_.Name -like ".cli-smoke*.ps1" -or $_.Name -like ".cli-smoke*.txt" }
$serviceRoot = Join-Path $resolvedRoot "services\cloudflare"
$serviceTmpDirs = @()
if (Test-Path -LiteralPath $serviceRoot) {
    $serviceTmpDirs = Get-ChildItem -LiteralPath $serviceRoot -Force -Directory |
        Where-Object { $_.Name -like ".cli-smoke*" }
}
$wranglerTmpPath = Join-Path $resolvedRoot "services\cloudflare\.wrangler\tmp"

$cleanupTargets = @()

foreach ($dir in $rootTmpDirs) {
    $cleanupTargets += [PSCustomObject]@{
        Kind = "root-temp-dir"
        Path = $dir.FullName
    }
}

foreach ($file in $rootTmpFiles) {
    $cleanupTargets += [PSCustomObject]@{
        Kind = "root-temp-file"
        Path = $file.FullName
    }
}

foreach ($dir in $serviceTmpDirs) {
    $cleanupTargets += [PSCustomObject]@{
        Kind = "service-temp-dir"
        Path = $dir.FullName
    }
}

if (Test-Path -LiteralPath $wranglerTmpPath) {
    $cleanupTargets += [PSCustomObject]@{
        Kind = "wrangler-tmp"
        Path = $wranglerTmpPath
    }
}

if ($cleanupTargets.Count -eq 0) {
    Write-Host "No test temp directories found under $resolvedRoot"
    exit 0
}

Write-Host "Found $($cleanupTargets.Count) cleanup target(s) under $resolvedRoot"

foreach ($target in $cleanupTargets) {
    if (-not $target.Path.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove path outside repo root: $($target.Path)"
    }

    if ($target.Kind -eq "wrangler-tmp") {
        $children = @(Get-ChildItem -LiteralPath $target.Path -Force -ErrorAction SilentlyContinue)
        if ($children.Count -eq 0) {
            continue
        }
        foreach ($child in $children) {
            if (-not $child.FullName.StartsWith($target.Path, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to remove path outside wrangler tmp root: $($child.FullName)"
            }
            if ($PSCmdlet.ShouldProcess($child.FullName, "Remove wrangler tmp content")) {
                Remove-Item -LiteralPath $child.FullName -Recurse -Force
            }
        }
        continue
    }

    if ($target.Kind -eq "root-temp-file") {
        if ($PSCmdlet.ShouldProcess($target.Path, "Remove temp file")) {
            Remove-Item -LiteralPath $target.Path -Force
        }
        continue
    }

    if ($PSCmdlet.ShouldProcess($target.Path, "Remove temp directory")) {
        Remove-Item -LiteralPath $target.Path -Recurse -Force
    }
}

Write-Host "Cleanup complete."
