[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$resolvedRoot = (Resolve-Path $RepoRoot).Path
$rootTmpDirs = Get-ChildItem -LiteralPath $resolvedRoot -Force -Directory |
    Where-Object { $_.Name -like ".tmp*" }
$wranglerTmpPath = Join-Path $resolvedRoot "services\cloudflare\.wrangler\tmp"

$cleanupTargets = @()

foreach ($dir in $rootTmpDirs) {
    $cleanupTargets += [PSCustomObject]@{
        Kind = "root-temp-dir"
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

    if ($PSCmdlet.ShouldProcess($target.Path, "Remove temp directory")) {
        Remove-Item -LiteralPath $target.Path -Recurse -Force
    }
}

Write-Host "Cleanup complete."
