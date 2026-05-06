param(
  [string]$CodeqlPath = "codeql",
  [string]$DatabaseDir = "db-java",
  [string]$OutputDir = "out\crypto-inventory",
  [string]$PackCache = (Join-Path $HOME ".codeql\packages"),
  [switch]$SkipPackInstall
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
  $PSNativeCommandUseErrorActionPreference = $true
}

$scriptDir = Split-Path -Parent $PSCommandPath
$repoRoot = Resolve-Path -LiteralPath (Join-Path $scriptDir "..")
Set-Location -LiteralPath $repoRoot

function Resolve-Codeql {
  param([string]$PathOrCommand)

  if (Test-Path -LiteralPath $PathOrCommand) {
    return (Resolve-Path -LiteralPath $PathOrCommand).Path
  }

  $command = Get-Command $PathOrCommand -ErrorAction Stop
  return $command.Source
}

function Remove-WorkspacePath {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    return
  }

  $root = (Resolve-Path -LiteralPath $repoRoot).Path
  $resolved = (Resolve-Path -LiteralPath $Path).Path
  if (-not $resolved.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove path outside workspace: $resolved"
  }

  Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Invoke-Checked {
  param(
    [string]$FilePath,
    [string[]]$Arguments
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "$FilePath exited with code $LASTEXITCODE"
  }
}

$codeql = Resolve-Codeql $CodeqlPath
$codeqlHome = Split-Path -Parent $codeql
$qlpacksDir = Join-Path $codeqlHome "qlpacks"
$searchPath = @($qlpacksDir, $PackCache, ".\queries") -join [IO.Path]::PathSeparator

$databasePath = Join-Path $repoRoot $DatabaseDir
$outputPath = Join-Path $repoRoot $OutputDir
$bqrsPath = Join-Path $outputPath "results.bqrs"
$decodedPath = Join-Path $outputPath "codeql-results.json"
$inventoryPath = Join-Path $outputPath "inventory.json"
$summaryPath = Join-Path $outputPath "summary.txt"

Write-Host "Using CodeQL: $codeql"
Invoke-Checked $codeql @("version")

if (-not $SkipPackInstall) {
  Invoke-Checked $codeql @("pack", "install", ".\queries", "--no-strict-mode")
}

Remove-WorkspacePath $databasePath
New-Item -ItemType Directory -Force $outputPath | Out-Null

Invoke-Checked $codeql @(
  "database", "create", $databasePath,
  "--language=java",
  "--source-root", ".",
  "--command", "javac -d build demo/src/Demo.java",
  "--overwrite"
)

Invoke-Checked $codeql @(
  "query", "run", ".\queries\crypto-inventory.ql",
  "--database", $databasePath,
  "--search-path", $searchPath,
  "--additional-packs", ".\queries",
  "--output", $bqrsPath
)

Invoke-Checked $codeql @(
  "bqrs", "decode",
  "--format=json",
  "--entities=string",
  "--output", $decodedPath,
  "--",
  $bqrsPath
)

Invoke-Checked "python" @(
  "scripts\cbom.py", "from-bqrs-json", $decodedPath,
  "--output", $inventoryPath,
  "--summary", $summaryPath
)

Invoke-Checked "python" @("scripts\assert_inventory.py", $inventoryPath)
Invoke-Checked "python" @("scripts\cbom.py", "summarize", $inventoryPath, "--fail-on-critical")

Write-Host "Inventory: $inventoryPath"
Write-Host "Summary:   $summaryPath"
