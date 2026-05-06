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
$searchPath = @($qlpacksDir, $PackCache, ".\queries", ".\queries-python") -join [IO.Path]::PathSeparator

$javaDatabasePath = Join-Path $repoRoot $DatabaseDir
$pythonDatabasePath = Join-Path $repoRoot "db-python"
$outputPath = Join-Path $repoRoot $OutputDir
$javaBqrsPath = Join-Path $outputPath "java-results.bqrs"
$javaDecodedPath = Join-Path $outputPath "java-codeql-results.json"
$javaInventoryPath = Join-Path $outputPath "inventory-java.json"
$pythonBqrsPath = Join-Path $outputPath "python-results.bqrs"
$pythonDecodedPath = Join-Path $outputPath "python-codeql-results.json"
$pythonInventoryPath = Join-Path $outputPath "inventory-python.json"
$configInventoryPath = Join-Path $outputPath "inventory-config.json"
$pcapInventoryPath = Join-Path $outputPath "inventory-pcap.json"
$inventoryPath = Join-Path $outputPath "inventory.json"
$summaryPath = Join-Path $outputPath "summary.txt"

Write-Host "Using CodeQL: $codeql"
Invoke-Checked $codeql @("version")

if (-not $SkipPackInstall) {
  Invoke-Checked $codeql @("pack", "install", ".\queries", "--no-strict-mode")
  Invoke-Checked $codeql @("pack", "install", ".\queries-python", "--no-strict-mode")
}

Remove-WorkspacePath $javaDatabasePath
Remove-WorkspacePath $pythonDatabasePath
New-Item -ItemType Directory -Force $outputPath | Out-Null

Invoke-Checked $codeql @(
  "database", "create", $javaDatabasePath,
  "--language=java",
  "--source-root", ".",
  "--command", "javac -d build demo/src/Demo.java",
  "--overwrite"
)

Invoke-Checked $codeql @(
  "query", "run", ".\queries\crypto-inventory.ql",
  "--database", $javaDatabasePath,
  "--search-path", $searchPath,
  "--additional-packs", ".\queries",
  "--output", $javaBqrsPath
)

Invoke-Checked $codeql @(
  "bqrs", "decode",
  "--format=json",
  "--entities=string",
  "--output", $javaDecodedPath,
  "--",
  $javaBqrsPath
)

Invoke-Checked "python" @(
  "scripts\cbom.py", "from-bqrs-json", $javaDecodedPath,
  "--output", $javaInventoryPath
)

Invoke-Checked $codeql @(
  "database", "create", $pythonDatabasePath,
  "--language=python",
  "--source-root", ".",
  "--overwrite"
)

Invoke-Checked $codeql @(
  "query", "run", ".\queries-python\python-crypto-inventory.ql",
  "--database", $pythonDatabasePath,
  "--search-path", $searchPath,
  "--additional-packs", ".\queries-python",
  "--output", $pythonBqrsPath
)

Invoke-Checked $codeql @(
  "bqrs", "decode",
  "--format=json",
  "--entities=string",
  "--output", $pythonDecodedPath,
  "--",
  $pythonBqrsPath
)

Invoke-Checked "python" @(
  "scripts\cbom.py", "from-bqrs-json", $pythonDecodedPath,
  "--output", $pythonInventoryPath
)

Invoke-Checked "python" @("scripts\scan_tls_config.py", ".", "--output", $configInventoryPath)
Invoke-Checked "python" @("scripts\scan_pcap.py", "demo\pcap", "--output", $pcapInventoryPath)

Invoke-Checked "python" @(
  "scripts\cbom.py", "combine",
  $javaInventoryPath,
  $pythonInventoryPath,
  $configInventoryPath,
  $pcapInventoryPath,
  "--output", $inventoryPath,
  "--summary", $summaryPath
)

Invoke-Checked "python" @("scripts\assert_inventory.py", $inventoryPath)
Invoke-Checked "python" @("scripts\cbom.py", "summarize", $inventoryPath, "--fail-on-critical")

Write-Host "Inventory: $inventoryPath"
Write-Host "Summary:   $summaryPath"
