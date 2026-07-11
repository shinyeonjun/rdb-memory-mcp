[CmdletBinding()]
param(
  [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
  $OutputDirectory = Join-Path $root "dist"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$rootPath = [IO.Path]::GetFullPath($root)
if (-not $OutputDirectory.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Release output must stay inside the repository: $OutputDirectory"
}

function Get-Sha256([string]$Path) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $algorithm = [Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
  } finally {
    $algorithm.Dispose()
    $stream.Dispose()
  }
}

$cli = Join-Path $root "target\release\database-memory.exe"
$mcp = Join-Path $root "target\release\database-memory-mcp.exe"
foreach ($path in $cli, $mcp, (Join-Path $root "README.md"), (Join-Path $root "LICENSE")) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Release input is missing: $path"
  }
}

$contract = & $cli contract --format json | ConvertFrom-Json
if ($contract.contract_version -ne 1 -or $contract.metadata_only -ne $true -or $contract.row_data_access -ne $false) {
  throw "CLI contract does not satisfy the metadata-only release boundary."
}

$stage = Join-Path $OutputDirectory "rdb-memory-mcp-windows-amd64"
$archive = Join-Path $OutputDirectory "rdb-memory-mcp-windows-amd64.zip"
$checksums = Join-Path $OutputDirectory "checksums.txt"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item -LiteralPath $cli, $mcp, (Join-Path $root "README.md"), (Join-Path $root "LICENSE") -Destination $stage

Add-Type -AssemblyName System.IO.Compression.FileSystem
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
[IO.Compression.ZipFile]::CreateFromDirectory($stage, $archive, [IO.Compression.CompressionLevel]::Optimal, $false)
$archiveHash = Get-Sha256 $archive
$cliHash = Get-Sha256 $cli
[IO.File]::WriteAllLines(
  $checksums,
  @(
    "$archiveHash  rdb-memory-mcp-windows-amd64.zip",
    "$cliHash  database-memory.exe"
  ),
  [Text.UTF8Encoding]::new($false)
)

Write-Output "PASS: release package created."
Write-Output "Archive: $archive"
Write-Output "Archive SHA256: $archiveHash"
Write-Output "CLI SHA256: $cliHash"

