[CmdletBinding()]
param(
  [ValidateSet("auto", "windows-amd64", "linux-amd64")]
  [string]$Platform = "auto",
  [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
  $OutputDirectory = Join-Path $root "dist"
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

function Assert-PathInsideRepository([string]$Path, [string]$Label) {
  $relative = [IO.Path]::GetRelativePath($root, [IO.Path]::GetFullPath($Path))
  $separator = [IO.Path]::DirectorySeparatorChar
  $alternate = [IO.Path]::AltDirectorySeparatorChar
  if (
    [IO.Path]::IsPathRooted($relative) -or
    $relative -eq ".." -or
    $relative.StartsWith("..$separator") -or
    $relative.StartsWith("..$alternate")
  ) {
    throw "$Label must stay inside the repository: $Path"
  }
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

function Invoke-Contract([string]$CliPath) {
  $json = & $CliPath contract --format json
  if ($LASTEXITCODE -ne 0) {
    throw "Packaged CLI contract command failed: $CliPath"
  }
  $contract = $json | ConvertFrom-Json
  $outcomes = @($contract.authoritative_outcomes)
  if (
    $contract.contract_version -ne 2 -or
    $contract.complete_snapshot_contract_version -ne 2 -or
    $contract.metadata_only -ne $true -or
    $contract.row_data_access -ne $false -or
    $outcomes.Count -ne 2 -or
    $outcomes[0] -ne "complete" -or
    $outcomes[1] -ne "failed" -or
    @($contract.support).Count -eq 0
  ) {
    throw "CLI contract does not satisfy the complete metadata-only release boundary."
  }
  return [ordered]@{
    Json = ($json -join [Environment]::NewLine)
    Value = $contract
  }
}

$runningOnWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
  [Runtime.InteropServices.OSPlatform]::Windows
)
$runningOnLinux = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
  [Runtime.InteropServices.OSPlatform]::Linux
)
$runningArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($runningArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
  throw "amd64 release packaging requires an X64 host; detected $runningArchitecture."
}
if ($Platform -eq "auto") {
  if ($runningOnWindows) {
    $Platform = "windows-amd64"
  } elseif ($runningOnLinux) {
    $Platform = "linux-amd64"
  } else {
    throw "Automatic release packaging supports Windows and Linux hosts only."
  }
}
if (
  ($Platform -eq "windows-amd64" -and -not $runningOnWindows) -or
  ($Platform -eq "linux-amd64" -and -not $runningOnLinux)
) {
  throw "Platform '$Platform' must be packaged on its matching host OS."
}

Assert-PathInsideRepository $OutputDirectory "Release output"
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$binaryExtension = if ($runningOnWindows) { ".exe" } else { "" }
$cliName = "database-memory$binaryExtension"
$mcpName = "database-memory-mcp$binaryExtension"
$cli = Join-Path $root "target/release/$cliName"
$mcp = Join-Path $root "target/release/$mcpName"
$readme = Join-Path $root "README.md"
$license = Join-Path $root "LICENSE"
$install = Join-Path $root "docs/install.md"
foreach ($path in @($cli, $mcp, $readme, $license, $install)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Release input is missing: $path"
  }
}

$contract = Invoke-Contract $cli
$packageName = "rdb-memory-mcp-$Platform"
$stage = [IO.Path]::GetFullPath((Join-Path $OutputDirectory $packageName))
$verify = [IO.Path]::GetFullPath((Join-Path $OutputDirectory "$packageName-verify"))
$archiveName = if ($runningOnWindows) { "$packageName.zip" } else { "$packageName.tar.gz" }
$archive = [IO.Path]::GetFullPath((Join-Path $OutputDirectory $archiveName))
$checksumsName = "checksums-$Platform.txt"
$checksums = [IO.Path]::GetFullPath((Join-Path $OutputDirectory $checksumsName))
foreach ($path in @($stage, $verify, $archive, $checksums)) {
  Assert-PathInsideRepository $path "Release artifact path"
}
foreach ($directory in @($stage, $verify)) {
  if (Test-Path -LiteralPath $directory) {
    Remove-Item -LiteralPath $directory -Recurse -Force
  }
}
foreach ($file in @($archive, $checksums)) {
  if (Test-Path -LiteralPath $file) {
    Remove-Item -LiteralPath $file -Force
  }
}

New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item -LiteralPath @($cli, $mcp, $readme, $license, $install) -Destination $stage
$supportLedger = Join-Path $stage "support-ledger.json"
[IO.File]::WriteAllText($supportLedger, "$($contract.Json)$([Environment]::NewLine)", [Text.UTF8Encoding]::new($false))
$manifest = [ordered]@{
  product = $contract.Value.product
  version = $contract.Value.version
  platform = $Platform
  contract_version = $contract.Value.contract_version
  complete_snapshot_contract_version = $contract.Value.complete_snapshot_contract_version
  metadata_only = $true
  row_data_access = $false
  files = @(
    [ordered]@{ name = $cliName; sha256 = (Get-Sha256 (Join-Path $stage $cliName)) },
    [ordered]@{ name = $mcpName; sha256 = (Get-Sha256 (Join-Path $stage $mcpName)) },
    [ordered]@{ name = "support-ledger.json"; sha256 = (Get-Sha256 $supportLedger) }
  )
}
$manifestPath = Join-Path $stage "manifest.json"
[IO.File]::WriteAllText(
  $manifestPath,
  ($manifest | ConvertTo-Json -Depth 10),
  [Text.UTF8Encoding]::new($false)
)

if ($runningOnWindows) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [IO.Compression.ZipFile]::CreateFromDirectory(
    $stage,
    $archive,
    [IO.Compression.CompressionLevel]::Optimal,
    $false
  )
  [IO.Compression.ZipFile]::ExtractToDirectory($archive, $verify)
} else {
  & tar -czf $archive -C $stage .
  if ($LASTEXITCODE -ne 0) {
    throw "Could not create Linux release archive."
  }
  New-Item -ItemType Directory -Path $verify -Force | Out-Null
  & tar -xzf $archive -C $verify
  if ($LASTEXITCODE -ne 0) {
    throw "Could not extract Linux release archive."
  }
}

$verifiedContract = Invoke-Contract (Join-Path $verify $cliName)
if ($verifiedContract.Value.version -ne $contract.Value.version) {
  throw "Extracted CLI version does not match the staged release."
}
$verifiedManifest = Get-Content -LiteralPath (Join-Path $verify "manifest.json") -Raw | ConvertFrom-Json
foreach ($file in @($verifiedManifest.files)) {
  $verifiedPath = Join-Path $verify $file.name
  if (-not (Test-Path -LiteralPath $verifiedPath -PathType Leaf)) {
    throw "Extracted package is missing '$($file.name)'."
  }
  if ((Get-Sha256 $verifiedPath) -ne $file.sha256) {
    throw "Extracted package checksum failed for '$($file.name)'."
  }
}

$archiveHash = Get-Sha256 $archive
[IO.File]::WriteAllText(
  $checksums,
  "$archiveHash  $archiveName$([Environment]::NewLine)",
  [Text.UTF8Encoding]::new($false)
)
if ((Get-Sha256 $archive) -ne $archiveHash) {
  throw "Release archive changed while writing its checksum."
}

Remove-Item -LiteralPath $stage -Recurse -Force
Remove-Item -LiteralPath $verify -Recurse -Force
Write-Output "PASS: release package created and extracted contract verified."
Write-Output "Platform: $Platform"
Write-Output "Archive: $archive"
Write-Output "Archive SHA256: $archiveHash"
Write-Output "Checksums: $checksums"
