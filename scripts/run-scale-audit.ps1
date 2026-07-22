[CmdletBinding()]
param(
  [string]$Targets = "10000,50000,100000,1000000",
  [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $OutputPath = Join-Path $root "target\scale-audit\report.json"
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)

function Assert-PathInsideRepository([string]$Path, [string]$Label) {
  $relative = [IO.Path]::GetRelativePath($root, [IO.Path]::GetFullPath($Path))
  if ([IO.Path]::IsPathRooted($relative) -or $relative -eq ".." -or $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)")) {
    throw "$Label must stay inside the repository: $Path"
  }
}

Assert-PathInsideRepository $OutputPath "Scale report path"
$targetValues = @($Targets.Split(",", [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object {
  $parsed = 0L
  if (-not [long]::TryParse($_.Trim(), [ref]$parsed)) {
    throw "Scale target is not an integer: $_"
  }
  $parsed
})
if ($targetValues.Count -eq 0) {
  throw "At least one scale target is required."
}
$workDirectory = Join-Path $root "target\scale-audit\work"
Assert-PathInsideRepository $workDirectory "Scale work directory"
New-Item -ItemType Directory -Path (Split-Path -Parent $OutputPath) -Force | Out-Null
New-Item -ItemType Directory -Path $workDirectory -Force | Out-Null

& cargo build --locked --release -p database-memory-core --example scale-audit --features bench-support
if ($LASTEXITCODE -ne 0) {
  throw "Could not build the release scale audit binary."
}

$binaryName = if ($IsWindows) { "scale-audit.exe" } else { "scale-audit" }
$binary = Join-Path $root "target\release\examples\$binaryName"
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
  throw "Scale audit binary is missing: $binary"
}

$results = @()
foreach ($target in $targetValues) {
  if ($target -le 0 -or $target -gt 1100000) {
    throw "Scale target must be between 1 and 1100000: $target"
  }
  $cachePath = Join-Path $workDirectory "graph-$target.sqlite"
  foreach ($candidate in @($cachePath, "$cachePath-journal", "$cachePath-wal", "$cachePath-shm")) {
    Assert-PathInsideRepository $candidate "Scale cache path"
    if (Test-Path -LiteralPath $candidate) {
      Remove-Item -LiteralPath $candidate -Force
    }
  }

  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $binary
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.ArgumentList.Add("--target")
  $startInfo.ArgumentList.Add([string]$target)
  $startInfo.ArgumentList.Add("--cache-path")
  $startInfo.ArgumentList.Add($cachePath)

  $process = [Diagnostics.Process]::Start($startInfo)
  $peakWorkingSet = 0L
  $timeoutSeconds = if ($target -ge 1000000) { 1800 } elseif ($target -ge 100000) { 300 } elseif ($target -ge 50000) { 180 } else { 90 }
  $deadline = [DateTime]::UtcNow.AddSeconds($timeoutSeconds)
  while (-not $process.WaitForExit(1000)) {
    $process.Refresh()
    $peakWorkingSet = [Math]::Max($peakWorkingSet, $process.PeakWorkingSet64)
    if ([DateTime]::UtcNow -ge $deadline) {
      $process.Kill($true)
      throw "Scale target $target exceeded its $timeoutSeconds second process deadline."
    }
  }
  $process.Refresh()
  $peakWorkingSet = [Math]::Max($peakWorkingSet, $process.PeakWorkingSet64)
  $stdout = $process.StandardOutput.ReadToEnd()
  $stderr = $process.StandardError.ReadToEnd()
  if ($process.ExitCode -ne 0) {
    throw "Scale target $target failed with exit code $($process.ExitCode): $stderr"
  }
  $evidence = $stdout | ConvertFrom-Json
  $memoryBudget = 805306368L + ([long]$target * 12288L)
  $cacheBudget = 67108864L + ([long]$target * 8192L)
  if ([long]$evidence.cache_bytes -gt $cacheBudget) {
    throw "Scale target $target exceeded its cache budget: $($evidence.cache_bytes) > $cacheBudget bytes."
  }
  if ($peakWorkingSet -gt $memoryBudget) {
    throw "Scale target $target exceeded its memory budget: $peakWorkingSet > $memoryBudget bytes."
  }
  $evidence | Add-Member -NotePropertyName peak_working_set_bytes -NotePropertyValue $peakWorkingSet
  $evidence | Add-Member -NotePropertyName process_timeout_seconds -NotePropertyValue $timeoutSeconds
  $evidence | Add-Member -NotePropertyName memory_budget_bytes -NotePropertyValue $memoryBudget
  $evidence | Add-Member -NotePropertyName cache_budget_bytes -NotePropertyValue $cacheBudget
  $results += $evidence

  foreach ($candidate in @($cachePath, "$cachePath-journal", "$cachePath-wal", "$cachePath-shm")) {
    if (Test-Path -LiteralPath $candidate) {
      Remove-Item -LiteralPath $candidate -Force
    }
  }
}

$report = [ordered]@{
  contract = "database-memory-scale-audit-v1"
  generated_at_utc = [DateTime]::UtcNow.ToString("o")
  rustc = (& rustc --version)
  platform = [Runtime.InteropServices.RuntimeInformation]::OSDescription
  architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
  results = $results
}
[IO.File]::WriteAllText(
  $OutputPath,
  ($report | ConvertTo-Json -Depth 10),
  [Text.UTF8Encoding]::new($false)
)
Write-Output "PASS: scale audit completed for $($targetValues.Count) target(s)."
Write-Output "Report: $OutputPath"
