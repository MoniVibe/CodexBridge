param(
  [Parameter(Mandatory = $true)] [string] $Command,
  [Parameter(Mandatory = $true)] [string] $Cwd,
  [Parameter(Mandatory = $true)] [string] $LogPath,
  [Parameter(Mandatory = $true)] [string] $ExitPath
)

$ErrorActionPreference = 'Continue'

try {
  if (-not (Test-Path -LiteralPath $Cwd)) {
    throw "CWD not found: $Cwd"
  }

  Push-Location -LiteralPath $Cwd
  try {
    Invoke-Expression $Command 2>&1 | Tee-Object -FilePath $LogPath -Append
    $ec = if ($LASTEXITCODE -ne $null) { $LASTEXITCODE } else { 0 }
  } catch {
    $_ | Out-String | Tee-Object -FilePath $LogPath -Append
    $ec = 1
  } finally {
    Pop-Location
  }
} catch {
  $_ | Out-String | Tee-Object -FilePath $LogPath -Append
  $ec = 1
}

try {
  Set-Content -LiteralPath $ExitPath -Value $ec
} catch {
  # Ignore exit write failures
}
