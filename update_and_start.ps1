param(
  [string]$RepoDir = $PSScriptRoot,
  [switch]$SkipPull,
  [ValidateSet('auto','agent','broker','both')]
  [string]$Role = 'auto'
)

$ErrorActionPreference = 'Stop'

function Get-Secret {
  param([string]$SecretFile)
  if (Test-Path -LiteralPath $SecretFile) {
    $line = Get-Content -LiteralPath $SecretFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '^AGENT_SECRET=' } | Select-Object -First 1
    if ($line) { return ($line -replace '^AGENT_SECRET=', '').Trim() }
  }
  if ($env:CODEXBRIDGE_AGENT_SECRET) { return $env:CODEXBRIDGE_AGENT_SECRET }
  if ($env:TELEBOT_AGENT_SECRET) { return $env:TELEBOT_AGENT_SECRET }
  return $null
}

function Set-EnvSecret {
  param([string]$Path, [string]$Secret)
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $lines = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
  $found = $false
  $updated = $lines | ForEach-Object {
    if ($_ -match '^AGENT_SECRET=') { $found = $true; "AGENT_SECRET=$Secret" } else { $_ }
  }
  if (-not $found) { $updated += "AGENT_SECRET=$Secret" }
  Set-Content -LiteralPath $Path -Value $updated
}

function Get-EnvValueFromFile {
  param([string]$Path, [string]$Key)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  $line = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue | Where-Object { $_ -match ("^" + [regex]::Escape($Key) + "=") } | Select-Object -First 1
  if (-not $line) { return $null }
  return ($line -replace ("^" + [regex]::Escape($Key) + "="), '').Trim()
}

function Restart-ByScriptPath {
  param([string]$ScriptPath)
  if (-not (Test-Path -LiteralPath $ScriptPath)) { return }

  $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*$ScriptPath*" }
  foreach ($p in $procs) {
    try { Stop-Process -Id $p.ProcessId -Force } catch {}
  }

  $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
  if (-not $pwsh) { $pwsh = (Get-Command powershell -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1) }
  if (-not $pwsh) { throw 'pwsh or powershell not found.' }

  Start-Process -FilePath $pwsh -ArgumentList "-NoProfile -File `"$ScriptPath`""
}

$legacyBotScript = Join-Path $RepoDir 'bot.ps1'
$secretFile = Join-Path $RepoDir 'secret.env'
$agentEnv = Join-Path $RepoDir 'agent.env'
$brokerEnv = Join-Path $RepoDir 'broker.env'
$agentScript = Join-Path $RepoDir 'agent.ps1'
$brokerScript = Join-Path $RepoDir 'broker.ps1'

if (-not $SkipPull) {
  try {
    if (Test-Path -LiteralPath (Join-Path $RepoDir '.git')) {
      git -C $RepoDir fetch origin | Out-Null
      git -C $RepoDir pull --rebase origin main | Out-Null
    }
  } catch {
    Write-Host "update_and_start: git pull failed: $($_.Exception.Message)"
  }
}

$secret = Get-Secret -SecretFile $secretFile
if ($secret) {
  Set-EnvSecret -Path $agentEnv -Secret $secret
  Set-EnvSecret -Path $brokerEnv -Secret $secret
}

$runAgent = $false
$runBroker = $false

# Always stop any legacy polling bot (it conflicts with broker getUpdates and causes 409s).
if (Test-Path -LiteralPath $legacyBotScript) {
  $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*$legacyBotScript*" }
  foreach ($p in $procs) {
    try { Stop-Process -Id $p.ProcessId -Force } catch {}
  }
}

switch ($Role.ToLowerInvariant()) {
  'agent' { $runAgent = $true }
  'broker' { $runBroker = $true }
  'both' { $runAgent = $true; $runBroker = $true }
  default {
    $runAgent = $true

    $tgToken = Get-EnvValueFromFile -Path $brokerEnv -Key 'TG_BOT_TOKEN'
    $hasBrokerCfg = [bool]($tgToken -and $tgToken.Trim())

    # With the "one broker per machine" setup: start broker whenever broker.env is populated.
    if ($hasBrokerCfg) { $runBroker = $true }
  }
}

# If this machine should not run the broker, stop any stray broker instance to avoid Telegram 409 conflicts.
if (-not $runBroker) {
  $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*$brokerScript*" }
  foreach ($p in $procs) {
    try { Stop-Process -Id $p.ProcessId -Force } catch {}
  }
}

if ($runBroker) { Restart-ByScriptPath -ScriptPath $brokerScript }
if ($runAgent) { Restart-ByScriptPath -ScriptPath $agentScript }
