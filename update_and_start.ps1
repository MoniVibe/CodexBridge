param(
  [string]$RepoDir = $PSScriptRoot,
  [switch]$SkipPull,
  [ValidateSet('auto','agent','broker','both')]
  [string]$Role = 'auto',
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

# Broker autostart guard:
# - Desktop defaults to on
# - Laptop defaults to off
# Override with TELEBOT_AUTOSTART=1 or -Force.
$autostart = $env:TELEBOT_AUTOSTART
if (-not $autostart) {
  if ($env:COMPUTERNAME -ieq 'DESKTOP-9VVJV75') { $autostart = '1' } else { $autostart = '0' }
}
$allowBroker = $Force -or ($autostart -match '^(1|true|yes)$')

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
  param([string]$ScriptPath, [string]$PidFile = $null)
  if (-not (Test-Path -LiteralPath $ScriptPath)) { return }

  # Prefer PID files over WMI/CIM (CommandLine queries can hang when the machine is under process thrash).
  if ($PidFile -and (Test-Path -LiteralPath $PidFile)) {
    try {
      $pidText = (Get-Content -LiteralPath $PidFile -Raw -ErrorAction Stop).Trim()
      $procId = 0
      if ([int]::TryParse($pidText, [ref]$procId) -and $procId -gt 0) {
        try { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } catch {}
      }
    } catch {}
  }

  # Best-effort fallback: attempt a bounded CIM scan.
  try {
    $procs = Get-CimInstance Win32_Process -OperationTimeoutSec 2 | Where-Object { $_.CommandLine -like "*$ScriptPath*" }
    foreach ($p in $procs) {
      try { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
    }
  } catch {}

  $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
  if (-not $pwsh) { $pwsh = (Get-Command powershell -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1) }
  if (-not $pwsh) { throw 'pwsh or powershell not found.' }

  $visible = $false
  if ($env:TELEBOT_VISIBLE) { $visible = ($env:TELEBOT_VISIBLE -match '^(1|true|yes)$') }
  $ws = if ($visible) { 'Normal' } else { 'Hidden' }

  $logs = Join-Path $RepoDir 'logs'
  try { New-Item -ItemType Directory -Force -Path $logs | Out-Null } catch {}
  $base = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
  $stdout = Join-Path $logs "${base}.service.stdout.log"
  $stderr = Join-Path $logs "${base}.service.stderr.log"

  $p = @{
    FilePath = $pwsh
    WorkingDirectory = $RepoDir
    WindowStyle = $ws
    ArgumentList = @('-NoProfile','-File', $ScriptPath)
  }

  # When running hidden/background, redirect stdout/stderr so no console windows or hangs.
  if (-not $visible) {
    $p.RedirectStandardOutput = $stdout
    $p.RedirectStandardError = $stderr
  }

  Start-Process @p | Out-Null
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

# Laptop default: never autostart the broker unless explicitly overridden.
if ($runBroker -and -not $allowBroker) {
  Write-Host "update_and_start: broker suppressed (TELEBOT_AUTOSTART=0). Use -Force or set TELEBOT_AUTOSTART=1 to start the broker."
  $runBroker = $false
}

# If this machine should not run the broker, stop any stray broker instance to avoid Telegram 409 conflicts.
if (-not $runBroker) {
  $logs = Join-Path $RepoDir 'logs'
  $pidFile = Join-Path $logs 'broker.pid'
  if (Test-Path -LiteralPath $pidFile) {
    try {
      $pidText = (Get-Content -LiteralPath $pidFile -Raw -ErrorAction Stop).Trim()
      $procId = 0
      if ([int]::TryParse($pidText, [ref]$procId) -and $procId -gt 0) {
        try { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } catch {}
      }
    } catch {}
  }
}

$logs = Join-Path $RepoDir 'logs'
try { New-Item -ItemType Directory -Force -Path $logs | Out-Null } catch {}
$brokerPidFile = Join-Path $logs 'broker.pid'
$agentPort = 8765
try {
  $p = Get-EnvValueFromFile -Path $agentEnv -Key 'LISTEN_PORT'
  if ($p -and $p -match '^\\d+$') { $agentPort = [int]$p }
} catch {}
$agentPidFile = Join-Path $logs ("agent_{0}.pid" -f $agentPort)

if ($runBroker) { Restart-ByScriptPath -ScriptPath $brokerScript -PidFile $brokerPidFile }
if ($runAgent) { Restart-ByScriptPath -ScriptPath $agentScript -PidFile $agentPidFile }
