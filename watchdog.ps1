param(
  [int]$IntervalSec = 30
)

$ErrorActionPreference = 'SilentlyContinue'

$repoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logPath = Join-Path $repoDir 'logs\watchdog.log'

function Write-Log {
  param([string]$Message)
  try {
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -LiteralPath $logPath -Value "[$ts] $Message"
  } catch {}
}

# Single instance guard
$mutex = $null
try {
  $created = $false
  $mutex = New-Object System.Threading.Mutex($true, 'Global\CodexBridgeWatchdog', [ref]$created)
  if (-not $created) { return }
} catch {
  # best-effort
}

function Is-RunningByScript {
  param([string]$ScriptName, [string]$ConfigPath)
  try {
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match [regex]::Escape($ScriptName) }
    if ($ConfigPath) {
      $procs = $procs | Where-Object { $_.CommandLine -match [regex]::Escape($ConfigPath) }
    }
    return ($procs | Select-Object -First 1)
  } catch { return $null }
}

function Ensure-Process {
  param([string]$Label, [string]$ScriptPath, [string[]]$Args, [string]$ConfigPath)
  $running = Is-RunningByScript -ScriptName $ScriptPath -ConfigPath $ConfigPath
  if ($running) { return $false }
  try {
    Start-Process -FilePath pwsh -ArgumentList $Args -WorkingDirectory $repoDir -WindowStyle Hidden | Out-Null
    Write-Log "Started $Label"
    return $true
  } catch {
    Write-Log "Failed to start ${Label}: $($_.Exception.Message)"
    return $false
  }
}

$agentScript = Join-Path $repoDir 'agent.ps1'
$brokerScript = Join-Path $repoDir 'broker.ps1'
$consoleEnv = Join-Path $repoDir 'agent_console.env'

Write-Log 'Watchdog started.'

$lastStart = @{
  agent = Get-Date '1900-01-01'
  agent_console = Get-Date '1900-01-01'
  broker = Get-Date '1900-01-01'
}

while ($true) {
  if (((Get-Date) - $lastStart.agent).TotalSeconds -ge 60) {
    if (Ensure-Process -Label 'agent' -ScriptPath $agentScript -Args @('-NoProfile','-File', $agentScript)) {
      $lastStart.agent = Get-Date
    }
  }
  if (((Get-Date) - $lastStart.agent_console).TotalSeconds -ge 60) {
    if (Test-Path -LiteralPath $consoleEnv) {
      if (Ensure-Process -Label 'agent_console' -ScriptPath $agentScript -Args @('-NoProfile','-File', $agentScript, '-ConfigPath', $consoleEnv) -ConfigPath $consoleEnv) {
        $lastStart.agent_console = Get-Date
      }
    } else {
      # No console config present; don't spam restarts.
      $lastStart.agent_console = Get-Date
    }
  }
  if (((Get-Date) - $lastStart.broker).TotalSeconds -ge 60) {
    if (Ensure-Process -Label 'broker' -ScriptPath $brokerScript -Args @('-NoProfile','-File', $brokerScript)) {
      $lastStart.broker = Get-Date
    }
  }
  Start-Sleep -Seconds $IntervalSec
}
