param(
  [int]$IntervalSec = 30
)

$ErrorActionPreference = 'SilentlyContinue'

$repoDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logPath = Join-Path $repoDir 'logs\watchdog.log'
$disableSentinel = Join-Path $repoDir 'logs\watchdog.disabled'
$script:QuickExitCount = @{}
$script:BackoffUntil = @{}

function Is-Truthy {
  param([string]$Value)
  if (-not $Value) { return $false }
  return ($Value.Trim() -match '^(1|true|yes|y|on)$')
}

function Write-Log {
  param([string]$Message)
  try {
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -LiteralPath $logPath -Value "[$ts] $Message"
  } catch {}
}

if (Test-Path -LiteralPath $disableSentinel) {
  Write-Log ("Watchdog disabled via sentinel: {0}" -f $disableSentinel)
  return
}

$pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
if (-not $pwshPath) { $pwshPath = (Get-Command powershell -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1) }

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
    $leaf = [System.IO.Path]::GetFileName($ScriptName)
    if ($leaf -ieq 'agent.ps1') {
      $pidFiles = Get-ChildItem -Path (Join-Path $repoDir 'logs') -Filter 'agent_*.pid' -ErrorAction SilentlyContinue
      foreach ($pf in $pidFiles) {
        $pidText = (Get-Content -Raw $pf.FullName -ErrorAction SilentlyContinue).Trim()
        $procId = 0
        if ([int]::TryParse($pidText, [ref]$procId) -and $procId -gt 0) {
          try {
            if (Get-Process -Id $procId -ErrorAction Stop) { return $true }
          } catch {
            # If the process exists but is not queryable (rare), avoid restart thrash.
            # If it truly doesn't exist, Get-Process typically throws "Cannot find a process..." which we treat as not running.
            if ($_.Exception.Message -notmatch 'Cannot find a process') { return $true }
          }
        }
      }
      return $false
    }
    if ($leaf -ieq 'broker.ps1') {
      # Broker owns a named mutex; this is the most reliable single-instance signal.
      $mx = $null
      if ([System.Threading.Mutex]::TryOpenExisting('Global\CodexBridgeBroker', [ref]$mx)) {
        try { if ($mx) { $mx.Dispose() } } catch {}
        return $true
      }
      if ([System.Threading.Mutex]::TryOpenExisting('Local\CodexBridgeBroker', [ref]$mx)) {
        try { if ($mx) { $mx.Dispose() } } catch {}
        return $true
      }

      $pidFile = Join-Path $repoDir 'logs\broker.pid'
      if (Test-Path -LiteralPath $pidFile) {
        $pidText = (Get-Content -Raw $pidFile -ErrorAction SilentlyContinue).Trim()
        $procId = 0
        if ([int]::TryParse($pidText, [ref]$procId) -and $procId -gt 0) {
          try {
            if (Get-Process -Id $procId -ErrorAction Stop) { return $true }
          } catch {
            if ($_.Exception.Message -notmatch 'Cannot find a process') { return $true }
          }
        }
        try { Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue } catch {}
      }

      # Last fallback for missing pid files in mixed launch scenarios.
      try {
        $scriptPathFull = [System.IO.Path]::GetFullPath($ScriptName)
        $procs = Get-CimInstance Win32_Process -OperationTimeoutSec 2 | Where-Object {
          $_.Name -in @('pwsh.exe', 'powershell.exe') -and $_.CommandLine -and
          $_.CommandLine -match '(?i)(?:^|\s)-File\s+("([^"]+)"|''([^'']+)''|(\S+))'
        }
        foreach ($p in $procs) {
          $fileMatches = [regex]::Matches($p.CommandLine, '(?i)(?:^|\s)-File\s+("([^"]+)"|''([^'']+)''|(\S+))')
          foreach ($m in $fileMatches) {
            $candidate = $m.Groups[2].Value
            if (-not $candidate) { $candidate = $m.Groups[3].Value }
            if (-not $candidate) { $candidate = $m.Groups[4].Value }
            if (-not $candidate) { continue }
            $candidateFull = $candidate
            try { $candidateFull = [System.IO.Path]::GetFullPath($candidate) } catch {}
            if ($candidateFull -ieq $scriptPathFull) { return $true }
          }
        }
      } catch {}
      return $false
    }
  } catch {}
  return $false
}

function Is-PortListening {
  param([int]$Port)
  if ($Port -le 0) { return $false }
  try {
    $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    foreach ($ep in $listeners) {
      if ($ep.Port -eq $Port) { return $true }
    }
  } catch {}
  try {
    if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop | Select-Object -First 1) { return $true }
  } catch {}
  return ((Get-ListenPidForPort -Port $Port) -gt 0)
}

function Get-ListenPidForPort {
  param([int]$Port)
  if ($Port -le 0) { return 0 }
  try {
    foreach ($line in (& netstat.exe -ano -p tcp)) {
      if (-not $line) { continue }
      # Example:
      # TCP    0.0.0.0:8765           0.0.0.0:0              LISTENING       18960
      # TCP    [::]:8765              [::]:0                 LISTENING       18960
      if ($line -match '^\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$') {
        $p = 0
        $listenPid = 0
        if ([int]::TryParse($Matches[1], [ref]$p) -and $p -eq $Port) {
          if ([int]::TryParse($Matches[2], [ref]$listenPid) -and $listenPid -gt 0) { return $listenPid }
        }
      }
      return $false
    }
  } catch {}
  return 0
}

function Ensure-Process {
  param([string]$Label, [string]$ScriptPath, [string[]]$LaunchArgs, [string]$ConfigPath, [int]$ListenPort = 0)
  $now = Get-Date
  $backoffUntil = $script:BackoffUntil[$Label]
  if ($backoffUntil -and $now -lt $backoffUntil) { return $false }

  $listenPid = 0
  if ($ListenPort -gt 0) {
    if (Is-PortListening -Port $ListenPort) {
      # Self-heal pid files if the agent is already up (e.g. started manually or pid file was deleted/stale).
      if ($Label -eq 'agent' -or $Label -eq 'agent_console') {
        try {
          $listenPid = Get-ListenPidForPort -Port $ListenPort
          $pf = Join-Path (Join-Path $repoDir 'logs') ("agent_{0}.pid" -f $ListenPort)
          if ($listenPid -gt 0) { Set-Content -LiteralPath $pf -Value $listenPid -ErrorAction SilentlyContinue }
        } catch {}
      }
      return $false
    }
  }
  $running = Is-RunningByScript -ScriptName $ScriptPath -ConfigPath $ConfigPath
  if ($running) { return $false }
  try {
    if (-not $pwshPath) { Write-Log 'Failed to locate pwsh or powershell'; return $false }
    Write-Log ("Restarting {0}: listenPort={1} listenPid={2} running={3}" -f $Label, $ListenPort, $listenPid, $running)
    $stdoutPath = Join-Path $repoDir ("logs\watchdog_{0}.stdout.log" -f $Label)
    $stderrPath = Join-Path $repoDir ("logs\watchdog_{0}.stderr.log" -f $Label)
    $proc = Start-Process -FilePath $pwshPath -ArgumentList $LaunchArgs -WorkingDirectory $repoDir -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
    Start-Sleep -Milliseconds 800
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) {
      $count = 0
      if ($script:QuickExitCount.ContainsKey($Label)) { $count = [int]$script:QuickExitCount[$Label] }
      $count++
      $script:QuickExitCount[$Label] = $count
      if ($count -ge 3) {
        $until = (Get-Date).AddMinutes(5)
        $script:BackoffUntil[$Label] = $until
        Write-Log ("Backoff for {0} until {1:yyyy-MM-dd HH:mm:ss} after {2} quick exits." -f $Label, $until, $count)
      }
      Write-Log "Launch for $Label exited quickly (pid=$($proc.Id), exit=$($proc.ExitCode)). stderr=$stderrPath"
      return $false
    }
    $script:QuickExitCount[$Label] = 0
    $script:BackoffUntil[$Label] = $null
    Write-Log "Started $Label (pid=$($proc.Id))"
    return $true
  } catch {
    Write-Log "Failed to start ${Label}: $($_.Exception.Message)"
    return $false
  }
}

$agentScript = Join-Path $repoDir 'agent.ps1'
$brokerScript = Join-Path $repoDir 'broker.ps1'
$consoleEnv = Join-Path $repoDir 'agent_console.env'

Write-Log ("Watchdog started. repoDir={0}" -f $repoDir)
try {
  $logsDir = Join-Path $repoDir 'logs'
  $agentPids = Get-ChildItem -Path $logsDir -Filter 'agent_*.pid' -ErrorAction SilentlyContinue
  foreach ($pf in $agentPids) {
    $v = (Get-Content -Raw $pf.FullName -ErrorAction SilentlyContinue).Trim()
    Write-Log ("Found pid file {0}={1}" -f $pf.Name, $v)
  }
  $brokerPidFile = Join-Path $logsDir 'broker.pid'
  if (Test-Path -LiteralPath $brokerPidFile) {
    $v = (Get-Content -Raw $brokerPidFile -ErrorAction SilentlyContinue).Trim()
    Write-Log ("Found pid file broker.pid={0}" -f $v)
  }
} catch {}

$startConsoleAgent = $false
if ($env:TELEBOT_WATCHDOG_START_CONSOLE_AGENT) {
  $startConsoleAgent = Is-Truthy -Value $env:TELEBOT_WATCHDOG_START_CONSOLE_AGENT
}

while ($true) {
  Ensure-Process -Label 'agent' -ScriptPath $agentScript -LaunchArgs @('-NoProfile','-File', $agentScript) -ListenPort 8765 | Out-Null

  # Console agent is opt-in; it can spawn visible terminals and can thrash if misconfigured.
  if ($startConsoleAgent -and (Test-Path -LiteralPath $consoleEnv)) {
    Ensure-Process -Label 'agent_console' -ScriptPath $agentScript -LaunchArgs @('-NoProfile','-File', $agentScript, '-ConfigPath', $consoleEnv) -ConfigPath $consoleEnv -ListenPort 8766 | Out-Null
  }

  Ensure-Process -Label 'broker' -ScriptPath $brokerScript -LaunchArgs @('-NoProfile','-File', $brokerScript) | Out-Null
  Start-Sleep -Seconds $IntervalSec
}
