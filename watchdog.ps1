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
    $filePattern = '(?i)(?:^|\s)-File\s+("([^"]+)"|''([^'']+)''|(\S+))'
    $cfgPattern = '(?i)(?:^|\s)-ConfigPath\s+("([^"]+)"|''([^'']+)''|(\S+))'
    $procs = Get-CimInstance Win32_Process | Where-Object {
      if (-not $_.CommandLine) { return $false }
      if ($_.Name -notin @('pwsh.exe', 'powershell.exe')) { return $false }

      $fileOk = $false
      $fileMatches = [regex]::Matches($_.CommandLine, $filePattern)
      foreach ($m in $fileMatches) {
        $candidate = $m.Groups[2].Value
        if (-not $candidate) { $candidate = $m.Groups[3].Value }
        if (-not $candidate) { $candidate = $m.Groups[4].Value }
        if ($candidate -and $candidate.Trim() -ieq $ScriptName) {
          $fileOk = $true
          break
        }
      }
      if (-not $fileOk) { return $false }

      if (-not $ConfigPath) { return $true }

      $cfgMatches = [regex]::Matches($_.CommandLine, $cfgPattern)
      foreach ($m in $cfgMatches) {
        $candidate = $m.Groups[2].Value
        if (-not $candidate) { $candidate = $m.Groups[3].Value }
        if (-not $candidate) { $candidate = $m.Groups[4].Value }
        if ($candidate -and $candidate.Trim() -ieq $ConfigPath) {
          return $true
        }
      }
      return $false
    }
    return ($procs | Select-Object -First 1)
  } catch { return $null }
}

function Ensure-Process {
  param([string]$Label, [string]$ScriptPath, [string[]]$LaunchArgs, [string]$ConfigPath)
  $running = Is-RunningByScript -ScriptName $ScriptPath -ConfigPath $ConfigPath
  if ($running) { return $false }
  try {
    $stdoutPath = Join-Path $repoDir ("logs\watchdog_{0}.stdout.log" -f $Label)
    $stderrPath = Join-Path $repoDir ("logs\watchdog_{0}.stderr.log" -f $Label)
    $proc = Start-Process -FilePath pwsh -ArgumentList $LaunchArgs -WorkingDirectory $repoDir -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
    Start-Sleep -Milliseconds 800
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) {
      Write-Log "Launch for $Label exited quickly (pid=$($proc.Id), exit=$($proc.ExitCode)). stderr=$stderrPath"
      return $false
    }
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

Write-Log 'Watchdog started.'

while ($true) {
  Ensure-Process -Label 'agent' -ScriptPath $agentScript -LaunchArgs @('-NoProfile','-File', $agentScript) | Out-Null

  if (Test-Path -LiteralPath $consoleEnv) {
    Ensure-Process -Label 'agent_console' -ScriptPath $agentScript -LaunchArgs @('-NoProfile','-File', $agentScript, '-ConfigPath', $consoleEnv) -ConfigPath $consoleEnv | Out-Null
  }

  Ensure-Process -Label 'broker' -ScriptPath $brokerScript -LaunchArgs @('-NoProfile','-File', $brokerScript) | Out-Null
  Start-Sleep -Seconds $IntervalSec
}
