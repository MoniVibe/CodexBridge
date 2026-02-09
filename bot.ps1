param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.env')
)

$ErrorActionPreference = 'Stop'

function Import-DotEnv {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $lines = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
  foreach ($line in $lines) {
    $trim = $line.Trim()
    if (-not $trim) { continue }
    if ($trim.StartsWith('#')) { continue }
    $idx = $trim.IndexOf('=')
    if ($idx -lt 1) { continue }
    $key = $trim.Substring(0, $idx).Trim()
    $val = $trim.Substring($idx + 1).Trim()
    if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'" ) -and $val.EndsWith("'"))) {
      $val = $val.Substring(1, $val.Length - 2)
    }
    if ($key) { Set-Item -Path "env:$key" -Value $val }
  }
}

function Get-Config {
  param([string]$ConfigPath)

  $cfg = [ordered]@{
    BotToken = $null
    ChatIds = @()
    Secret = $null
    Root = $PSScriptRoot
    LogDir = (Join-Path $PSScriptRoot 'logs')
    StateFile = (Join-Path $PSScriptRoot 'state.json')
    JobsFile = (Join-Path $PSScriptRoot 'jobs.json')
    RunnerPath = (Join-Path $PSScriptRoot 'runner.ps1')
    DefaultCwd = 'C:\\dev\\unity_clean'
    AllowPrefixes = @('git','pwsh','python','dotnet','cmd','C:\\dev\\unity_clean')
    MaxMessageChars = 3500
    TailLines = 80
    PollTimeoutSec = 20
    BotLog = (Join-Path $PSScriptRoot 'bot.log')
  }

  Import-DotEnv -Path $ConfigPath

  if ($env:TG_BOT_TOKEN) { $cfg.BotToken = $env:TG_BOT_TOKEN }
  if ($env:TG_CHAT_ID) {
    $cfg.ChatIds = $env:TG_CHAT_ID.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  }
  if ($env:TG_SECRET) { $cfg.Secret = $env:TG_SECRET }
  if ($env:DEFAULT_CWD) { $cfg.DefaultCwd = $env:DEFAULT_CWD }
  if ($env:ALLOW_PREFIXES) {
    $cfg.AllowPrefixes = $env:ALLOW_PREFIXES.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  }
  if ($env:MAX_OUTPUT_CHARS) { $cfg.MaxMessageChars = [int]$env:MAX_OUTPUT_CHARS }
  if ($env:TAIL_LINES) { $cfg.TailLines = [int]$env:TAIL_LINES }
  if ($env:POLL_TIMEOUT_SEC) { $cfg.PollTimeoutSec = [int]$env:POLL_TIMEOUT_SEC }

  if (-not $cfg.BotToken) {
    throw 'TG_BOT_TOKEN missing. Set it in config.env.'
  }
  if (-not $cfg.ChatIds -or $cfg.ChatIds.Count -eq 0) {
    throw 'TG_CHAT_ID missing. Set it in config.env.'
  }
  if (-not (Test-Path -LiteralPath $cfg.RunnerPath)) {
    throw "runner.ps1 missing at $($cfg.RunnerPath)"
  }

  New-Item -ItemType Directory -Force -Path $cfg.LogDir | Out-Null

  $cfg.PwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
  if (-not $cfg.PwshPath) {
    $cfg.PwshPath = (Get-Command powershell -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
  }
  if (-not $cfg.PwshPath) {
    throw 'pwsh or powershell not found in PATH.'
  }

  return $cfg
}

function Write-BotLog {
  param([string]$Path, [string]$Message)
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  try {
    Add-Content -LiteralPath $Path -Value "[$ts] $Message"
  } catch {}
}

function Load-State {
  param($cfg)
  if (Test-Path -LiteralPath $cfg.StateFile) {
    try {
      $obj = Get-Content -LiteralPath $cfg.StateFile -Raw | ConvertFrom-Json
      if (-not $obj.default_cwd) { $obj | Add-Member -NotePropertyName default_cwd -NotePropertyValue $cfg.DefaultCwd -Force }
      return $obj
    } catch {}
  }
  return [ordered]@{ last_update_id = 0; default_cwd = $cfg.DefaultCwd; last_job_id = $null }
}

function Save-State {
  param($cfg, $state)
  $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cfg.StateFile
}

function Load-Jobs {
  param($cfg)
  if (Test-Path -LiteralPath $cfg.JobsFile) {
    try {
      return Get-Content -LiteralPath $cfg.JobsFile -Raw | ConvertFrom-Json
    } catch {}
  }
  return @()
}

function Save-Jobs {
  param($cfg, $jobs)
  $jobs | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cfg.JobsFile
}

function Send-TgMessage {
  param($cfg, [string]$ChatId, [string]$Text)
  if (-not $Text) { $Text = '(empty)' }
  $uri = "https://api.telegram.org/bot$($cfg.BotToken)/sendMessage"
  $body = @{ chat_id = $ChatId; text = $Text; disable_web_page_preview = $true }
  try {
    Invoke-RestMethod -Method Post -Uri $uri -Body $body | Out-Null
  } catch {
    Write-BotLog -Path $cfg.BotLog -Message "sendMessage failed: $($_.Exception.Message)"
  }
}

function Send-ChunkedText {
  param($cfg, [string]$ChatId, [string]$Text)
  $max = $cfg.MaxMessageChars
  if ($Text.Length -le $max) {
    Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $Text
    return
  }
  $lines = $Text -split "`n"
  $buffer = ''
  foreach ($line in $lines) {
    $candidate = if ($buffer) { $buffer + "`n" + $line } else { $line }
    if ($candidate.Length -gt $max) {
      if ($buffer) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $buffer }
      $buffer = $line
    } else {
      $buffer = $candidate
    }
  }
  if ($buffer) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $buffer }
}

function Get-TgUpdates {
  param($cfg, [int]$Offset)
  $uri = "https://api.telegram.org/bot$($cfg.BotToken)/getUpdates"
  $body = @{ timeout = $cfg.PollTimeoutSec; offset = $Offset }
  try {
    return Invoke-RestMethod -Method Post -Uri $uri -Body $body
  } catch {
    Write-BotLog -Path $cfg.BotLog -Message "getUpdates failed: $($_.Exception.Message)"
    return @{ ok = $false; result = @() }
  }
}

function Is-AllowedChat {
  param($cfg, [string]$ChatId)
  if (-not $cfg.ChatIds -or $cfg.ChatIds.Count -eq 0) { return $true }
  return $cfg.ChatIds -contains $ChatId
}

function Unquote {
  param([string]$Value)
  if (-not $Value) { return $Value }
  if (($Value.StartsWith('"') -and $Value.EndsWith('"')) -or ($Value.StartsWith("'") -and $Value.EndsWith("'"))) {
    return $Value.Substring(1, $Value.Length - 2)
  }
  return $Value
}

function Get-FirstToken {
  param([string]$Command)
  if ($Command -match '^\s*("[^"]+"|''[^'']+''|\S+)') {
    return Unquote $Matches[1]
  }
  return $null
}

function Is-AllowedCommand {
  param($cfg, [string]$Exe)
  if (-not $Exe) { return $false }
  $exeNorm = $Exe.Trim()
  $isPath = ($exeNorm -match '^[A-Za-z]:\\') -or $exeNorm.StartsWith('.\\') -or $exeNorm.StartsWith('..\\') -or $exeNorm.StartsWith('\\')

  foreach ($a in $cfg.AllowPrefixes) {
    $allow = $a.Trim()
    if (-not $allow) { continue }
    if ($allow -eq '*') { return $true }
    if ($isPath) {
      if ($allow.EndsWith('*')) {
        $prefix = $allow.TrimEnd('*')
        if ($exeNorm.StartsWith($prefix, $true, [System.Globalization.CultureInfo]::InvariantCulture)) { return $true }
      } elseif ($exeNorm.StartsWith($allow, $true, [System.Globalization.CultureInfo]::InvariantCulture)) { return $true }
    } else {
      if ($exeNorm.Equals($allow, [System.StringComparison]::InvariantCultureIgnoreCase)) { return $true }
      if ($exeNorm.Equals("$allow.exe", [System.StringComparison]::InvariantCultureIgnoreCase)) { return $true }
    }
  }
  return $false
}

function New-JobId {
  $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
  $rand = Get-Random -Minimum 1000 -Maximum 9999
  return "${ts}_${rand}"
}

function Get-LogTail {
  param([string]$LogPath, [int]$Lines)
  if (-not (Test-Path -LiteralPath $LogPath)) { return '(log missing)' }
  $content = Get-Content -LiteralPath $LogPath -Tail $Lines -ErrorAction SilentlyContinue
  return ($content -join "`n")
}

function Start-RemoteJob {
  param($cfg, $state, $jobs, [string]$ChatId, [string]$Command, [string]$Cwd)

  $jobId = New-JobId
  $logPath = Join-Path $cfg.LogDir "$jobId.log"
  $exitPath = Join-Path $cfg.LogDir "$jobId.exit"

  $argList = @('-NoProfile','-File', $cfg.RunnerPath, '-Command', $Command, '-Cwd', $Cwd, '-LogPath', $logPath, '-ExitPath', $exitPath)
  $proc = Start-Process -FilePath $cfg.PwshPath -ArgumentList $argList -PassThru -WindowStyle Hidden

  $job = [ordered]@{
    id = $jobId
    cmd = $Command
    cwd = $Cwd
    log = $logPath
    exit = $exitPath
    pid = $proc.Id
    start = (Get-Date).ToString('o')
    status = 'running'
    exit_code = $null
    completed = $null
    notified = $false
    chat_id = $ChatId
  }

  $jobs += $job
  $state.last_job_id = $jobId

  Save-Jobs -cfg $cfg -jobs $jobs
  Save-State -cfg $cfg -state $state

  return $job
}

function Refresh-Jobs {
  param($cfg, $jobs)

  for ($i = 0; $i -lt $jobs.Count; $i++) {
    $job = $jobs[$i]
    if ($job.status -eq 'running') {
      if (Test-Path -LiteralPath $job.exit) {
        try {
          $exitCode = Get-Content -LiteralPath $job.exit -TotalCount 1
          $job.exit_code = [int]$exitCode
        } catch {
          $job.exit_code = 1
        }
        $job.status = if ($job.exit_code -eq 0) { 'done' } else { 'failed' }
        $job.completed = (Get-Date).ToString('o')
      }
    }
    $jobs[$i] = $job
  }

  return $jobs
}

function Notify-CompletedJobs {
  param($cfg, $jobs)

  for ($i = 0; $i -lt $jobs.Count; $i++) {
    $job = $jobs[$i]
    if (($job.status -eq 'done' -or $job.status -eq 'failed') -and (-not $job.notified)) {
      $tail = Get-LogTail -LogPath $job.log -Lines $cfg.TailLines
      $msg = "Job $($job.id) finished (exit $($job.exit_code)).`n" + $tail
      Send-ChunkedText -cfg $cfg -ChatId $job.chat_id -Text $msg
      $job.notified = $true
      $jobs[$i] = $job
    }
  }

  return $jobs
}

function Handle-Command {
  param($cfg, $state, $jobs, [string]$ChatId, [string]$Text)

  $clean = $Text.Trim()
  if (-not $clean) { return $jobs }
  if ($clean.StartsWith('/')) { $clean = $clean.Substring(1) }

  $parts = $clean -split '\s+', 2
  $cmd = $parts[0].ToLowerInvariant()
  $args = if ($parts.Count -gt 1) { $parts[1] } else { '' }

  switch ($cmd) {
    'help' {
      $msg = "Commands: help, run, status, jobs, last, tail <id> [lines], get <id>, setcwd <path>, pwd, kill <id>"
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $msg
      return $jobs
    }
    'status' {
      $running = @($jobs | Where-Object { $_.status -eq 'running' }).Count
      $msg = "Bot OK. Default CWD: $($state.default_cwd). Running jobs: $running"
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $msg
      return $jobs
    }
    'jobs' {
      $runningJobs = $jobs | Where-Object { $_.status -eq 'running' }
      if (-not $runningJobs) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'No running jobs.'
      } else {
        $lines = $runningJobs | ForEach-Object { "$($_.id) | pid $($_.pid) | $($_.cmd)" }
        Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text ($lines -join "`n")
      }
      return $jobs
    }
    'pwd' {
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $state.default_cwd
      return $jobs
    }
    'setcwd' {
      if (-not $args) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: setcwd C:\\path'
        return $jobs
      }
      $path = Unquote $args
      if (-not (Test-Path -LiteralPath $path)) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Path not found: $path"
        return $jobs
      }
      $state.default_cwd = $path
      Save-State -cfg $cfg -state $state
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Default CWD set to $path"
      return $jobs
    }

    'last' {
      $lines = $cfg.TailLines
      if ($args -match '^\d+$') { $lines = [int]$args }
      if (-not $state.last_job_id) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'No job history.'
        return $jobs
      }
      $job = $jobs | Where-Object { $_.id -eq $state.last_job_id } | Select-Object -First 1
      if (-not $job) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Last job not found.'
        return $jobs
      }
      $tail = Get-LogTail -LogPath $job.log -Lines $lines
      $msg = "Job $($job.id) (status $($job.status), exit $($job.exit_code))`n" + $tail
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $msg
      return $jobs
    }
    'tail' {
      if (-not $args) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: tail <jobId> [lines]'
        return $jobs
      }
      $p = $args -split '\s+', 2
      $jobId = $p[0]
      $lines = $cfg.TailLines
      if ($p.Count -gt 1 -and $p[1] -match '^\d+$') { $lines = [int]$p[1] }
      $job = $jobs | Where-Object { $_.id -eq $jobId } | Select-Object -First 1
      if (-not $job) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Job not found: $jobId"
        return $jobs
      }
      $tail = Get-LogTail -LogPath $job.log -Lines $lines
      $msg = "Job $($job.id) (status $($job.status), exit $($job.exit_code))`n" + $tail
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $msg
      return $jobs
    }

    'get' {
      if (-not $args) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: get <jobId>'
        return $jobs
      }
      $jobId = $args.Trim()
      $job = $jobs | Where-Object { $_.id -eq $jobId } | Select-Object -First 1
      if (-not $job) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Job not found: $jobId"
        return $jobs
      }
      if (-not (Test-Path -LiteralPath $job.log)) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Log not found.'
        return $jobs
      }
      $content = Get-Content -LiteralPath $job.log -Raw -ErrorAction SilentlyContinue
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $content
      return $jobs
    }
    'kill' {
      if (-not $args) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: kill <jobId>'
        return $jobs
      }
      $jobId = $args.Trim()
      $job = $jobs | Where-Object { $_.id -eq $jobId } | Select-Object -First 1
      if (-not $job) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Job not found: $jobId"
        return $jobs
      }
      try {
        Stop-Process -Id $job.pid -Force -ErrorAction Stop
        $job.status = 'failed'
        $job.exit_code = 1
        $job.completed = (Get-Date).ToString('o')
        $jobs = $jobs | ForEach-Object { if ($_.id -eq $jobId) { $job } else { $_ } }
        Save-Jobs -cfg $cfg -jobs $jobs
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Killed job $jobId"
      } catch {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Failed to kill job ${jobId}: $($_.Exception.Message)"
      }
      return $jobs
    }

    'run' {
      if (-not $args) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: run <cmd>'
        return $jobs
      }

      if ($cfg.Secret) {
        $secretParts = $args -split '\s+', 2
        if ($secretParts[0] -ne $cfg.Secret) {
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Invalid secret.'
          return $jobs
        }
        $args = if ($secretParts.Count -gt 1) { $secretParts[1] } else { '' }
      }

      $cwd = $state.default_cwd
      if ($args -match '^\s*--cwd=("[^"]+"|\S+)\s+(.*)$') {
        $cwd = Unquote $Matches[1]
        $args = $Matches[2]
      }

      if (-not $args) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'No command provided.'
        return $jobs
      }

      if ($args -match "[;&|><`r`n]") {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Command rejected (disallowed operators).'
        return $jobs
      }
      if ($args -match '`') {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Command rejected (backtick not allowed).'
        return $jobs
      }

      $exe = Get-FirstToken -Command $args
      if (-not (Is-AllowedCommand -cfg $cfg -Exe $exe)) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Command not allowed: $exe"
        return $jobs
      }

      $job = Start-RemoteJob -cfg $cfg -state $state -jobs $jobs -ChatId $ChatId -Command $args -Cwd $cwd
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Queued job $($job.id) in $cwd"
      return $jobs
    }
    default {
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Unknown command. Send help for usage.'
      return $jobs
    }
  }
}

$cfg = Get-Config -ConfigPath $ConfigPath
$state = Load-State -cfg $cfg
$jobs = @(Load-Jobs -cfg $cfg)

Write-BotLog -Path $cfg.BotLog -Message 'Bot started.'

$offset = [int]$state.last_update_id

while ($true) {
  $jobs = Refresh-Jobs -cfg $cfg -jobs $jobs
  $jobs = Notify-CompletedJobs -cfg $cfg -jobs $jobs
  Save-Jobs -cfg $cfg -jobs $jobs

  $updates = Get-TgUpdates -cfg $cfg -Offset $offset
  if ($updates.ok -and $updates.result) {
    foreach ($update in $updates.result) {
      $offset = [int]$update.update_id + 1
      $state.last_update_id = $offset
      Save-State -cfg $cfg -state $state

      $msg = $update.message
      if (-not $msg) { continue }
      if (-not $msg.text) { continue }
      $chatId = [string]$msg.chat.id

      if (-not (Is-AllowedChat -cfg $cfg -ChatId $chatId)) { continue }

      try {
        $jobs = Handle-Command -cfg $cfg -state $state -jobs $jobs -ChatId $chatId -Text $msg.text
      } catch {
        Write-BotLog -Path $cfg.BotLog -Message "Handle-Command failed: $($_.Exception.Message)"
        Send-TgMessage -cfg $cfg -ChatId $chatId -Text 'Command failed. Check bot.log on PC.'
      }
    }
  }
}
