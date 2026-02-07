
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'broker.env')
)

$ErrorActionPreference = 'Stop'

try { $Host.UI.RawUI.WindowTitle = 'TelebotBroker' } catch {}

$script:BrokerMutex = $null
$script:LastWebhookClear = Get-Date '1900-01-01'

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
    if (($val.StartsWith('"') -and $val.EndsWith('"')) -or ($val.StartsWith("'") -and $val.EndsWith("'"))) {
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
    Targets = @{}
    DefaultTarget = 'pc'
    AgentSecret = ''
    AgentTimeoutSec = 300
    AgentConnectTimeoutSec = 3
    PollTimeoutSec = 20
    MaxMessageChars = 3500
    BotLog = (Join-Path $PSScriptRoot 'broker.log')
    StateFile = (Join-Path $PSScriptRoot 'state.json')
    SttCmd = $null
    SttTimeoutSec = 120
    VoiceDir = (Join-Path $PSScriptRoot 'logs')
    VoiceTarget = $null
  }

  Import-DotEnv -Path $ConfigPath

  if ($env:TG_BOT_TOKEN) { $cfg.BotToken = $env:TG_BOT_TOKEN }
  if ($env:TG_CHAT_ID) {
    $cfg.ChatIds = $env:TG_CHAT_ID.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  }
  if ($env:TG_SECRET) { $cfg.Secret = $env:TG_SECRET }
  $defaultFromEnv = $false
  if ($env:DEFAULT_TARGET) { $cfg.DefaultTarget = $env:DEFAULT_TARGET; $defaultFromEnv = $true }
  if ($env:AGENT_SECRET) { $cfg.AgentSecret = $env:AGENT_SECRET }
  if ($env:AGENT_TIMEOUT_SEC) { $cfg.AgentTimeoutSec = [int]$env:AGENT_TIMEOUT_SEC }
  if ($env:AGENT_CONNECT_TIMEOUT_SEC) { $cfg.AgentConnectTimeoutSec = [int]$env:AGENT_CONNECT_TIMEOUT_SEC }
  if ($env:POLL_TIMEOUT_SEC) { $cfg.PollTimeoutSec = [int]$env:POLL_TIMEOUT_SEC }
  if ($env:MAX_OUTPUT_CHARS) { $cfg.MaxMessageChars = [int]$env:MAX_OUTPUT_CHARS }
  if ($env:STT_CMD) { $cfg.SttCmd = $env:STT_CMD }
  if ($env:STT_TIMEOUT_SEC) { $cfg.SttTimeoutSec = [int]$env:STT_TIMEOUT_SEC }
  if ($env:VOICE_TARGET) { $cfg.VoiceTarget = $env:VOICE_TARGET }
  if ($env:BROKER_STATE_FILE) { $cfg.StateFile = $env:BROKER_STATE_FILE }

  $all = [System.Environment]::GetEnvironmentVariables()
  foreach ($key in $all.Keys) {
    if ($key -like 'TARGET_*') {
      $name = $key.Substring(7).ToLowerInvariant()
      $cfg.Targets[$name] = [System.Environment]::GetEnvironmentVariable($key)
    }
  }

  if (-not $cfg.BotToken) { throw 'TG_BOT_TOKEN missing in broker.env' }
  if (-not $cfg.ChatIds -or $cfg.ChatIds.Count -eq 0) { throw 'TG_CHAT_ID missing in broker.env' }

  # Per-machine default: if no TARGET_* entries are present, dispatch to the local agent.
  # (You can still configure multiple TARGET_* entries for router mode.)
  if ($cfg.Targets.Count -eq 0) {
    $port = 8765
    try {
      $agentEnv = Join-Path $PSScriptRoot 'agent.env'
      if (Test-Path -LiteralPath $agentEnv) {
        $line = Get-Content -LiteralPath $agentEnv -ErrorAction SilentlyContinue | Where-Object { $_ -match '^LISTEN_PORT\s*=\s*\d+' } | Select-Object -First 1
        if ($line -match '^LISTEN_PORT\s*=\s*(\d+)') { $port = [int]$Matches[1] }
      }
    } catch {}
    $cfg.Targets['local'] = "127.0.0.1:$port"
    if (-not $cfg.DefaultTarget) { $cfg.DefaultTarget = 'local' }
  }

  # Normalize DEFAULT_TARGET: keep lower-case and ensure it exists.
  if (-not $cfg.DefaultTarget) { $cfg.DefaultTarget = '' }
  $cfg.DefaultTarget = $cfg.DefaultTarget.ToLowerInvariant()
  if (-not $cfg.Targets.ContainsKey($cfg.DefaultTarget)) {
    if ($cfg.Targets.ContainsKey('local')) { $cfg.DefaultTarget = 'local' }
    else { $cfg.DefaultTarget = ($cfg.Targets.Keys | Sort-Object | Select-Object -First 1) }
  }

  New-Item -ItemType Directory -Force -Path $cfg.VoiceDir | Out-Null

  return $cfg
}
function Write-BotLog {
  param([string]$Path, [string]$Message)
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  try { Add-Content -LiteralPath $Path -Value "[$ts] $Message" } catch {}
}

function Ensure-StateProperty {
  param($state, [string]$Name, $Value)
  if (-not ($state.PSObject.Properties.Name -contains $Name)) {
    try { $state | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force } catch {}
  }
}

function Load-State {
  param($cfg)
  if ($cfg.StateFile -and (Test-Path -LiteralPath $cfg.StateFile)) {
    try {
      $obj = Get-Content -LiteralPath $cfg.StateFile -Raw | ConvertFrom-Json
      if ($null -ne $obj) {
        Ensure-StateProperty -state $obj -Name 'last_update_id' -Value 0
        Ensure-StateProperty -state $obj -Name 'pending_codex_jobs' -Value @()
        return $obj
      }
    } catch {}
  }
  return [pscustomobject]@{ last_update_id = 0; pending_codex_jobs = @() }
}

function Save-State {
  param($cfg, $state)
  if (-not $cfg.StateFile) { return }
  try {
    $json = $state | ConvertTo-Json -Depth 8
    $tmp = $cfg.StateFile + '.tmp'
    Set-Content -LiteralPath $tmp -Value $json
    Move-Item -LiteralPath $tmp -Destination $cfg.StateFile -Force
  } catch {}
}

function Send-TgMessage {
  param($cfg, [string]$ChatId, [string]$Text)
  if (-not $Text) { $Text = '(empty)' }
  $uri = "https://api.telegram.org/bot$($cfg.BotToken)/sendMessage"
  $body = @{ chat_id = $ChatId; text = $Text; disable_web_page_preview = $true }
  try { Invoke-RestMethod -Method Post -Uri $uri -Body $body | Out-Null } catch {
    Write-BotLog -Path $cfg.BotLog -Message "sendMessage failed: $($_.Exception.Message)"
  }
}

function Clear-TgWebhook {
  param($cfg, [string]$Reason = 'startup')
  $uri = "https://api.telegram.org/bot$($cfg.BotToken)/deleteWebhook"
  try {
    Invoke-RestMethod -Method Post -Uri $uri | Out-Null
    Write-BotLog -Path $cfg.BotLog -Message "deleteWebhook ok ($Reason)"
  } catch {
    Write-BotLog -Path $cfg.BotLog -Message "deleteWebhook failed ($Reason): $($_.Exception.Message)"
  }
}

function Maybe-ClearWebhook {
  param($cfg, [string]$Reason)
  $now = Get-Date
  if (($now - $script:LastWebhookClear).TotalSeconds -lt 30) { return }
  $script:LastWebhookClear = $now
  Clear-TgWebhook -cfg $cfg -Reason $Reason
}

function Send-ChunkedText {
  param($cfg, [string]$ChatId, [string]$Text)
  $max = $cfg.MaxMessageChars
  if ($Text.Length -le $max) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $Text; return }
  $lines = $Text -split "`n"
  $buffer = ''
  foreach ($line in $lines) {
    $candidate = if ($buffer) { $buffer + "`n" + $line } else { $line }
    if ($candidate.Length -gt $max) {
      if ($buffer) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $buffer }
      $buffer = $line
    } else { $buffer = $candidate }
  }
  if ($buffer) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $buffer }
}

function Get-TgFile {
  param($cfg, [string]$FileId)
  $uri = "https://api.telegram.org/bot$($cfg.BotToken)/getFile"
  $body = @{ file_id = $FileId }
  try { return Invoke-RestMethod -Method Post -Uri $uri -Body $body } catch {
    Write-BotLog -Path $cfg.BotLog -Message "getFile failed: $($_.Exception.Message)"
    return @{ ok = $false; result = $null }
  }
}

function Download-TgFile {
  param($cfg, [string]$FilePath, [string]$OutPath)
  $uri = "https://api.telegram.org/file/bot$($cfg.BotToken)/$FilePath"
  try {
    Invoke-WebRequest -Uri $uri -OutFile $OutPath | Out-Null
    return $true
  } catch {
    Write-BotLog -Path $cfg.BotLog -Message "download failed: $($_.Exception.Message)"
    return $false
  }
}

function Invoke-Stt {
  param($cfg, [string]$InputPath)
  if (-not $cfg.SttCmd) { throw 'STT_CMD not set.' }
  $quoted = '"' + $InputPath + '"'
  $cmd = $cfg.SttCmd.Replace('{input}', $quoted)

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'cmd.exe'
  $psi.Arguments = "/c $cmd"
  $psi.WorkingDirectory = $PSScriptRoot
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true

  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  $null = $proc.Start()

  $outTask = $proc.StandardOutput.ReadToEndAsync()
  $errTask = $proc.StandardError.ReadToEndAsync()
  $timeoutMs = [Math]::Max(5, $cfg.SttTimeoutSec) * 1000
  $exited = $proc.WaitForExit($timeoutMs)
  if (-not $exited) {
    try { $proc.Kill() } catch {}
    throw "STT timed out after $($cfg.SttTimeoutSec)s"
  }
  $null = [System.Threading.Tasks.Task]::WaitAll(@($outTask, $errTask), 3000)
  $outText = $outTask.Result
  if (-not $outText) { $outText = $errTask.Result }
  return ($outText | Out-String).Trim()
}

function Get-TgUpdates {
  param($cfg, [int]$Offset)
  $uri = "https://api.telegram.org/bot$($cfg.BotToken)/getUpdates"
  $body = @{ timeout = $cfg.PollTimeoutSec; offset = $Offset }
  try { return Invoke-RestMethod -Method Post -Uri $uri -Body $body } catch {
    Write-BotLog -Path $cfg.BotLog -Message "getUpdates failed: $($_.Exception.Message)"
    if ($_.Exception.Message -match '\b409\b') {
      Maybe-ClearWebhook -cfg $cfg -Reason '409 conflict'
    }
    return @{ ok = $false; result = @() }
  }
}

function Is-AllowedChat {
  param($cfg, [string]$ChatId)
  if (-not $cfg.ChatIds -or $cfg.ChatIds.Count -eq 0) { return $true }
  return $cfg.ChatIds -contains $ChatId
}
function Send-AgentRequest {
  param($cfg, [string]$Target, [hashtable]$Payload)

  if (-not $cfg.Targets.ContainsKey($Target)) {
    return @{ ok = $false; error = "Unknown target $Target" }
  }

  $endpoint = $cfg.Targets[$Target]
  $parts = $endpoint.Split(':')
  if ($parts.Count -lt 2) { return @{ ok = $false; error = "Invalid target endpoint: $endpoint" } }
  $targetHost = $parts[0]
  $port = [int]$parts[1]

  $payload.secret = $cfg.AgentSecret

  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $connectMs = [Math]::Max(1, [int]$cfg.AgentConnectTimeoutSec) * 1000
    $connectTask = $client.ConnectAsync($targetHost, $port)
    try {
      if (-not $connectTask.Wait($connectMs)) {
        try { $client.Close() } catch {}
        return @{ ok = $false; error = "Connect timeout after $($cfg.AgentConnectTimeoutSec)s ($($targetHost):$port)" }
      }
    } catch {
      try { $client.Close() } catch {}
      $ex = $_.Exception
      if ($ex -and $ex.InnerException) { $ex = $ex.InnerException }
      if ($ex -is [System.AggregateException] -and $ex.InnerExceptions.Count -gt 0) { $ex = $ex.InnerExceptions[0] }
      $msg = if ($ex) { $ex.Message } else { $_.Exception.Message }
      return @{ ok = $false; error = "Connect failed ($($targetHost):$port): $msg" }
    }
    if ($connectTask.IsFaulted) {
      $ex = $connectTask.Exception
      if ($ex -and $ex.InnerException) { $ex = $ex.InnerException }
      if ($ex -is [System.AggregateException] -and $ex.InnerExceptions.Count -gt 0) { $ex = $ex.InnerExceptions[0] }
      $msg = if ($ex) { $ex.Message } else { 'unknown connect error' }
      try { $client.Close() } catch {}
      return @{ ok = $false; error = "Connect failed ($($targetHost):$port): $msg" }
    }
    $timeoutMs = [Math]::Max(5, $cfg.AgentTimeoutSec) * 1000
    $client.ReceiveTimeout = $timeoutMs
    $client.SendTimeout = $timeoutMs
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    $reader = New-Object System.IO.StreamReader($stream)

    $writer.WriteLine(($payload | ConvertTo-Json -Compress -Depth 8))
    $line = $reader.ReadLine()
    $client.Close()
    if (-not $line) { return @{ ok = $false; error = 'Empty response.' } }
    return ($line | ConvertFrom-Json)
  } catch {
    return @{ ok = $false; error = $_.Exception.Message }
  }
}

function Format-ResultText {
  param($resp)
  if (-not $resp.ok) { return "Error: $($resp.error)" }
  if ($resp.result -and $resp.result.output) { return $resp.result.output }
  return ($resp | ConvertTo-Json -Depth 8)
}
function Is-WhitespaceChar {
  param([char]$Ch)
  if ([char]::IsWhiteSpace($Ch)) { return $true }
  $cat = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($Ch)
  return ($cat -eq [System.Globalization.UnicodeCategory]::SpaceSeparator)
}
function Trim-WhitespaceLike {
  param([string]$Text)
  if (-not $Text) { return '' }
  $len = $Text.Length
  $start = 0
  $end = $len - 1
  while ($start -le $end -and (Is-WhitespaceChar -Ch $Text[$start])) { $start++ }
  while ($end -ge $start -and (Is-WhitespaceChar -Ch $Text[$end])) { $end-- }
  if ($start -gt $end) { return '' }
  return $Text.Substring($start, $end - $start + 1)
}
function Split-FirstToken {
  param([string]$Text)
  if (-not $Text) { return @{ token = ''; rest = '' } }
  $len = $Text.Length
  $i = 0
  while ($i -lt $len -and (Is-WhitespaceChar -Ch $Text[$i])) { $i++ }
  if ($i -ge $len) { return @{ token = ''; rest = '' } }
  $start = $i
  while ($i -lt $len -and -not (Is-WhitespaceChar -Ch $Text[$i])) { $i++ }
  $token = $Text.Substring($start, $i - $start)
  $rest = ''
  if ($i -lt $len) {
    $rest = $Text.Substring($i)
    $rest = $rest.TrimStart()
  }
  return @{ token = $token; rest = $rest }
}
function Normalize-Token {
  param([string]$Token)
  if (-not $Token) { return '' }
  $t = $Token.Trim()
  if (-not $t) { return '' }
  $t = $t -replace '[\.\,\:\;\!\?\)\]\}\>\"'']+$',''
  return $t
}

function Acquire-BrokerMutex {
  param([string]$Name)
  try {
    $created = $false
    $mutex = New-Object System.Threading.Mutex($true, $Name, [ref]$created)
    if (-not $created) { return $null }
    return $mutex
  } catch {
    return $null
  }
}

function Ensure-SingleBroker {
  param($cfg)
  $mutex = Acquire-BrokerMutex -Name 'Global\CodexBridgeBroker'
  if (-not $mutex) { $mutex = Acquire-BrokerMutex -Name 'Local\CodexBridgeBroker' }
  if (-not $mutex) {
    Write-BotLog -Path $cfg.BotLog -Message 'Broker already running. Exiting.'
    Write-Host 'Broker already running. Exiting.'
    exit 1
  }
  $script:BrokerMutex = $mutex
}

function Is-KnownCommandOrTarget {
  param($cfg, [string]$Text)
  if (-not $Text) { return $false }
  $split = Split-FirstToken -Text $Text
  $token = (Normalize-Token -Token $split.token).ToLowerInvariant()
  if (-not $token) { return $false }
  if ($cfg.Targets.ContainsKey($token)) { return $true }
  $known = @(
    'help','status','run','last','tail','get','codex','codexnew','codexfresh','agent',
    'codexsession','codexjob','codexcancel','codexmodel','codexuse','codexresume','codexreset','codexstart','codexstop','codexlist','codexlast',
    'cancel','job','model','session'
  )
  return $known -contains $token
}

function Build-VoiceCommand {
  param($cfg, [string]$Text)
  $clean = Trim-WhitespaceLike -Text $Text
  if (-not $clean) { return $clean }
  if (Is-KnownCommandOrTarget -cfg $cfg -Text $clean) { return $clean }
  $target = if ($cfg.VoiceTarget) { $cfg.VoiceTarget } else { $cfg.DefaultTarget }
  return "$target codex $clean"
}

function Handle-VoiceMessage {
  param($cfg, $state, [string]$ChatId, $Msg)

  $voice = $Msg.voice
  $audio = $Msg.audio
  $fileId = $null
  if ($voice) { $fileId = $voice.file_id }
  elseif ($audio) { $fileId = $audio.file_id }
  if (-not $fileId) { return }

  try {
    $fileResp = Get-TgFile -cfg $cfg -FileId $fileId
    if (-not $fileResp.ok -or -not $fileResp.result.file_path) { throw 'Unable to fetch file path.' }
    $filePath = $fileResp.result.file_path
    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $safeId = $fileId.Substring(0, [Math]::Min(10, $fileId.Length))
    $ext = [System.IO.Path]::GetExtension($filePath)
    if (-not $ext) { $ext = '.ogg' }
    $local = Join-Path $cfg.VoiceDir ("voice_{0}_{1}{2}" -f $stamp, $safeId, $ext)
    if (-not (Download-TgFile -cfg $cfg -FilePath $filePath -OutPath $local)) { throw 'Download failed.' }

    $text = Invoke-Stt -cfg $cfg -InputPath $local
    if (-not $text) { throw 'Transcription empty.' }

    $cmdText = Build-VoiceCommand -cfg $cfg -Text $text
    Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Heard: " + $text)
    if ($cmdText) {
      Handle-Command -cfg $cfg -state $state -ChatId $ChatId -Text $cmdText
    }
  } catch {
    Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Voice failed: " + $_.Exception.Message)
  }
}
function Handle-Command {
  param($cfg, $state, [string]$ChatId, [string]$Text)

  $clean = Trim-WhitespaceLike -Text $Text
  if (-not $clean) { return }
  if ($clean.StartsWith('/')) { $clean = $clean.Substring(1) }

  $raw = Trim-WhitespaceLike -Text $clean
  if (-not $raw) { return }

  $rawLog = $raw -replace "`r","\\r" -replace "`n","\\n"
  Write-BotLog -Path $cfg.BotLog -Message "recv[$ChatId]: $rawLog"

  $target = $cfg.DefaultTarget
  $split1 = Split-FirstToken -Text $raw
  $token1 = Normalize-Token -Token $split1.token
  $rest1 = $split1.rest

  $token1Lower = $token1.ToLowerInvariant()
  if ($cfg.Targets.ContainsKey($token1Lower)) {
    $target = $token1Lower
    $split2 = Split-FirstToken -Text $rest1
    $cmd = (Normalize-Token -Token $split2.token).ToLowerInvariant()
    $rest = $split2.rest
  } else {
    $cmd = $token1Lower
    $rest = $rest1
  }

  # Convenience: allow "lapcancel" (no space) by splitting known target prefixes.
  if (-not $cfg.Targets.ContainsKey($token1Lower)) {
    foreach ($t in $cfg.Targets.Keys) {
      if ($token1Lower.StartsWith($t, [System.StringComparison]::InvariantCultureIgnoreCase) -and $token1Lower.Length -gt $t.Length) {
        $suffix = $token1Lower.Substring($t.Length)
        if (Is-KnownCommandOrTarget -cfg $cfg -Text $suffix) {
          $target = $t
          $cmd = $suffix
          $rest = $rest1
          break
        }
      }
    }
  }

  # Command aliases for lazy mobile typing.
  $aliases = @{
    'cancel'  = 'codexcancel'
    'job'     = 'codexjob'
    'codexstatus' = 'codexjob'
    'model'   = 'codexmodel'
    'session' = 'codexsession'
    'agent'   = 'codex'
  }
  if ($aliases.ContainsKey($cmd)) { $cmd = $aliases[$cmd] }

  Write-BotLog -Path $cfg.BotLog -Message ("parse: target={0} cmd={1} restLen={2}" -f $target, $cmd, ($rest | ForEach-Object { $_.Length }))

  function Add-PendingCodexJob {
    param([string]$JobId, [string]$Target, [string]$ChatId)
    if (-not $state) { return }
    Ensure-StateProperty -state $state -Name 'pending_codex_jobs' -Value @()
    $existing = @()
    try { $existing = @($state.pending_codex_jobs) } catch { $existing = @() }
    $filtered = @($existing | Where-Object { $_ -and $_.job_id -ne $JobId })
    $filtered += [pscustomobject]@{
      job_id = $JobId
      target = $Target
      chat_id = $ChatId
      queued_at = (Get-Date).ToString('o')
    }
    $state.pending_codex_jobs = $filtered
    Save-State -cfg $cfg -state $state
  }

  switch ($cmd) {
    'help' {
      $msg = "Default: plain text is sent to Codex. Targets: $($cfg.Targets.Keys -join ', '). Commands: [<target>] codex <prompt> | codexnew <prompt> | codexfresh <prompt> | codexsession | codexjob | codexcancel (alias: cancel) | codexmodel [model] [reset] (alias: model) | codexuse <session> (alias: codexresume) | codexreset | codexstart [session] | codexstop [session] | codexlist | codexlast [lines] | run <cmd> | last [lines] | tail <jobId> [lines] | get <jobId> | status"
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $msg
      return
    }
    'status' {
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'ping' }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'run' {
      if (-not $rest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: run <cmd>'; return }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'run'; cmd = $rest }
      if ($resp.ok) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Job queued: $($resp.result.job_id)"
      } else {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      }
      return
    }
    'last' {
      $lines = if ($rest -match '^\d+$') { [int]$rest } else { $null }
      $payload = @{ op = 'last' }
      if ($lines) { $payload.lines = $lines }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload $payload
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'tail' {
      if (-not $rest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: tail <jobId> [lines]'; return }
      $t = $rest -split '\s+', 2
      $payload = @{ op = 'tail'; job_id = $t[0] }
      if ($t.Count -gt 1 -and $t[1] -match '^\d+$') { $payload.lines = [int]$t[1] }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload $payload
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'get' {
      if (-not $rest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: get <jobId>'; return }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'get'; job_id = $rest }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codex' {
      if (-not $rest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: codex <prompt>'; return }

      # Convenience: treat "codex status/job/cancel/last/session" as control commands, not prompts.
      $subSplit = Split-FirstToken -Text $rest
      $subCmd = (Normalize-Token -Token $subSplit.token).ToLowerInvariant()
      $subRest = Trim-WhitespaceLike -Text $subSplit.rest

      if (-not $subRest) {
        switch ($subCmd) {
          'status' { $cmd = 'codexjob'; $rest = ''; break }
          'job' { $cmd = 'codexjob'; $rest = ''; break }
          'cancel' { $cmd = 'codexcancel'; $rest = ''; break }
          'session' { $cmd = 'codexsession'; $rest = ''; break }
        }
      }

      if ($subCmd -eq 'last' -and (-not $subRest -or $subRest -match '^[0-9]+$')) {
        $cmd = 'codexlast'
        $rest = $subRest
      }

      if ($cmd -ne 'codex') {
        # Re-dispatch through the main switch with the rewritten cmd/rest.
        Handle-Command -cfg $cfg -state $state -ChatId $ChatId -Text ("$target $cmd $rest".Trim())
        return
      }

      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.send'; prompt = $rest; session = 'default'; auto_start = $true }
      if ($resp.ok) {
        $out = $resp.result.output
        $jobId = $null
        $jobPid = $null
        if ($resp.result -and $resp.result.job_id) { $jobId = [string]$resp.result.job_id }
        if ($resp.result -and $resp.result.pid) { $jobPid = [string]$resp.result.pid }
        if ($jobId -and $jobPid) {
          Add-PendingCodexJob -JobId $jobId -Target $target -ChatId $ChatId
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex job $jobId. I'll reply here when it's done.")
        } else {
          if (-not $out) { $out = "No output yet. Use '$target codexlast' in a moment." }
          Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
        }
      } else {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      }
      return
    }
    'codexnew' {
      if (-not $rest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: codexnew <prompt>'; return }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.new'; prompt = $rest }
      if ($resp.ok) {
        $out = $resp.result.output
        $jobId = $null
        $jobPid = $null
        if ($resp.result -and $resp.result.job_id) { $jobId = [string]$resp.result.job_id }
        if ($resp.result -and $resp.result.pid) { $jobPid = [string]$resp.result.pid }
        if ($jobId -and $jobPid) {
          Add-PendingCodexJob -JobId $jobId -Target $target -ChatId $ChatId
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex job $jobId (new thread). I'll reply here when it's done.")
        } else {
          if (-not $out) { $out = "No output yet. Session: $($resp.result.session)." }
          Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
        }
      } else {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      }
      return
    }
    'codexfresh' {
      if (-not $rest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: codexfresh <prompt>'; return }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.new'; prompt = $rest }
      if ($resp.ok) {
        $out = $resp.result.output
        $jobId = $null
        $jobPid = $null
        if ($resp.result -and $resp.result.job_id) { $jobId = [string]$resp.result.job_id }
        if ($resp.result -and $resp.result.pid) { $jobPid = [string]$resp.result.pid }
        if ($jobId -and $jobPid) {
          Add-PendingCodexJob -JobId $jobId -Target $target -ChatId $ChatId
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex job $jobId (new thread). I'll reply here when it's done.")
        } else {
          if (-not $out) { $out = "No output yet. Session: $($resp.result.session)." }
          Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
        }
      } else {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      }
      return
    }
    'codexstart' {
      $session = if ($rest) { $rest } else { 'default' }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.start'; session = $session }
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexstop' {
      $session = if ($rest) { $rest } else { 'default' }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.stop'; session = $session }
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexlist' {
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.list' }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexsession' {
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.session' }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexjob' {
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.job' }
      if (-not $resp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp); return }
      $job = $resp.result.job
      if (-not $job) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'No codex job.'; return }
      $msg = "Codex job: id=$($job.id) running=$($job.running) pid=$($job.pid) exit_code=$($job.exit_code) thread_id=$($job.thread_id)"
      if ($job.error) { $msg += "`nerror: $($job.error)" }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $msg
      return
    }
    'codexcancel' {
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.cancel' }
      if (-not $resp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp); return }
      $msg = "Cancelled: $($resp.result.cancelled)"
      $job = $resp.result.job
      if ($job) { $msg += "`nCodex job: id=$($job.id) running=$($job.running) pid=$($job.pid)" }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $msg
      return
    }
    'codexmodel' {
      if (-not $rest) {
        $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.model.get' }
        Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
        return
      }

      $tokens = $rest -split '\s+'
      $reset = $false
      if ($tokens.Count -gt 1 -and $tokens[-1].ToLowerInvariant() -eq 'reset') {
        $reset = $true
        $tokens = $tokens[0..($tokens.Count - 2)]
      }
      $model = ($tokens -join ' ').Trim()
      if ($model.ToLowerInvariant() -in @('default','clear','none')) { $model = '' }

      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.model'; model = $model; reset = $reset }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexuse' {
      if (-not $rest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: codexuse <session>'; return }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.use'; session = $rest }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexresume' {
      if (-not $rest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: codexresume <session>'; return }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.use'; session = $rest }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexreset' {
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.reset' }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexlast' {
      $lines = if ($rest -match '^\d+$') { [int]$rest } else { $null }
      $payload = @{ op = 'codex.last'; session = 'default' }
      if ($lines) { $payload.lines = $lines }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload $payload
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    default {
      # Vanilla mode: if this isn't a known command, treat the message as a Codex prompt.
      $promptText = $raw
      if ($cfg.Targets.ContainsKey($token1Lower) -and $rest1) {
        # Preserve original casing/punctuation by using the original "rest after target" rather than normalized tokens.
        $promptText = $rest1
      }
      if (-not (Trim-WhitespaceLike -Text $promptText)) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Unknown command. Send help for usage.'
        return
      }

      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.send'; prompt = $promptText; session = 'default'; auto_start = $true }
      if ($resp.ok) {
        $out = $resp.result.output
        $jobId = $null
        $jobPid = $null
        if ($resp.result -and $resp.result.job_id) { $jobId = [string]$resp.result.job_id }
        if ($resp.result -and $resp.result.pid) { $jobPid = [string]$resp.result.pid }
        if ($jobId -and $jobPid) {
          Add-PendingCodexJob -JobId $jobId -Target $target -ChatId $ChatId
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex job $jobId. I'll reply here when it's done.")
        } else {
          if (-not $out) { $out = "No output yet. Use '$target codexlast' in a moment." }
          Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
        }
      } else {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      }
      return
    }
  }
}
$cfg = Get-Config -ConfigPath $ConfigPath
$state = Load-State -cfg $cfg
Write-BotLog -Path $cfg.BotLog -Message 'Broker started.'

Ensure-SingleBroker -cfg $cfg
Clear-TgWebhook -cfg $cfg -Reason 'startup'

$offset = 0
try { $offset = [int]$state.last_update_id } catch { $offset = 0 }

while ($true) {
  # If the agent is running Codex asynchronously, push completed jobs without requiring codexlast.
  try {
    Ensure-StateProperty -state $state -Name 'pending_codex_jobs' -Value @()
    $pending = @()
    try { $pending = @($state.pending_codex_jobs) } catch { $pending = @() }
    if ($pending.Count -gt 0) {
      $remaining = @()
      foreach ($j in $pending) {
        if (-not $j) { continue }
        $jobId = $null
        $tgt = $cfg.DefaultTarget
        $cid = $null
        try { $jobId = [string]$j.job_id } catch {}
        try { if ($j.target) { $tgt = [string]$j.target } } catch {}
        try { $cid = [string]$j.chat_id } catch {}
        if (-not $cid) { continue }

        $jr = Send-AgentRequest -cfg $cfg -Target $tgt -Payload @{ op = 'codex.job' }
        if (-not $jr.ok) { $remaining += $j; continue }
        $job = $jr.result.job
        if (-not $job) { $remaining += $j; continue }
        if ($jobId -and $job.id -and ($job.id -ne $jobId)) { $remaining += $j; continue }
        if ($job.running) { $remaining += $j; continue }

        $lr = Send-AgentRequest -cfg $cfg -Target $tgt -Payload @{ op = 'codex.last'; session = 'default' }
        Send-ChunkedText -cfg $cfg -ChatId $cid -Text (Format-ResultText $lr)
      }
      $state.pending_codex_jobs = $remaining
      Save-State -cfg $cfg -state $state
    }
  } catch {
    Write-BotLog -Path $cfg.BotLog -Message ("pending tick failed: " + $_.Exception.Message)
  }

  $updates = Get-TgUpdates -cfg $cfg -Offset $offset
  if ($updates.ok -and $updates.result) {
    foreach ($update in $updates.result) {
      $offset = [int]$update.update_id + 1
      try { $state.last_update_id = $offset } catch { Ensure-StateProperty -state $state -Name 'last_update_id' -Value $offset; try { $state.last_update_id = $offset } catch {} }
      Save-State -cfg $cfg -state $state
      $msg = $update.message
      if (-not $msg) { continue }
      $chatId = [string]$msg.chat.id

      if (-not (Is-AllowedChat -cfg $cfg -ChatId $chatId)) { continue }

      try {
        if ($msg.text) {
          $full = [string]$msg.text
          $trim = Trim-WhitespaceLike -Text $full
          if (-not $trim) { continue }

          # Preserve multi-line prompts unless the message clearly starts with a known command/target.
          $hasNewline = ($full -match "`r`n|`n")
          $split = Split-FirstToken -Text $trim
          $firstTok = (Normalize-Token -Token $split.token).ToLowerInvariant()
          $shouldSplit = $false
          if ($hasNewline -and (Is-KnownCommandOrTarget -cfg $cfg -Text $trim -or $trim.StartsWith('/'))) { $shouldSplit = $true }

          if ($shouldSplit) {
            $lines = $full -split "`r?`n"
            foreach ($line in $lines) {
              if (-not (Trim-WhitespaceLike -Text $line)) { continue }
              Handle-Command -cfg $cfg -state $state -ChatId $chatId -Text $line
            }
          } else {
            Handle-Command -cfg $cfg -state $state -ChatId $chatId -Text $full
          }
        } elseif ($msg.voice -or $msg.audio) {
          Handle-VoiceMessage -cfg $cfg -state $state -ChatId $chatId -Msg $msg
        }
      } catch {
        Write-BotLog -Path $cfg.BotLog -Message "Handle-Command failed: $($_.Exception.Message)"
        Send-TgMessage -cfg $cfg -ChatId $chatId -Text 'Command failed. Check broker.log.'
      }
    }
  }
}
