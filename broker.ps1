
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'broker.env')
)

$ErrorActionPreference = 'Stop'

try { $Host.UI.RawUI.WindowTitle = 'TelebotBroker' } catch {}

$script:BrokerMutex = $null
$script:LastWebhookClear = Get-Date '1900-01-01'
$script:Consecutive409 = 0
$script:Last409At = $null
$script:LastMessageAt = $null
$script:LastHeartbeatAt = Get-Date '1900-01-01'

function Is-Truthy {
  param([string]$Value)
  if (-not $Value) { return $false }
  return ($Value.Trim() -match '^(1|true|yes|y|on)$')
}

$script:TelebotQuiet = $false
if (Is-Truthy -Value $env:TELEBOT_QUIET) { $script:TelebotQuiet = $true }
if (Is-Truthy -Value $env:BROKER_QUIET) { $script:TelebotQuiet = $true }

function Write-Console {
  param([string]$Text)
  if ($script:TelebotQuiet) { return }
  if (-not $Text) { return }
  try { Write-Host $Text } catch {}
}

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
    ConsoleTarget = $null
    ExitOn409 = $true
    ExitOn409Threshold = 3
    ConsoleFallbackExec = $false
    ConsoleHeartbeatSec = 0
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
  if ($env:CONSOLE_TARGET) { $cfg.ConsoleTarget = $env:CONSOLE_TARGET }
  if ($env:BROKER_EXIT_ON_409) { $cfg.ExitOn409 = ($env:BROKER_EXIT_ON_409 -match '^(1|true|yes)$') }
  if ($env:BROKER_EXIT_ON_409_THRESHOLD) { $cfg.ExitOn409Threshold = [int]$env:BROKER_EXIT_ON_409_THRESHOLD }
  if ($env:CONSOLE_FALLBACK_EXEC) { $cfg.ConsoleFallbackExec = ($env:CONSOLE_FALLBACK_EXEC -match '^(1|true|yes)$') }
  if ($env:BROKER_STATE_FILE) { $cfg.StateFile = $env:BROKER_STATE_FILE }
  if ($env:BROKER_HEARTBEAT_SEC) { $cfg.ConsoleHeartbeatSec = [int]$env:BROKER_HEARTBEAT_SEC }
  elseif ($env:TELEBOT_HEARTBEAT_SEC) { $cfg.ConsoleHeartbeatSec = [int]$env:TELEBOT_HEARTBEAT_SEC }

  $all = [System.Environment]::GetEnvironmentVariables()
  foreach ($key in $all.Keys) {
    if ($key -like 'TARGET_*') {
      $name = $key.Substring(7).ToLowerInvariant()
      $cfg.Targets[$name] = [System.Environment]::GetEnvironmentVariable($key)
    }
  }

  if (-not $cfg.BotToken) { throw 'TG_BOT_TOKEN missing in broker.env' }

  # Allow running without TG_CHAT_ID (accept commands from any chat).
  # This matches Is-AllowedChat() behavior and helps bootstrap a new bot.
  if (-not $cfg.ChatIds -or $cfg.ChatIds.Count -eq 0) {
    $cfg.ChatIds = @()
    Write-Console 'WARN: TG_CHAT_ID not set; broker will accept commands from any chat.'
  }

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
        Ensure-StateProperty -state $obj -Name 'chat_target_map' -Value @{}
        Ensure-StateProperty -state $obj -Name 'chat_lane_map' -Value @{}
        Ensure-StateProperty -state $obj -Name 'lane_session_map' -Value @{}
        Ensure-StateProperty -state $obj -Name 'pending_codex_prompts' -Value @()
        return $obj
      }
    } catch {}
  }
  return [pscustomobject]@{
    last_update_id = 0
    pending_codex_jobs = @()
    chat_target_map = @{}
    chat_lane_map = @{}
    lane_session_map = @{}
    pending_codex_prompts = @()
  }
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
  param($cfg, [string]$ChatId, [string]$Text, $ReplyMarkup = $null)
  if (-not $Text) { $Text = '(empty)' }
  $uri = "https://api.telegram.org/bot$($cfg.BotToken)/sendMessage"
  $body = @{ chat_id = $ChatId; text = $Text; disable_web_page_preview = $true }
  if ($ReplyMarkup) { $body.reply_markup = ($ReplyMarkup | ConvertTo-Json -Compress -Depth 8) }
  try { Invoke-RestMethod -Method Post -Uri $uri -Body $body | Out-Null } catch {
    Write-BotLog -Path $cfg.BotLog -Message "sendMessage failed: $($_.Exception.Message)"
  }
}

function Answer-TgCallback {
  param($cfg, [string]$CallbackQueryId, [string]$Text = '')
  if (-not $CallbackQueryId) { return }
  $uri = "https://api.telegram.org/bot$($cfg.BotToken)/answerCallbackQuery"
  $body = @{ callback_query_id = $CallbackQueryId }
  if ($Text) { $body.text = $Text }
  try { Invoke-RestMethod -Method Post -Uri $uri -Body $body | Out-Null } catch {
    Write-BotLog -Path $cfg.BotLog -Message "answerCallbackQuery failed: $($_.Exception.Message)"
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
      $script:Consecutive409 += 1
      $script:Last409At = Get-Date
    } else {
      $script:Consecutive409 = 0
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
function Is-NoOutputText {
  param([string]$Text)
  if (-not $Text) { return $true }
  $t = $Text.Trim().ToLowerInvariant()
  return ($t -eq '(no output yet)' -or $t -eq '(sent; no output yet)' -or $t -eq '(no output)')
}
function Try-Resolve-ConsoleOutput {
  param($cfg, [string]$Target, [int]$Attempts = 6, [int]$DelayMs = 500)
  for ($i = 0; $i -lt $Attempts; $i++) {
    if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
    $lr = Send-AgentRequest -cfg $cfg -Target $Target -Payload @{ op = 'codex.last'; session = 'default' }
    if (-not $lr.ok) { continue }
    if (-not $lr.result -or -not $lr.result.output) { continue }
    $txt = [string]$lr.result.output
    if (-not (Is-NoOutputText -Text $txt)) { return $txt }
  }
  return $null
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

function Parse-ModeCommand {
  param([string]$Text)
  $trim = Trim-WhitespaceLike -Text $Text
  if (-not $trim) { return @{ action = 'set'; prompt = '' } }
  $split = Split-FirstToken -Text $trim
  $token = (Normalize-Token -Token $split.token).ToLowerInvariant()
  if ($token -eq 'new') { return @{ action = 'new'; prompt = $split.rest } }
  return @{ action = 'send'; prompt = $trim }
}

function Get-CodexConfigSnapshot {
  param($cfg, [string]$Target)
  $m = Send-AgentRequest -cfg $cfg -Target $Target -Payload @{ op = 'codex.model.get' }
  if (-not $m.ok) { return @{ ok = $false; error = $m.error } }
  $r = Send-AgentRequest -cfg $cfg -Target $Target -Payload @{ op = 'codex.reasoning.get' }
  if (-not $r.ok) { return @{ ok = $false; error = $r.error } }
  $mode = Send-AgentRequest -cfg $cfg -Target $Target -Payload @{ op = 'codex.mode.get' }
  if (-not $mode.ok) { return @{ ok = $false; error = $mode.error } }

  $modelRaw = ''
  if ($m.result -and $m.result.model) { $modelRaw = [string]$m.result.model }
  $reasoningRaw = ''
  if ($r.result -and $r.result.reasoning_effort) { $reasoningRaw = [string]$r.result.reasoning_effort }
  $modeRaw = 'exec'
  if ($mode.result -and $mode.result.mode) { $modeRaw = ([string]$mode.result.mode).ToLowerInvariant() }

  return @{
    ok = $true
    model_raw = $modelRaw
    reasoning_raw = $reasoningRaw
    mode_raw = $modeRaw
  }
}

function New-CodexConfigMarkup {
  param([string]$Target, [string]$ModelRaw, [string]$ReasoningRaw, [string]$ModeRaw)
  $targetSafe = if ($Target) { $Target } else { 'local' }
  $modelVal = if ($ModelRaw) { $ModelRaw } else { '' }
  $reasoningVal = if ($ReasoningRaw) { $ReasoningRaw.ToLowerInvariant() } else { '' }
  $modeVal = if ($ModeRaw) { $ModeRaw.ToLowerInvariant() } else { 'exec' }

  $execLabel = if ($modeVal -eq 'exec') { '[x] Exec mode' } else { '[ ] Exec mode' }
  $m53Label = if ($modelVal -eq 'gpt-5.3-codex') { '[x] gpt-5.3-codex' } else { '[ ] gpt-5.3-codex' }
  $m52Label = if ($modelVal -eq 'gpt-5.2-codex') { '[x] gpt-5.2-codex' } else { '[ ] gpt-5.2-codex' }
  $mDefLabel = if (-not $modelVal) { '[x] model: default' } else { '[ ] model: default' }
  $rLowLabel = if ($reasoningVal -eq 'low') { '[x] reasoning: low' } else { '[ ] reasoning: low' }
  $rMedLabel = if ($reasoningVal -eq 'medium') { '[x] reasoning: medium' } else { '[ ] reasoning: medium' }
  $rHighLabel = if ($reasoningVal -eq 'high') { '[x] reasoning: high' } else { '[ ] reasoning: high' }
  $rXHighLabel = if ($reasoningVal -eq 'xhigh') { '[x] reasoning: xhigh' } else { '[ ] reasoning: xhigh' }
  $rDefLabel = if (-not $reasoningVal) { '[x] reasoning: default' } else { '[ ] reasoning: default' }

  return @{
    inline_keyboard = @(
      @(
        @{ text = $execLabel; callback_data = "cf|$targetSafe|x|exec" },
        @{ text = 'Refresh'; callback_data = "cf|$targetSafe|r|_" }
      ),
      @(
        @{ text = $m53Label; callback_data = "cf|$targetSafe|m|gpt-5.3-codex" }
      ),
      @(
        @{ text = $m52Label; callback_data = "cf|$targetSafe|m|gpt-5.2-codex" },
        @{ text = $mDefLabel; callback_data = "cf|$targetSafe|m|def" }
      ),
      @(
        @{ text = $rLowLabel; callback_data = "cf|$targetSafe|e|low" },
        @{ text = $rMedLabel; callback_data = "cf|$targetSafe|e|medium" }
      ),
      @(
        @{ text = $rHighLabel; callback_data = "cf|$targetSafe|e|high" },
        @{ text = $rXHighLabel; callback_data = "cf|$targetSafe|e|xhigh" },
        @{ text = $rDefLabel; callback_data = "cf|$targetSafe|e|def" }
      )
    )
  }
}

function Send-CodexConfigPanel {
  param($cfg, [string]$ChatId, [string]$Target, [string]$Notice = '')
  $snap = Get-CodexConfigSnapshot -cfg $cfg -Target $Target
  if (-not $snap.ok) {
    Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Error: " + $snap.error)
    return
  }
  $mode = if ($snap.mode_raw) { $snap.mode_raw } else { 'exec' }
  $model = if ($snap.model_raw) { $snap.model_raw } else { 'default' }
  $reasoning = if ($snap.reasoning_raw) { $snap.reasoning_raw } else { 'default' }
  $targets = @($cfg.Targets.Keys | Sort-Object)
  $targetsText = if ($targets.Count -gt 0) { $targets -join ', ' } else { '(none)' }
  $text = "[telebot] target: $Target`nmode: $mode`nmodel: $model`nreasoning: $reasoning`ntargets: $targetsText`nlanes: idN (id1, id2, ...) on active target`n`nExec is default for prompts. Use idN prefixes for lane routing."
  if ($Notice) { $text = $Notice + "`n`n" + $text }
  $markup = New-CodexConfigMarkup -Target $Target -ModelRaw $snap.model_raw -ReasoningRaw $snap.reasoning_raw -ModeRaw $snap.mode_raw
  Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $text -ReplyMarkup $markup
}

function Handle-CallbackQuery {
  param($cfg, $state, $Query)
  $cbId = ''
  $data = ''
  try { if ($Query.id) { $cbId = [string]$Query.id } } catch {}
  try { if ($Query.data) { $data = [string]$Query.data } } catch {}
  if (-not $cbId) { return }

  $chatId = $null
  try { if ($Query.message -and $Query.message.chat -and $Query.message.chat.id) { $chatId = [string]$Query.message.chat.id } } catch {}
  if (-not $chatId) {
    try { if ($Query.from -and $Query.from.id) { $chatId = [string]$Query.from.id } } catch {}
  }
  if (-not $chatId) {
    Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'No chat context.'
    return
  }
  if (-not (Is-AllowedChat -cfg $cfg -ChatId $chatId)) {
    Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'Unauthorized chat.'
    return
  }
  if (-not $data.StartsWith('cf|')) {
    Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'Unsupported action.'
    return
  }

  $parts = $data -split '\|', 4
  if ($parts.Count -lt 4) {
    Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'Malformed action.'
    return
  }

  $target = $parts[1].ToLowerInvariant()
  if (-not $cfg.Targets.ContainsKey($target)) { $target = $cfg.DefaultTarget }
  $action = $parts[2].ToLowerInvariant()
  $value = $parts[3]
  $notice = ''

  switch ($action) {
    'r' {
      Send-CodexConfigPanel -cfg $cfg -ChatId $chatId -Target $target -Notice 'Refreshed config.'
      Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'Refreshed.'
      return
    }
    'x' {
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.mode'; mode = 'exec' }
      if (-not $resp.ok) {
        Send-TgMessage -cfg $cfg -ChatId $chatId -Text (Format-ResultText $resp)
        Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'Failed.'
        return
      }
      $notice = 'Mode set to exec.'
    }
    'm' {
      $model = $value
      if ($model.ToLowerInvariant() -eq 'def') { $model = '' }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.model'; model = $model; reset = $false }
      if (-not $resp.ok) {
        Send-TgMessage -cfg $cfg -ChatId $chatId -Text (Format-ResultText $resp)
        Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'Failed.'
        return
      }
      try { $null = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.mode'; mode = 'exec' } } catch {}
      if (-not $model) { $notice = 'Model set to default.' } else { $notice = "Model set to $model." }
    }
    'e' {
      $reasoning = $value.ToLowerInvariant()
      if ($reasoning -eq 'def') { $reasoning = '' }
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.reasoning'; reasoning_effort = $reasoning; reset = $false }
      if (-not $resp.ok) {
        Send-TgMessage -cfg $cfg -ChatId $chatId -Text (Format-ResultText $resp)
        Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'Failed.'
        return
      }
      try { $null = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.mode'; mode = 'exec' } } catch {}
      if (-not $reasoning) { $notice = 'Reasoning set to default.' } else { $notice = "Reasoning set to $reasoning." }
    }
    default {
      Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'Unknown action.'
      return
    }
  }

  Send-CodexConfigPanel -cfg $cfg -ChatId $chatId -Target $target -Notice $notice
  Answer-TgCallback -cfg $cfg -CallbackQueryId $cbId -Text 'Updated.'
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
    Write-Console 'Broker already running. Exiting.'
    exit 1
  }
  $script:BrokerMutex = $mutex
}

function Get-SortedTargetKeys {
  param($cfg)
  if (-not $cfg -or -not $cfg.Targets) { return @() }
  return @($cfg.Targets.Keys | Sort-Object)
}

function Resolve-TargetAlias {
  param($cfg, [string]$Token, [string]$FallbackTarget = '')
  $t = (Normalize-Token -Token $Token).ToLowerInvariant()
  if (-not $t) { return @{ ok = $false; target = $null; is_id = $false; id = 0; alias = '' } }
  if ($cfg.Targets.ContainsKey($t)) {
    return @{ ok = $true; target = $t; is_id = $false; id = 0; alias = $t }
  }

  $m = [System.Text.RegularExpressions.Regex]::Match($t, '^id([1-9]\d*)$')
  if (-not $m.Success) { return @{ ok = $false; target = $null; is_id = $false; id = 0; alias = '' } }

  $id = [int]$m.Groups[1].Value
  $targetResolved = $null
  $fallbackNorm = (Normalize-Token -Token $FallbackTarget).ToLowerInvariant()
  if ($fallbackNorm -and $cfg.Targets.ContainsKey($fallbackNorm)) {
    $targetResolved = $fallbackNorm
  } elseif ($cfg.DefaultTarget -and $cfg.Targets.ContainsKey($cfg.DefaultTarget)) {
    $targetResolved = [string]$cfg.DefaultTarget
  } else {
    $keys = @(Get-SortedTargetKeys -cfg $cfg)
    if ($keys.Count -gt 0) { $targetResolved = [string]$keys[0] }
  }

  if (-not $targetResolved) { return @{ ok = $false; target = $null; is_id = $true; id = $id; alias = ("id{0}" -f $id) } }
  return @{ ok = $true; target = $targetResolved; is_id = $true; id = $id; alias = ("id{0}" -f $id) }
}

function Get-TargetIdMapText {
  param($cfg)
  $keys = @(Get-SortedTargetKeys -cfg $cfg)
  if ($keys.Count -eq 0) { return '(no targets)' }
  $pairs = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $keys.Count; $i++) {
    $pairs.Add(("id{0}={1}" -f ($i + 1), $keys[$i]))
  }
  return ($pairs -join ', ')
}

function Get-TargetIdLabel {
  param($cfg, [string]$Target)
  if (-not $Target) { return $null }
  $targetNorm = $Target.ToLowerInvariant()
  $keys = @(Get-SortedTargetKeys -cfg $cfg)
  for ($i = 0; $i -lt $keys.Count; $i++) {
    if ([string]$keys[$i] -eq $targetNorm) { return ("id{0}" -f ($i + 1)) }
  }
  return $null
}

function Ensure-ChatTargetMap {
  param($state)
  if (-not $state) { return $null }
  Ensure-StateProperty -state $state -Name 'chat_target_map' -Value @{}
  try {
    if ($null -eq $state.chat_target_map) { $state.chat_target_map = @{} }
  } catch {
    try { $state | Add-Member -NotePropertyName 'chat_target_map' -NotePropertyValue @{} -Force } catch {}
  }
  return $state.chat_target_map
}

function Get-ChatStickyTarget {
  param($cfg, $state, [string]$ChatId)
  if (-not $ChatId) { return $null }
  $map = Ensure-ChatTargetMap -state $state
  if ($null -eq $map) { return $null }

  $raw = $null
  if ($map -is [System.Collections.IDictionary]) {
    if ($map.Contains($ChatId)) {
      try { $raw = [string]$map[$ChatId] } catch {}
    }
  } else {
    try {
      $prop = $map.PSObject.Properties[$ChatId]
      if ($prop) { $raw = [string]$prop.Value }
    } catch {}
  }

  if (-not $raw) { return $null }
  $target = $raw.ToLowerInvariant()
  if (-not $cfg.Targets.ContainsKey($target)) { return $null }
  return $target
}

function Set-ChatStickyTarget {
  param($cfg, $state, [string]$ChatId, [string]$Target)
  if (-not $state -or -not $ChatId -or -not $Target) { return }
  $targetNorm = $Target.ToLowerInvariant()
  if (-not $cfg.Targets.ContainsKey($targetNorm)) { return }

  $map = Ensure-ChatTargetMap -state $state
  if ($null -eq $map) { return }

  $updated = $false
  if ($map -is [System.Collections.IDictionary]) {
    try { $map[$ChatId] = $targetNorm; $updated = $true } catch {}
  } else {
    try {
      if ($map.PSObject.Properties.Name -contains $ChatId) { $map.$ChatId = $targetNorm }
      else { $map | Add-Member -NotePropertyName $ChatId -NotePropertyValue $targetNorm -Force }
      $updated = $true
    } catch {}
  }

  if ($updated) { Save-State -cfg $cfg -state $state }
}

function Ensure-ChatLaneMap {
  param($state)
  if (-not $state) { return $null }
  Ensure-StateProperty -state $state -Name 'chat_lane_map' -Value @{}
  try {
    if ($null -eq $state.chat_lane_map) { $state.chat_lane_map = @{} }
  } catch {
    try { $state | Add-Member -NotePropertyName 'chat_lane_map' -NotePropertyValue @{} -Force } catch {}
  }
  return $state.chat_lane_map
}

function Get-ChatStickyLane {
  param($state, [string]$ChatId)
  if (-not $ChatId) { return $null }
  $map = Ensure-ChatLaneMap -state $state
  if ($null -eq $map) { return $null }

  $raw = $null
  if ($map -is [System.Collections.IDictionary]) {
    if ($map.Contains($ChatId)) {
      try { $raw = [string]$map[$ChatId] } catch {}
    }
  } else {
    try {
      $prop = $map.PSObject.Properties[$ChatId]
      if ($prop) { $raw = [string]$prop.Value }
    } catch {}
  }

  if (-not $raw) { return $null }
  return $raw.ToLowerInvariant()
}

function Set-ChatStickyLane {
  param($cfg, $state, [string]$ChatId, [string]$LaneKey)
  if (-not $state -or -not $ChatId -or -not $LaneKey) { return }
  $laneNorm = $LaneKey.ToLowerInvariant()

  $map = Ensure-ChatLaneMap -state $state
  if ($null -eq $map) { return }

  $updated = $false
  if ($map -is [System.Collections.IDictionary]) {
    try { $map[$ChatId] = $laneNorm; $updated = $true } catch {}
  } else {
    try {
      if ($map.PSObject.Properties.Name -contains $ChatId) { $map.$ChatId = $laneNorm }
      else { $map | Add-Member -NotePropertyName $ChatId -NotePropertyValue $laneNorm -Force }
      $updated = $true
    } catch {}
  }

  if ($updated) { Save-State -cfg $cfg -state $state }
}

function Ensure-LaneSessionMap {
  param($state)
  if (-not $state) { return $null }
  Ensure-StateProperty -state $state -Name 'lane_session_map' -Value @{}
  try {
    if ($null -eq $state.lane_session_map) { $state.lane_session_map = @{} }
  } catch {
    try { $state | Add-Member -NotePropertyName 'lane_session_map' -NotePropertyValue @{} -Force } catch {}
  }
  return $state.lane_session_map
}

function Get-LaneSessionMapKey {
  param([string]$ChatId, [string]$Target, [string]$LaneKey)
  if (-not $ChatId -or -not $Target) { return '' }
  $targetNorm = $Target.ToLowerInvariant()
  $laneNorm = if ($LaneKey) { $LaneKey.ToLowerInvariant() } else { $targetNorm }
  return "$ChatId|$targetNorm|$laneNorm"
}

function Get-LaneSessionId {
  param($state, [string]$ChatId, [string]$Target, [string]$LaneKey)
  $map = Ensure-LaneSessionMap -state $state
  if ($null -eq $map) { return $null }
  $key = Get-LaneSessionMapKey -ChatId $ChatId -Target $Target -LaneKey $LaneKey
  if (-not $key) { return $null }

  $raw = $null
  if ($map -is [System.Collections.IDictionary]) {
    if ($map.Contains($key)) {
      try { $raw = [string]$map[$key] } catch {}
    }
  } else {
    try {
      $prop = $map.PSObject.Properties[$key]
      if ($prop) { $raw = [string]$prop.Value }
    } catch {}
  }
  if (-not $raw) { return $null }
  return $raw.Trim()
}

function Set-LaneSessionId {
  param($cfg, $state, [string]$ChatId, [string]$Target, [string]$LaneKey, [string]$SessionId)
  if (-not $state -or -not $ChatId -or -not $Target) { return }
  if (-not $SessionId) { return }
  $sid = $SessionId.Trim()
  if (-not $sid) { return }
  $key = Get-LaneSessionMapKey -ChatId $ChatId -Target $Target -LaneKey $LaneKey
  if (-not $key) { return }

  $map = Ensure-LaneSessionMap -state $state
  if ($null -eq $map) { return }
  $updated = $false
  if ($map -is [System.Collections.IDictionary]) {
    try { $map[$key] = $sid; $updated = $true } catch {}
  } else {
    try {
      if ($map.PSObject.Properties.Name -contains $key) { $map.PSObject.Properties[$key].Value = $sid }
      else { $map | Add-Member -NotePropertyName $key -NotePropertyValue $sid -Force }
      $updated = $true
    } catch {}
  }
  if ($updated) { Save-State -cfg $cfg -state $state }
}

function Clear-LaneSessionId {
  param($cfg, $state, [string]$ChatId, [string]$Target, [string]$LaneKey)
  if (-not $state -or -not $ChatId -or -not $Target) { return }
  $key = Get-LaneSessionMapKey -ChatId $ChatId -Target $Target -LaneKey $LaneKey
  if (-not $key) { return }
  $map = Ensure-LaneSessionMap -state $state
  if ($null -eq $map) { return }

  $updated = $false
  if ($map -is [System.Collections.IDictionary]) {
    if ($map.Contains($key)) {
      try { $null = $map.Remove($key); $updated = $true } catch {}
    }
  } else {
    try {
      if ($map.PSObject.Properties.Name -contains $key) {
        $map.PSObject.Properties.Remove($key)
        $updated = $true
      }
    } catch {}
  }
  if ($updated) { Save-State -cfg $cfg -state $state }
}

function Try-ExtractCodexSessionIdFromText {
  param([string]$Text)
  if (-not $Text) { return $null }
  $m = [System.Text.RegularExpressions.Regex]::Match($Text, 'codex_session_id:\s*([0-9a-fA-F-]{16,})')
  if ($m.Success) { return [string]$m.Groups[1].Value }
  $m2 = [System.Text.RegularExpressions.Regex]::Match($Text, 'thread_id=([0-9a-fA-F-]{16,})')
  if ($m2.Success) { return [string]$m2.Groups[1].Value }
  return $null
}

function Ensure-PendingCodexPromptQueue {
  param($state)
  if (-not $state) { return @() }
  Ensure-StateProperty -state $state -Name 'pending_codex_prompts' -Value @()
  try {
    if ($null -eq $state.pending_codex_prompts) { $state.pending_codex_prompts = @() }
  } catch {
    try { $state | Add-Member -NotePropertyName 'pending_codex_prompts' -NotePropertyValue @() -Force } catch {}
  }
  return @($state.pending_codex_prompts)
}

function Is-KnownCommandOrTarget {
  param($cfg, [string]$Text)
  if (-not $Text) { return $false }
  $split = Split-FirstToken -Text $Text
  $token = (Normalize-Token -Token $split.token).ToLowerInvariant()
  if (-not $token) { return $false }
  if ($cfg.Targets.ContainsKey($token)) { return $true }
  if ($token -match '^id[1-9]\d*$') { return $true }
  $known = @(
    'help','status','run','last','tail','get','codex','codexnew','codexfresh','codexfreshconsole','agent',
    'codexsession','codexjob','codexcancel','codexmodel','codexreasoning','codexconfig','codexuse','codexresume','codexreset','codexstart','codexstop','codexlist','codexlast',
    'codexexec','codexexecnew','codexforceexec','codexforceexecnew','codexconsole','codexconsolenew','codexconsoleexec','codexconsoleexecnew',
    'cancel','job','model','reasoning','config','session','console','ai'
  )
  return $known -contains $token
}

function Build-VoiceCommand {
  param($cfg, [string]$Text)
  $clean = Trim-WhitespaceLike -Text $Text
  if (-not $clean) { return $clean }
  if (Is-KnownCommandOrTarget -cfg $cfg -Text $clean) { return $clean }
  $target = if ($cfg.VoiceTarget) { $cfg.VoiceTarget } else { $cfg.DefaultTarget }
  return "$target codexexec $clean"
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

  $stickyTarget = Get-ChatStickyTarget -cfg $cfg -state $state -ChatId $ChatId
  $target = if ($stickyTarget) { $stickyTarget } else { $cfg.DefaultTarget }
  $stickyLane = Get-ChatStickyLane -state $state -ChatId $ChatId
  $laneKey = if ($stickyLane) { $stickyLane } else { $target }
  $split1 = Split-FirstToken -Text $raw
  $token1 = Normalize-Token -Token $split1.token
  $rest1 = $split1.rest

  $token1Lower = $token1.ToLowerInvariant()
  $routeWasExplicit = $false
  $routeResolved = Resolve-TargetAlias -cfg $cfg -Token $token1Lower -FallbackTarget $target
  if ($routeResolved.ok) {
    $target = [string]$routeResolved.target
    $laneKey = if ($routeResolved.alias) { [string]$routeResolved.alias } else { $target }
    $routeWasExplicit = $true
    $split2 = Split-FirstToken -Text $rest1
    $cmd = (Normalize-Token -Token $split2.token).ToLowerInvariant()
    $rest = $split2.rest
  } elseif ($routeResolved.is_id) {
    Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Unable to resolve active target for lane id{0}. Set a target first (for example: pc) then retry." -f $routeResolved.id)
    return
  } else {
    $cmd = $token1Lower
    $rest = $rest1
  }

  # Convenience: allow "lapcancel" (no space) by splitting known target prefixes.
  if (-not $routeWasExplicit) {
    foreach ($t in $cfg.Targets.Keys) {
      if ($token1Lower.StartsWith($t, [System.StringComparison]::InvariantCultureIgnoreCase) -and $token1Lower.Length -gt $t.Length) {
        $suffix = $token1Lower.Substring($t.Length)
        if (Is-KnownCommandOrTarget -cfg $cfg -Text $suffix) {
          $target = $t
          $laneKey = $t
          $routeWasExplicit = $true
          $cmd = $suffix
          $rest = $rest1
          break
        }
      }
    }
  }

  if ($routeWasExplicit) {
    Set-ChatStickyTarget -cfg $cfg -state $state -ChatId $ChatId -Target $target
    Set-ChatStickyLane -cfg $cfg -state $state -ChatId $ChatId -LaneKey $laneKey
    if (-not $cmd) {
      $targetDesc = $target
      $laneDesc = if ($laneKey) { $laneKey } else { $target }
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Active target set to {0}. Active lane: {1}. Next plain prompts will use this lane." -f $targetDesc, $laneDesc)
      return
    }
  }

  # Command aliases for lazy mobile typing.
  $aliases = @{
    'cancel'  = 'codexcancel'
    'job'     = 'codexjob'
    'codexstatus' = 'codexjob'
    'model'   = 'codexmodel'
    'reasoning' = 'codexreasoning'
    'config' = 'codexconfig'
    'session' = 'codexsession'
    'agent'   = 'codex'
    'console' = 'codexconsole'
    'skill'   = 'skills'
  }
  if ($aliases.ContainsKey($cmd)) { $cmd = $aliases[$cmd] }

  Write-BotLog -Path $cfg.BotLog -Message ("parse: target={0} lane={1} cmd={2} restLen={3}" -f $target, $laneKey, $cmd, ($rest | ForEach-Object { $_.Length }))

  function Add-PendingCodexJob {
    param([string]$JobId, [string]$Target, [string]$ChatId, [string]$LaneKey = '')
    if (-not $state) { return }
    Ensure-StateProperty -state $state -Name 'pending_codex_jobs' -Value @()
    $existing = @()
    try { $existing = @($state.pending_codex_jobs) } catch { $existing = @() }
    $filtered = @($existing | Where-Object { $_ -and $_.job_id -ne $JobId })
    $filtered += [pscustomobject]@{
      job_id = $JobId
      target = $Target
      chat_id = $ChatId
      lane_key = $LaneKey
      queued_at = (Get-Date).ToString('o')
    }
    $state.pending_codex_jobs = $filtered
    Save-State -cfg $cfg -state $state
  }

  function Add-PendingCodexPrompt {
    param([string]$Target, [string]$ChatId, [string]$CommandText, [string]$LaneKey = '')
    if (-not $state -or -not $Target -or -not $ChatId -or -not $CommandText) { return '' }
    Ensure-StateProperty -state $state -Name 'pending_codex_prompts' -Value @()
    $existing = @()
    try { $existing = @($state.pending_codex_prompts) } catch { $existing = @() }
    $entryId = "{0}_{1}" -f (Get-Date).ToString('yyyyMMdd_HHmmss'), (Get-Random -Minimum 1000 -Maximum 9999)
    $existing += [pscustomobject]@{
      id = $entryId
      target = $Target
      chat_id = $ChatId
      lane_key = $LaneKey
      command_text = $CommandText
      queued_at = (Get-Date).ToString('o')
    }
    $state.pending_codex_prompts = $existing
    Save-State -cfg $cfg -state $state
    return $entryId
  }

  function Get-LaneStatusLabel {
    param([string]$LaneCandidate, [string]$TargetCandidate)
    if ($LaneCandidate) { return $LaneCandidate }
    if ($TargetCandidate) { return $TargetCandidate }
    return 'default'
  }

  function Invoke-LaneExecPrompt {
    param([string]$Prompt, [bool]$ForceNew = $false, [string]$QueuedCommandText = '')

    if (-not (Trim-WhitespaceLike -Text $Prompt)) {
      return @{ ok = $false; queued = $false; message = 'Prompt missing.' }
    }

    $laneNorm = if ($laneKey) { $laneKey.ToLowerInvariant() } else { $target }
    $resp = $null
    if ($ForceNew) {
      Clear-LaneSessionId -cfg $cfg -state $state -ChatId $ChatId -Target $target -LaneKey $laneNorm
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.new.exec'; prompt = $Prompt }
    } else {
      $laneSession = Get-LaneSessionId -state $state -ChatId $ChatId -Target $target -LaneKey $laneNorm
      if ($laneSession) {
        $useResp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.use'; session = $laneSession }
        if (-not $useResp.ok) {
          Clear-LaneSessionId -cfg $cfg -state $state -ChatId $ChatId -Target $target -LaneKey $laneNorm
          $laneSession = $null
        }
      }

      if (-not $laneSession -and $laneNorm -match '^id[1-9]\d*$') {
        $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.new.exec'; prompt = $Prompt }
      } else {
        $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.send.exec'; prompt = $Prompt; session = 'default'; auto_start = $true }
      }
    }

    if (-not $resp.ok) {
      $errText = [string]$resp.error
      if ($errText -match 'Codex job already running') {
        $routePrefix = if ($laneNorm -match '^id[1-9]\d*$') { $laneNorm } else { $target }
        $queueText = if ($QueuedCommandText) { $QueuedCommandText } else { ("{0} {1}" -f $routePrefix, $Prompt) }
        $qid = Add-PendingCodexPrompt -Target $target -ChatId $ChatId -CommandText $queueText -LaneKey $laneNorm
        return @{
          ok = $true
          queued = $true
          message = ("Target {0} is busy. Queued lane {1} as {2}." -f $target, $laneNorm, $qid)
        }
      }
      return @{ ok = $false; queued = $false; message = (Format-ResultText $resp) }
    }

    $out = $resp.result.output
    $jobId = $null
    $jobPid = $null
    if ($resp.result -and $resp.result.job_id) { $jobId = [string]$resp.result.job_id }
    if ($resp.result -and $resp.result.pid) { $jobPid = [string]$resp.result.pid }

    if ($jobId -and $jobPid) {
      Add-PendingCodexJob -JobId $jobId -Target $target -ChatId $ChatId -LaneKey $laneNorm
      return @{
        ok = $true
        queued = $false
        has_job = $true
        job_id = $jobId
        out = $out
      }
    }

    $sid = Try-ExtractCodexSessionIdFromText -Text ([string]$out)
    if ($sid) {
      Set-LaneSessionId -cfg $cfg -state $state -ChatId $ChatId -Target $target -LaneKey $laneNorm -SessionId $sid
    }

    return @{
      ok = $true
      queued = $false
      has_job = $false
      out = $out
    }
  }

  switch ($cmd) {
    'help' {
      $activeTarget = if ($target) { $target } else { $cfg.DefaultTarget }
      $msg = "Default: plain text is sent to Codex exec on the active target. Active target (this chat): $activeTarget. Targets: $($cfg.Targets.Keys -join ', '). Lanes: idN (id1, id2, ...) on the active target. Use idN <prompt> or <target> <prompt>; the last explicit id/target becomes sticky for this chat. idN lanes on the same target keep separate sessions; when target is busy, prompts are queued per lane. Commands: [<target>] codex <prompt> | codexnew [prompt] | codexfresh [prompt] | codexfreshconsole [prompt] | codexsession | codexjob | codexcancel (alias: cancel) | codexmodel [model] [reset] (alias: model) | codexreasoning [low|medium|high|xhigh|default] [reset] (alias: reasoning) | codexconfig (alias: config) | codexuse <session> (alias: codexresume) | codexreset | codexstart [session] | codexstop [session] | codexlist | codexlast [lines] | codexexec [new] [prompt] | codexconsole [new] [prompt] (alias: console) | codexconsoleexec [new] [prompt] | ai diag <run_id> | ai route <run_id> | ai scoreboard <path> | ai capabilities [command] | skills list|info <name>|doctor|run <name> [args...] | run <cmd> | last [lines] | tail <jobId> [lines] | get <jobId> | status"
      Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $msg
      return
    }
    'status' {
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'ping' }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'ai' {
      if (-not $rest) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: ai diag <run_id> | ai route <run_id> | ai scoreboard <path> | ai capabilities [command]'
        return
      }

      $subSplit = Split-FirstToken -Text $rest
      $subCmd = (Normalize-Token -Token $subSplit.token).ToLowerInvariant()
      $subRest = Trim-WhitespaceLike -Text $subSplit.rest
      $payload = @{ op = 'ai.sidecar' }

      switch ($subCmd) {
        'diag' {
          if (-not $subRest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: ai diag <run_id>'; return }
          $payload.action = 'diag'
          $payload.run_id = $subRest
        }
        'route' {
          if (-not $subRest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: ai route <run_id>'; return }
          $payload.action = 'route'
          $payload.run_id = $subRest
        }
        'scoreboard' {
          if (-not $subRest) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: ai scoreboard <path>'; return }
          $payload.action = 'scoreboard'
          $payload.path = $subRest
        }
        'capabilities' {
          $payload.action = 'capabilities'
          if ($subRest) { $payload.command = $subRest }
        }
        default {
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: ai diag <run_id> | ai route <run_id> | ai scoreboard <path> | ai capabilities [command]'
          return
        }
      }

      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload $payload
      if (-not $resp.ok) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
        return
      }

      $result = $resp.result
      if (-not $result) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'AI command returned no result.'
        return
      }

      $lines = New-Object System.Collections.Generic.List[string]
      $lines.Add("AI action: $($result.action)")
      if ($result.summary) { $lines.Add("summary: $($result.summary)") }
      if ($result.output_json_path) { $lines.Add("output_json: $($result.output_json_path)") }
      if ($result.output_markdown_path) { $lines.Add("output_md: $($result.output_markdown_path)") }
      if ($result.ai_output) {
        switch ($result.action) {
          'diag' {
            if ($result.ai_output.recommended_next_lane) { $lines.Add("recommended_next_lane: $($result.ai_output.recommended_next_lane)") }
            if ($result.ai_output.confidence -ne $null) { $lines.Add("confidence: $($result.ai_output.confidence)") }
          }
          'route' {
            if ($result.ai_output.next_skill) { $lines.Add("next_skill: $($result.ai_output.next_skill)") }
            if ($result.ai_output.reason) { $lines.Add("reason: $($result.ai_output.reason)") }
          }
          'scoreboard' {
            if ($result.ai_output.headline) { $lines.Add("headline: $($result.ai_output.headline)") }
            if ($result.ai_output.suggested_next_run) { $lines.Add("suggested_next_run: $($result.ai_output.suggested_next_run)") }
          }
          'capabilities' {
            if ($result.ai_output.commands) {
              $count = @($result.ai_output.commands).Count
              $lines.Add("commands: $count")
              foreach ($cmdInfo in @($result.ai_output.commands) | Select-Object -First 6) {
                if ($cmdInfo.name) { $lines.Add(" - $($cmdInfo.name)") }
              }
            }
          }
        }
      }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text ($lines -join "`n")
      return
    }
    'skills' {
      if (-not $rest) { $rest = 'list' }
      $skillsScript = Join-Path $PSScriptRoot 'skills.ps1'
      $scriptArg = '"' + ($skillsScript -replace '"','""') + '"'
      $cmdText = ('pwsh -NoProfile -ExecutionPolicy Bypass -File {0} {1}' -f $scriptArg, $rest).Trim()
      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'run'; cmd = $cmdText }
      if ($resp.ok) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text "Job queued: $($resp.result.job_id)"
      } else {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      }
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
      if ($rest -and ($rest -notmatch '^\d+$')) {
        # Treat natural language that starts with "last" as a prompt, not a command.
        $promptText = $raw
        if ($routeWasExplicit -and $rest1) { $promptText = $rest1 }
        if (-not (Trim-WhitespaceLike -Text $promptText)) {
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Unknown command. Send help for usage.'
          return
        }
        $queuePrefix = if ($laneKey -and $laneKey -match '^id[1-9]\d*$') { $laneKey } else { $target }
        $queueText = if ($routeWasExplicit) { $raw } else { ("{0} {1}" -f $queuePrefix, $promptText) }
        $laneResp = Invoke-LaneExecPrompt -Prompt $promptText -ForceNew:$false -QueuedCommandText $queueText
        if (-not $laneResp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
        if ($laneResp.queued) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
        if ($laneResp.has_job) {
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex exec job $($laneResp.job_id) [lane=$(Get-LaneStatusLabel -LaneCandidate $laneKey -TargetCandidate $target)]. I'll reply here when it's done.")
          return
        }
        $out = $laneResp.out
        if (-not $out) { $out = "No output yet. Use '$target codexlast' in a moment." }
        Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
        return
      }
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

      # Allow "codex exec ..." shorthand.
      if ($subCmd -eq 'exec') {
        $cmd = 'codexexec'
        $rest = $subRest
      }
      if ($subCmd -eq 'model') {
        $cmd = 'codexmodel'
        $rest = $subRest
      }
      if ($subCmd -eq 'reasoning') {
        $cmd = 'codexreasoning'
        $rest = $subRest
      }
      if ($subCmd -eq 'config') {
        $cmd = 'codexconfig'
        $rest = $subRest
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

      $queuePrefix = if ($laneKey -and $laneKey -match '^id[1-9]\d*$') { $laneKey } else { $target }
      $queueText = if ($routeWasExplicit) { $raw } else { ("{0} codex {1}" -f $queuePrefix, $rest) }
      $laneResp = Invoke-LaneExecPrompt -Prompt $rest -ForceNew:$false -QueuedCommandText $queueText
      if (-not $laneResp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
      if ($laneResp.queued) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
      if ($laneResp.has_job) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex exec job $($laneResp.job_id) [lane=$(Get-LaneStatusLabel -LaneCandidate $laneKey -TargetCandidate $target)]. I'll reply here when it's done.")
        return
      }
      $out = $laneResp.out
      if (-not $out) { $out = "No output yet. Use '$target codexlast' in a moment." }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
      return
    }
    'codexnew' {
      if (-not $rest) {
        $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.new.exec' }
        if ($resp.ok) {
          Clear-LaneSessionId -cfg $cfg -state $state -ChatId $ChatId -Target $target -LaneKey $laneKey
        }
        Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
        return
      }

      $queuePrefix = if ($laneKey -and $laneKey -match '^id[1-9]\d*$') { $laneKey } else { $target }
      $queueText = if ($routeWasExplicit) { $raw } else { ("{0} codexnew {1}" -f $queuePrefix, $rest) }
      $laneResp = Invoke-LaneExecPrompt -Prompt $rest -ForceNew:$true -QueuedCommandText $queueText
      if (-not $laneResp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
      if ($laneResp.queued) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
      if ($laneResp.has_job) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex exec job $($laneResp.job_id) (new thread) [lane=$(Get-LaneStatusLabel -LaneCandidate $laneKey -TargetCandidate $target)]. I'll reply here when it's done.")
        return
      }
      $out = $laneResp.out
      if (-not $out) { $out = 'No output yet.' }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
      return
    }
    'codexexec' {
      $parsed = Parse-ModeCommand -Text $rest
      $modeResp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.mode'; mode = 'exec' }
      if (-not $modeResp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $modeResp); return }

      if ($parsed.action -eq 'set') {
        Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $modeResp)
        return
      }

      $queuePrefix = if ($laneKey -and $laneKey -match '^id[1-9]\d*$') { $laneKey } else { $target }
      $queueText = if ($routeWasExplicit) { $raw } else { ("{0} codexexec {1}" -f $queuePrefix, $rest) }
      $forceNew = ($parsed.action -eq 'new')
      $laneResp = Invoke-LaneExecPrompt -Prompt $parsed.prompt -ForceNew:$forceNew -QueuedCommandText $queueText
      if (-not $laneResp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
      if ($laneResp.queued) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
      if ($laneResp.has_job) {
        $tag = if ($forceNew) { ' (new thread)' } else { '' }
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex exec job $($laneResp.job_id)$tag [lane=$(Get-LaneStatusLabel -LaneCandidate $laneKey -TargetCandidate $target)]. I'll reply here when it's done.")
        return
      }
      $out = $laneResp.out
      if (-not $out) { $out = "No output yet. Use '$target codexlast' in a moment." }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
      return
    }
    'codexconsole' {
      $parsed = Parse-ModeCommand -Text $rest
      $consoleTarget = $target
      if ($cfg.ConsoleTarget) {
        $ct = $cfg.ConsoleTarget.ToLowerInvariant()
        if ($cfg.Targets.ContainsKey($ct)) { $consoleTarget = $ct }
      }
      $modeResp = Send-AgentRequest -cfg $cfg -Target $consoleTarget -Payload @{ op = 'codex.mode'; mode = 'console' }
      if (-not $modeResp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $modeResp); return }

      if ($parsed.action -eq 'set') {
        Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $modeResp)
        return
      }

      if ($parsed.action -eq 'new') {
        $payload = @{ op = 'codex.new' }
        if ($parsed.prompt) { $payload.prompt = $parsed.prompt }
        $resp = Send-AgentRequest -cfg $cfg -Target $consoleTarget -Payload $payload
      } else {
        $resp = Send-AgentRequest -cfg $cfg -Target $consoleTarget -Payload @{ op = 'codex.send'; prompt = $parsed.prompt }
      }

      if ($resp.ok) {
        $out = $resp.result.output
        $jobId = $null
        $jobPid = $null
        if ($resp.result -and $resp.result.job_id) { $jobId = [string]$resp.result.job_id }
        if ($resp.result -and $resp.result.pid) { $jobPid = [string]$resp.result.pid }

        if ($parsed.prompt -and (Is-NoOutputText -Text $out)) {
          $polledOut = Try-Resolve-ConsoleOutput -cfg $cfg -Target $consoleTarget
          if ($polledOut) { $out = $polledOut }
        }

        if ($cfg.ConsoleFallbackExec -and $parsed.prompt -and (Is-NoOutputText -Text $out)) {
          $fallback = Send-AgentRequest -cfg $cfg -Target $consoleTarget -Payload @{ op = 'codex.send.exec'; prompt = $parsed.prompt }
          if ($fallback.ok) {
            $resp = $fallback
            $out = $resp.result.output
            $jobId = $null
            $jobPid = $null
            if ($resp.result -and $resp.result.job_id) { $jobId = [string]$resp.result.job_id }
            if ($resp.result -and $resp.result.pid) { $jobPid = [string]$resp.result.pid }
          }
        }

        if ($jobId -and $jobPid) {
          Add-PendingCodexJob -JobId $jobId -Target $consoleTarget -ChatId $ChatId
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex console job $jobId. I'll reply here when it's done.")
        } else {
          if (-not $out) { $out = "No output yet. Use '$target codexlast' in a moment." }
          Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
        }
      } else {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      }
      return
    }
    'codexconsoleexec' {
      $parsed = Parse-ModeCommand -Text $rest
      $consoleTarget = $target
      if ($cfg.ConsoleTarget) {
        $ct = $cfg.ConsoleTarget.ToLowerInvariant()
        if ($cfg.Targets.ContainsKey($ct)) { $consoleTarget = $ct }
      }
      $modeResp = Send-AgentRequest -cfg $cfg -Target $consoleTarget -Payload @{ op = 'codex.mode'; mode = 'console' }
      if (-not $modeResp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $modeResp); return }

      if ($parsed.action -eq 'set') {
        Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $modeResp)
        return
      }

      if ($parsed.action -eq 'new') {
        $payload = @{ op = 'codex.new' }
        if ($parsed.prompt) { $payload.prompt = $parsed.prompt }
        $resp = Send-AgentRequest -cfg $cfg -Target $consoleTarget -Payload $payload
      } else {
        $resp = Send-AgentRequest -cfg $cfg -Target $consoleTarget -Payload @{ op = 'codex.send'; prompt = $parsed.prompt }
      }

      if ($resp.ok) {
        $out = $resp.result.output
        $jobId = $null
        $jobPid = $null
        if ($resp.result -and $resp.result.job_id) { $jobId = [string]$resp.result.job_id }
        if ($resp.result -and $resp.result.pid) { $jobPid = [string]$resp.result.pid }

        if ($parsed.prompt -and (Is-NoOutputText -Text $out)) {
          $polledOut = Try-Resolve-ConsoleOutput -cfg $cfg -Target $consoleTarget
          if ($polledOut) { $out = $polledOut }
        }

        if ($parsed.prompt -and (Is-NoOutputText -Text $out)) {
          $fallback = Send-AgentRequest -cfg $cfg -Target $consoleTarget -Payload @{ op = 'codex.send.exec'; prompt = $parsed.prompt }
          if ($fallback.ok) {
            $resp = $fallback
            $out = $resp.result.output
            $jobId = $null
            $jobPid = $null
            if ($resp.result -and $resp.result.job_id) { $jobId = [string]$resp.result.job_id }
            if ($resp.result -and $resp.result.pid) { $jobPid = [string]$resp.result.pid }
          }
        }

        if ($jobId -and $jobPid) {
          Add-PendingCodexJob -JobId $jobId -Target $consoleTarget -ChatId $ChatId
          Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex console job $jobId. I'll reply here when it's done.")
        } else {
          if (-not $out) { $out = "No output yet. Use '$target codexlast' in a moment." }
          Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
        }
      } else {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      }
      return
    }
    'codexexecnew' {
      Handle-Command -cfg $cfg -state $state -ChatId $ChatId -Text ("$target codexexec new $rest".Trim())
      return
    }
    'codexconsolenew' {
      Handle-Command -cfg $cfg -state $state -ChatId $ChatId -Text ("$target codexconsole new $rest".Trim())
      return
    }
    'codexconsoleexecnew' {
      Handle-Command -cfg $cfg -state $state -ChatId $ChatId -Text ("$target codexconsoleexec new $rest".Trim())
      return
    }
    'codexforceexec' {
      Handle-Command -cfg $cfg -state $state -ChatId $ChatId -Text ("$target codexexec $rest".Trim())
      return
    }
    'codexforceexecnew' {
      Handle-Command -cfg $cfg -state $state -ChatId $ChatId -Text ("$target codexexec new $rest".Trim())
      return
    }
    'codexfresh' {
      # Always start a fresh exec session (never console). Optional prompt.
      try { $null = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.cancel' } } catch {}
      $modeResp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.mode'; mode = 'exec' }
      if (-not $modeResp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $modeResp); return }
      if (-not $rest) {
        $resetResp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.new.exec' }
        if ($resetResp.ok) {
          Clear-LaneSessionId -cfg $cfg -state $state -ChatId $ChatId -Target $target -LaneKey $laneKey
        }
        Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resetResp)
        return
      }

      $queuePrefix = if ($laneKey -and $laneKey -match '^id[1-9]\d*$') { $laneKey } else { $target }
      $queueText = if ($routeWasExplicit) { $raw } else { ("{0} codexfresh {1}" -f $queuePrefix, $rest) }
      $laneResp = Invoke-LaneExecPrompt -Prompt $rest -ForceNew:$true -QueuedCommandText $queueText
      if (-not $laneResp.ok) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
      if ($laneResp.queued) { Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message; return }
      if ($laneResp.has_job) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex exec job $($laneResp.job_id) (fresh) [lane=$(Get-LaneStatusLabel -LaneCandidate $laneKey -TargetCandidate $target)]. I'll reply here when it's done.")
        return
      }
      $out = $laneResp.out
      if (-not $out) { $out = "No output yet. Use '$target codexlast' in a moment." }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
      return
    }
    'codexfreshconsole' {
      # Always start a fresh console session. Optional prompt.
      Handle-Command -cfg $cfg -state $state -ChatId $ChatId -Text ("$target codexconsole new $rest".Trim())
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
      if ($tokens.Count -ge 1 -and $tokens[-1].ToLowerInvariant() -eq 'reset') {
        $reset = $true
        if ($tokens.Count -gt 1) { $tokens = $tokens[0..($tokens.Count - 2)] } else { $tokens = @() }
      }
      $model = ($tokens -join ' ').Trim()
      if ($model.ToLowerInvariant() -in @('default','clear','none')) { $model = '' }

      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.model'; model = $model; reset = $reset }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexreasoning' {
      if (-not $rest) {
        $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.reasoning.get' }
        Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
        return
      }

      $tokens = $rest -split '\s+'
      $reset = $false
      if ($tokens.Count -ge 1 -and $tokens[-1].ToLowerInvariant() -eq 'reset') {
        $reset = $true
        if ($tokens.Count -gt 1) { $tokens = $tokens[0..($tokens.Count - 2)] } else { $tokens = @() }
      }
      $reasoning = (($tokens -join ' ').Trim()).ToLowerInvariant()
      if ($reasoning -in @('default','clear','none')) { $reasoning = '' }
      if ($reasoning -and ($reasoning -notin @('low','medium','high','xhigh'))) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Usage: codexreasoning [low|medium|high|xhigh|default] [reset]'
        return
      }

      $resp = Send-AgentRequest -cfg $cfg -Target $target -Payload @{ op = 'codex.reasoning'; reasoning_effort = $reasoning; reset = $reset }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text (Format-ResultText $resp)
      return
    }
    'codexconfig' {
      Send-CodexConfigPanel -cfg $cfg -ChatId $ChatId -Target $target
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
      if ($routeWasExplicit -and $rest1) {
        # Preserve original casing/punctuation by using the original "rest after explicit route token".
        $promptText = $rest1
      }
      if (-not (Trim-WhitespaceLike -Text $promptText)) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text 'Unknown command. Send help for usage.'
        return
      }

      $queueText = if ($routeWasExplicit) {
        $raw
      } else {
        $routePrefix = if ($laneKey -and $laneKey -match '^id[1-9]\d*$') { $laneKey } else { $target }
        ("{0} {1}" -f $routePrefix, $promptText)
      }
      $laneResp = Invoke-LaneExecPrompt -Prompt $promptText -ForceNew:$false -QueuedCommandText $queueText
      if (-not $laneResp.ok) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message
        return
      }
      if ($laneResp.queued) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text $laneResp.message
        return
      }
      if ($laneResp.has_job) {
        Send-TgMessage -cfg $cfg -ChatId $ChatId -Text ("Queued codex exec job $($laneResp.job_id) [lane=$(Get-LaneStatusLabel -LaneCandidate $laneKey -TargetCandidate $target)]. I'll reply here when it's done.")
        return
      }
      $out = $laneResp.out
      if (-not $out) { $out = "No output yet. Use '$target codexlast' in a moment." }
      Send-ChunkedText -cfg $cfg -ChatId $ChatId -Text $out
      return
    }
  }
}
$cfg = Get-Config -ConfigPath $ConfigPath
$state = Load-State -cfg $cfg
Write-BotLog -Path $cfg.BotLog -Message 'Broker started.'
Write-Console ("Broker up. default_target={0} targets={1} poll_timeout={2}s log={3}" -f $cfg.DefaultTarget, $cfg.Targets.Count, $cfg.PollTimeoutSec, $cfg.BotLog)

Ensure-SingleBroker -cfg $cfg
Clear-TgWebhook -cfg $cfg -Reason 'startup'

# Only write pid after acquiring the single-broker mutex, so pid files are always "the active broker".
try {
  $logs = Join-Path $PSScriptRoot 'logs'
  New-Item -ItemType Directory -Force -Path $logs | Out-Null
  Set-Content -LiteralPath (Join-Path $logs 'broker.pid') -Value $PID
} catch {}

$offset = 0
try { $offset = [int]$state.last_update_id } catch { $offset = 0 }

while ($true) {
  # If the agent is running Codex asynchronously, push completed jobs without requiring codexlast.
  try {
    Ensure-StateProperty -state $state -Name 'pending_codex_jobs' -Value @()
    Ensure-StateProperty -state $state -Name 'pending_codex_prompts' -Value @()
    $pending = @()
    try { $pending = @($state.pending_codex_jobs) } catch { $pending = @() }
    if ($pending.Count -gt 0) {
      $remaining = @()
      foreach ($j in $pending) {
        if (-not $j) { continue }
        $jobId = $null
        $tgt = $cfg.DefaultTarget
        $cid = $null
        $laneKey = ''
        try { $jobId = [string]$j.job_id } catch {}
        try { if ($j.target) { $tgt = [string]$j.target } } catch {}
        try { $cid = [string]$j.chat_id } catch {}
        try { if ($j.lane_key) { $laneKey = [string]$j.lane_key } } catch {}
        if (-not $cid) { continue }

        $jr = Send-AgentRequest -cfg $cfg -Target $tgt -Payload @{ op = 'codex.job' }
        if (-not $jr.ok) { $remaining += $j; continue }
        $job = $jr.result.job
        $currentJobId = $null
        $currentJobRunning = $false
        if ($job) {
          try { if ($job.id) { $currentJobId = [string]$job.id } } catch {}
          try { $currentJobRunning = [bool]$job.running } catch { $currentJobRunning = $false }
        }
        if ($jobId -and $currentJobId -and ($jobId -eq $currentJobId) -and $currentJobRunning) {
          $remaining += $j
          continue
        }

        $lrPayload = @{ op = 'codex.last'; session = 'default' }
        if ($jobId) { $lrPayload.job_id = $jobId }
        $lr = Send-AgentRequest -cfg $cfg -Target $tgt -Payload $lrPayload
        if (-not $lr.ok) {
          $remaining += $j
          continue
        }
        $outText = Format-ResultText $lr
        if ($lr.ok -and $laneKey) {
          $sid = Try-ExtractCodexSessionIdFromText -Text $outText
          if ($sid) {
            Set-LaneSessionId -cfg $cfg -state $state -ChatId $cid -Target $tgt -LaneKey $laneKey -SessionId $sid
          }
        }
        $laneLabel = if ($laneKey) { $laneKey } else { $tgt }
        $jobLabel = if ($jobId) { $jobId } else { 'n/a' }
        $prefix = "[telebot] lane: $laneLabel | target: $tgt | job_id: $jobLabel"
        if ($outText) { $outText = "$prefix`n`n$outText" } else { $outText = $prefix }
        Send-ChunkedText -cfg $cfg -ChatId $cid -Text $outText
      }
      $state.pending_codex_jobs = $remaining
      Save-State -cfg $cfg -state $state
    }

    $queuedPrompts = @()
    try { $queuedPrompts = @($state.pending_codex_prompts) } catch { $queuedPrompts = @() }
    if ($queuedPrompts.Count -gt 0) {
      $keepQueued = @()
      $dispatchedTargets = New-Object 'System.Collections.Generic.HashSet[string]'
      foreach ($qp in ($queuedPrompts | Sort-Object queued_at)) {
        if (-not $qp) { continue }
        $qid = ''
        $tgt = $cfg.DefaultTarget
        $cid = ''
        $cmdText = ''
        try { if ($qp.id) { $qid = [string]$qp.id } } catch {}
        try { if ($qp.target) { $tgt = [string]$qp.target } } catch {}
        try { if ($qp.chat_id) { $cid = [string]$qp.chat_id } } catch {}
        try { if ($qp.command_text) { $cmdText = [string]$qp.command_text } } catch {}

        if (-not $cid -or -not $cmdText) { continue }
        if (-not $cfg.Targets.ContainsKey($tgt)) {
          Send-TgMessage -cfg $cfg -ChatId $cid -Text ("Dropped queued prompt {0}: target '{1}' is no longer configured." -f $qid, $tgt)
          continue
        }
        if ($dispatchedTargets.Contains($tgt)) {
          $keepQueued += $qp
          continue
        }

        $jr = Send-AgentRequest -cfg $cfg -Target $tgt -Payload @{ op = 'codex.job' }
        if (-not $jr.ok) {
          $keepQueued += $qp
          continue
        }
        $job = $jr.result.job
        if ($job -and $job.running) {
          $keepQueued += $qp
          continue
        }

        Write-BotLog -Path $cfg.BotLog -Message ("dispatch queued prompt id={0} target={1}" -f $qid, $tgt)
        try {
          Handle-Command -cfg $cfg -state $state -ChatId $cid -Text $cmdText
        } catch {
          Write-BotLog -Path $cfg.BotLog -Message ("queued dispatch failed id={0}: {1}" -f $qid, $_.Exception.Message)
          $keepQueued += $qp
          continue
        }
        $null = $dispatchedTargets.Add($tgt)
      }
      $state.pending_codex_prompts = $keepQueued
      Save-State -cfg $cfg -state $state
    }
  } catch {
    Write-BotLog -Path $cfg.BotLog -Message ("pending tick failed: " + $_.Exception.Message)
  }

  $updates = Get-TgUpdates -cfg $cfg -Offset $offset
  if ($cfg.ExitOn409 -and $script:Consecutive409 -ge $cfg.ExitOn409Threshold) {
    Write-BotLog -Path $cfg.BotLog -Message "Exiting after $($script:Consecutive409) consecutive 409 conflicts (another broker is polling this bot)."
    Write-Console "Broker exiting: another broker is polling this bot (409 conflict)."
    exit 2
  }

  if ($updates.ok -and $updates.result) {
    foreach ($update in $updates.result) {
      $script:LastMessageAt = Get-Date
      $offset = [int]$update.update_id + 1
      try { $state.last_update_id = $offset } catch { Ensure-StateProperty -state $state -Name 'last_update_id' -Value $offset; try { $state.last_update_id = $offset } catch {} }
      Save-State -cfg $cfg -state $state
      $cb = $update.callback_query
      if ($cb) {
        try {
          Handle-CallbackQuery -cfg $cfg -state $state -Query $cb
        } catch {
          Write-BotLog -Path $cfg.BotLog -Message "Handle-CallbackQuery failed: $($_.Exception.Message)"
          try {
            $cbid = [string]$cb.id
            if ($cbid) { Answer-TgCallback -cfg $cfg -CallbackQueryId $cbid -Text 'Action failed.' }
          } catch {}
        }
        continue
      }
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

  # Optional console heartbeat (for visible console runs). Off by default.
  if ($cfg.ConsoleHeartbeatSec -gt 0) {
    $now = Get-Date
    if ((($now - $script:LastHeartbeatAt).TotalSeconds) -ge $cfg.ConsoleHeartbeatSec) {
      $pendingCount = 0
      try { $pendingCount = @($state.pending_codex_jobs).Count } catch { $pendingCount = 0 }
      $queuedPromptCount = 0
      try { $queuedPromptCount = @($state.pending_codex_prompts).Count } catch { $queuedPromptCount = 0 }
      $last = if ($script:LastMessageAt) { $script:LastMessageAt.ToString('HH:mm:ss') } else { 'never' }
      $off = 0
      try { $off = [int]$state.last_update_id } catch { $off = 0 }
      Write-Console ("[{0}] heartbeat: last_msg={1} pending_jobs={2} queued_prompts={3} offset={4} 409s={5}" -f $now.ToString('HH:mm:ss'), $last, $pendingCount, $queuedPromptCount, $off, $script:Consecutive409)
      $script:LastHeartbeatAt = $now
    }
  }
}
