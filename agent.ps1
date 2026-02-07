param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'agent.env')
)

$ErrorActionPreference = 'Stop'

try { $Host.UI.RawUI.WindowTitle = 'TelebotAgent' } catch {}

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

function Try-Read-CodexUserConfig {
  param([string]$Path)
  $model = ''
  $reasoning = ''
  if (-not $Path) { return @{ model = $model; reasoning = $reasoning } }
  if (-not (Test-Path -LiteralPath $Path)) { return @{ model = $model; reasoning = $reasoning } }
  try {
    $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
  } catch {
    return @{ model = $model; reasoning = $reasoning }
  }
  foreach ($line in ($text -split "`r?`n")) {
    $trim = $line.Trim()
    if (-not $trim) { continue }
    if ($trim.StartsWith('#')) { continue }

    if (-not $model -and $trim -match '^model\s*=\s*["'']([^"'']+)["'']') {
      $model = $Matches[1]
      continue
    }
    if (-not $reasoning -and $trim -match '^model_reasoning_effort\s*=\s*["'']([^"'']+)["'']') {
      $reasoning = $Matches[1]
      continue
    }
  }
  return @{ model = $model; reasoning = $reasoning }
}

function Get-Config {
  param([string]$ConfigPath)

  $cfg = [ordered]@{
    Name = 'pc'
    ListenAddr = '0.0.0.0'
    ListenPort = 8765
    Secret = ''
    DefaultCwd = 'C:\\dev\\unity_clean'
    CodexCwd = 'C:\\dev\\unity_clean'
    AllowPrefixes = @('git','pwsh','python','dotnet','cmd','C:\\dev\\unity_clean')
    TailLines = 80
    LogDir = (Join-Path $PSScriptRoot 'logs')
    StateFile = (Join-Path $PSScriptRoot 'agent_state.json')
    RunnerPath = (Join-Path $PSScriptRoot 'runner.ps1')
    CodexJobScript = (Join-Path $PSScriptRoot 'codex_job.ps1')
    CodexBaseCmd = 'codex -a never --sandbox danger-full-access --no-alt-screen'
    CodexTimeoutSec = 300
    CodexWaitSec = 15
    CodexWindowTitle = 'CODEX_BRIDGE'
    CodexTranscript = (Join-Path $PSScriptRoot 'logs\\codex_console.log')
    CodexConsoleScript = (Join-Path $PSScriptRoot 'codex_console.ps1')
    CodexConsoleAutoStart = $true
    CodexStartWaitSec = 8
    CodexSendKey = 'enter'
    ClientTimeoutSec = 300
    CodexDangerous = $true
    CodexModel = ''
    CodexReasoningEffort = ''
    CodexUserConfigPath = ''
    CodexUserConfigModel = ''
    CodexUserConfigReasoningEffort = ''
    CodexAsync = $true
    CodexJobTailLines = 60
    CodexAutoInit = $false
    CodexInitPrompt = 'Initialize session. Reply "ready".'
    CodexAppendSession = $true
  }

  Import-DotEnv -Path $ConfigPath

  if ($env:AGENT_NAME) { $cfg.Name = $env:AGENT_NAME }
  if ($env:LISTEN_ADDR) { $cfg.ListenAddr = $env:LISTEN_ADDR }
  if ($env:LISTEN_PORT) { $cfg.ListenPort = [int]$env:LISTEN_PORT }
  if ($env:AGENT_SECRET) { $cfg.Secret = $env:AGENT_SECRET }
  if ($env:DEFAULT_CWD) { $cfg.DefaultCwd = $env:DEFAULT_CWD }
  if ($env:CODEX_CWD) { $cfg.CodexCwd = $env:CODEX_CWD }
  if ($env:ALLOW_PREFIXES) {
    $cfg.AllowPrefixes = $env:ALLOW_PREFIXES.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  }
  if ($env:TAIL_LINES) { $cfg.TailLines = [int]$env:TAIL_LINES }
  if ($env:CODEX_BASE_CMD) { $cfg.CodexBaseCmd = $env:CODEX_BASE_CMD }
  if ($env:CODEX_MODEL) { $cfg.CodexModel = $env:CODEX_MODEL }
  if ($env:CODEX_TIMEOUT_SEC) { $cfg.CodexTimeoutSec = [int]$env:CODEX_TIMEOUT_SEC }
  if ($env:CODEX_MODE) { $cfg.CodexMode = $env:CODEX_MODE }
  if ($env:CODEX_WINDOW_TITLE) { $cfg.CodexWindowTitle = $env:CODEX_WINDOW_TITLE }
  if ($env:CODEX_TRANSCRIPT) { $cfg.CodexTranscript = $env:CODEX_TRANSCRIPT }
  if ($env:CODEX_CONSOLE_SCRIPT) { $cfg.CodexConsoleScript = $env:CODEX_CONSOLE_SCRIPT }
  if ($env:CODEX_CONSOLE_AUTOSTART) { $cfg.CodexConsoleAutoStart = ($env:CODEX_CONSOLE_AUTOSTART -match '^(1|true|yes)$') }
  if ($env:CODEX_START_WAIT_SEC) { $cfg.CodexStartWaitSec = [int]$env:CODEX_START_WAIT_SEC }
  if ($env:CODEX_SEND_KEY) { $cfg.CodexSendKey = $env:CODEX_SEND_KEY }
  if ($env:CODEX_WAIT_SEC) { $cfg.CodexWaitSec = [int]$env:CODEX_WAIT_SEC }
  if ($env:CLIENT_TIMEOUT_SEC) { $cfg.ClientTimeoutSec = [int]$env:CLIENT_TIMEOUT_SEC }
  if ($env:CODEX_DANGEROUS) { $cfg.CodexDangerous = ($env:CODEX_DANGEROUS -match '^(1|true|yes)$') }
  if ($env:CODEX_REASONING_EFFORT) { $cfg.CodexReasoningEffort = $env:CODEX_REASONING_EFFORT }
  if ($env:CODEX_ASYNC) { $cfg.CodexAsync = ($env:CODEX_ASYNC -match '^(1|true|yes)$') }
  if ($env:CODEX_AUTO_INIT) { $cfg.CodexAutoInit = ($env:CODEX_AUTO_INIT -match '^(1|true|yes)$') }
  if ($env:CODEX_INIT_PROMPT) { $cfg.CodexInitPrompt = $env:CODEX_INIT_PROMPT }
  if ($env:CODEX_APPEND_SESSION) { $cfg.CodexAppendSession = ($env:CODEX_APPEND_SESSION -match '^(1|true|yes)$') }

  if (-not (Test-Path -LiteralPath $cfg.RunnerPath)) {
    throw "runner.ps1 missing at $($cfg.RunnerPath)"
  }
  if ($cfg.CodexAsync -and -not (Test-Path -LiteralPath $cfg.CodexJobScript)) {
    throw "codex_job.ps1 missing at $($cfg.CodexJobScript)"
  }

  New-Item -ItemType Directory -Force -Path $cfg.LogDir | Out-Null

  $cfg.PwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
  if (-not $cfg.PwshPath) { $cfg.PwshPath = (Get-Command powershell -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1) }
  if (-not $cfg.PwshPath) { throw 'pwsh or powershell not found in PATH.' }

  if (-not (Test-Path -LiteralPath $cfg.CodexCwd)) { $cfg.CodexCwd = $cfg.DefaultCwd }
  if ($cfg.CodexCwd -and ($cfg.CodexBaseCmd -notmatch '\s(-C|--cd)\s')) {
    $cfg.CodexBaseCmd = "$($cfg.CodexBaseCmd) -C $($cfg.CodexCwd)"
  }
  if ($cfg.CodexModel -and ($cfg.CodexBaseCmd -notmatch '(^|\s)(-m|--model)\s')) {
    $cfg.CodexBaseCmd = "$($cfg.CodexBaseCmd) -m $($cfg.CodexModel)"
  }

  $cfg.CodexUserConfigPath = Join-Path $env:USERPROFILE '.codex\\config.toml'
  $userCfg = Try-Read-CodexUserConfig -Path $cfg.CodexUserConfigPath
  if ($userCfg) {
    if ($userCfg.model) { $cfg.CodexUserConfigModel = [string]$userCfg.model }
    if ($userCfg.reasoning) { $cfg.CodexUserConfigReasoningEffort = [string]$userCfg.reasoning }
  }

  return $cfg
}

function Split-Command {
  param([string]$Command)
  if (-not $Command) { return $null }
  $text = $Command.Trim()
  if (-not $text) { return $null }

  $len = $text.Length
  $i = 0
  $exe = ''
  $args = ''

  if ($text[0] -eq '"') {
    $i = 1
    while ($i -lt $len -and $text[$i] -ne '"') { $i++ }
    if ($i -ge $len) { return $null }
    $exe = $text.Substring(1, $i - 1)
    $i++
  } else {
    while ($i -lt $len -and -not [char]::IsWhiteSpace($text[$i])) { $i++ }
    $exe = $text.Substring(0, $i)
  }

  if ($i -lt $len) { $args = $text.Substring($i).TrimStart() }
  return @{ exe = $exe; args = $args }
}


function Quote-CmdArg {
  param([string]$Arg)
  if ($Arg -match '[\s\"^&|<>]') {
    $escaped = $Arg -replace '"', '""'
    return '"' + $escaped + '"'
  }
  return $Arg
}

function Parse-Args {
  param([string]$Args)
  if (-not $Args) { return @() }
  $errs = $null
  $tokens = [System.Management.Automation.PSParser]::Tokenize($Args, [ref]$errs)
  $list = @()
  foreach ($t in $tokens) {
    if ($t.Type -in 'CommandArgument','String','CommandParameter') { $list += $t.Content }
  }
  return $list
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

function Start-CodexConsole {
  param($cfg)
  if (-not (Test-Path -LiteralPath $cfg.CodexConsoleScript)) {
    throw "codex_console.ps1 missing at $($cfg.CodexConsoleScript)"
  }

  $args = @(
    '-NoProfile',
    '-File', $cfg.CodexConsoleScript,
    '-Title', $cfg.CodexWindowTitle,
    '-Transcript', $cfg.CodexTranscript,
    '-WorkingDir', $cfg.CodexCwd
  )
  if ($cfg.CodexModel) { $args += @('-Model', $cfg.CodexModel) }

  $null = Start-Process -FilePath $cfg.PwshPath -ArgumentList $args -WorkingDirectory $cfg.CodexCwd
}

function Stop-CodexConsole {
  param($cfg)
  $stopped = $false
  try {
    $pattern = [regex]::Escape($cfg.CodexConsoleScript)
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match $pattern }
    foreach ($p in $procs) {
      try {
        Stop-Process -Id $p.ProcessId -Force
        $stopped = $true
      } catch {}
    }
  } catch {}
  return $stopped
}

function Send-CodexConsolePrompt {
  param($cfg, $state, [string]$Prompt)

  Ensure-StateProperty -state $state -Name 'codex_console_offset' -Value 0

  Add-Type -AssemblyName System.Windows.Forms
  $shell = New-Object -ComObject WScript.Shell
  $ok = $shell.AppActivate($cfg.CodexWindowTitle)
  if (-not $ok -and $cfg.CodexConsoleAutoStart) {
    Start-CodexConsole -cfg $cfg
    Start-Sleep -Seconds $cfg.CodexStartWaitSec
    $ok = $shell.AppActivate($cfg.CodexWindowTitle)
  }
  if (-not $ok) { throw "Codex window not found: $($cfg.CodexWindowTitle)" }

  if ($state.codex_console_offset -eq 0 -and (Test-Path -LiteralPath $cfg.CodexTranscript)) {
    $state.codex_console_offset = (Get-Item -LiteralPath $cfg.CodexTranscript).Length
    Save-State -cfg $cfg -state $state
  }

  Start-Sleep -Milliseconds 200
  [System.Windows.Forms.SendKeys]::SendWait($Prompt)
  switch ($cfg.CodexSendKey.ToLowerInvariant()) {
    'ctrl+enter' { [System.Windows.Forms.SendKeys]::SendWait("^{ENTER}") }
    'shift+enter' { [System.Windows.Forms.SendKeys]::SendWait("+{ENTER}") }
    default { [System.Windows.Forms.SendKeys]::SendWait("{ENTER}") }
  }

  Start-Sleep -Seconds $cfg.CodexWaitSec

  $offset = 0
  if ($state.codex_console_offset) { $offset = [long]$state.codex_console_offset }
  $delta = Read-LogDelta -Path $cfg.CodexTranscript -Offset $offset
  $state.codex_console_offset = $delta.newOffset
  Save-State -cfg $cfg -state $state

  if (-not $delta.text) { return '(no output yet)' }
  $clean = Clean-TranscriptText -Text $delta.text
  if (-not $clean) { return '(sent; no output yet)' }
  return $clean
}

function Read-LogDelta {
  param([string]$Path, [long]$Offset)
  if (-not (Test-Path -LiteralPath $Path)) { return @{ text = ''; newOffset = $Offset } }
  $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try {
    $null = $fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
    $sr = New-Object System.IO.StreamReader($fs)
    $text = $sr.ReadToEnd()
    $newOffset = $fs.Length
    return @{ text = $text; newOffset = $newOffset }
  } finally {
    if ($sr) { $sr.Dispose() }
    $fs.Dispose()
  }
}

function Clean-TranscriptText {
  param([string]$Text)
  if (-not $Text) { return '' }
  $lines = $Text -split "`r?`n"
  $clean = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if (-not $line) { continue }
    if ($line -match '^\*{6,}$') { continue }
    if ($line -match '^(PowerShell transcript|Start time:|End time:|Username:|RunAs User:|Configuration Name:|Machine:|Host Application:|Process ID:|PSVersion:|PSEdition:|GitCommitId:|OS:|Platform:|PSCompatibleVersions:|PSRemotingProtocolVersion:|SerializationVersion:|WSManStackVersion:)') { continue }
    $clean.Add($line)
  }
  return ($clean -join "`n")
}

function Append-SessionInfo {
  param($cfg, $state, [string]$Text)
  if (-not $cfg.CodexAppendSession) { return $Text }
  $sid = $null
  if ($state.PSObject.Properties.Name -contains 'codex_session_id') { $sid = $state.codex_session_id }
  if (-not $sid) { return $Text }
  $model = $null
  if ($state.PSObject.Properties.Name -contains 'codex_model' -and $state.codex_model) { $model = $state.codex_model }
  elseif ($cfg.CodexModel) { $model = $cfg.CodexModel }
  elseif ($cfg.CodexUserConfigModel) { $model = $cfg.CodexUserConfigModel }
  if (-not $model) { $model = 'default' }

  $reasoning = $null
  if ($state.PSObject.Properties.Name -contains 'codex_reasoning_effort' -and $state.codex_reasoning_effort) { $reasoning = $state.codex_reasoning_effort }
  elseif ($cfg.CodexReasoningEffort) { $reasoning = $cfg.CodexReasoningEffort }
  elseif ($cfg.CodexUserConfigReasoningEffort) { $reasoning = $cfg.CodexUserConfigReasoningEffort }
  if (-not $reasoning) { $reasoning = 'default' }

  $cwd = $null
  if ($state.PSObject.Properties.Name -contains 'codex_cwd') { $cwd = $state.codex_cwd }
  if (-not $cwd) { $cwd = $cfg.CodexCwd }
  if (-not $cwd) { $cwd = $cfg.DefaultCwd }
  $perms = if ($cfg.CodexDangerous) { 'full' } else { 'restricted' }
  $agentName = $cfg.Name
  $machineName = $env:COMPUTERNAME
  $agentLabel = if ($agentName -and $machineName -and ($agentName -ne $machineName)) { "$agentName@$machineName" }
    elseif ($agentName) { $agentName }
    elseif ($machineName) { $machineName }
    else { 'unknown' }
  $suffix = "[telebot] codex_session_id: $sid | model: $model | reasoning: $reasoning | perms: $perms | cwd: $cwd | agent: $agentLabel"
  if (-not $Text) { return $suffix }
  return ($Text.TrimEnd() + "`n`n" + $suffix)
}

function Get-LogTail {
  param([string]$LogPath, [int]$Lines)
  if (-not (Test-Path -LiteralPath $LogPath)) { return '(log missing)' }
  $content = Get-Content -LiteralPath $LogPath -Tail $Lines -ErrorAction SilentlyContinue
  return ($content -join "`n")
}

function Load-State {
  param($cfg)
  if (Test-Path -LiteralPath $cfg.StateFile) {
    try {
      $obj = Get-Content -LiteralPath $cfg.StateFile -Raw | ConvertFrom-Json
      Ensure-StateProperty -state $obj -Name 'last_job_id' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_has_session' -Value $false
      Ensure-StateProperty -state $obj -Name 'codex_last_log' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_session_id' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_console_offset' -Value 0
      Ensure-StateProperty -state $obj -Name 'codex_cwd' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_model' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_reasoning_effort' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_id' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_pid' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_prompt' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_outfile' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_stdout' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_stderr' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_result' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_exit' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_started' -Value $null
      if (-not $obj.codex_session_id) { $obj.codex_has_session = $false }
      return $obj
    } catch {}
  }
  $obj = [ordered]@{
    last_job_id = $null
    codex_has_session = $false
    codex_last_log = $null
    codex_session_id = $null
    codex_console_offset = 0
    codex_cwd = $null
    codex_model = $null
    codex_reasoning_effort = $null
    codex_job_id = $null
    codex_job_pid = $null
    codex_job_prompt = $null
    codex_job_outfile = $null
    codex_job_stdout = $null
    codex_job_stderr = $null
    codex_job_result = $null
    codex_job_exit = $null
    codex_job_started = $null
  }
  return $obj
}

function Save-State {
  param($cfg, $state)
  $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cfg.StateFile
}
function Ensure-StateProperty {
  param($state, [string]$Name, $Value)
  if ($state -is [System.Collections.IDictionary]) {
    if (-not $state.Contains($Name)) { $state[$Name] = $Value }
    return
  }
  if (-not ($state.PSObject.Properties.Name -contains $Name)) {
    $state | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
  }
}


function Start-RunJob {
  param($cfg, $state, [string]$Command, [string]$Cwd)

  $jobId = New-JobId
  $logPath = Join-Path $cfg.LogDir "job_${jobId}.log"
  $exitPath = Join-Path $cfg.LogDir "job_${jobId}.exit"

  $argList = @('-NoProfile','-File', $cfg.RunnerPath, '-Command', $Command, '-Cwd', $Cwd, '-LogPath', $logPath, '-ExitPath', $exitPath)
  $null = Start-Process -FilePath $cfg.PwshPath -ArgumentList $argList -WindowStyle Minimized

  $state.last_job_id = $jobId
  Save-State -cfg $cfg -state $state

  return @{ id = $jobId; log = $logPath; exit = $exitPath }
}

$Sessions = @{}


function Resolve-Command {
  param($cfg, [string]$Exe, [string]$ArgString)

  $exePath = $Exe
  if (-not $exePath) { return $null }

  $isPath = ($exePath -match '^[A-Za-z]:\\') -or $exePath.StartsWith('.\\') -or $exePath.StartsWith('..\\') -or $exePath.StartsWith('\\')
  if (-not $isPath) {
    $cmd = Get-Command $exePath -ErrorAction SilentlyContinue
    if (-not $cmd -and $exePath -ieq 'codex') {
      $npmBin = Join-Path $env:APPDATA 'npm'
      $fallback = Join-Path $npmBin 'codex.ps1'
      if (Test-Path -LiteralPath $fallback) {
        $cmd = [pscustomobject]@{ Source = $fallback }
      }
    }
    if ($cmd) {
      $src = $cmd.Source
      if ($src -and $src.ToLowerInvariant().EndsWith('.ps1')) {
        $exePath = $cfg.PwshPath
        $ArgString = "-NoProfile -File `"$src`" $ArgString"
      } else {
        $exePath = $src
      }
    }
  }

  return @{ exe = $exePath; args = $ArgString }
}


function Build-CodexCommand {
  param($cfg, [bool]$Resume, [string]$OutFile, [string]$SessionId)
  $out = ""
  if ($OutFile) { $out = "--output-last-message `"$OutFile`" --color never" }
  $resumePart = ""
  if ($Resume -and $SessionId) { $resumePart = "resume $SessionId" }
  return "$($cfg.CodexBaseCmd) exec $out --skip-git-repo-check $resumePart"
}

function Invoke-CodexExec {
  param($cfg, $state, [string]$Prompt, [bool]$Resume)

  $jobId = New-JobId
  $outFile = Join-Path $cfg.LogDir "codex_exec_${jobId}.out"
  $logPath = Join-Path $cfg.LogDir "codex_exec_${jobId}.log"
  $stdoutPath = Join-Path $cfg.LogDir "codex_exec_${jobId}.stdout.log"
  $stderrPath = Join-Path $cfg.LogDir "codex_exec_${jobId}.stderr.log"

  $sessionId = $null
  if ($state.PSObject.Properties.Name -contains 'codex_session_id') { $sessionId = $state.codex_session_id }

  $codexPath = (Get-Command codex -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
  if (-not $codexPath) { throw 'codex not found in PATH.' }

  $codexArgs = @()
  if ($cfg.CodexDangerous) {
    $codexArgs += '--dangerously-bypass-approvals-and-sandbox'
  } else {
    $codexArgs += @('-a', 'never', '--sandbox', 'danger-full-access')
  }
  $model = $null
  if ($state.PSObject.Properties.Name -contains 'codex_model' -and $state.codex_model) { $model = $state.codex_model }
  elseif ($cfg.CodexModel) { $model = $cfg.CodexModel }
  elseif ($cfg.CodexUserConfigModel) { $model = $cfg.CodexUserConfigModel }
  if ($model) { $codexArgs += @('-m', $model) }
  $reasoning = $null
  if ($state.PSObject.Properties.Name -contains 'codex_reasoning_effort' -and $state.codex_reasoning_effort) { $reasoning = $state.codex_reasoning_effort }
  elseif ($cfg.CodexReasoningEffort) { $reasoning = $cfg.CodexReasoningEffort }
  elseif ($cfg.CodexUserConfigReasoningEffort) { $reasoning = $cfg.CodexUserConfigReasoningEffort }
  if ($reasoning) { $codexArgs += @('-c', "model_reasoning_effort=$reasoning") }
  $codexArgs += @('--no-alt-screen', 'exec', '--json', '--output-last-message', $outFile, '--color', 'never', '--skip-git-repo-check')
  if ($Resume -and $sessionId) { $codexArgs += @('resume', $sessionId) }
  $codexArgs += '-'  # read prompt from stdin

  $argString = '-NoProfile -File ' + (Quote-CmdArg -Arg $codexPath) + ' ' + (($codexArgs | ForEach-Object { Quote-CmdArg -Arg $_ }) -join ' ')

  $workDir = $cfg.DefaultCwd
  if ($cfg.CodexCwd -and (Test-Path -LiteralPath $cfg.CodexCwd)) { $workDir = $cfg.CodexCwd }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $cfg.PwshPath
  $psi.Arguments = $argString
  $psi.WorkingDirectory = $workDir
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true

  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  $null = $proc.Start()

  $outTask = $proc.StandardOutput.ReadToEndAsync()
  $errTask = $proc.StandardError.ReadToEndAsync()
  $proc.StandardInput.Write($Prompt)
  $proc.StandardInput.Close()
  $exited = $proc.WaitForExit($cfg.CodexTimeoutSec * 1000)
  if (-not $exited) {
    try { $proc.Kill() } catch {}
    throw "codex exec timed out after $($cfg.CodexTimeoutSec)s"
  }
  $null = $proc.WaitForExit()
  $null = [System.Threading.Tasks.Task]::WaitAll(@($outTask, $errTask), 5000)
  $stdoutText = $outTask.Result
  $stderrText = $errTask.Result
  if ($stdoutText) { Set-Content -LiteralPath $stdoutPath -Value $stdoutText }
  if ($stderrText) { Set-Content -LiteralPath $stderrPath -Value $stderrText }

  if (-not (Test-Path -LiteralPath $outFile)) {
    $output = "Error: codex did not write output file."
  } else {
    $output = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue
  }

  if (-not $output) { $output = '(no output)' }

  $sessionText = ''
  if ($stdoutText) { $sessionText += $stdoutText }
  if ($stderrText) { $sessionText += $stderrText }
  if ($sessionText -match '\"thread_id\":\"([0-9a-f-]{16,})\"') {
    $state.codex_session_id = $Matches[1]
    $state.codex_has_session = $true
  }
  $state.codex_cwd = $workDir
  $output = Append-SessionInfo -cfg $cfg -state $state -Text $output
  Set-Content -LiteralPath $logPath -Value $output
  $state.codex_last_log = $logPath
  Save-State -cfg $cfg -state $state

  return @{ output = $output; log = $logPath; job_id = $jobId }
}

function Get-ActiveCodexModel {
  param($cfg, $state)
  if ($state.PSObject.Properties.Name -contains 'codex_model' -and $state.codex_model) { return $state.codex_model }
  if ($cfg.CodexModel) { return $cfg.CodexModel }
  if ($cfg.CodexUserConfigModel) { return $cfg.CodexUserConfigModel }
  return ''
}

function Get-ActiveCodexReasoningEffort {
  param($cfg, $state)
  if ($state.PSObject.Properties.Name -contains 'codex_reasoning_effort' -and $state.codex_reasoning_effort) { return $state.codex_reasoning_effort }
  if ($cfg.CodexReasoningEffort) { return $cfg.CodexReasoningEffort }
  if ($cfg.CodexUserConfigReasoningEffort) { return $cfg.CodexUserConfigReasoningEffort }
  return ''
}

function Test-ProcessRunning {
  param([object]$ProcessId)
  if (-not $ProcessId) { return $false }
  try {
    $p = Get-Process -Id ([int]$ProcessId) -ErrorAction SilentlyContinue
    return ($null -ne $p)
  } catch {
    return $false
  }
}

function Get-CodexJobInfo {
  param($cfg, $state)

  $jobId = $null
  if ($state.PSObject.Properties.Name -contains 'codex_job_id') { $jobId = $state.codex_job_id }
  if (-not $jobId) { return $null }

  $procId = $null
  if ($state.PSObject.Properties.Name -contains 'codex_job_pid') { $procId = $state.codex_job_pid }
  $running = Test-ProcessRunning -ProcessId $procId

  $exitCode = $null
  if ($state.PSObject.Properties.Name -contains 'codex_job_exit' -and $state.codex_job_exit -and (Test-Path -LiteralPath $state.codex_job_exit)) {
    $raw = (Get-Content -LiteralPath $state.codex_job_exit -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($raw -match '^-?\d+$') { $exitCode = [int]$raw }
  }

  $res = $null
  if ($state.PSObject.Properties.Name -contains 'codex_job_result' -and $state.codex_job_result -and (Test-Path -LiteralPath $state.codex_job_result)) {
    try { $res = Get-Content -LiteralPath $state.codex_job_result -Raw | ConvertFrom-Json } catch {}
  }

  return [ordered]@{
    id = $jobId
    pid = $procId
    running = $running
    started = $state.codex_job_started
    exit_code = $exitCode
    thread_id = if ($res -and $res.thread_id) { $res.thread_id } else { $null }
    error = if ($res -and -not $res.ok) { $res.error } else { $null }
    out_file = $state.codex_job_outfile
    stdout_file = $state.codex_job_stdout
    stderr_file = $state.codex_job_stderr
    result_file = $state.codex_job_result
  }
}

function Refresh-CodexJobState {
  param($cfg, $state)

  $info = Get-CodexJobInfo -cfg $cfg -state $state
  if (-not $info) { return $null }

  if ($info.running) { return $info }

  # If the job is done and we haven't promoted its output into codex_last_log/session yet, do it now.
  $jobId = $info.id
  $outFile = $info.out_file
  $threadId = $info.thread_id
  if ($threadId -and ($state.codex_session_id -ne $threadId)) {
    $state.codex_session_id = $threadId
    $state.codex_has_session = $true
  }

  $finalLog = Join-Path $cfg.LogDir "codex_exec_${jobId}.log"
  if (-not $state.codex_last_log -or ($state.codex_last_log -ne $finalLog) -or -not (Test-Path -LiteralPath $finalLog)) {
    $output = $null
    if ($outFile -and (Test-Path -LiteralPath $outFile)) {
      $output = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue
    }
    if (-not $output) { $output = '(no output)' }
    $output = Append-SessionInfo -cfg $cfg -state $state -Text $output
    try { Set-Content -LiteralPath $finalLog -Value $output } catch {}
    $state.codex_last_log = $finalLog
  }

  # Clear PID so we don't treat the job as running again after it exits.
  $state.codex_job_pid = $null
  Save-State -cfg $cfg -state $state

  return (Get-CodexJobInfo -cfg $cfg -state $state)
}

function Start-CodexExecJob {
  param($cfg, $state, [string]$Prompt, [bool]$Resume)

  $existing = Get-CodexJobInfo -cfg $cfg -state $state
  if ($existing -and $existing.running) {
    throw "Codex job already running (job_id=$($existing.id), pid=$($existing.pid)). Use codexlast or codexcancel."
  }

  $jobId = New-JobId
  $promptPath = Join-Path $cfg.LogDir "codex_exec_${jobId}.prompt.txt"
  $outFile = Join-Path $cfg.LogDir "codex_exec_${jobId}.out"
  $stdoutPath = Join-Path $cfg.LogDir "codex_exec_${jobId}.stdout.log"
  $stderrPath = Join-Path $cfg.LogDir "codex_exec_${jobId}.stderr.log"
  $resultPath = Join-Path $cfg.LogDir "codex_exec_${jobId}.result.json"
  $exitPath = Join-Path $cfg.LogDir "codex_exec_${jobId}.exit"

  Set-Content -LiteralPath $promptPath -Value $Prompt

  $model = Get-ActiveCodexModel -cfg $cfg -state $state
  $reasoning = Get-ActiveCodexReasoningEffort -cfg $cfg -state $state

  $workDir = $cfg.DefaultCwd
  if ($cfg.CodexCwd -and (Test-Path -LiteralPath $cfg.CodexCwd)) { $workDir = $cfg.CodexCwd }

  $resumeThread = ''
  if ($Resume -and $state.codex_session_id) { $resumeThread = $state.codex_session_id }

  $argList = @(
    '-NoProfile',
    '-File', $cfg.CodexJobScript,
    '-PromptPath', $promptPath,
    '-OutFile', $outFile,
    '-StdoutPath', $stdoutPath,
    '-StderrPath', $stderrPath,
    '-ResultPath', $resultPath,
    '-ExitPath', $exitPath,
    '-WorkingDir', $workDir,
    '-TimeoutSec', $cfg.CodexTimeoutSec
  )
  if ($resumeThread) { $argList += @('-ResumeThreadId', $resumeThread) }
  if ($model) { $argList += @('-Model', $model) }
  if ($reasoning) { $argList += @('-ReasoningEffort', $reasoning) }
  if ($cfg.CodexDangerous) { $argList += '-Dangerous' }

  $proc = Start-Process -FilePath $cfg.PwshPath -ArgumentList $argList -WorkingDirectory $workDir -WindowStyle Hidden -PassThru

  $state.codex_job_id = $jobId
  $state.codex_job_pid = $proc.Id
  $state.codex_job_prompt = $promptPath
  $state.codex_job_outfile = $outFile
  $state.codex_job_stdout = $stdoutPath
  $state.codex_job_stderr = $stderrPath
  $state.codex_job_result = $resultPath
  $state.codex_job_exit = $exitPath
  $state.codex_job_started = (Get-Date).ToString('o')
  $state.codex_cwd = $workDir
  Save-State -cfg $cfg -state $state

  $modelLabel = if ($model) { $model } else { 'default' }
  $reasoningLabel = if ($reasoning) { $reasoning } else { 'default' }
  $resumeLabel = if ($resumeThread) { "resume $resumeThread" } else { 'new thread' }
  $msg = "Queued codex job $jobId ($resumeLabel, model=$modelLabel, reasoning=$reasoningLabel). Use 'codexlast' to check output."

  return @{ output = $msg; job_id = $jobId; pid = $proc.Id }
}

function Cancel-CodexJob {
  param($cfg, $state)
  $info = Get-CodexJobInfo -cfg $cfg -state $state
  if (-not $info) { return $false }
  if ($info.running -and $info.pid) {
    $pidInt = [int]$info.pid
    try {
      & taskkill.exe /PID $pidInt /T /F | Out-Null
    } catch {
      try { Stop-Process -Id $pidInt -Force } catch {}
    }
  }
  if ($state.codex_job_exit) {
    try { Set-Content -LiteralPath $state.codex_job_exit -Value -1 } catch {}
  }
  if ($state.codex_job_result) {
    $res = [ordered]@{ ok = $false; error = 'cancelled'; thread_id = $null }
    try { $res | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $state.codex_job_result } catch {}
  }
  $state.codex_job_pid = $null
  Save-State -cfg $cfg -state $state
  return $true
}
function Start-CodexSession {
  param($cfg, [string]$SessionId)

  if ($Sessions.ContainsKey($SessionId)) {
    $sess = $Sessions[$SessionId]
    if ($sess.process -and -not $sess.process.HasExited) { return $sess }
    $Sessions.Remove($SessionId)
  }

  $split = Split-Command -Command $cfg.CodexBaseCmd
  if (-not $split) { throw 'CODEX_CMD invalid.' }

  $resolved = Resolve-Command -cfg $cfg -Exe $split.exe -ArgString $split.args
  if (-not $resolved) { throw 'CODEX_CMD invalid.' }

  $logPath = Join-Path $cfg.LogDir "codex_${SessionId}.log"
  New-Item -ItemType File -Force -Path $logPath | Out-Null

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $resolved.exe
  $psi.Arguments = $resolved.args
  $psi.WorkingDirectory = $cfg.DefaultCwd
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true

  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi
  $null = $proc.Start()

  $action = {
    param($sender, $eventArgs)
    if ($eventArgs.Data) {
      Add-Content -LiteralPath $using:logPath -Value $eventArgs.Data
    }
  }

  Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action $action | Out-Null
  Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action $action | Out-Null
  $proc.BeginOutputReadLine()
  $proc.BeginErrorReadLine()

  $sess = [ordered]@{
    id = $SessionId
    process = $proc
    log = $logPath
    last_offset = 0
    started = (Get-Date).ToString('o')
  }

  $Sessions[$SessionId] = $sess
  return $sess
}

function Send-CodexPrompt {
  param($cfg, [string]$SessionId, [string]$Prompt)

  $sess = Start-CodexSession -cfg $cfg -SessionId $SessionId
  if ($sess.process.HasExited) { throw 'Codex session already exited.' }

  Add-Content -LiteralPath $sess.log -Value ">>> $Prompt"
  $sess.last_offset = (Get-Item -LiteralPath $sess.log).Length

  $sess.process.StandardInput.WriteLine($Prompt)
  $sess.process.StandardInput.Flush()

  $deadline = (Get-Date).AddSeconds($cfg.CodexWaitSec)
  $newText = ''
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 250
    $delta = Read-LogDelta -Path $sess.log -Offset $sess.last_offset
    if ($delta.text) {
      $newText = $delta.text
      $sess.last_offset = $delta.newOffset
      break
    }
  }

  if (-not $newText) {
    $delta = Read-LogDelta -Path $sess.log -Offset $sess.last_offset
    if ($delta.text) {
      $newText = $delta.text
      $sess.last_offset = $delta.newOffset
    }
  }

  return @{ session = $sess.id; output = $newText }
}

function Stop-CodexSession {
  param([string]$SessionId)
  if (-not $Sessions.ContainsKey($SessionId)) { return $false }
  $sess = $Sessions[$SessionId]
  try {
    if ($sess.process -and -not $sess.process.HasExited) {
      $sess.process.Kill()
    }
  } catch {}
  $Sessions.Remove($SessionId)
  return $true
}

function List-CodexSessions {
  $list = @()
  foreach ($k in $Sessions.Keys) {
    $s = $Sessions[$k]
    $running = $false
    if ($s.process -and -not $s.process.HasExited) { $running = $true }
    $list += [ordered]@{ id = $s.id; running = $running; started = $s.started }
  }
  return $list
}

$cfg = Get-Config -ConfigPath $ConfigPath
$state = Load-State -cfg $cfg

if ($cfg.CodexMode -ne 'console' -and $cfg.CodexAutoInit -and -not $state.codex_session_id) {
  try {
    if ($cfg.CodexAsync) {
      $null = Start-CodexExecJob -cfg $cfg -state $state -Prompt $cfg.CodexInitPrompt -Resume:$false
    } else {
      $null = Invoke-CodexExec -cfg $cfg -state $state -Prompt $cfg.CodexInitPrompt -Resume:$false
    }
  } catch {
    try { Add-Content -LiteralPath (Join-Path $cfg.LogDir 'agent_init.log') -Value ("init failed: " + $_.Exception.Message) } catch {}
  }
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($cfg.ListenAddr), $cfg.ListenPort)
$listener.Start()

Write-Host "Agent $($cfg.Name) listening on $($cfg.ListenAddr):$($cfg.ListenPort)"

while ($true) {
  $client = $listener.AcceptTcpClient()
  $timeoutMs = [Math]::Max(5, $cfg.ClientTimeoutSec) * 1000
  $client.ReceiveTimeout = $timeoutMs
  $client.SendTimeout = $timeoutMs
  $stream = $client.GetStream()
  $reader = New-Object System.IO.StreamReader($stream)
  $writer = New-Object System.IO.StreamWriter($stream)
  $writer.AutoFlush = $true

  $line = $reader.ReadLine()
  $resp = @{}
  try {
    if (-not $line) { throw 'Empty request.' }
    $req = $line | ConvertFrom-Json

    if ($cfg.Secret -and $req.secret -ne $cfg.Secret) { throw 'Unauthorized.' }

    switch ($req.op) {
      'ping' {
        $activeModel = $null
        if ($state.PSObject.Properties.Name -contains 'codex_model' -and $state.codex_model) { $activeModel = $state.codex_model }
        elseif ($cfg.CodexModel) { $activeModel = $cfg.CodexModel }
        $null = Refresh-CodexJobState -cfg $cfg -state $state
        $job = Get-CodexJobInfo -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ name = $cfg.Name; sessions = (List-CodexSessions); codex_model = $activeModel; codex_job = $job } }
      }
      'run' {
        if (-not $req.cmd) { throw 'cmd missing.' }
        if ($req.cmd -match "[;&|><`r`n]") { throw 'Command rejected (operators not allowed).'
        }
        if ($req.cmd -match '`') { throw 'Command rejected (backtick not allowed).' }
        $split = Split-Command -Command $req.cmd
        if (-not (Is-AllowedCommand -cfg $cfg -Exe $split.exe)) { throw "Command not allowed: $($split.exe)" }
        $cwd = if ($req.cwd) { $req.cwd } else { $cfg.DefaultCwd }
        $job = Start-RunJob -cfg $cfg -state $state -Command $req.cmd -Cwd $cwd
        $resp = @{ ok = $true; result = @{ job_id = $job.id } }
      }
      'last' {
        $lines = if ($req.lines) { [int]$req.lines } else { $cfg.TailLines }
        if (-not $state.last_job_id) { throw 'No last job.' }
        $log = Join-Path $cfg.LogDir "job_$($state.last_job_id).log"
        $tail = Get-LogTail -LogPath $log -Lines $lines
        $resp = @{ ok = $true; result = @{ job_id = $state.last_job_id; output = $tail } }
      }
      'tail' {
        if (-not $req.job_id) { throw 'job_id missing.' }
        $lines = if ($req.lines) { [int]$req.lines } else { $cfg.TailLines }
        $log = Join-Path $cfg.LogDir "job_$($req.job_id).log"
        $tail = Get-LogTail -LogPath $log -Lines $lines
        $resp = @{ ok = $true; result = @{ job_id = $req.job_id; output = $tail } }
      }
      'get' {
        if (-not $req.job_id) { throw 'job_id missing.' }
        $log = Join-Path $cfg.LogDir "job_$($req.job_id).log"
        if (-not (Test-Path -LiteralPath $log)) { throw 'Log not found.' }
        $text = Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue
        $resp = @{ ok = $true; result = @{ job_id = $req.job_id; output = $text } }
      }
      'codex.send' {
        if (-not $req.prompt) { throw 'prompt missing.' }
        if ($cfg.CodexMode -eq 'console') {
          $outText = Send-CodexConsolePrompt -cfg $cfg -state $state -Prompt $req.prompt
          $resp = @{ ok = $true; result = @{ output = $outText } }
        } else {
          $null = Refresh-CodexJobState -cfg $cfg -state $state
          $resume = $false
          if ($state.PSObject.Properties.Name -contains 'codex_session_id' -and $state.codex_session_id) { $resume = $true }
          if ($cfg.CodexAsync) {
            $out = Start-CodexExecJob -cfg $cfg -state $state -Prompt $req.prompt -Resume:$resume
          } else {
            $out = Invoke-CodexExec -cfg $cfg -state $state -Prompt $req.prompt -Resume:$resume
          }
          $resp = @{ ok = $true; result = $out }
        }
      }
      'codex.new' {
        if (-not $req.prompt) { throw 'prompt missing.' }
        if ($cfg.CodexMode -eq 'console') {
          $null = Stop-CodexConsole -cfg $cfg
          Start-CodexConsole -cfg $cfg
          Start-Sleep -Seconds $cfg.CodexStartWaitSec
          $state.codex_console_offset = 0
          Save-State -cfg $cfg -state $state
          $outText = Send-CodexConsolePrompt -cfg $cfg -state $state -Prompt $req.prompt
          $resp = @{ ok = $true; result = @{ output = $outText } }
        } else {
          $null = Refresh-CodexJobState -cfg $cfg -state $state
          if ($cfg.CodexAsync) {
            $out = Start-CodexExecJob -cfg $cfg -state $state -Prompt $req.prompt -Resume:$false
          } else {
            $out = Invoke-CodexExec -cfg $cfg -state $state -Prompt $req.prompt -Resume:$false
          }
          $resp = @{ ok = $true; result = $out }
        }
      }
      'codex.start' {
        $state.codex_has_session = $true
        Save-State -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ session = 'default' } }
      }
      'codex.stop' {
        $state.codex_has_session = $false
        Save-State -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ session = 'default' } }
      }
      'codex.list' {
        $resp = @{ ok = $true; result = @{ sessions = @(@{ id = 'default'; running = $state.codex_has_session }) } }
      }
      'codex.session' {
        $null = Refresh-CodexJobState -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ session = $state.codex_session_id } }
      }
      'codex.job' {
        $job = Refresh-CodexJobState -cfg $cfg -state $state
        if (-not $job) { $job = Get-CodexJobInfo -cfg $cfg -state $state }
        $resp = @{ ok = $true; result = @{ job = $job } }
      }
      'codex.cancel' {
        $ok = Cancel-CodexJob -cfg $cfg -state $state
        $job = Get-CodexJobInfo -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ cancelled = $ok; job = $job } }
      }
      'codex.model.get' {
        $activeModel = $null
        if ($state.PSObject.Properties.Name -contains 'codex_model' -and $state.codex_model) { $activeModel = $state.codex_model }
        elseif ($cfg.CodexModel) { $activeModel = $cfg.CodexModel }
        $resp = @{ ok = $true; result = @{ model = $activeModel; state_model = $state.codex_model; config_model = $cfg.CodexModel } }
      }
      'codex.model' {
        $m = ''
        if ($req.model) { $m = [string]$req.model }
        $m = $m.Trim()
        if (-not $m) { $state.codex_model = $null } else { $state.codex_model = $m }

        $doReset = $false
        if ($req.reset -ne $null) {
          $doReset = ([string]$req.reset -match '^(1|true|yes)$')
        }

        $job = Get-CodexJobInfo -cfg $cfg -state $state
        if ($job -and $job.running -and -not $doReset) {
          throw "Codex job running (job_id=$($job.id)). Use reset to cancel+clear first."
        }
        if ($doReset) {
          $null = Cancel-CodexJob -cfg $cfg -state $state
          $state.codex_session_id = $null
          $state.codex_has_session = $false
          $state.codex_job_id = $null
          $state.codex_job_pid = $null
          $state.codex_job_prompt = $null
          $state.codex_job_outfile = $null
          $state.codex_job_stdout = $null
          $state.codex_job_stderr = $null
          $state.codex_job_result = $null
          $state.codex_job_exit = $null
          $state.codex_job_started = $null
        }

        Save-State -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ model = $state.codex_model; reset = $doReset } }
      }
      'codex.use' {
        if (-not $req.session) { throw 'session missing.' }
        $job = Get-CodexJobInfo -cfg $cfg -state $state
        if ($job -and $job.running) { throw "Codex job running (job_id=$($job.id)). Cancel it first." }
        $state.codex_session_id = $req.session
        $state.codex_has_session = $true
        Save-State -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ session = $state.codex_session_id } }
      }
      'codex.reset' {
        $null = Cancel-CodexJob -cfg $cfg -state $state
        $state.codex_session_id = $null
        $state.codex_has_session = $false
        $state.codex_job_id = $null
        $state.codex_job_pid = $null
        $state.codex_job_prompt = $null
        $state.codex_job_outfile = $null
        $state.codex_job_stdout = $null
        $state.codex_job_stderr = $null
        $state.codex_job_result = $null
        $state.codex_job_exit = $null
        $state.codex_job_started = $null
        Save-State -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ session = $null } }
      }
      'codex.last' {
        if ($cfg.CodexMode -eq 'console') {
          $lines = if ($req.lines) { [int]$req.lines } else { $cfg.TailLines }
          $tail = Get-LogTail -LogPath $cfg.CodexTranscript -Lines $lines
          $resp = @{ ok = $true; result = @{ session = 'default'; output = $tail } }
        } else {
          $job = Refresh-CodexJobState -cfg $cfg -state $state
          if ($job -and $job.running) {
            $tailLines = if ($req.lines) { [int]$req.lines } else { $cfg.CodexJobTailLines }
            $parts = New-Object System.Collections.Generic.List[string]
            $parts.Add(("Codex job running: id={0} pid={1} started={2}" -f $job.id, $job.pid, $job.started))
            if ($job.stdout_file -and (Test-Path -LiteralPath $job.stdout_file)) {
              $parts.Add('')
              $parts.Add('--- stdout (tail) ---')
              $parts.Add((Get-LogTail -LogPath $job.stdout_file -Lines $tailLines))
            }
            if ($job.stderr_file -and (Test-Path -LiteralPath $job.stderr_file)) {
              $parts.Add('')
              $parts.Add('--- stderr (tail) ---')
              $parts.Add((Get-LogTail -LogPath $job.stderr_file -Lines $tailLines))
            }
            $resp = @{ ok = $true; result = @{ session = 'default'; output = ($parts -join "`n") } }
          } else {
            if (-not $state.codex_last_log) { throw 'No codex output yet.' }
            $lines = if ($req.lines) { [int]$req.lines } else { $cfg.TailLines }
            $tail = Get-LogTail -LogPath $state.codex_last_log -Lines $lines
            $resp = @{ ok = $true; result = @{ session = 'default'; output = $tail } }
          }
        }
      }
      default {
        throw "Unknown op: $($req.op)"
      }
    }
  } catch {
    $resp = @{ ok = $false; error = $_.Exception.Message }
  }

  try {
    $writer.WriteLine(($resp | ConvertTo-Json -Compress -Depth 8))
  } catch {
    # Client may have disconnected while we were processing; keep the agent alive.
  }
  try { $client.Close() } catch {}
}

