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

function Get-Config {
  param([string]$ConfigPath)

  $cfg = [ordered]@{
    Name = 'pc'
    ListenAddr = '0.0.0.0'
    ListenPort = 8765
    Secret = ''
    DefaultCwd = 'C:\\dev\\tri'
    CodexCwd = 'C:\\dev\\tri\\godgame'
    AllowPrefixes = @('git','pwsh','python','dotnet','cmd','C:\\dev\\tri')
    TailLines = 80
    LogDir = (Join-Path $PSScriptRoot 'logs')
    StateFile = (Join-Path $PSScriptRoot 'agent_state.json')
    RunnerPath = (Join-Path $PSScriptRoot 'runner.ps1')
    CodexBaseCmd = 'codex -a never --sandbox workspace-write --no-alt-screen --skip-git-repo-check'
    CodexTimeoutSec = 300
    CodexWaitSec = 15
    CodexWindowTitle = 'CODEX_BRIDGE'
    CodexTranscript = (Join-Path $PSScriptRoot 'logs\\codex_console.log')
    CodexConsoleScript = (Join-Path $PSScriptRoot 'codex_console.ps1')
    CodexConsoleAutoStart = $true
    CodexStartWaitSec = 8
    CodexSendKey = 'enter'
    ClientTimeoutSec = 300
    CodexDangerous = $false
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
  if ($env:CODEX_AUTO_INIT) { $cfg.CodexAutoInit = ($env:CODEX_AUTO_INIT -match '^(1|true|yes)$') }
  if ($env:CODEX_INIT_PROMPT) { $cfg.CodexInitPrompt = $env:CODEX_INIT_PROMPT }
  if ($env:CODEX_APPEND_SESSION) { $cfg.CodexAppendSession = ($env:CODEX_APPEND_SESSION -match '^(1|true|yes)$') }

  if (-not (Test-Path -LiteralPath $cfg.RunnerPath)) {
    throw "runner.ps1 missing at $($cfg.RunnerPath)"
  }

  New-Item -ItemType Directory -Force -Path $cfg.LogDir | Out-Null

  $cfg.PwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
  if (-not $cfg.PwshPath) { $cfg.PwshPath = (Get-Command powershell -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1) }
  if (-not $cfg.PwshPath) { throw 'pwsh or powershell not found in PATH.' }

  if (-not (Test-Path -LiteralPath $cfg.CodexCwd)) { $cfg.CodexCwd = $cfg.DefaultCwd }
  if ($cfg.CodexCwd -and ($cfg.CodexBaseCmd -notmatch '\s(-C|--cd)\s')) {
    $cfg.CodexBaseCmd = "$($cfg.CodexBaseCmd) -C $($cfg.CodexCwd)"
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

  $null = Start-Process -FilePath $cfg.PwshPath -ArgumentList $args -WorkingDirectory $cfg.CodexCwd
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
  $suffix = "[telebot] codex_session_id: $sid"
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
      if (-not $obj.codex_session_id) { $obj.codex_has_session = $false }
      return $obj
    } catch {}
  }
  $obj = [ordered]@{ last_job_id = $null; codex_has_session = $false; codex_last_log = $null; codex_session_id = $null; codex_console_offset = 0 }
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
  $codexArgs += @('--no-alt-screen', 'exec', '--json', '--output-last-message', $outFile, '--color', 'never', '--skip-git-repo-check')
  if ($Resume -and $sessionId) { $codexArgs += @('resume', $sessionId) }
  $codexArgs += '-'  # read prompt from stdin

  $argString = '-NoProfile -File ' + (Quote-CmdArg -Arg $codexPath) + ' ' + (($codexArgs | ForEach-Object { Quote-CmdArg -Arg $_ }) -join ' ')

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $cfg.PwshPath
  $psi.Arguments = $argString
  $psi.WorkingDirectory = $cfg.DefaultCwd
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
  $output = Append-SessionInfo -cfg $cfg -state $state -Text $output
  Set-Content -LiteralPath $logPath -Value $output
  $state.codex_last_log = $logPath
  Save-State -cfg $cfg -state $state

  return @{ output = $output; log = $logPath; job_id = $jobId }
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
    $null = Invoke-CodexExec -cfg $cfg -state $state -Prompt $cfg.CodexInitPrompt -Resume:$false
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
        $resp = @{ ok = $true; result = @{ name = $cfg.Name; sessions = (List-CodexSessions) } }
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
          $resume = $false
          if ($state.PSObject.Properties.Name -contains 'codex_session_id' -and $state.codex_session_id) { $resume = $true }
          $out = Invoke-CodexExec -cfg $cfg -state $state -Prompt $req.prompt -Resume:$resume
          $resp = @{ ok = $true; result = $out }
        }
      }
      'codex.new' {
        if ($cfg.CodexMode -eq 'console') { throw 'codexnew not supported in console mode.' }
        if (-not $req.prompt) { throw 'prompt missing.' }
        $out = Invoke-CodexExec -cfg $cfg -state $state -Prompt $req.prompt -Resume:$false
        $resp = @{ ok = $true; result = $out }
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
        $resp = @{ ok = $true; result = @{ session = $state.codex_session_id } }
      }
      'codex.use' {
        if (-not $req.session) { throw 'session missing.' }
        $state.codex_session_id = $req.session
        $state.codex_has_session = $true
        Save-State -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ session = $state.codex_session_id } }
      }
      'codex.reset' {
        $state.codex_session_id = $null
        $state.codex_has_session = $false
        Save-State -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ session = $null } }
      }
      'codex.last' {
        if ($cfg.CodexMode -eq 'console') {
          $lines = if ($req.lines) { [int]$req.lines } else { $cfg.TailLines }
          $tail = Get-LogTail -LogPath $cfg.CodexTranscript -Lines $lines
          $resp = @{ ok = $true; result = @{ session = 'default'; output = $tail } }
        } else {
          if (-not $state.codex_last_log) { throw 'No codex output yet.' }
          $lines = if ($req.lines) { [int]$req.lines } else { $cfg.TailLines }
          $tail = Get-LogTail -LogPath $state.codex_last_log -Lines $lines
          $resp = @{ ok = $true; result = @{ session = 'default'; output = $tail } }
        }
      }
      default {
        throw "Unknown op: $($req.op)"
      }
    }
  } catch {
    $resp = @{ ok = $false; error = $_.Exception.Message }
  }

  $writer.WriteLine(($resp | ConvertTo-Json -Compress -Depth 8))
  $client.Close()
}
