param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'agent.env')
)

$ErrorActionPreference = 'Stop'

try { $Host.UI.RawUI.WindowTitle = 'TelebotAgent' } catch {}

function Is-Truthy {
  param([string]$Value)
  if (-not $Value) { return $false }
  return ($Value.Trim() -match '^(1|true|yes|y|on)$')
}

$script:TelebotQuiet = $false
if (Is-Truthy -Value $env:TELEBOT_QUIET) { $script:TelebotQuiet = $true }
if (Is-Truthy -Value $env:AGENT_QUIET) { $script:TelebotQuiet = $true }

$script:ConsoleLogRequests = $false
if (Is-Truthy -Value $env:TELEBOT_ACTIVITY) { $script:ConsoleLogRequests = $true }
if (Is-Truthy -Value $env:AGENT_LOG_REQUESTS) { $script:ConsoleLogRequests = $true }

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
    CodexSendKeyMethod = 'auto'
    ClientTimeoutSec = 300
    CodexDangerous = $true
    CodexModel = ''
    CodexReasoningEffort = ''
    CodexNewDelaySec = 0
    CodexModeOverride = ''
    CodexUserConfigPath = ''
    CodexUserConfigModel = ''
    CodexUserConfigReasoningEffort = ''
    CodexAsync = $true
    CodexJobTailLines = 60
    CodexAutoInit = $false
    CodexInitPrompt = 'Initialize session. Reply "ready".'
    CodexAppendSession = $true
    HeadlessRebuildToolRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Tools\HeadlessRebuildTool')
    AiInvokeScript = ''
    AiArtifactsDir = ''
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
  if ($env:LOG_DIR) { $cfg.LogDir = $env:LOG_DIR }
  if ($env:STATE_FILE) { $cfg.StateFile = $env:STATE_FILE }
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
  if ($env:CODEX_SEND_KEY_METHOD) { $cfg.CodexSendKeyMethod = $env:CODEX_SEND_KEY_METHOD }
  if ($env:CODEX_WAIT_SEC) { $cfg.CodexWaitSec = [int]$env:CODEX_WAIT_SEC }
  if ($env:CODEX_NEW_DELAY_SEC) { $cfg.CodexNewDelaySec = [int]$env:CODEX_NEW_DELAY_SEC }
  if ($env:CLIENT_TIMEOUT_SEC) { $cfg.ClientTimeoutSec = [int]$env:CLIENT_TIMEOUT_SEC }
  if ($env:CODEX_DANGEROUS) { $cfg.CodexDangerous = ($env:CODEX_DANGEROUS -match '^(1|true|yes)$') }
  if ($env:CODEX_REASONING_EFFORT) { $cfg.CodexReasoningEffort = $env:CODEX_REASONING_EFFORT }
  if ($env:CODEX_ASYNC) { $cfg.CodexAsync = ($env:CODEX_ASYNC -match '^(1|true|yes)$') }
  if ($env:CODEX_AUTO_INIT) { $cfg.CodexAutoInit = ($env:CODEX_AUTO_INIT -match '^(1|true|yes)$') }
  if ($env:CODEX_INIT_PROMPT) { $cfg.CodexInitPrompt = $env:CODEX_INIT_PROMPT }
  if ($env:CODEX_APPEND_SESSION) { $cfg.CodexAppendSession = ($env:CODEX_APPEND_SESSION -match '^(1|true|yes)$') }
  if ($env:CODEX_MODE_OVERRIDE) { $cfg.CodexModeOverride = $env:CODEX_MODE_OVERRIDE }
  if ($env:HEADLESS_REBUILD_TOOL_ROOT) { $cfg.HeadlessRebuildToolRoot = $env:HEADLESS_REBUILD_TOOL_ROOT }
  if ($env:AI_INVOKE_SCRIPT) { $cfg.AiInvokeScript = $env:AI_INVOKE_SCRIPT }
  if ($env:AI_ARTIFACTS_DIR) { $cfg.AiArtifactsDir = $env:AI_ARTIFACTS_DIR }

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

  if (-not $cfg.AiInvokeScript) {
    $cfg.AiInvokeScript = Join-Path $cfg.HeadlessRebuildToolRoot '.agents\skills\_shared\scripts\invoke_ai_sidecar.ps1'
  }
  if (-not $cfg.AiArtifactsDir) {
    $cfg.AiArtifactsDir = Join-Path $cfg.HeadlessRebuildToolRoot '.agents\skills\artifacts\codexbridge-ai'
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
  param($cfg, $state)
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

  $proc = Start-Process -FilePath $cfg.PwshPath -ArgumentList $args -WorkingDirectory $cfg.CodexCwd -PassThru
  if ($state -and $proc) {
    $state.codex_console_pid = $proc.Id
    Save-State -cfg $cfg -state $state
  }
  return $proc.Id
}

function Stop-CodexConsole {
  param($cfg, $state)
  $stopped = $false
  $activated = $false
  try {
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    if ($state -and $state.PSObject.Properties.Name -contains 'codex_console_pid' -and $state.codex_console_pid) {
      try { $activated = $shell.AppActivate([int]$state.codex_console_pid) } catch { $activated = $false }
    }
    if (-not $activated -and $cfg.CodexWindowTitle) {
      try { $activated = $shell.AppActivate($cfg.CodexWindowTitle) } catch { $activated = $false }
    }
    if ($activated) {
      [System.Windows.Forms.SendKeys]::SendWait("^+w")
      Start-Sleep -Milliseconds 200
    }
    if ($cfg.CodexWindowTitle) {
      for ($i = 0; $i -lt 5; $i++) {
        $ok = $false
        try { $ok = $shell.AppActivate($cfg.CodexWindowTitle) } catch { $ok = $false }
        if (-not $ok) { break }
        [System.Windows.Forms.SendKeys]::SendWait("^+w")
        Start-Sleep -Milliseconds 200
      }
    }
  } catch {}

  $consolePids = New-Object 'System.Collections.Generic.HashSet[int]'
  if ($state -and $state.PSObject.Properties.Name -contains 'codex_console_pid' -and $state.codex_console_pid) {
    $null = $consolePids.Add([int]$state.codex_console_pid)
    $state.codex_console_pid = $null
    try { Save-State -cfg $cfg -state $state } catch {}
  }
  try {
    $pattern = [regex]::Escape($cfg.CodexConsoleScript)
    $procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match $pattern }
    foreach ($p in $procs) { $null = $consolePids.Add([int]$p.ProcessId) }
  } catch {}
  try {
    $title = $cfg.CodexWindowTitle
    if ($title) {
      $uiProcs = Get-Process | Where-Object {
        $_.MainWindowTitle -eq $title -and ($_.ProcessName -match '^(pwsh|powershell)$')
      }
      foreach ($p in $uiProcs) { $null = $consolePids.Add([int]$p.Id) }
    }
  } catch {}
  if ($consolePids.Count -gt 0) {
    try {
      $childCodex = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq 'codex.exe' -and $consolePids.Contains([int]$_.ParentProcessId)
      }
      foreach ($p in $childCodex) {
        try {
          Stop-Process -Id $p.ProcessId -Force
          $stopped = $true
        } catch {}
      }
    } catch {}
    foreach ($procId in $consolePids) {
      try {
        Stop-Process -Id $procId -Force
        $stopped = $true
      } catch {}
    }
  }
  return $stopped
}

function Send-KeyCombo {
  param([string]$Combo, [string]$Method)
  if (-not $Combo) { $Combo = 'enter' }
  $combo = $Combo.Trim().ToLowerInvariant()
  $method = if ($Method) { $Method.Trim().ToLowerInvariant() } else { 'sendinput' }

  $sendKeysMap = @{
    'enter'      = '{ENTER}'
    'ctrl+enter' = '^{ENTER}'
    'shift+enter' = '+{ENTER}'
    'alt+enter'  = '%{ENTER}'
    'ctrl+d'     = '^d'
    'ctrl+z'     = '^z'
    'ctrl+v'     = '^v'
  }

  if ($method -eq 'sendkeys') {
    $seq = $sendKeysMap[$combo]
    if (-not $seq) { $seq = '{ENTER}' }
    [System.Windows.Forms.SendKeys]::SendWait($seq)
    return
  }

  if (-not ('NativeInput' -as [type])) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class NativeInput {
  [StructLayout(LayoutKind.Sequential)]
  public struct INPUT {
    public uint type;
    public InputUnion U;
  }
  [StructLayout(LayoutKind.Explicit)]
  public struct InputUnion {
    [FieldOffset(0)] public KEYBDINPUT ki;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct KEYBDINPUT {
    public ushort wVk;
    public ushort wScan;
    public uint dwFlags;
    public uint time;
    public IntPtr dwExtraInfo;
  }
  public const uint INPUT_KEYBOARD = 1;
  [DllImport("user32.dll", SetLastError=true)]
  public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
  public const uint KEYEVENTF_KEYUP = 0x0002;

  public static void SendKeyCombo(params ushort[] vks) {
    if (vks == null || vks.Length == 0) return;
    INPUT[] inputs = new INPUT[vks.Length * 2];
    int idx = 0;
    for (int i = 0; i < vks.Length; i++) {
      inputs[idx] = new INPUT();
      inputs[idx].type = INPUT_KEYBOARD;
      inputs[idx].U.ki.wVk = vks[i];
      idx++;
    }
    for (int i = vks.Length - 1; i >= 0; i--) {
      inputs[idx] = new INPUT();
      inputs[idx].type = INPUT_KEYBOARD;
      inputs[idx].U.ki.wVk = vks[i];
      inputs[idx].U.ki.dwFlags = KEYEVENTF_KEYUP;
      idx++;
    }
    SendInput((uint)inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
  }
}
"@
  }

  $keys = @()

  switch ($combo) {
    'enter' {
      $keys = @(0x0D)
    }
    'ctrl+enter' {
      $keys = @(0x11, 0x0D)
    }
    'shift+enter' {
      $keys = @(0x10, 0x0D)
    }
    'alt+enter' {
      $keys = @(0x12, 0x0D)
    }
    'ctrl+d' {
      $keys = @(0x11, 0x44)
    }
    'ctrl+z' {
      $keys = @(0x11, 0x5A)
    }
    'ctrl+v' {
      $keys = @(0x11, 0x56)
    }
    default {
      $keys = @(0x0D)
    }
  }

  try {
    [NativeInput]::SendKeyCombo([ushort[]]$keys)
    return
  } catch {}

  # fallback
  $fallbackSeq = $sendKeysMap[$combo]
  if (-not $fallbackSeq) { $fallbackSeq = '{ENTER}' }
  [System.Windows.Forms.SendKeys]::SendWait($fallbackSeq)
}

function Get-ForegroundWindowTitle {
  if (-not ('NativeWindowUtil' -as [type])) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class NativeWindowUtil {
  [DllImport("user32.dll")]
  public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll", CharSet = CharSet.Unicode)]
  public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
  [DllImport("user32.dll")]
  public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
"@
  }
  try {
    $h = [NativeWindowUtil]::GetForegroundWindow()
    if ($h -eq [IntPtr]::Zero) { return '' }
    $sb = New-Object System.Text.StringBuilder 512
    $null = [NativeWindowUtil]::GetWindowText($h, $sb, $sb.Capacity)
    return $sb.ToString()
  } catch { return '' }
}

function Get-ForegroundWindowInfo {
  $info = @{
    title = ''
    pid = 0
    process = ''
  }
  try {
    $h = [NativeWindowUtil]::GetForegroundWindow()
    if ($h -eq [IntPtr]::Zero) { return $info }
    $sb = New-Object System.Text.StringBuilder 512
    $null = [NativeWindowUtil]::GetWindowText($h, $sb, $sb.Capacity)
    $info.title = $sb.ToString()
    [uint32]$pid = 0
    $null = [NativeWindowUtil]::GetWindowThreadProcessId($h, [ref]$pid)
    if ($pid -gt 0) {
      $info.pid = [int]$pid
      try { $info.process = (Get-Process -Id ([int]$pid) -ErrorAction Stop).ProcessName } catch {}
    }
  } catch {}
  return $info
}

function Get-ParentProcessId {
  param([int]$ProcessId)
  if ($ProcessId -le 0) { return 0 }
  try {
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
    if ($proc -and $proc.ParentProcessId) { return [int]$proc.ParentProcessId }
  } catch {}
  return 0
}

function Test-RelatedProcess {
  param([int]$A, [int]$B)
  if ($A -le 0 -or $B -le 0) { return $false }
  if ($A -eq $B) { return $true }
  $pa = Get-ParentProcessId -ProcessId $A
  $pb = Get-ParentProcessId -ProcessId $B
  if ($pa -eq $B -or $pb -eq $A) { return $true }
  if ($pa -gt 0 -and $pb -gt 0 -and $pa -eq $pb) { return $true }
  return $false
}

function Ensure-WindowForeground {
  param($shell, [string]$Title, [int]$Attempts = 8, [int]$ConsolePid = 0)
  if (-not $Title -and $ConsolePid -le 0) { return $false }
  for ($i = 0; $i -lt $Attempts; $i++) {
    $activated = $false
    if ($ConsolePid -gt 0) {
      try { $activated = $shell.AppActivate($ConsolePid) } catch { $activated = $false }
    }
    if (-not $activated -and $Title) {
      try { $activated = $shell.AppActivate($Title) } catch {}
    }
    Start-Sleep -Milliseconds 100
    $fg = Get-ForegroundWindowInfo
    if ($ConsolePid -gt 0 -and (Test-RelatedProcess -A ([int]$fg.pid) -B $ConsolePid)) { return $true }
    if ($Title -and $fg.title -and ($fg.title -eq $Title -or $fg.title -like "$Title*" -or $fg.title -like "*$Title*")) { return $true }
  }
  return $false
}

function Send-ConsoleInputText {
  param([string]$Text, [string]$Method)
  if (-not $Text) { return $true }
  try {
    $old = $null
    $hadOld = $false
    try {
      $old = Get-Clipboard -Raw -ErrorAction Stop
      $hadOld = $true
    } catch {}
    try {
      Set-Clipboard -Value $Text
      Send-KeyCombo -Combo 'ctrl+v' -Method $Method
      return $true
    } finally {
      if ($hadOld) { try { Set-Clipboard -Value $old } catch {} }
    }
  } catch {}
  try {
    [System.Windows.Forms.SendKeys]::SendWait($Text)
    return $true
  } catch {}
  return $false
}

function Send-CodexConsolePrompt {
  param($cfg, $state, [string]$Prompt)

  Ensure-StateProperty -state $state -Name 'codex_console_offset' -Value 0
  Ensure-StateProperty -state $state -Name 'codex_console_pid' -Value $null

  Add-Type -AssemblyName System.Windows.Forms
  $shell = New-Object -ComObject WScript.Shell
  $ok = $false
  $consolePid = 0
  if ($state.codex_console_pid) {
    try { $consolePid = [int]$state.codex_console_pid } catch { $consolePid = 0 }
  }
  if ($state.codex_console_pid) {
    try { $ok = $shell.AppActivate([int]$state.codex_console_pid) } catch { $ok = $false }
  }
  if (-not $ok) { $ok = $shell.AppActivate($cfg.CodexWindowTitle) }
  if (-not $ok -and $cfg.CodexConsoleAutoStart) {
    $null = Start-CodexConsole -cfg $cfg -state $state
    Start-Sleep -Seconds $cfg.CodexStartWaitSec
    if ($state.codex_console_pid) {
      try { $ok = $shell.AppActivate([int]$state.codex_console_pid) } catch { $ok = $false }
      try { $consolePid = [int]$state.codex_console_pid } catch { $consolePid = 0 }
    }
    if (-not $ok) { $ok = $shell.AppActivate($cfg.CodexWindowTitle) }
  }
  if (-not $ok) { throw "Codex window not found: $($cfg.CodexWindowTitle)" }
  if (-not (Ensure-WindowForeground -shell $shell -Title $cfg.CodexWindowTitle -Attempts 10 -ConsolePid $consolePid)) {
    $fg = Get-ForegroundWindowInfo
    $fgLabel = if ($fg.process) { "$($fg.process)#$($fg.pid)" } elseif ($fg.pid) { "pid=$($fg.pid)" } else { 'unknown' }
    throw "Codex window not foreground: $($cfg.CodexWindowTitle) (foreground=$fgLabel title='$($fg.title)')"
  }

  if ($state.codex_console_offset -eq 0 -and (Test-Path -LiteralPath $cfg.CodexTranscript)) {
    $state.codex_console_offset = (Get-Item -LiteralPath $cfg.CodexTranscript).Length
    Save-State -cfg $cfg -state $state
  }

  Start-Sleep -Milliseconds 200
  $sendMethod = $cfg.CodexSendKeyMethod
  if (-not $sendMethod -or $sendMethod -eq 'auto') {
    $sendMethod = 'sendinput'
    try {
      $proc = Get-Process | Where-Object { $_.MainWindowTitle -eq $cfg.CodexWindowTitle } | Select-Object -First 1
      if ($proc -and $proc.ProcessName -match '^(windowsterminal|wt)$') { $sendMethod = 'sendkeys' }
    } catch {}
  }
  if (-not (Ensure-WindowForeground -shell $shell -Title $cfg.CodexWindowTitle -Attempts 3 -ConsolePid $consolePid)) {
    throw "Codex window focus lost before input."
  }
  if (-not (Send-ConsoleInputText -Text $Prompt -Method $sendMethod)) {
    throw 'Failed to send console prompt text.'
  }
  if (-not (Ensure-WindowForeground -shell $shell -Title $cfg.CodexWindowTitle -Attempts 3 -ConsolePid $consolePid)) {
    throw "Codex window focus lost before submit."
  }
  Send-KeyCombo -Combo $cfg.CodexSendKey -Method $sendMethod

  $sentAt = Get-Date
  Ensure-StateProperty -state $state -Name 'codex_console_last_prompt_at' -Value $null
  $state.codex_console_last_prompt_at = $sentAt.ToString('o')
  Save-State -cfg $cfg -state $state
  $rolloutSessionId = $null
  if ($state.PSObject.Properties.Name -contains 'codex_session_id' -and $state.codex_session_id) {
    $rolloutSessionId = [string]$state.codex_session_id
  }
  $rolloutBaseline = @{ id = ''; timestamp = $null; text = '' }
  $rolloutBaselineReady = $false
  if ($rolloutSessionId) {
    $rolloutBaseline = Get-LatestAssistantTextFromRollout -SessionId $rolloutSessionId
    $rolloutBaselineReady = $true
  }

  $offset = 0
  if ($state.codex_console_offset) { $offset = [long]$state.codex_console_offset }
  $maxWaitMs = [Math]::Max(2000, [int]$cfg.CodexWaitSec * 1000)
  $idleSettleMs = 1200
  $pollMs = 250
  $deadline = (Get-Date).AddMilliseconds($maxWaitMs)
  $raw = ''
  $lastCleanAt = $null
  $rolloutText = ''

  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds $pollMs
    $delta = Read-LogDelta -Path $cfg.CodexTranscript -Offset $offset
    if ($delta.newOffset -ne $offset) {
      $offset = $delta.newOffset
      if ($delta.text) {
        if ($raw) { $raw += "`n" }
        $raw += $delta.text
        $chunk = Clean-TranscriptText -Text $delta.text
        if ($chunk) { $lastCleanAt = Get-Date }
      }
    }

    # Transcript is unreliable on some setups; fall back to Codex rollout files for console replies.
    if (-not $rolloutSessionId) {
      $resolvedSid = Resolve-CodexSessionFromRollout -StartTime $sentAt.AddMinutes(-10) -EndTime (Get-Date)
      if ($resolvedSid) {
        $rolloutSessionId = $resolvedSid
        if ($state.codex_session_id -ne $rolloutSessionId) {
          $state.codex_session_id = $rolloutSessionId
          $state.codex_has_session = $true
          Save-State -cfg $cfg -state $state
        }
      }
    }
    if ($rolloutSessionId) {
      $snap = Get-LatestAssistantTextFromRollout -SessionId $rolloutSessionId
      if (-not $rolloutBaselineReady) {
        $rolloutBaseline = $snap
        $rolloutBaselineReady = $true
      } elseif ($snap.id -and $snap.id -ne $rolloutBaseline.id -and $snap.text) {
        $rolloutText = $snap.text
        break
      }
    }

    if ($lastCleanAt -and (((Get-Date) - $lastCleanAt).TotalMilliseconds -ge $idleSettleMs)) { break }
  }

  $state.codex_console_offset = $offset
  Save-State -cfg $cfg -state $state

  $clean = Clean-TranscriptText -Text $raw
  if ($clean) { return $clean }
  if ($rolloutText) { return $rolloutText }
  if (-not $raw) { return '(no output yet)' }
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
  if (-not $sid) {
    $startTime = $null
    try { if ($state.codex_job_started) { $startTime = [DateTime]::Parse($state.codex_job_started) } } catch {}
    $sid = Resolve-CodexSessionFromRollout -StartTime $startTime -EndTime (Get-Date)
    if ($sid) {
      $state.codex_session_id = $sid
      $state.codex_has_session = $true
      Save-State -cfg $cfg -state $state
    }
  }
  if (-not $sid) { return $Text }

  # Prefer the most recent run metadata, then fall back to config/state defaults.
  $model = $null
  if ($state.PSObject.Properties.Name -contains 'codex_last_model' -and $state.codex_last_model) { $model = $state.codex_last_model }
  elseif ($state.PSObject.Properties.Name -contains 'codex_model' -and $state.codex_model) { $model = $state.codex_model }
  elseif ($cfg.CodexModel) { $model = $cfg.CodexModel }
  elseif ($cfg.CodexUserConfigModel) { $model = $cfg.CodexUserConfigModel }
  if (-not $model) { $model = 'default' }

  $reasoning = $null
  if ($state.PSObject.Properties.Name -contains 'codex_last_reasoning_effort' -and $state.codex_last_reasoning_effort) { $reasoning = $state.codex_last_reasoning_effort }
  elseif ($state.PSObject.Properties.Name -contains 'codex_reasoning_effort' -and $state.codex_reasoning_effort) { $reasoning = $state.codex_reasoning_effort }
  elseif ($cfg.CodexReasoningEffort) { $reasoning = $cfg.CodexReasoningEffort }
  elseif ($cfg.CodexUserConfigReasoningEffort) { $reasoning = $cfg.CodexUserConfigReasoningEffort }
  if (-not $reasoning) { $reasoning = 'default' }

  $cwd = $null
  if ($state.PSObject.Properties.Name -contains 'codex_last_cwd' -and $state.codex_last_cwd) { $cwd = $state.codex_last_cwd }
  elseif ($state.PSObject.Properties.Name -contains 'codex_cwd' -and $state.codex_cwd) { $cwd = $state.codex_cwd }
  if (-not $cwd) { $cwd = $cfg.CodexCwd }
  if (-not $cwd) { $cwd = $cfg.DefaultCwd }

  $perms = $null
  if ($state.PSObject.Properties.Name -contains 'codex_last_perms' -and $state.codex_last_perms) { $perms = $state.codex_last_perms }
  if (-not $perms) { $perms = if ($cfg.CodexDangerous) { 'full' } else { 'restricted' } }
  $agentName = $cfg.Name
  $machineName = $env:COMPUTERNAME
  $agentLabel = if ($agentName -and $machineName -and ($agentName -ne $machineName)) { "$agentName@$machineName" }
    elseif ($agentName) { $agentName }
    elseif ($machineName) { $machineName }
    else { 'unknown' }
  $suffix = "[telebot] codex_session_id: $sid | model: $model | reasoning: $reasoning | perms: $perms | cwd: $cwd | agent: $agentLabel"

  # Normalize any trailing telebot suffix lines so repeated append paths still yield one suffix.
  $base = if ($Text) { $Text.TrimEnd() } else { '' }
  if ($base) {
    $lines = $base -split "`r?`n"
    $i = $lines.Length - 1
    while ($i -ge 0 -and $lines[$i].Trim() -eq '') { $i-- }
    $sawSuffix = $false
    while ($i -ge 0) {
      if ($lines[$i].Trim() -eq '') {
        if ($sawSuffix) { $i--; continue }
        break
      }
      if ($lines[$i] -match '^\[telebot\] codex_session_id:') {
        $sawSuffix = $true
        $i--
        continue
      }
      break
    }
    if ($sawSuffix) {
      if ($i -ge 0) { $base = (($lines[0..$i] -join "`n").TrimEnd()) } else { $base = '' }
    }
  }

  if (-not $base) { return $suffix }
  return ($base + "`n`n" + $suffix)
}

function Ensure-SessionInfoSuffix {
  param($cfg, $state, [string]$Text)
  if (-not $cfg.CodexAppendSession) { return $Text }
  if (-not $Text) { return $Text }
  return (Append-SessionInfo -cfg $cfg -state $state -Text $Text)
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
      if ($obj -is [System.Collections.IDictionary]) { $obj = [pscustomobject]$obj }
      Ensure-StateProperty -state $obj -Name 'last_job_id' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_has_session' -Value $false
      Ensure-StateProperty -state $obj -Name 'codex_last_log' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_session_id' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_console_offset' -Value 0
      Ensure-StateProperty -state $obj -Name 'codex_console_pid' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_console_last_prompt_at' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_cwd' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_model' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_reasoning_effort' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_last_model' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_last_reasoning_effort' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_last_perms' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_last_cwd' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_mode_override' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_id' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_pid' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_prompt' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_outfile' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_stdout' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_stderr' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_result' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_exit' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_started' -Value $null
      Ensure-StateProperty -state $obj -Name 'codex_job_resume_thread' -Value $null
      if (-not $obj.codex_session_id) { $obj.codex_has_session = $false }
      return $obj
    } catch {}
  }
  $obj = [pscustomobject][ordered]@{
    last_job_id = $null
    codex_has_session = $false
    codex_last_log = $null
    codex_session_id = $null
    codex_console_offset = 0
    codex_console_pid = $null
    codex_console_last_prompt_at = $null
    codex_cwd = $null
    codex_model = $null
    codex_reasoning_effort = $null
    codex_last_model = $null
    codex_last_reasoning_effort = $null
    codex_last_perms = $null
    codex_last_cwd = $null
    codex_mode_override = $null
    codex_job_id = $null
    codex_job_pid = $null
    codex_job_prompt = $null
    codex_job_outfile = $null
    codex_job_stdout = $null
    codex_job_stderr = $null
    codex_job_result = $null
    codex_job_exit = $null
    codex_job_started = $null
    codex_job_resume_thread = $null
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

  $startedAt = Get-Date

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
    $output = Get-Content -LiteralPath $outFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  }

  if (-not $output) { $output = '(no output)' }

  $sessionText = ''
  if ($stdoutText) { $sessionText += $stdoutText }
  if ($stderrText) { $sessionText += $stderrText }
  if ($sessionText -match '\"thread_id\":\"([0-9a-f-]{16,})\"') {
    $state.codex_session_id = $Matches[1]
    $state.codex_has_session = $true
  } elseif (-not $Resume) {
    # Best-effort: map this exec to the created rollout file and capture the new session id.
    $sid = Resolve-CodexSessionFromRollout -StartTime $startedAt -EndTime (Get-Date)
    if ($sid) {
      $state.codex_session_id = $sid
      $state.codex_has_session = $true
    }
  }

  # Record run metadata so the appended suffix reflects what actually ran.
  $state.codex_last_model = if ($model) { $model } elseif ($cfg.CodexUserConfigModel) { $cfg.CodexUserConfigModel } else { 'default' }
  $state.codex_last_reasoning_effort = if ($reasoning) { $reasoning } elseif ($cfg.CodexUserConfigReasoningEffort) { $cfg.CodexUserConfigReasoningEffort } else { 'default' }
  $state.codex_last_perms = if ($cfg.CodexDangerous) { 'full' } else { 'restricted' }
  $state.codex_last_cwd = $workDir
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

function Get-EffectiveCodexMode {
  param($cfg, $state)
  $mode = $null
  if ($state.PSObject.Properties.Name -contains 'codex_mode_override' -and $state.codex_mode_override) { $mode = $state.codex_mode_override }
  elseif ($cfg.CodexModeOverride) { $mode = $cfg.CodexModeOverride }
  elseif ($cfg.CodexMode) { $mode = $cfg.CodexMode }
  if (-not $mode) { $mode = 'exec' }
  return $mode.ToLowerInvariant()
}

function Get-CodexSessionRoot {
  $homeDir = $env:USERPROFILE
  if (-not $homeDir -and $env:HOMEDRIVE -and $env:HOMEPATH) { $homeDir = Join-Path $env:HOMEDRIVE $env:HOMEPATH }
  if (-not $homeDir) { $homeDir = $env:HOME }
  if (-not $homeDir -and $env:USERNAME) { $homeDir = Join-Path 'C:\\Users' $env:USERNAME }
  if (-not $homeDir) { return $null }
  $sessionRoot = Join-Path $homeDir '.codex\\sessions'
  if (-not (Test-Path -LiteralPath $sessionRoot)) { return $null }
  return $sessionRoot
}

function Resolve-RolloutFileForSession {
  param([string]$SessionId)
  if (-not $SessionId) { return $null }
  try {
    $sessionRoot = Get-CodexSessionRoot
    if (-not $sessionRoot) { return $null }

    $pattern = "rollout-*-${SessionId}.jsonl"
    $now = Get-Date
    $dates = @($now.Date, $now.AddDays(-1).Date, $now.AddDays(1).Date) | Select-Object -Unique
    $candidates = @()
    foreach ($dt in $dates) {
      $dir = Join-Path $sessionRoot ($dt.ToString('yyyy\\MM\\dd'))
      if (Test-Path -LiteralPath $dir) {
        $files = Get-ChildItem -LiteralPath $dir -Filter $pattern -ErrorAction SilentlyContinue
        if ($files) { $candidates += $files }
      }
    }
    if ($candidates.Count -eq 0) {
      $candidates = Get-ChildItem -LiteralPath $sessionRoot -Recurse -Filter $pattern -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 10
    }
    if ($candidates.Count -eq 0) { return $null }
    $pick = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($pick) { return $pick.FullName }
  } catch {}
  return $null
}

function Get-LatestAssistantTextFromRollout {
  param([string]$SessionId, [int]$TailLines = 400)
  $out = @{ id = ''; timestamp = $null; text = ''; path = $null }
  if (-not $SessionId) { return $out }
  $path = Resolve-RolloutFileForSession -SessionId $SessionId
  if (-not $path) { return $out }
  $out.path = $path
  try {
    $lines = Get-Content -LiteralPath $path -Tail $TailLines -ErrorAction SilentlyContinue
    if (-not $lines) { return $out }
    foreach ($line in $lines) {
      if (-not $line) { continue }
      $obj = $null
      try { $obj = $line | ConvertFrom-Json -Depth 20 } catch { continue }
      if (-not $obj) { continue }
      if ($obj.type -ne 'response_item') { continue }
      if (-not $obj.payload) { continue }
      if ($obj.payload.type -ne 'message' -or $obj.payload.role -ne 'assistant') { continue }

      $parts = New-Object System.Collections.Generic.List[string]
      foreach ($c in @($obj.payload.content)) {
        if (-not $c) { continue }
        try {
          if ($c.type -eq 'output_text' -and $c.text) { $parts.Add([string]$c.text) }
          elseif ($c.type -eq 'text' -and $c.text) { $parts.Add([string]$c.text) }
        } catch {}
      }
      if ($parts.Count -eq 0) { continue }
      $txt = ($parts -join "`n").Trim()
      if (-not $txt) { continue }

      $ts = $null
      try { if ($obj.timestamp) { $ts = [datetime]$obj.timestamp } } catch {}
      $id = ''
      if ($obj.timestamp) { $id = [string]$obj.timestamp } else { $id = ("len:{0}" -f $txt.Length) }

      $out.id = $id
      $out.timestamp = $ts
      $out.text = $txt
    }
  } catch {}
  return $out
}

function Resolve-CodexSessionFromRollout {
  # Accept null values from callers. Many call sites use a best-effort start time which can be missing.
  param([Nullable[datetime]]$StartTime, [Nullable[datetime]]$EndTime)
  try {
    $sessionRoot = Get-CodexSessionRoot
    if (-not (Test-Path -LiteralPath $sessionRoot)) { return $null }

    $dates = @()
    if ($StartTime) { $dates += $StartTime.Date }
    if ($EndTime) { $dates += $EndTime.Date }
    $dates = $dates | Select-Object -Unique

    $candidates = @()
    foreach ($dt in $dates) {
      $dir = Join-Path $sessionRoot ($dt.ToString('yyyy\\MM\\dd'))
      if (Test-Path -LiteralPath $dir) {
        $files = Get-ChildItem -LiteralPath $dir -Filter 'rollout-*.jsonl' -ErrorAction SilentlyContinue
        if ($files) { $candidates += $files }
      }
    }
    if ($candidates.Count -eq 0) {
      $candidates = Get-ChildItem -LiteralPath $sessionRoot -Recurse -Filter 'rollout-*.jsonl' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 20
    }
    if ($candidates.Count -eq 0) { return $null }

    $windowStart = if ($StartTime) { $StartTime.AddMinutes(-2) } else { (Get-Date).AddMinutes(-5) }
    $windowEnd = if ($EndTime) { $EndTime.AddMinutes(2) } else { (Get-Date).AddMinutes(1) }

    # Prefer parsing the timestamp embedded in the filename (more accurate than LastWriteTime).
    $parsed = @()
    foreach ($f in $candidates) {
      if ($f.Name -match '^rollout-(\d{4})-(\d{2})-(\d{2})T(\d{2})-(\d{2})-(\d{2})-([0-9a-f-]{16,})\.jsonl$') {
        try {
          $dt = [datetime]::new([int]$Matches[1],[int]$Matches[2],[int]$Matches[3],[int]$Matches[4],[int]$Matches[5],[int]$Matches[6])
          $parsed += [pscustomobject]@{ file = $f; dt = $dt; thread_id = $Matches[7] }
        } catch {}
      }
    }
    if ($parsed.Count -gt 0) {
      $inWindow = @($parsed | Where-Object { $_.dt -ge $windowStart -and $_.dt -le $windowEnd })
      if ($inWindow.Count -eq 0) { $inWindow = $parsed }
      if ($StartTime) {
        $pick = $inWindow | Sort-Object @{ Expression = { [Math]::Abs(($_.dt - $StartTime).TotalSeconds) } }, @{ Expression = { $_.dt }; Descending = $true } | Select-Object -First 1
        if ($pick -and $pick.thread_id) { return $pick.thread_id }
      } else {
        $pick = $inWindow | Sort-Object dt -Descending | Select-Object -First 1
        if ($pick -and $pick.thread_id) { return $pick.thread_id }
      }
    }

    # Fallback to file timestamps.
    $pick = $candidates | Where-Object { $_.LastWriteTime -ge $windowStart -and $_.LastWriteTime -le $windowEnd } |
      Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $pick) { $pick = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1 }
    if ($pick -and $pick.Name -match 'rollout-.*-([0-9a-f-]{16,})\\.jsonl$') { return $Matches[1] }
  } catch {}
  return $null
}

function Convert-ToDateTimeSafe {
  param([object]$Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [datetime]) { return [datetime]$Value }
  if ($Value -is [datetimeoffset]) { return ([datetimeoffset]$Value).DateTime }
  $s = [string]$Value
  if (-not $s) { return $null }
  $s = $s.Trim()
  if (-not $s) { return $null }
  try {
    return [datetime]::Parse(
      $s,
      [System.Globalization.CultureInfo]::InvariantCulture,
      [System.Globalization.DateTimeStyles]::RoundtripKind
    )
  } catch {}
  try { return [datetime]::Parse($s) } catch {}
  return $null
}

function Test-ProcessRunning {
  param(
    [object]$ProcessId,
    [string]$ExpectedScriptPath,
    [object]$StartedAt
  )
  if (-not $ProcessId) { return $false }
  $pidInt = 0
  if (-not [int]::TryParse([string]$ProcessId, [ref]$pidInt)) { return $false }
  try {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId = $pidInt" -ErrorAction SilentlyContinue
    if (-not $p) { return $false }

    # Guard against PID reuse: if this PID now belongs to another process/script, it's not our job.
    if ($ExpectedScriptPath) {
      $cmd = [string]$p.CommandLine
      if (-not $cmd -or $cmd -notmatch [regex]::Escape($ExpectedScriptPath)) { return $false }
    }

    # Additional PID reuse guard: process creation must not be much later than the job start.
    $jobStarted = Convert-ToDateTimeSafe -Value $StartedAt
    if ($jobStarted -and $p.CreationDate) {
      $procStarted = Convert-ToDateTimeSafe -Value $p.CreationDate
      if ($procStarted -and $procStarted -gt $jobStarted.AddMinutes(2)) { return $false }
    }
    return $true
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
  $startedAt = $null
  if ($state.PSObject.Properties.Name -contains 'codex_job_started') { $startedAt = $state.codex_job_started }
  $running = Test-ProcessRunning -ProcessId $procId -ExpectedScriptPath $cfg.CodexJobScript -StartedAt $startedAt

  $exitCode = $null
  if ($state.PSObject.Properties.Name -contains 'codex_job_exit' -and $state.codex_job_exit -and (Test-Path -LiteralPath $state.codex_job_exit)) {
    $raw = (Get-Content -LiteralPath $state.codex_job_exit -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($raw -match '^-?\d+$') { $exitCode = [int]$raw }
  }

  $res = $null
  if ($state.PSObject.Properties.Name -contains 'codex_job_result' -and $state.codex_job_result -and (Test-Path -LiteralPath $state.codex_job_result)) {
    try { $res = Get-Content -LiteralPath $state.codex_job_result -Raw | ConvertFrom-Json } catch {}
  }

  # If terminal artifacts exist, consider the job complete even if the process record is stale.
  if ($exitCode -ne $null -or $res) { $running = $false }

  # Some codex runs can hang after writing the final output file. If that file exists and
  # has been stable for a bit, end the stale wrapper and treat the job as complete.
  if ($running -and $state.PSObject.Properties.Name -contains 'codex_job_outfile' -and $state.codex_job_outfile -and (Test-Path -LiteralPath $state.codex_job_outfile)) {
    try {
      $outItem = Get-Item -LiteralPath $state.codex_job_outfile -ErrorAction SilentlyContinue
      if ($outItem -and $outItem.Length -gt 0) {
        $ageSec = ((Get-Date) - $outItem.LastWriteTime).TotalSeconds
        if ($ageSec -ge 20 -and $procId) {
          try { & taskkill.exe /PID ([int]$procId) /T /F | Out-Null } catch {}
          $running = $false
        }
      }
    } catch {}
  }

  return [ordered]@{
    id = $jobId
    pid = $procId
    running = $running
    started = $state.codex_job_started
    exit_code = $exitCode
    thread_id = if ($res -and $res.thread_id) { $res.thread_id } else { $null }
    resume_thread_id = if ($res -and $res.resume_thread_id) { $res.resume_thread_id } else { $null }
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
  if (-not $threadId) {
    $startTime = $null
    try { if ($state.codex_job_started) { $startTime = [DateTime]::Parse($state.codex_job_started) } } catch {}
    $endTime = Get-Date
    $threadId = Resolve-CodexSessionFromRollout -StartTime $startTime -EndTime $endTime
  }
  if ($threadId -and ($state.codex_session_id -ne $threadId)) {
    $state.codex_session_id = $threadId
    $state.codex_has_session = $true
  }
  if (-not $threadId) {
    $resumeThread = $null
    if ($info.PSObject.Properties.Name -contains 'resume_thread_id') { $resumeThread = $info.resume_thread_id }
    if (-not $resumeThread) {
      if ($state.PSObject.Properties.Name -contains 'codex_job_resume_thread') { $resumeThread = $state.codex_job_resume_thread }
    }
    if ($resumeThread) {
      $state.codex_session_id = $resumeThread
      $state.codex_has_session = $true
    } else {
      $since = $null
      if ($state.codex_job_started) {
        try { $since = [datetime]$state.codex_job_started } catch {}
      }
      if (-not $since -and $info.started) {
        try { $since = [datetime]$info.started } catch {}
      }
      if (-not $since) { $since = Get-Date }
      # Keep current session; do not attempt a filesystem fallback here.
    }
  }

  # Promote run metadata from the result json when available, so the appended suffix is accurate.
  $resultObj = $null
  if ($state.PSObject.Properties.Name -contains 'codex_job_result' -and $state.codex_job_result -and (Test-Path -LiteralPath $state.codex_job_result)) {
    try {
      $resultObj = Get-Content -LiteralPath $state.codex_job_result -Raw | ConvertFrom-Json
      if ($resultObj) {
        if ($resultObj.model) { $state.codex_last_model = [string]$resultObj.model }
        if ($resultObj.reasoning_effort) { $state.codex_last_reasoning_effort = [string]$resultObj.reasoning_effort }
        if ($resultObj.working_dir) { $state.codex_last_cwd = [string]$resultObj.working_dir }
        if ($resultObj.dangerous -ne $null) { $state.codex_last_perms = if ([bool]$resultObj.dangerous) { 'full' } else { 'restricted' } }
      }
    } catch {}
  }

  $finalLog = Join-Path $cfg.LogDir "codex_exec_${jobId}.log"
  $output = $null
  if ($outFile -and (Test-Path -LiteralPath $outFile)) {
    $output = Get-Content -LiteralPath $outFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
  }
  if ($output) { $output = $output.Trim() }

  if (-not $output -and $resultObj -and ($resultObj.ok -eq $false)) {
    $err = if ($resultObj.error) { [string]$resultObj.error } else { 'unknown error' }
    $ended = ''
    if ($resultObj.ended) { $ended = " ended=$($resultObj.ended)" }
    $code = ''
    if ($resultObj.exit_code -ne $null) { $code = " exit_code=$($resultObj.exit_code)" }
    $output = "Codex job failed: $err.$code$ended"
  }

  if (-not $output -and $state.PSObject.Properties.Name -contains 'codex_job_stderr' -and $state.codex_job_stderr -and (Test-Path -LiteralPath $state.codex_job_stderr)) {
    $stderrTail = Get-LogTail -LogPath $state.codex_job_stderr -Lines 40
    if ($stderrTail) { $stderrTail = $stderrTail.Trim() }
    if ($stderrTail) {
      $output = "(no stdout)`n`n--- stderr (tail) ---`n$stderrTail"
    }
  }
  if (-not $output) { $output = '(no output)' }
  $output = Append-SessionInfo -cfg $cfg -state $state -Text $output
  try { Set-Content -LiteralPath $finalLog -Value $output } catch {}
  $state.codex_last_log = $finalLog

  # Clear PID so we don't treat the job as running again after it exits.
  $state.codex_job_pid = $null
  Ensure-StateProperty -state $state -Name 'codex_job_resume_thread' -Value $null
  $state.codex_job_resume_thread = $null
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

  Ensure-StateProperty -state $state -Name 'codex_job_resume_thread' -Value $null
  $state.codex_job_id = $jobId
  $state.codex_job_pid = $proc.Id
  $state.codex_job_prompt = $promptPath
  $state.codex_job_outfile = $outFile
  $state.codex_job_stdout = $stdoutPath
  $state.codex_job_stderr = $stderrPath
  $state.codex_job_result = $resultPath
  $state.codex_job_exit = $exitPath
  $state.codex_job_started = (Get-Date).ToString('o')
  $state.codex_job_resume_thread = if ($resumeThread) { $resumeThread } else { $null }
  $state.codex_cwd = $workDir
  Save-State -cfg $cfg -state $state

  # If we're starting a fresh exec thread, try to resolve the new session id immediately.
  # rollout-*.jsonl files are created at the start of the run.
  $resolvedSid = $null
  if (-not $Resume) {
    $jobStart = $null
    try { $jobStart = [DateTime]::Parse($state.codex_job_started) } catch { $jobStart = Get-Date }
    for ($i = 0; $i -lt 10; $i++) {
      $resolvedSid = Resolve-CodexSessionFromRollout -StartTime $jobStart -EndTime (Get-Date)
      if ($resolvedSid) { break }
      Start-Sleep -Milliseconds 200
    }
    if ($resolvedSid -and ($state.codex_session_id -ne $resolvedSid)) {
      $state.codex_session_id = $resolvedSid
      $state.codex_has_session = $true
      Save-State -cfg $cfg -state $state
    }
  }

  $modelLabel = if ($model) { $model } else { 'default' }
  $reasoningLabel = if ($reasoning) { $reasoning } else { 'default' }
  $resumeLabel = if ($resumeThread) { "resume $resumeThread" } else { 'new thread' }
  $sidLabel = if ($resolvedSid) { " thread_id=$resolvedSid" } else { '' }
  $msg = "Queued codex job $jobId ($resumeLabel, model=$modelLabel, reasoning=$reasoningLabel).$sidLabel Use 'codexlast' to check output."

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

function Ensure-Dir {
  param([string]$Path)
  if (-not $Path) { return }
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Resolve-TriRootFromHeadless {
  param($cfg)
  if (-not $cfg.HeadlessRebuildToolRoot) { return '' }
  try {
    $toolsRoot = Split-Path -Parent $cfg.HeadlessRebuildToolRoot
    return (Split-Path -Parent $toolsRoot)
  } catch {
    return ''
  }
}

function Find-DiagSummaryPath {
  param($cfg, [string]$RunId)
  if (-not $RunId) { return $null }
  $triRoot = Resolve-TriRootFromHeadless -cfg $cfg
  if (-not $triRoot) { return $null }

  $searchRoots = @(
    (Join-Path $triRoot 'reports'),
    (Join-Path $triRoot 'tmp')
  ) | Where-Object { Test-Path -LiteralPath $_ }

  $hits = @()
  foreach ($root in $searchRoots) {
    try {
      $hits += Get-ChildItem -Path $root -Recurse -File -Filter 'diag_*.md' -ErrorAction SilentlyContinue | Where-Object {
        $_.FullName -match [regex]::Escape($RunId)
      }
    } catch {}
  }

  if (-not $hits -or $hits.Count -eq 0) { return $null }
  return ($hits | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

function Resolve-RunMonitorState {
  param($cfg, [string]$RunId, [bool]$DiagPresent)
  $state = [ordered]@{
    run_id = $RunId
    run_status = 'completed'
    queue_status = 'unknown'
    diag_present = $DiagPresent
    lock_state = 'unknown'
    active_title = 'space4x'
    monitor_next_skill = ''
    monitor_reason = ''
  }

  $monitorDir = Join-Path $cfg.HeadlessRebuildToolRoot '.agents\skills\artifacts\buildbox-run-monitor'
  if (-not (Test-Path -LiteralPath $monitorDir)) { return $state }

  $statusFiles = @(Get-ChildItem -Path $monitorDir -File -Filter 'monitor_status_*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
  foreach ($file in $statusFiles) {
    try {
      $obj = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
      if (-not $obj.run -or -not $obj.run.id) { continue }
      if ([string]$obj.run.id -ne $RunId) { continue }
      $state.run_status = if ($obj.run.status) { [string]$obj.run.status } else { 'unknown' }
      $state.diag_present = if ($obj.diagnostics) { [bool]$obj.diagnostics.found } else { $DiagPresent }
      $state.monitor_next_skill = if ($obj.next_skill) { [string]$obj.next_skill } else { '' }
      $state.monitor_reason = if ($obj.next_reason) { [string]$obj.next_reason } else { '' }
      if ($obj.run -and $obj.run.head_branch) {
        $branch = [string]$obj.run.head_branch
        if ($branch -match '(?i)godgame') { $state.active_title = 'godgame' }
      }
      return $state
    } catch {}
  }
  return $state
}

function Invoke-AiSidecar {
  param(
    $cfg,
    [string]$Command,
    [object]$InputObject
  )
  if (-not (Test-Path -LiteralPath $cfg.AiInvokeScript)) {
    throw "AI invoke script not found: $($cfg.AiInvokeScript)"
  }

  Ensure-Dir -Path $cfg.AiArtifactsDir
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $jsonOut = Join-Path $cfg.AiArtifactsDir ("{0}_{1}.json" -f $Command, $stamp)
  $mdOut = Join-Path $cfg.AiArtifactsDir ("{0}_{1}.md" -f $Command, $stamp)

  $raw = & $cfg.AiInvokeScript -Command $Command -InputObject $InputObject -OutputJsonPath $jsonOut -OutputMarkdownPath $mdOut
  if (-not $raw) { throw "AI sidecar returned no envelope for $Command" }
  $meta = $raw | ConvertFrom-Json

  $payload = $null
  if (Test-Path -LiteralPath $jsonOut) {
    try { $payload = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json } catch {}
  }

  return [ordered]@{
    metadata = $meta
    output = $payload
    output_json_path = $jsonOut
    output_markdown_path = $mdOut
  }
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

try {
  New-Item -ItemType Directory -Force -Path $cfg.LogDir | Out-Null
  $pidFile = Join-Path $cfg.LogDir ("agent_{0}.pid" -f $cfg.ListenPort)
  Set-Content -LiteralPath $pidFile -Value $PID
} catch {}

Write-Console ("Agent up. name={0} listen={1}:{2} log_dir={3} state={4}" -f $cfg.Name, $cfg.ListenAddr, $cfg.ListenPort, $cfg.LogDir, $cfg.StateFile)

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

    if ($script:ConsoleLogRequests -and $req -and $req.op) {
      Write-Console ("[{0}] req op={1}" -f (Get-Date).ToString('HH:mm:ss'), [string]$req.op)
    }

    if ($cfg.Secret -and $req.secret -ne $cfg.Secret) { throw 'Unauthorized.' }

    switch ($req.op) {
      'ping' {
        $activeModel = $null
        if ($state.PSObject.Properties.Name -contains 'codex_model' -and $state.codex_model) { $activeModel = $state.codex_model }
        elseif ($cfg.CodexModel) { $activeModel = $cfg.CodexModel }
        $activeReasoning = $null
        if ($state.PSObject.Properties.Name -contains 'codex_reasoning_effort' -and $state.codex_reasoning_effort) { $activeReasoning = $state.codex_reasoning_effort }
        elseif ($cfg.CodexReasoningEffort) { $activeReasoning = $cfg.CodexReasoningEffort }
        elseif ($cfg.CodexUserConfigReasoningEffort) { $activeReasoning = $cfg.CodexUserConfigReasoningEffort }
        $activeMode = Get-EffectiveCodexMode -cfg $cfg -state $state
        $null = Refresh-CodexJobState -cfg $cfg -state $state
        $job = Get-CodexJobInfo -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ name = $cfg.Name; sessions = (List-CodexSessions); codex_model = $activeModel; codex_reasoning_effort = $activeReasoning; codex_mode = $activeMode; codex_mode_override = $state.codex_mode_override; codex_job = $job } }
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
      'ai.sidecar' {
        if (-not $req.action) { throw 'action missing (diag|route|scoreboard|capabilities).' }
        $action = ([string]$req.action).ToLowerInvariant()
        switch ($action) {
          'diag' {
            if (-not $req.run_id) { throw 'run_id missing for ai diag.' }
            $runId = [string]$req.run_id
            $diagPath = Find-DiagSummaryPath -cfg $cfg -RunId $runId
            if (-not $diagPath) { throw "diag summary not found for run_id=$runId" }
            $resultDir = Split-Path -Parent $diagPath
            $evidence = @()
            $candidateFiles = @(
              @{ path = (Join-Path $resultDir 'meta.json'); kind = 'json' },
              @{ path = (Join-Path $resultDir 'out\run_summary.json'); kind = 'json' },
              @{ path = (Join-Path $resultDir 'out\watchdog.json'); kind = 'json' },
              @{ path = (Join-Path $resultDir 'out\player.log'); kind = 'log' }
            )
            foreach ($candidate in $candidateFiles) {
              $p = [string]$candidate.path
              if (-not (Test-Path -LiteralPath $p)) { continue }
              $snippet = (Get-Content -LiteralPath $p -ErrorAction SilentlyContinue | Select-Object -First 120) -join "`n"
              if (-not $snippet) { continue }
              $evidence += [ordered]@{
                path = $p
                kind = [string]$candidate.kind
                excerpt = $snippet
              }
            }

            $inputObj = [ordered]@{
              diag_summary_path = $diagPath
              diag_summary_text = (Get-Content -LiteralPath $diagPath -Raw -ErrorAction SilentlyContinue)
              evidence = $evidence
              context = [ordered]@{
                run_id = $runId
              }
            }

            $aiResult = Invoke-AiSidecar -cfg $cfg -Command 'ai_diag_summary' -InputObject $inputObj
            $summary = ''
            if ($aiResult.output) {
              $summary = "next_lane=$($aiResult.output.recommended_next_lane) confidence=$($aiResult.output.confidence)"
            }
            $resp = @{
              ok = $true
              result = @{
                action = 'diag'
                run_id = $runId
                diag_summary_path = $diagPath
                output_json_path = $aiResult.output_json_path
                output_markdown_path = $aiResult.output_markdown_path
                ai_output = $aiResult.output
                metadata = $aiResult.metadata.metadata
                summary = $summary
              }
            }
          }
          'route' {
            if (-not $req.run_id) { throw 'run_id missing for ai route.' }
            $runId = [string]$req.run_id
            $diagPath = Find-DiagSummaryPath -cfg $cfg -RunId $runId
            $runState = Resolve-RunMonitorState -cfg $cfg -RunId $runId -DiagPresent ([bool]$diagPath)
            $aiResult = Invoke-AiSidecar -cfg $cfg -Command 'ai_next_lane_router' -InputObject $runState
            $summary = ''
            if ($aiResult.output) {
              $summary = "next_skill=$($aiResult.output.next_skill) safe_mode=$($aiResult.output.safe_mode)"
            }
            $resp = @{
              ok = $true
              result = @{
                action = 'route'
                run_id = $runId
                run_state = $runState
                output_json_path = $aiResult.output_json_path
                output_markdown_path = $aiResult.output_markdown_path
                ai_output = $aiResult.output
                metadata = $aiResult.metadata.metadata
                summary = $summary
              }
            }
          }
          'scoreboard' {
            if (-not $req.path) { throw 'path missing for ai scoreboard.' }
            $rawPath = [string]$req.path
            if (-not (Test-Path -LiteralPath $rawPath)) { throw "scoreboard path not found: $rawPath" }

            $scoreboardPath = $rawPath
            if ((Get-Item -LiteralPath $rawPath).PSIsContainer) {
              $scoreboardPath = Join-Path $rawPath 'scoreboard.json'
            }
            if (-not (Test-Path -LiteralPath $scoreboardPath)) {
              throw "scoreboard file not found: $scoreboardPath"
            }

            $scoreboardJson = $null
            try { $scoreboardJson = Get-Content -LiteralPath $scoreboardPath -Raw | ConvertFrom-Json } catch { $scoreboardJson = @{} }
            $inputObj = [ordered]@{
              scoreboard_json = $scoreboardJson
              scoreboard_text = Get-Content -LiteralPath $scoreboardPath -Raw -ErrorAction SilentlyContinue
              thresholds = @{}
              recent_receipts = @()
              context = [ordered]@{
                scoreboard_path = $scoreboardPath
              }
            }

            $aiResult = Invoke-AiSidecar -cfg $cfg -Command 'ai_scoreboard_headline' -InputObject $inputObj
            $summary = ''
            if ($aiResult.output) {
              $summary = "headline=$($aiResult.output.headline)"
            }
            $resp = @{
              ok = $true
              result = @{
                action = 'scoreboard'
                scoreboard_path = $scoreboardPath
                output_json_path = $aiResult.output_json_path
                output_markdown_path = $aiResult.output_markdown_path
                ai_output = $aiResult.output
                metadata = $aiResult.metadata.metadata
                summary = $summary
              }
            }
          }
          'capabilities' {
            $inputObj = @{}
            if ($req.command) { $inputObj.command = [string]$req.command }

            $aiResult = Invoke-AiSidecar -cfg $cfg -Command 'ai_capabilities' -InputObject $inputObj
            $summary = ''
            if ($aiResult.output -and $aiResult.output.commands) {
              $summary = "commands=$(@($aiResult.output.commands).Count)"
            }
            $resp = @{
              ok = $true
              result = @{
                action = 'capabilities'
                output_json_path = $aiResult.output_json_path
                output_markdown_path = $aiResult.output_markdown_path
                ai_output = $aiResult.output
                metadata = $aiResult.metadata.metadata
                summary = $summary
              }
            }
          }
          default {
            throw "Unknown ai action: $action"
          }
        }
      }
      'codex.send' {
        if (-not $req.prompt) { throw 'prompt missing.' }
        $mode = Get-EffectiveCodexMode -cfg $cfg -state $state
        if ($mode -eq 'console') {
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
      'codex.send.exec' {
        if (-not $req.prompt) { throw 'prompt missing.' }
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
      'codex.new' {
        $mode = Get-EffectiveCodexMode -cfg $cfg -state $state
        if ($mode -eq 'console') {
          $null = Stop-CodexConsole -cfg $cfg -state $state
          $null = Start-CodexConsole -cfg $cfg -state $state
          Start-Sleep -Seconds $cfg.CodexStartWaitSec
          if ($cfg.CodexNewDelaySec -gt 0) { Start-Sleep -Seconds $cfg.CodexNewDelaySec }
          $state.codex_console_offset = 0
          Save-State -cfg $cfg -state $state
          if (-not $req.prompt) {
            $resp = @{ ok = $true; result = @{ output = 'Console restarted.' } }
          } else {
            $outText = Send-CodexConsolePrompt -cfg $cfg -state $state -Prompt $req.prompt
            $resp = @{ ok = $true; result = @{ output = $outText } }
          }
        } else {
          if (-not $req.prompt) {
            $state.codex_session_id = $null
            $state.codex_has_session = $false
            Save-State -cfg $cfg -state $state
            $resp = @{ ok = $true; result = @{ output = 'Exec session reset.' } }
            break
          }
          $null = Refresh-CodexJobState -cfg $cfg -state $state
          # Fresh exec thread: clear any stale session id before launching.
          $state.codex_session_id = $null
          $state.codex_has_session = $false
          Save-State -cfg $cfg -state $state
          if ($cfg.CodexAsync) {
            $out = Start-CodexExecJob -cfg $cfg -state $state -Prompt $req.prompt -Resume:$false
          } else {
            $out = Invoke-CodexExec -cfg $cfg -state $state -Prompt $req.prompt -Resume:$false
          }
          $resp = @{ ok = $true; result = $out }
        }
      }
      'codex.new.exec' {
        if (-not $req.prompt) {
          $state.codex_session_id = $null
          $state.codex_has_session = $false
          Save-State -cfg $cfg -state $state
          $resp = @{ ok = $true; result = @{ output = 'Exec session reset.' } }
          break
        }
        $null = Refresh-CodexJobState -cfg $cfg -state $state
        # Fresh exec thread: clear any stale session id before launching.
        $state.codex_session_id = $null
        $state.codex_has_session = $false
        Save-State -cfg $cfg -state $state
        if ($cfg.CodexAsync) {
          $out = Start-CodexExecJob -cfg $cfg -state $state -Prompt $req.prompt -Resume:$false
        } else {
          $out = Invoke-CodexExec -cfg $cfg -state $state -Prompt $req.prompt -Resume:$false
        }
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
      'codex.reasoning.get' {
        $activeReasoning = $null
        if ($state.PSObject.Properties.Name -contains 'codex_reasoning_effort' -and $state.codex_reasoning_effort) { $activeReasoning = $state.codex_reasoning_effort }
        elseif ($cfg.CodexReasoningEffort) { $activeReasoning = $cfg.CodexReasoningEffort }
        elseif ($cfg.CodexUserConfigReasoningEffort) { $activeReasoning = $cfg.CodexUserConfigReasoningEffort }
        $resp = @{ ok = $true; result = @{ reasoning_effort = $activeReasoning; state_reasoning_effort = $state.codex_reasoning_effort; config_reasoning_effort = $cfg.CodexReasoningEffort; user_config_reasoning_effort = $cfg.CodexUserConfigReasoningEffort } }
      }
      'codex.mode.get' {
        $activeMode = Get-EffectiveCodexMode -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ mode = $activeMode; override = $state.codex_mode_override; config_mode = $cfg.CodexMode } }
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
      'codex.reasoning' {
        $r = ''
        if ($req.reasoning_effort) { $r = [string]$req.reasoning_effort }
        $r = $r.Trim().ToLowerInvariant()
        if ($r -in @('default','clear','none')) { $r = '' }
        if (-not $r) { $state.codex_reasoning_effort = $null } else { $state.codex_reasoning_effort = $r }

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
        $resp = @{ ok = $true; result = @{ reasoning_effort = $state.codex_reasoning_effort; reset = $doReset } }
      }
      'codex.mode' {
        $m = ''
        if ($req.mode) { $m = [string]$req.mode }
        $m = $m.Trim().ToLowerInvariant()
        if (-not $m -or $m -in @('default','clear','none')) {
          $state.codex_mode_override = $null
        } elseif ($m -in @('exec','console')) {
          $state.codex_mode_override = $m
        } else {
          throw "Unknown mode: $m"
        }
        Save-State -cfg $cfg -state $state
        $activeMode = Get-EffectiveCodexMode -cfg $cfg -state $state
        $resp = @{ ok = $true; result = @{ mode = $activeMode; override = $state.codex_mode_override; config_mode = $cfg.CodexMode } }
      }
      'codex.use' {
        if (-not $req.session) { throw 'session missing.' }
        $job = Get-CodexJobInfo -cfg $cfg -state $state
        if ($job -and $job.running) { throw "Codex job running (job_id=$($job.id)). Cancel it first." }
        $state.codex_session_id = $req.session
        $state.codex_has_session = $true
        $state.codex_job_id = $null
        $state.codex_job_pid = $null
        $state.codex_job_prompt = $null
        $state.codex_job_outfile = $null
        $state.codex_job_stdout = $null
        $state.codex_job_stderr = $null
        $state.codex_job_result = $null
        $state.codex_job_exit = $null
        $state.codex_job_started = $null
        Ensure-StateProperty -state $state -Name 'codex_job_resume_thread' -Value $null
        $state.codex_job_resume_thread = $null
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
        $mode = Get-EffectiveCodexMode -cfg $cfg -state $state
        if ($mode -eq 'console') {
          $lines = if ($req.lines) { [int]$req.lines } else { $cfg.TailLines }
          $tail = Get-LogTail -LogPath $cfg.CodexTranscript -Lines $lines
          $cleanTail = Clean-TranscriptText -Text $tail
          if ($cleanTail) {
            $tail = $cleanTail
          } else {
            $tail = '(no output yet)'
            $sid = $null
            if ($state.PSObject.Properties.Name -contains 'codex_session_id' -and $state.codex_session_id) { $sid = [string]$state.codex_session_id }
            if (-not $sid) { $sid = Resolve-CodexSessionFromRollout -StartTime (Get-Date).AddMinutes(-30) -EndTime (Get-Date) }
            if ($sid) {
              $snap = Get-LatestAssistantTextFromRollout -SessionId $sid
              $promptAt = $null
              if ($state.PSObject.Properties.Name -contains 'codex_console_last_prompt_at' -and $state.codex_console_last_prompt_at) {
                try { $promptAt = [datetime]$state.codex_console_last_prompt_at } catch { $promptAt = $null }
              }
              $fresh = $true
              if ($promptAt) {
                if ($snap.timestamp) { $fresh = ([datetime]$snap.timestamp -ge $promptAt.AddSeconds(-1)) }
                else { $fresh = $false }
              }
              if ($snap.text -and $fresh) { $tail = $snap.text }
            }
          }
          $resp = @{ ok = $true; result = @{ session = 'default'; output = $tail } }
        } else {
          $requestedJobId = $null
          if ($req.job_id) { $requestedJobId = [string]$req.job_id }
          if ($requestedJobId) { $requestedJobId = $requestedJobId.Trim() }

          $job = Refresh-CodexJobState -cfg $cfg -state $state
          if ($requestedJobId) {
            if ($job -and $job.id -and ([string]$job.id -eq $requestedJobId) -and $job.running) {
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
              $lines = if ($req.lines) { [int]$req.lines } else { $cfg.TailLines }
              $requestedLog = Join-Path $cfg.LogDir "codex_exec_${requestedJobId}.log"
              if (Test-Path -LiteralPath $requestedLog) {
                $tail = Get-LogTail -LogPath $requestedLog -Lines $lines
                $tail = Ensure-SessionInfoSuffix -cfg $cfg -state $state -Text $tail
                $resp = @{ ok = $true; result = @{ session = 'default'; output = $tail } }
              } else {
                $requestedOut = Join-Path $cfg.LogDir "codex_exec_${requestedJobId}.out"
                if (Test-Path -LiteralPath $requestedOut) {
                  $outText = Get-Content -LiteralPath $requestedOut -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                  if ($outText) { $outText = $outText.Trim() }
                  if (-not $outText) { $outText = '(no output)' }
                  $outText = Ensure-SessionInfoSuffix -cfg $cfg -state $state -Text $outText
                  $resp = @{ ok = $true; result = @{ session = 'default'; output = $outText } }
                } else {
                  throw "No codex output for job $requestedJobId yet."
                }
              }
            }
          } else {
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
              $tail = Ensure-SessionInfoSuffix -cfg $cfg -state $state -Text $tail
              $resp = @{ ok = $true; result = @{ session = 'default'; output = $tail } }
            }
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

