param(
  [Parameter(Mandatory = $true)] [string] $PromptPath,
  [Parameter(Mandatory = $true)] [string] $OutFile,
  [Parameter(Mandatory = $true)] [string] $StdoutPath,
  [Parameter(Mandatory = $true)] [string] $StderrPath,
  [Parameter(Mandatory = $true)] [string] $ResultPath,
  [Parameter(Mandatory = $true)] [string] $ExitPath,
  [string] $ResumeThreadId = '',
  [string] $Model = '',
  [string] $WorkingDir = '',
  [int] $TimeoutSec = 7200,
  [switch] $Dangerous
)

$ErrorActionPreference = 'Stop'

function Ensure-DirForFile {
  param([string]$Path)
  if (-not $Path) { return }
  $dir = Split-Path -Parent $Path
  if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
}

function Quote-CmdArg {
  param([string]$Arg)
  if ($Arg -match '[\s\"^&|<>]') {
    $escaped = $Arg -replace '"', '""'
    return '"' + $escaped + '"'
  }
  return $Arg
}

function Get-PwshPath {
  $p = (Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
  if ($p) { return $p }
  $p = (Get-Command powershell -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
  if ($p) { return $p }
  throw 'pwsh or powershell not found in PATH.'
}

function Resolve-CodexLauncher {
  $cmd = Get-Command codex -ErrorAction SilentlyContinue
  if (-not $cmd) { throw 'codex not found in PATH.' }

  $src = $cmd.Source
  if ($src -and $src.ToLowerInvariant().EndsWith('.ps1')) {
    return @{ exe = (Get-PwshPath); preArgs = @('-NoProfile','-File', $src) }
  }

  return @{ exe = $src; preArgs = @() }
}

Ensure-DirForFile -Path $OutFile
Ensure-DirForFile -Path $StdoutPath
Ensure-DirForFile -Path $StderrPath
Ensure-DirForFile -Path $ResultPath
Ensure-DirForFile -Path $ExitPath

$started = (Get-Date).ToString('o')
$exitCode = 1
$threadId = $null
$err = $null

try {
  if (-not (Test-Path -LiteralPath $PromptPath)) { throw "PromptPath not found: $PromptPath" }
  $prompt = Get-Content -LiteralPath $PromptPath -Raw -ErrorAction Stop

  $launcher = Resolve-CodexLauncher

  $args = @()
  if ($Dangerous) {
    $args += '--dangerously-bypass-approvals-and-sandbox'
  } else {
    $args += @('-a', 'never', '--sandbox', 'danger-full-access')
  }
  if ($Model) { $args += @('-m', $Model) }
  $args += @('--no-alt-screen', 'exec', '--json', '--output-last-message', $OutFile, '--color', 'never', '--skip-git-repo-check')
  if ($ResumeThreadId) { $args += @('resume', $ResumeThreadId) }
  $args += '-'  # read prompt from stdin

  $argList = @()
  $argList += $launcher.preArgs
  $argList += $args

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $launcher.exe
  $psi.Arguments = ($argList | ForEach-Object { Quote-CmdArg -Arg $_ }) -join ' '
  if ($WorkingDir) { $psi.WorkingDirectory = $WorkingDir }
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

  $proc.StandardInput.Write($prompt)
  $proc.StandardInput.Close()

  $exited = $proc.WaitForExit([Math]::Max(5, $TimeoutSec) * 1000)
  if (-not $exited) {
    try { $proc.Kill() } catch {}
    throw "codex exec timed out after ${TimeoutSec}s"
  }

  $null = [System.Threading.Tasks.Task]::WaitAll(@($outTask, $errTask), 5000)
  $stdoutText = $outTask.Result
  $stderrText = $errTask.Result

  if ($stdoutText) { Set-Content -LiteralPath $StdoutPath -Value $stdoutText }
  if ($stderrText) { Set-Content -LiteralPath $StderrPath -Value $stderrText }

  $combined = ''
  if ($stdoutText) { $combined += $stdoutText }
  if ($stderrText) { $combined += $stderrText }

  if ($combined -match '\"thread_id\":\"([0-9a-f-]{16,})\"') {
    $threadId = $Matches[1]
  }

  $exitCode = $proc.ExitCode
} catch {
  $err = $_.Exception.Message
  try { Set-Content -LiteralPath $StderrPath -Value ($err | Out-String) } catch {}
  $exitCode = 1
}

$ended = (Get-Date).ToString('o')

$result = [ordered]@{
  ok = ($err -eq $null)
  error = $err
  thread_id = $threadId
  exit_code = $exitCode
  started = $started
  ended = $ended
  model = $Model
  resume_thread_id = $ResumeThreadId
  dangerous = [bool]$Dangerous
  working_dir = $WorkingDir
  out_file = $OutFile
  stdout_file = $StdoutPath
  stderr_file = $StderrPath
}

try { $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultPath } catch {}
try { Set-Content -LiteralPath $ExitPath -Value $exitCode } catch {}

