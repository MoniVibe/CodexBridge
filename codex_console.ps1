# Codex console launcher
param(
  [string]$Title = 'CODEX_BRIDGE',
  [string]$Transcript = "C:\dev\tri\ops\telebot\logs\codex_console.log",
  [string]$WorkingDir = "C:\dev\tri",
  [string]$ApprovalPolicy = 'never',
  [string]$Sandbox = 'danger-full-access',
  [string]$Model = ''
)

$Host.UI.RawUI.WindowTitle = $Title
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Transcript) | Out-Null
Start-Transcript -Path $Transcript -Append | Out-Null

try {
  if ($Model) {
    codex --no-alt-screen -m $Model -a $ApprovalPolicy --sandbox $Sandbox -C $WorkingDir
  } else {
    codex --no-alt-screen -a $ApprovalPolicy --sandbox $Sandbox -C $WorkingDir
  }
} finally {
  Stop-Transcript | Out-Null
}
