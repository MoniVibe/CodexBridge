@echo off
start "CODEX_BRIDGE" "C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File "C:\dev\tri\ops\telebot\codex_console.ps1" -Title CODEX_BRIDGE -Transcript "C:\dev\tri\ops\telebot\logs\codex_console.log" -WorkingDir "C:\dev\tri" -ApprovalPolicy never -Sandbox danger-full-access
rem give the console a moment to come up
ping -n 3 127.0.0.1 >nul
start "TelebotAgent" "C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File "C:\dev\tri\ops\telebot\agent.ps1"
