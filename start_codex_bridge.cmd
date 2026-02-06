@echo off
setlocal

rem default off on laptop; desktop can override by setting TELEBOT_AUTOSTART=1
if "%TELEBOT_AUTOSTART%"=="" (
  if /I "%COMPUTERNAME%"=="DESKTOP-9VVJV75" (
    set TELEBOT_AUTOSTART=1
  ) else (
    set TELEBOT_AUTOSTART=0
  )
)

set "CODEX_WORKDIR=%CODEX_CWD%"
if "%CODEX_WORKDIR%"=="" set "CODEX_WORKDIR=C:\Dev\unity_clean"

start "CODEX_BRIDGE" "C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File "C:\dev\tri\ops\telebot\codex_console.ps1" -Title CODEX_BRIDGE -Transcript "C:\dev\tri\ops\telebot\logs\codex_console.log" -WorkingDir "%CODEX_WORKDIR%" -ApprovalPolicy never -Sandbox danger-full-access
rem give the console a moment to come up
ping -n 3 127.0.0.1 >nul

if /I "%TELEBOT_AUTOSTART%"=="0" goto :eof
start "TelebotAgent" "C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File "C:\dev\tri\ops\telebot\agent.ps1"

