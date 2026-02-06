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

rem Optional visible Codex console (legacy fallback).
rem Set CODEX_BRIDGE_CONSOLE=1 to enable.
set "CODEX_WORKDIR=%CODEX_CWD%"
if "%CODEX_WORKDIR%"=="" set "CODEX_WORKDIR=C:\dev\unity_clean"

if /I "%CODEX_BRIDGE_CONSOLE%"=="1" (
  start "CODEX_BRIDGE" "C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File "C:\dev\unity_clean\CodexBridge\codex_console.ps1" -Title CODEX_BRIDGE -Transcript "C:\dev\unity_clean\CodexBridge\logs\codex_console.log" -WorkingDir "%CODEX_WORKDIR%" -ApprovalPolicy never -Sandbox danger-full-access
  rem give the console a moment to come up
  ping -n 3 127.0.0.1 >nul
)

rem Start agent (always) and broker (only if TELEBOT_AUTOSTART=1 and broker.env is populated).
start "CodexBridge" "C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File "C:\dev\unity_clean\CodexBridge\update_and_start.ps1" -SkipPull

