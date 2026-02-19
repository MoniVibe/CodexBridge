@echo off
set "ROOT=C:\Dev\unity_clean\CodexBridge"
set "TELEBOT_WATCHDOG_START_CONSOLE_AGENT=1"
set "WDLOG=%ROOT%\logs\watchdog_task2.log"
echo [%date% %time%] task start >> "%WDLOG%"
"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File "%ROOT%\watchdog.ps1" >> "%WDLOG%" 2>&1
