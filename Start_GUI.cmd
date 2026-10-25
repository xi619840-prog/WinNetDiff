@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0dist\WinNetDiff.exe" (
  start "" "%~dp0dist\WinNetDiff.exe"
) else (
  py -3 "%~dp0windows_net_diffdiag.py"
  if errorlevel 1 pause
)
