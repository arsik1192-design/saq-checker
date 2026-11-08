@echo off
rem ---------------------------------------------------------------
rem  CS2Check launcher.
rem  Asks Windows for administrator rights, then opens the GUI.
rem  Content is kept ASCII-only on purpose: cmd.exe reads .bat files
rem  in the console OEM codepage, and Cyrillic here breaks on some
rem  systems. All text the player sees lives in the GUI instead.
rem ---------------------------------------------------------------

cd /d "%~dp0"

if not exist "%~dp0CS2Check.App.ps1" goto missing
if not exist "%~dp0CS2Check.ps1"     goto missing

rem Already elevated? "net session" only succeeds for administrators.
net session >nul 2>&1
if %errorlevel% equ 0 goto run

rem Not elevated: relaunch this same file through the UAC prompt.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
exit /b

:run
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0CS2Check.App.ps1"
exit /b

:missing
echo.
echo   CS2Check.ps1 / CS2Check.App.ps1 not found next to this file.
echo   Keep every file from the archive in one folder.
echo.
pause
exit /b 1
