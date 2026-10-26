@ECHO OFF
TITLE Running WinPriv Tests
SETLOCAL ENABLEEXTENSIONS DISABLEDELAYEDEXPANSION

PWSH -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-WinPrivTests.ps1" %*
EXIT /B %ERRORLEVEL%
