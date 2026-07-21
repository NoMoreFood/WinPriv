@ECHO OFF
TITLE Running WinPriv Tests
SETLOCAL EnableExtensions EnableDelayedExpansion

pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-WinPrivTests.ps1" %*

PAUSE
