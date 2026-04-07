@ECHO OFF
TITLE Building WinPriv...
CLS
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0

:: do cleanup
RD /S /Q "%~dp0.vs" >NUL 2>&1
RD /S /Q "%~dp0x86\Temp" >NUL 2>&1
RD /S /Q "%~dp0x64\Temp" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.*pdb" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.*obj" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.zip" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.log" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.lib" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.dll" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.bsc" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.exp" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.last*" /C "CMD /C DEL /Q @path" >NUL 2>&1

:: zip up executatables
SET BINDIR=%~dp0
PUSHD "%BINDIR%"
%POWERSHELL% -Command "Compress-Archive -LiteralPath @('x86','x64') -DestinationPath '%BINDIR%\WinPriv.zip'"
POPD

:: output hash information
SET HASHFILE=%BINDIR%\WinPriv-hash.txt
IF EXIST "%HASHFILE%" DEL /F "%HASHFILE%"
FOR %%H IN (SHA256 SHA1 MD5) DO %POWERSHELL% -Command ^
   "Get-ChildItem -Include @('*.zip','*.exe') -Path '%BINDIR%' -Recurse | Get-FileHash -Algorithm %%H | Out-File -Append '%HASHFILE%' -Width 256"
%POWERSHELL% -Command "$Data = Get-Content '%HASHFILE%'; $Data.Replace((Get-Item -LiteralPath '%BINDIR%').FullName,'').Trim() | Set-Content '%HASHFILE%'"

PAUSE