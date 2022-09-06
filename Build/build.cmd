@ECHO OFF
TITLE Building WinPriv...
CLS
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0

:: cert info to use for signing
SET CERT=055E5F445405B24790B32F75FE9049884F2F3788
set TSAURL=http://time.certum.pl/
set LIBNAME=WinPriv
set LIBURL=https://github.com/NoMoreFood/WinPriv

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

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup commands and paths
SET POWERSHELL=POWERSHELL.EXE -NoProfile -NonInteractive -NoLogo
FOR /F "USEBACKQ DELIMS=" %%X IN (`DIR /OD /B /S "%PX86%\Windows Kits\10\SIGNTOOL.exe" ^| FINDSTR x64`) DO SET SIGNTOOL="%%~X"

:: sign the main executables
SET BINDIR=%~dp0
%SIGNTOOL% sign /sha1 %CERT% /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe"

:: zip up executatables
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