@ECHO OFF

:: cert info to use for signing
SET CERT=9CC90E20ABF21CDEF09EE4C467A79FD454140C5A
set TSAURL=http://time.certum.pl/
set LIBNAME=WinPriv
set LIBURL=https://github.com/NoMoreFood/WinPriv

:: do cleanup
RD /S /Q "%~dp0.vs" >NUL 2>&1
RD /S /Q "%~dp0x86\Temp" >NUL 2>&1
RD /S /Q "%~dp0x64\Temp" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.*pdb" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.*obj" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.log" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.lib" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.dll" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.bsc" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.exp" /C "CMD /C DEL /Q @path" >NUL 2>&1

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup paths
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0
SET PATH=%PATH%;%PX86%\Windows Kits\10\bin\x64
SET PATH=%PATH%;%PX86%\Windows Kits\8.1\bin\x64
SET PATH=%PATH%;%PX86%\Windows Kits\10\bin\10.0.16299.0\x64

:: sign the main executables
SET BINDIR=%~dp0
signtool sign /sha1 %CERT% /fd sha1 /tr %TSAURL% /td sha1 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe" 
signtool sign /sha1 %CERT% /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe"

PAUSE