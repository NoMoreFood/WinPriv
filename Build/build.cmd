@ECHO OFF
SETLOCAL ENABLEEXTENSIONS DISABLEDELAYEDEXPANSION
TITLE Building WinPriv...
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0;%PATH%
SET PSModulePath=%WINDIR%\system32\WindowsPowerShell\v1.0\Modules;%PSModulePath%
SET BINDIR=%~dp0
SET STAGEDIR=%~dp0PackageStage
SET PACKAGEONLY=
SET POWERSHELL=POWERSHELL.EXE -NoProfile -NonInteractive -NoLogo

:ARGUMENTS
IF "%~1"=="" GOTO :START
IF /I "%~1"=="/PackageOnly" (
    SET PACKAGEONLY=1
) ELSE IF /I "%~1"=="/SkipCodeSigning" (
    SET SkipCodeSigning=true
) ELSE (
    ECHO Usage: build.cmd [/PackageOnly] [/SkipCodeSigning]
    IF "%~1"=="/?" EXIT /B 0
    EXIT /B 1
)
SHIFT
GOTO :ARGUMENTS

:START
SET SEVENZIP=7z.exe
IF EXIST "%ProgramFiles(x86)%\7-Zip\7z.exe" SET SEVENZIP=%ProgramFiles(x86)%\7-Zip\7z.exe
IF EXIST "%ProgramFiles%\7-Zip\7z.exe" SET SEVENZIP=%ProgramFiles%\7-Zip\7z.exe
"%SEVENZIP%" i >NUL 2>&1
IF ERRORLEVEL 1 (
    ECHO ERROR: 7-Zip is required to create the release archive.
    EXIT /B 1
)
IF EXIST "%STAGEDIR%" (
    ECHO ERROR: "%STAGEDIR%" already exists. Finish or remove the previous staging operation first.
    EXIT /B 1
)
MD "%STAGEDIR%"
IF ERRORLEVEL 1 EXIT /B 1
IF NOT DEFINED PACKAGEONLY (
    CALL :BUILD
    IF ERRORLEVEL 1 GOTO :FAILED
)
CALL :PACKAGE
IF ERRORLEVEL 1 GOTO :FAILED
RD /S /Q "%STAGEDIR%"
IF EXIST "%STAGEDIR%" EXIT /B 1
ECHO Built "%BINDIR%WinPriv.zip" and "%BINDIR%WinPriv-hash.txt".
EXIT /B 0

:FAILED
RD /S /Q "%STAGEDIR%"
ECHO ERROR: Build or packaging failed.
EXIT /B 1

:BUILD
SET MSBUILD=
FOR /F "delims=" %%M IN ('WHERE MSBuild.exe 2^>NUL') DO IF NOT DEFINED MSBUILD SET MSBUILD=%%M
IF NOT DEFINED MSBUILD IF EXIST "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    FOR /F "usebackq delims=" %%M IN (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" ^
        -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\Current\Bin\MSBuild.exe`) DO SET MSBUILD=%%M
)
IF NOT DEFINED MSBUILD (
    ECHO ERROR: Install Visual Studio C++ build tools with MSBuild and the v145 x86, x64, and ARM64 toolchains.
    EXIT /B 1
)

:: All three payloads must finish building and signing before any launcher embeds them.
FOR %%P IN (
    WinPrivShared\WinPrivShared.vcxproj
    WinPrivLibrary\WinPrivLibrary.vcxproj
    WinPriv\WinPriv.vcxproj
    WinPrivCmd\WinPrivCmd.vcxproj
    Tests\Native\HookLoadingFixture\HookLoadingFixture.Import.vcxproj
    Tests\Native\HookLoadingFixture\HookLoadingFixture.DelayLoad.vcxproj
    Tests\Native\HookLoadingFixture\HookLoadingFixture.Dynamic.vcxproj
) DO (
    FOR %%A IN (Win32 x64 ARM64) DO (
        ECHO Building %%P [Release^|%%A]...
        "%MSBUILD%" "%BINDIR%..\%%P" /nologo /m:1 /t:Rebuild /v:minimal ^
            /p:Configuration=Release /p:Platform=%%A ^
            /p:BuildProjectReferences=false /p:WinPrivPayloadChildBuild=true /p:SkipCodeSigning=true
        IF ERRORLEVEL 1 EXIT /B 1
    )
    IF "%%P"=="WinPrivLibrary\WinPrivLibrary.vcxproj" (
        "%MSBUILD%" "%BINDIR%..\CodeSigning.targets" /nologo /v:minimal ^
            /t:SignOutput /p:CodeSigningBatch=Libraries
        IF ERRORLEVEL 1 EXIT /B 1
    )
)
"%MSBUILD%" "%BINDIR%..\CodeSigning.targets" /nologo /v:minimal ^
    /t:SignOutput /p:CodeSigningBatch=Executables
EXIT /B %ERRORLEVEL%

:PACKAGE
FOR %%A IN (x86 x64 ARM64) DO (
    MD "%STAGEDIR%\%%A"
    IF ERRORLEVEL 1 EXIT /B 1
    FOR %%E IN (WinPriv.exe WinPrivCmd.exe) DO (
        COPY /Y "%BINDIR%%%A\%%E" "%STAGEDIR%\%%A\%%E" >NUL
        IF ERRORLEVEL 1 EXIT /B 1
    )
)
MD "%STAGEDIR%\licenses"
IF ERRORLEVEL 1 EXIT /B 1
COPY /Y "%BINDIR%..\LICENSE" "%STAGEDIR%\licenses\WinPriv-LICENSE" >NUL
IF ERRORLEVEL 1 EXIT /B 1

:: zip up executatables
PUSHD "%STAGEDIR%"
IF ERRORLEVEL 1 EXIT /B 1
"%SEVENZIP%" a -tzip -mm=Deflate -mx=9 WinPriv.zip x86 x64 ARM64 licenses
SET ZIPRESULT=%ERRORLEVEL%
POPD
IF NOT "%ZIPRESULT%"=="0" EXIT /B 1

:: output hash information
%POWERSHELL% -Command ^
    "$ErrorActionPreference = 'Stop'; $base = $env:STAGEDIR + '\';" ^
    "$files = Get-ChildItem -LiteralPath $env:STAGEDIR -Recurse -File | Where-Object Extension -In '.zip','.exe';" ^
    "$lines = foreach ($algorithm in 'SHA256','SHA1','MD5') { $files | Get-FileHash -Algorithm $algorithm |" ^
    "ForEach-Object { '{0} {1} {2}' -f $_.Algorithm,$_.Hash,$_.Path.Substring($base.Length) } };" ^
    "$lines | Set-Content -LiteralPath ($base + 'WinPriv-hash.txt') -Encoding Unicode"
IF ERRORLEVEL 1 EXIT /B 1
COPY /Y "%STAGEDIR%\WinPriv.zip" "%BINDIR%WinPriv.zip" >NUL
IF ERRORLEVEL 1 EXIT /B 1
COPY /Y "%STAGEDIR%\WinPriv-hash.txt" "%BINDIR%WinPriv-hash.txt" >NUL
EXIT /B %ERRORLEVEL%
