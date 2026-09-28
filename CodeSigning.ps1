#requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = 'Files')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Files')]
    [string[]]$Path,

    [Parameter(Mandatory, ParameterSetName = 'Batch')]
    [ValidateSet('Libraries', 'Executables')]
    [string]$Batch,

    [string]$TimestampServer = 'http://time.certum.pl/'
)

$ErrorActionPreference = 'Stop'
$files = @()
try {
    $signTool = Get-Command signtool.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Source
    if (-not $signTool) {
        $kits = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots'
        $architecture = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or
            $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' }
            elseif ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
        $versions = Get-ChildItem -LiteralPath (Join-Path $kits.KitsRoot10 'bin') -Directory |
            Where-Object Name -Match '^\d+\.\d+\.\d+\.\d+$' | Sort-Object { [version]$_.Name } -Descending
        foreach ($version in $versions) {
            $candidate = Join-Path $version.FullName "$architecture\signtool.exe"
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $signTool = $candidate; break }
        }
    }
    if (-not $signTool) { throw 'SignTool was not found on PATH or in the installed Windows SDKs.' }

    if ($Batch) {
        $names = if ($Batch -eq 'Libraries') { @('WinPrivLibrary.dll') } else { @('WinPriv.exe', 'WinPrivCmd.exe') }
        $Path = foreach ($architecture in 'x86', 'x64', 'ARM64') {
            foreach ($name in $names) { Join-Path $PSScriptRoot "Build\$architecture\$name" }
        }
    }
    $suffix = [guid]::NewGuid().ToString('N')
    $files = @(foreach ($item in Get-Item -LiteralPath $Path) {
        [pscustomobject]@{
            Original = $item.FullName
            Staged = Join-Path $item.DirectoryName ($item.BaseName + ".$suffix.signing" + $item.Extension)
        }
    })
    foreach ($file in $files) { Copy-Item -LiteralPath $file.Original -Destination $file.Staged }
    $stagedPaths = @($files.Staged)
    & $signTool sign /a /fd SHA256 /t $TimestampServer @stagedPaths
    if ($LASTEXITCODE -ne 0) { throw "SignTool signing failed with exit code $LASTEXITCODE." }
    & $signTool verify /pa /tw @stagedPaths
    if ($LASTEXITCODE -ne 0) { throw "SignTool verification failed with exit code $LASTEXITCODE." }
    foreach ($file in $files) { Copy-Item -LiteralPath $file.Staged -Destination $file.Original -Force }
}
catch {
    Write-Host "Code signing failed: $_"
    exit 1
}
finally {
    foreach ($file in $files) { Remove-Item -LiteralPath $file.Staged -Force -ErrorAction SilentlyContinue }
}
