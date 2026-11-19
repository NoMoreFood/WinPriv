Set-StrictMode -Version 2.0

$script:ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$script:CapabilityResults = [Collections.Generic.List[object]]::new()
$script:TestHostProbeCache = @{}

function Initialize-WinPrivSupportType {
    param([Parameter(Mandatory = $true)][string]$TypeName, [Parameter(Mandatory = $true)][string]$FileName)
    if ($TypeName -as [type]) { return }
    $source = [IO.Path]::GetFullPath((Join-Path $script:ModuleRoot "..\..\Support\$FileName"))
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Required support source is missing: '$source'." }
    Add-Type -Path $source -ErrorAction Stop
}

function Test-WinPrivPathWithin {
    param([Parameter(Mandatory = $true)][string]$Child, [Parameter(Mandatory = $true)][string]$Parent)
    $childPath = [IO.Path]::GetFullPath($Child)
    $parentPath = [IO.Path]::GetFullPath($Parent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    return $childPath.Equals($parentPath, [StringComparison]::OrdinalIgnoreCase) -or
        $childPath.StartsWith($parentPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Write-WinPrivJson {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Value, [int]$Depth = 40)
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Path))
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth $Depth), $script:Utf8NoBom)
}

function Write-WinPrivJsonLine {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Value)
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Path))
    $json = $Value | ConvertTo-Json -Depth 30 -Compress
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $stream = $null; $writer = $null
        try {
            $stream = New-Object IO.FileStream($Path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            $writer = New-Object IO.StreamWriter($stream, $script:Utf8NoBom)
            $writer.WriteLine($json)
            $writer.Flush()
            return
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw }
            Start-Sleep -Milliseconds 50
        }
        finally {
            if ($null -ne $writer) { $writer.Dispose() }
            elseif ($null -ne $stream) { $stream.Dispose() }
        }
    } while ($true)
}

function Read-WinPrivJsonLines {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    return @(Get-Content -LiteralPath $Path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
}

function Get-WinPrivReparsePoints {
    param([Parameter(Mandatory = $true)][string]$Root, [switch]$IncludeRoot)
    $items = @()
    if ($IncludeRoot) { $items += Get-Item -LiteralPath $Root -Force -ErrorAction Stop }
    $items += @(Get-ChildItem -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue)
    return @($items | Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 })
}

function Get-WinPrivObjectValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) {
        return $(if ($Object.Contains($Name)) { $Object[$Name] } else { $null })
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Assert-WinPrivRunMarker {
    param([Parameter(Mandatory = $true)][string]$Root, [string]$Parent)
    $item = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'The run root is a reparse point.' }
    if (-not [string]::IsNullOrWhiteSpace($Parent) -and -not (Test-WinPrivPathWithin -Child $Root -Parent $Parent)) {
        throw 'The run root is outside the validated suite directory.'
    }
    $markerPath = Join-Path $Root '.winpriv-test-run.json'
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw 'The run ownership marker is missing.' }
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json -ErrorAction Stop
    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$marker.MarkerId, [ref]$guid) -or
        [IO.Path]::GetFullPath([string]$marker.Root) -ne $Root -or
        [string]$marker.RunId -ne (Split-Path -Leaf $Root)) {
        throw 'The run marker identity does not match its directory.'
    }
    return $marker
}

function Assert-WinPrivSandboxMarker {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$Parent,
        [string]$ExpectedMarkerId,
        [switch]$MatchDirectoryName
    )
    $item = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to access reparse-point sandbox '$Root'."
    }
    if (-not [string]::IsNullOrWhiteSpace($Parent) -and -not (Test-WinPrivPathWithin -Child $Root -Parent $Parent)) {
        throw "Sandbox '$Root' is outside '$Parent'."
    }
    $markerPath = Join-Path $Root '.winpriv-test-sandbox.json'
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        throw "Sandbox ownership marker is missing in '$Root'."
    }
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json -ErrorAction Stop
    $markerGuid = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$marker.MarkerId, [ref]$markerGuid) -or
        [IO.Path]::GetFullPath([string]$marker.Root) -ne $Root -or
        (-not [string]::IsNullOrWhiteSpace($ExpectedMarkerId) -and [string]$marker.MarkerId -ne $ExpectedMarkerId)) {
        throw "Sandbox marker identity does not match '$Root'."
    }
    if ($MatchDirectoryName) {
        $directoryGuid = [Guid]::Empty
        if (-not [Guid]::TryParse((Split-Path -Leaf $Root), [ref]$directoryGuid) -or $markerGuid -ne $directoryGuid) {
            throw "Sandbox directory name does not match its marker GUID in '$Root'."
        }
    }
    return $marker
}

function Get-WinPrivPeArchitecture {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $stream = $null; $reader = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { return $null }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or $peOffset -gt ($stream.Length - 6)) { return $null }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { return $null }
        switch ($reader.ReadUInt16()) {
            0x014C { return 'x86' }
            0x8664 { return 'x64' }
            0xAA64 { return 'ARM64' }
            default { return 'Unknown' }
        }
    }
    catch { return $null }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-WinPrivOsArchitecture {
    $architecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')
    }
    switch -Regex ($architecture) {
        'ARM64' { return 'ARM64' }
        'AMD64|x64' { return 'x64' }
        default { return 'x86' }
    }
}

function Get-WinPrivArchitectureDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryRoot,
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture
    )
    $root = [IO.Path]::GetFullPath($BinaryRoot)
    $child = Join-Path $root $Architecture
    if (Test-Path -LiteralPath $child -PathType Container) { return $child }
    if ((Split-Path -Leaf $root) -ieq $Architecture -and (Test-Path -LiteralPath $root -PathType Container)) { return $root }
    return $null
}

function ConvertFrom-WinPrivProbeOutput {
    param([string]$Text, [string]$Marker)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if ([string]::IsNullOrWhiteSpace($Marker)) {
        try { return $Text | ConvertFrom-Json -ErrorAction Stop } catch { }
    }
    $lines = @($Text -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    for ($index = $lines.Count - 1; $index -ge 0; $index--) {
        try {
            $parsed = $lines[$index] | ConvertFrom-Json -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($Marker) -or [string]$parsed.Marker -ceq $Marker) { return $parsed }
        }
        catch { }
    }
    return $null
}

function Test-WinPrivPowerShellHost {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture
    )

    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    $resolvedPath = $file.FullName
    $cacheKey = '{0}|{1}|{2}|{3}' -f $Architecture, $resolvedPath.ToUpperInvariant(), $file.Length, $file.LastWriteTimeUtc.Ticks
    if ($script:TestHostProbeCache.ContainsKey($cacheKey)) { return $script:TestHostProbeCache[$cacheKey] }

    $marker = 'WINPRIV_HOST_' + [Guid]::NewGuid().ToString('N')
    $probeScript = @'
$ErrorActionPreference = 'Stop'
try { $processArchitecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() }
catch {
    $processArchitecture = if ([IntPtr]::Size -eq 4) { 'X86' } else { [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') }
}
[pscustomobject]@{
    Marker = '__WINPRIV_HOST_MARKER__'
    PSEdition = [string]$PSVersionTable.PSEdition
    PSVersion = $PSVersionTable.PSVersion.ToString()
    ProcessArchitecture = $processArchitecture
    ExecutablePath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    ProcessId = $PID
} | ConvertTo-Json -Compress
'@.Replace('__WINPRIV_HOST_MARKER__', $marker)

    $invocation = $null; $state = $null; $reason = $null
    try {
        $invocation = Invoke-WinPrivContainedProcess -FilePath $resolvedPath -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', $probeScript
        ) -WorkingDirectory ([IO.Path]::GetTempPath()) -TimeoutSeconds 30
        if ($invocation.TimedOut) { $reason = "Host '$resolvedPath' did not complete the PowerShell identity probe within 30 seconds." }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$invocation.StartError)) { $reason = "Host '$resolvedPath' could not execute the PowerShell identity probe: $($invocation.StartError)" }
        elseif ($invocation.ExitCode -ne 0) { $reason = "Host '$resolvedPath' returned exit code $($invocation.ExitCode) from the PowerShell identity probe." }
        else {
            $state = ConvertFrom-WinPrivProbeOutput -Text ([string]$invocation.StdOut) -Marker $marker
            if ($null -eq $state) { $reason = "Host '$resolvedPath' did not emit a valid PowerShell identity record." }
        }
    }
    catch { $reason = "Host '$resolvedPath' could not execute the PowerShell identity probe: $($_.Exception.Message)" }

    $version = $null; $edition = $null; $processArchitecture = $null; $reportedExecutable = $null
    if ($null -ne $state) {
        $edition = [string]$state.PSEdition
        try { $version = [version]([string]$state.PSVersion) } catch { }
        $processArchitecture = switch (([string]$state.ProcessArchitecture).ToUpperInvariant()) {
            'X86' { 'x86' }; 'X64' { 'x64' }; 'ARM64' { 'ARM64' }
        }
        try { $reportedExecutable = [IO.Path]::GetFullPath([string]$state.ExecutablePath) } catch { }
        if ($processArchitecture -ne $Architecture) {
            $reason = "Host '$resolvedPath' reported process architecture '$processArchitecture', not '$Architecture'."
        }
        elseif ([string]::IsNullOrWhiteSpace($reportedExecutable) -or -not $reportedExecutable.Equals($resolvedPath, [StringComparison]::OrdinalIgnoreCase)) {
            $reason = "Host '$resolvedPath' executed PowerShell from '$reportedExecutable' instead of the candidate executable."
        }
        elseif ($Architecture -eq 'x86' -and ($edition -ne 'Desktop' -or $null -eq $version -or $version.Major -ne 5 -or $version.Minor -ne 1)) {
            $reason = "Host '$resolvedPath' reported PowerShell edition '$edition' version '$version'; x86 probes require Windows PowerShell exactly 5.1."
        }
        elseif ($Architecture -ne 'x86' -and ($edition -ne 'Core' -or $null -eq $version -or $version -lt [version]'7.6')) {
            $reason = "Host '$resolvedPath' reported PowerShell edition '$edition' version '$version'; $Architecture probes require PowerShell Core 7.6 or later."
        }
    }

    $result = [pscustomobject]@{
        Valid = $null -ne $state -and [string]::IsNullOrWhiteSpace($reason); Reason = $reason
        Version = $version; PSEdition = $edition; ProcessArchitecture = $processArchitecture
        ExecutablePath = $reportedExecutable; ProbeProcessId = if ($null -ne $state) { $state.ProcessId } else { $null }
        Invocation = $invocation
    }
    $script:TestHostProbeCache[$cacheKey] = $result
    return $result
}

function Get-WinPrivTestHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture,
        [switch]$Detailed
    )

    $path = $null; $reason = $null; $validation = $null
    $overrideName = 'WINPRIV_TEST_POWERSHELL_' + $Architecture.ToUpperInvariant()
    $override = [Environment]::GetEnvironmentVariable($overrideName)
    if ([string]::IsNullOrWhiteSpace($override)) {
        $override = [Environment]::GetEnvironmentVariable('WINPRIV_TEST_HOST_' + $Architecture.ToUpperInvariant())
    }

    if (-not [string]::IsNullOrWhiteSpace($override)) { $path = $override }
    elseif ($Architecture -eq 'x86') {
        $systemDirectory = if ((Get-WinPrivOsArchitecture) -eq 'x86') { 'System32' } else { 'SysWOW64' }
        $path = Join-Path ([Environment]::GetEnvironmentVariable('WINDIR')) "$systemDirectory\WindowsPowerShell\v1.0\powershell.exe"
    }
    else {
        $currentPath = $null
        try { $currentPath = (Get-Process -Id $PID -ErrorAction Stop).Path } catch { }
        if ($currentPath -and (Get-WinPrivPeArchitecture -Path $currentPath) -eq $Architecture) { $path = $currentPath }
        else {
            $programRoots = @(
                [Environment]::GetEnvironmentVariable('ProgramW6432'),
                [Environment]::GetEnvironmentVariable('ProgramFiles')
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            foreach ($programRoot in $programRoots) {
                $candidate = Join-Path $programRoot 'PowerShell\7\pwsh.exe'
                if ((Test-Path -LiteralPath $candidate -PathType Leaf) -and (Get-WinPrivPeArchitecture -Path $candidate) -eq $Architecture) {
                    $path = $candidate; break
                }
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $reason = "No $Architecture PowerShell host was found. Set $overrideName to override discovery."
        $path = $null
    }
    else {
        try { $path = (Get-Item -LiteralPath $path -ErrorAction Stop).FullName } catch { }
        $actualArchitecture = Get-WinPrivPeArchitecture -Path $path
        if ($actualArchitecture -ne $Architecture) {
            $reason = "Host '$path' is $actualArchitecture, not $Architecture."
            $path = $null
        }
        else {
            try {
                $validation = Test-WinPrivPowerShellHost -Path $path -Architecture $Architecture
                if (-not $validation.Valid) { $reason = $validation.Reason; $path = $null }
            }
            catch {
                $reason = "Host '$path' could not be validated as PowerShell: $($_.Exception.Message)"
                $path = $null
            }
        }
    }

    $result = [pscustomobject]@{
        Architecture        = $Architecture
        Path                = $path
        Version             = if ($null -ne $validation) { $validation.Version } else { $null }
        PSEdition           = if ($null -ne $validation) { $validation.PSEdition } else { $null }
        ProcessArchitecture = if ($null -ne $validation) { $validation.ProcessArchitecture } else { $null }
        ProbeProcessId      = if ($null -ne $validation) { $validation.ProbeProcessId } else { $null }
        Available           = $null -ne $path
        Reason              = $reason
    }
    if ($Detailed) { return $result }
    return $result.Path
}

function Get-WinPrivTestArchitectures {
    [CmdletBinding()]
    param(
        [ValidateSet('Auto', 'x86', 'x64', 'ARM64')][string[]]$Requested = @('Auto'),
        [string]$BinaryRoot = $env:WINPRIV_TEST_BINARY_ROOT,
        [switch]$Detailed
    )

    if (-not $PSBoundParameters.ContainsKey('Requested') -and -not [string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_ARCHITECTURES)) {
        $Requested = @($env:WINPRIV_TEST_ARCHITECTURES -split '[,;]' | Where-Object { $_ })
    }
    if ($Requested.Count -gt 1 -and ($Requested -contains 'Auto')) {
        throw "Architecture 'Auto' cannot be combined with an explicit architecture."
    }
    $requestedArchitectures = if ($Requested -contains 'Auto') { @('x86', 'x64', 'ARM64') } else { @($Requested | Select-Object -Unique) }
    $osArchitecture = Get-WinPrivOsArchitecture
    $details = [Collections.Generic.List[object]]::new()

    foreach ($item in $requestedArchitectures) {
        $osCompatible = switch ($item) {
            'x86' { $true }; 'x64' { $osArchitecture -in @('x64', 'ARM64') }; 'ARM64' { $osArchitecture -eq 'ARM64' }
        }
        $reasons = [Collections.Generic.List[string]]::new()
        if (-not $osCompatible) { [void]$reasons.Add("$item processes cannot run on $osArchitecture Windows.") }
        $hostInfo = Get-WinPrivTestHost -Architecture $item -Detailed
        if (-not $hostInfo.Available) { [void]$reasons.Add($hostInfo.Reason) }

        $binaryDirectory = $null; $binariesAvailable = $true
        if (-not [string]::IsNullOrWhiteSpace($BinaryRoot)) {
            $binaryDirectory = Get-WinPrivArchitectureDirectory -BinaryRoot $BinaryRoot -Architecture $item
            $binariesAvailable = $null -ne $binaryDirectory -and
                (Test-Path -LiteralPath (Join-Path $binaryDirectory 'WinPriv.exe') -PathType Leaf) -and
                (Test-Path -LiteralPath (Join-Path $binaryDirectory 'WinPrivCmd.exe') -PathType Leaf)
            if (-not $binariesAvailable) { [void]$reasons.Add("WinPriv.exe and WinPrivCmd.exe were not found for $item under '$BinaryRoot'.") }
        }

        [void]$details.Add([pscustomobject]@{
            Architecture = $item; OsArchitecture = $osArchitecture
            Compatible = $osCompatible -and $hostInfo.Available -and $binariesAvailable
            Host = $hostInfo.Path; HostVersion = $hostInfo.Version; HostEdition = $hostInfo.PSEdition
            HostProcessArchitecture = $hostInfo.ProcessArchitecture; HostProbeProcessId = $hostInfo.ProbeProcessId
            BinaryDirectory = $binaryDirectory; Reason = ($reasons -join ' ')
        })
    }

    if ($Detailed) { return $details.ToArray() }
    return @($details | Where-Object Compatible | ForEach-Object Architecture)
}

function New-WinPrivSandbox {
    [CmdletBinding()]
    param([ValidateSet('x86', 'x64', 'ARM64')][string[]]$Architecture, [string]$Purpose = 'test')

    $binaryRoot = $env:WINPRIV_TEST_BINARY_ROOT
    if ([string]::IsNullOrWhiteSpace($binaryRoot)) { throw 'WINPRIV_TEST_BINARY_ROOT is not set.' }
    if ($null -eq $Architecture -or $Architecture.Count -eq 0) {
        $Architecture = @($env:WINPRIV_TEST_ARCHITECTURES -split '[,;]' | Where-Object { $_ })
    }
    if ($Architecture.Count -eq 0) { throw 'No sandbox architecture was selected.' }

    $markerId = [Guid]::NewGuid().ToString('D')
    $runRoot = $env:WINPRIV_TEST_RUN_ROOT
    $root = if ([string]::IsNullOrWhiteSpace($runRoot)) {
        [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) "WinPrivSandbox-$markerId"))
    } else {
        [IO.Path]::GetFullPath((Join-Path (Join-Path $runRoot 'sandboxes') $markerId))
    }
    if (-not [string]::IsNullOrWhiteSpace($runRoot) -and -not (Test-WinPrivPathWithin -Child $root -Parent $runRoot)) {
        throw "Sandbox root '$root' is outside WINPRIV_TEST_RUN_ROOT '$runRoot'."
    }
    if (Test-Path -LiteralPath $root) { throw "Sandbox path already exists: '$root'." }

    $dirs = @{
        Temp = Join-Path $root 'temp'; Working = Join-Path $root 'work'
        Artifacts = Join-Path $root 'artifacts'; Logs = Join-Path $root 'logs'; Bin = Join-Path $root 'bin'
    }
    foreach ($directory in @($root) + @($dirs.Values)) { [void][IO.Directory]::CreateDirectory($directory) }

    $launchers = [ordered]@{}
    try {
        $nativeFixtureRoot = $env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT
        foreach ($item in ($Architecture | Select-Object -Unique)) {
            $sourceDirectory = Get-WinPrivArchitectureDirectory -BinaryRoot $binaryRoot -Architecture $item
            if ($null -eq $sourceDirectory) { throw "No $item binary directory exists under '$binaryRoot'." }
            foreach ($required in @('WinPriv.exe', 'WinPrivCmd.exe')) {
                if (-not (Test-Path -LiteralPath (Join-Path $sourceDirectory $required) -PathType Leaf)) {
                    throw "Required $item launcher '$required' is missing from '$sourceDirectory'."
                }
            }
            $destinationDirectory = Join-Path $dirs.Bin $item
            [void][IO.Directory]::CreateDirectory($destinationDirectory)
            Get-ChildItem -LiteralPath $sourceDirectory -File | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $destinationDirectory -Force
            }
            if (-not [string]::IsNullOrWhiteSpace($nativeFixtureRoot)) {
                $nativeFixtureDirectory = Join-Path ([IO.Path]::GetFullPath($nativeFixtureRoot)) $item
                foreach ($fixture in @('WinPrivHookImport.exe', 'WinPrivHookDelayLoad.exe', 'WinPrivHookDynamic.exe')) {
                    $fixturePath = Join-Path $nativeFixtureDirectory $fixture
                    if (Test-Path -LiteralPath $fixturePath -PathType Leaf) {
                        Copy-Item -LiteralPath $fixturePath -Destination $destinationDirectory -Force
                    }
                }
            }
            $launchers[$item] = [pscustomobject]@{
                Root = $destinationDirectory; WinPriv = Join-Path $destinationDirectory 'WinPriv.exe'
                WinPrivCmd = Join-Path $destinationDirectory 'WinPrivCmd.exe'
                Library = Join-Path $destinationDirectory 'WinPrivLibrary.dll'
            }
        }

        $markerPath = Join-Path $root '.winpriv-test-sandbox.json'
        Write-WinPrivJson -Path $markerPath -Depth 5 -Value ([ordered]@{
            SchemaVersion = 1; MarkerId = $markerId; Root = $root
            Purpose = $Purpose; CreatedUtc = [DateTime]::UtcNow.ToString('o'); ProcessId = $PID
        })
        return [pscustomobject]@{
            MarkerId = $markerId; Root = $root; Temp = $dirs.Temp; Working = $dirs.Working
            Artifacts = $dirs.Artifacts; Logs = $dirs.Logs; Bin = $dirs.Bin; MarkerPath = $markerPath
            Journal = Join-Path $root 'cleanup-journal.jsonl'; Launchers = [pscustomobject]$launchers; Purpose = $Purpose
        }
    }
    catch {
        if (Test-Path -LiteralPath $root -PathType Container) {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Write-WinPrivCleanupResult {
    param($Result)
    if (-not [string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_CLEANUP_EVENTS_PATH)) {
        Write-WinPrivJsonLine -Path $env:WINPRIV_TEST_CLEANUP_EVENTS_PATH -Value $Result
    }
}

function Remove-WinPrivSandbox {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Sandbox, [switch]$Force)
    $root = [IO.Path]::GetFullPath([string]$Sandbox.Root)
    [void](Assert-WinPrivSandboxMarker -Root $root -Parent $env:WINPRIV_TEST_RUN_ROOT -ExpectedMarkerId ([string]$Sandbox.MarkerId))
    Repair-WinPrivSandboxJournal -Sandbox $Sandbox | Out-Null

    if (-not $Force -and ($env:WINPRIV_TEST_KEEP_ARTIFACTS -eq '1' -or $env:WINPRIV_TEST_DEFER_SANDBOX_CLEANUP -eq '1')) {
        $keep = $env:WINPRIV_TEST_KEEP_ARTIFACTS -eq '1'
        $result = [pscustomobject]@{
            MarkerId = $Sandbox.MarkerId; Path = $root
            Status = if ($keep) { 'Preserved' } else { 'Deferred' }
            Reason = if ($keep) { 'KeepArtifacts was requested.' } else { 'The runner defers sandbox deletion until the final test outcome is known.' }
            TimestampUtc = [DateTime]::UtcNow.ToString('o')
        }
        Write-WinPrivCleanupResult -Result $result
        return $result
    }

    # Process images and filesystem filters can retain files briefly after process exit.
    $deleteDeadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $errorText = $null
        try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        catch { $errorText = $_.Exception.Message }
        $residual = Test-Path -LiteralPath $root
        if ($residual) { Start-Sleep -Milliseconds 50 }
    } while ($residual -and [DateTime]::UtcNow -lt $deleteDeadline)
    $result = [pscustomobject]@{
        MarkerId = $Sandbox.MarkerId; Path = $root; Status = if ($residual) { 'Residual' } else { 'Clean' }
        Reason = $errorText; TimestampUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-WinPrivCleanupResult -Result $result
    if ($residual) { throw "Sandbox cleanup left residual state at '$root': $errorText" }
    return $result
}

function Add-WinPrivCleanupJournalEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Sandbox,
        [Parameter(Mandatory = $true)][ValidateSet('Process', 'Acl', 'LocalPrincipalIntent', 'LocalPrincipal', 'LsaRight', 'Registry')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Identifier,
        $OriginalState,
        [hashtable]$Metadata
    )
    $entry = [pscustomobject]@{
        SchemaVersion = 1; EntryId = [Guid]::NewGuid().ToString('D'); MarkerId = $Sandbox.MarkerId
        Kind = $Kind; Identifier = $Identifier; OriginalState = $OriginalState
        Metadata = $Metadata; CreatedUtc = [DateTime]::UtcNow.ToString('o'); ProcessId = $PID
    }
    Write-WinPrivJsonLine -Path $Sandbox.Journal -Value $entry
    return $entry
}

function Get-WinPrivLocalPrincipalIdentity {
    param([string]$MachineName, [string]$Name, [ValidateSet('user', 'group')][string]$Type)
    $path = "WinNT://$MachineName/$Name,$Type"
    try { $exists = [DirectoryServices.DirectoryEntry]::Exists($path) }
    catch {
        $current = $_.Exception; $code = $null
        while ($null -ne $current) {
            if ($current -is [ComponentModel.Win32Exception]) { $code = [int]$current.NativeErrorCode; break }
            if ($current -is [Runtime.InteropServices.COMException]) { $code = ([int]$current.ErrorCode -band 0xFFFF); break }
            $current = $current.InnerException
        }
        if ($code -in @(2220, 2221)) { return [pscustomobject]@{ Exists = $false; Sid = $null; Description = $null; Path = $path } }
        throw
    }
    if (-not $exists) { return [pscustomobject]@{ Exists = $false; Sid = $null; Description = $null; Path = $path } }

    $principal = [ADSI]$path
    try {
        $sidBytes = [byte[]]$principal.Properties['objectSid'].Value
        if ($null -eq $sidBytes -or $sidBytes.Count -eq 0) { throw "The existing local $Type '$Name' has no readable object SID." }
        return [pscustomobject]@{
            Exists = $true; Sid = [Security.Principal.SecurityIdentifier]::new($sidBytes, 0).Value
            Description = [string]$principal.Properties['Description'].Value; Path = $path
        }
    }
    finally { [void]$principal.Close() }
}

function Remove-WinPrivUserProfileBySid {
    param([string]$Sid, [string]$ExpectedName)
    try { $canonicalSid = [Security.Principal.SecurityIdentifier]::new($Sid).Value }
    catch { throw "Invalid profile SID '$Sid'." }
    if ($ExpectedName -notmatch '^WPTU[0-9A-Fa-f]{12}$') { throw "Invalid fixture profile name '$ExpectedName'." }
    $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$canonicalSid"
    if (-not (Test-Path -LiteralPath $profileKey)) { return $false }
    $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$canonicalSid'" -ErrorAction Stop
    if ($null -eq $profile) { throw "A profile registry entry exists for '$canonicalSid', but Win32_UserProfile did not return it." }
    $profileLeaf = Split-Path -Leaf ([string]$profile.LocalPath)
    if ($profile.Special -or ($profileLeaf -ne $ExpectedName -and -not $profileLeaf.StartsWith("$ExpectedName.", [StringComparison]::OrdinalIgnoreCase))) {
        throw "The profile for '$canonicalSid' is special or its path does not match the fixture name."
    }
    if ($profile.Loaded) { throw "The fixture profile for '$canonicalSid' is still loaded." }
    [void](Remove-CimInstance -InputObject $profile -ErrorAction Stop)
    return $true
}

function Repair-WinPrivSandboxJournal {
    param([Parameter(Mandatory = $true)]$Sandbox, [switch]$AllowRecovery, [switch]$NoThrow)

    $entries = @(Read-WinPrivJsonLines -Path ([string]$Sandbox.Journal))
    if ($entries.Count -eq 0) { return }
    $root = [IO.Path]::GetFullPath([string]$Sandbox.Root)
    $deltas = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[object]]::new()

    $reparsePoints = @(Get-WinPrivReparsePoints -Root $root -IncludeRoot)
    if ($reparsePoints.Count -gt 0) {
        [void]$errors.Add([pscustomobject]@{
            Kind = 'ReparsePoint'; Identifier = ($reparsePoints.FullName -join '; ')
            Reason = 'Journal repair was refused because the sandbox contains a reparse point.'
        })
        $entries = @()
    }
    foreach ($entry in $entries) {
        $entryId = [Guid]::Empty
        if (-not [Guid]::TryParse([string]$entry.EntryId, [ref]$entryId) -or [string]$entry.MarkerId -ne [string]$Sandbox.MarkerId) {
            [void]$errors.Add([pscustomobject]@{ Kind = 'Journal'; Identifier = [string]$entry.EntryId; Reason = 'The journal entry GUID or sandbox marker does not match.' })
        }
    }
    if (@($errors | Where-Object Kind -eq 'Journal').Count -gt 0) { $entries = @() }

    foreach ($entry in @($entries | Where-Object Kind -eq 'Process')) {
        $processId = [int](Get-WinPrivObjectValue $entry.Metadata 'ProcessId')
        if ($processId -le 0) { [void][int]::TryParse([string]$entry.Identifier, [ref]$processId) }
        $path = [string](Get-WinPrivObjectValue $entry.Metadata 'Path')
        $started = [string](Get-WinPrivObjectValue $entry.Metadata 'StartTimeUtc')
        if ($processId -le 0 -or [string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($started)) {
            [void]$errors.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $entry.Identifier; Reason = 'PID, image path, and start time are required.' })
            continue
        }
        if (Test-WinPrivProcessIdentity -ProcessId $processId -ExpectedPath $path -ExpectedStartUtc $started) {
            try {
                Stop-Process -Id $processId -Force -ErrorAction Stop
                [void]$deltas.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $processId; Action = 'TerminatedRecordedProcess' })
            }
            catch { [void]$errors.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $processId; Reason = $_.Exception.Message }) }
        }
    }

    foreach ($entry in @($entries | Where-Object Kind -eq 'Registry')) {
        $path = [string]$entry.Identifier
        $originalExisted = [bool](Get-WinPrivObjectValue $entry.OriginalState 'Existed')
        $allowed = $path -match '^Registry::HKEY_CURRENT_USER\\Software\\WinPrivTests\\Case[0-9A-Fa-f]{32}(Sibling)?$' -or
            $path -match '^Registry::HKEY_CURRENT_USER\\Software\\Policies\\WinPrivTests\\[0-9A-Fa-f]{32}$'
        if ($originalExisted -or -not $allowed) {
            [void]$errors.Add([pscustomobject]@{ Kind = 'Registry'; Identifier = $path; Reason = 'Only absent-before-test GUID HKCU fixture keys can be reconciled automatically.' })
            continue
        }
        if (Test-Path -LiteralPath $path) {
            try {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                [void]$deltas.Add([pscustomobject]@{ Kind = 'Registry'; Identifier = $path; Action = 'RemovedFixtureKey' })
            }
            catch { [void]$errors.Add([pscustomobject]@{ Kind = 'Registry'; Identifier = $path; Reason = $_.Exception.Message }) }
        }
    }

    foreach ($entry in @($entries | Where-Object Kind -eq 'Acl')) {
        $path = [IO.Path]::GetFullPath([string]$entry.Identifier)
        $sddl = [string](Get-WinPrivObjectValue $entry.OriginalState 'Sddl')
        if (-not (Test-WinPrivPathWithin -Child $path -Parent $root) -or [string]::IsNullOrWhiteSpace($sddl)) {
            [void]$errors.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Reason = 'ACL path is outside the sandbox or original SDDL is missing.' })
            continue
        }
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            if ($acl.Sddl -ne $sddl) {
                $acl.SetSecurityDescriptorSddlForm($sddl)
                Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
                [void]$deltas.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Action = 'RestoredSddl' })
            }
            $expectedContent = [string](Get-WinPrivObjectValue $entry.Metadata 'ContentBase64')
            if (-not [string]::IsNullOrWhiteSpace($expectedContent) -and
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne [string](Get-WinPrivObjectValue $entry.Metadata 'ContentSha256')) {
                [IO.File]::WriteAllBytes($path, [Convert]::FromBase64String($expectedContent))
                [void]$deltas.Add([pscustomobject]@{ Kind = 'Path'; Identifier = $path; Action = 'RestoredContent' })
            }
        }
        catch { [void]$errors.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Reason = $_.Exception.Message }) }
    }

    $lsaEntries = @($entries | Where-Object Kind -eq 'LsaRight')
    if ($lsaEntries.Count -gt 0) {
        try { Initialize-WinPrivSupportType 'WinPrivTests.LsaPolicy' 'WinPriv.LsaPolicy.cs' }
        catch { [void]$errors.Add([pscustomobject]@{ Kind = 'LsaRight'; Identifier = 'Add-Type'; Reason = $_.Exception.Message }) }
    }
    if ('WinPrivTests.LsaPolicy' -as [type]) {
        foreach ($entry in $lsaEntries) {
            try {
                if ([string]$entry.Identifier -eq 'global-deny-rights-snapshot') {
                    $assignments = @((Get-WinPrivObjectValue $entry.OriginalState 'Assignments'))
                    $rights = @($assignments | ForEach-Object { [string]$_.Right }) + @((Get-WinPrivObjectValue $entry.OriginalState 'Rights'))
                    foreach ($right in @($rights | Where-Object { $_ } | Sort-Object -Unique)) {
                        $desired = [string[]]@($assignments | Where-Object Right -eq $right | ForEach-Object { [string]$_.Account })
                        if ([WinPrivTests.LsaPolicy]::SetAccountsWithRight($right, $desired)) {
                            [void]$deltas.Add([pscustomobject]@{ Kind = 'LsaRight'; Identifier = $right; Action = 'RestoredGlobalAssignments' })
                        }
                    }
                    continue
                }
                $sid = [string](Get-WinPrivObjectValue $entry.Metadata 'Sid')
                $name = [string](Get-WinPrivObjectValue $entry.Metadata 'PrincipalName')
                if ($sid -notmatch '^S-1-' -or $name -notmatch '^WPT[GU][0-9A-Fa-f]{12}$' -or
                    -not ([string]$entry.Identifier).EndsWith("\$name", [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'The fixture SID/name/account marker is incomplete or invalid.'
                }
                $desired = [string[]]@((Get-WinPrivObjectValue $entry.OriginalState 'Rights') | Where-Object { $null -ne $_ })
                if ([WinPrivTests.LsaPolicy]::SetRights($sid, $desired)) {
                    [void]$deltas.Add([pscustomobject]@{ Kind = 'LsaRight'; Identifier = $sid; Action = 'RestoredAccountRights' })
                }
            }
            catch { [void]$errors.Add([pscustomobject]@{ Kind = 'LsaRight'; Identifier = $entry.Identifier; Reason = $_.Exception.Message }) }
        }
    }

    $lsaRepairFailed = @($errors | Where-Object Kind -eq 'LsaRight').Count -gt 0
    $completedPrincipals = @($entries | Where-Object Kind -eq 'LocalPrincipal')
    $completedNames = @($completedPrincipals | ForEach-Object { [string]$_.Identifier })
    $principalEntries = $completedPrincipals + @($entries | Where-Object {
        $_.Kind -eq 'LocalPrincipalIntent' -and [string]$_.Identifier -notin $completedNames
    })
    foreach ($entry in $principalEntries) {
        $isIntent = $entry.Kind -eq 'LocalPrincipalIntent'
        $name = [string]$entry.Identifier
        $type = [string](Get-WinPrivObjectValue $entry.Metadata 'Type')
        $description = [string](Get-WinPrivObjectValue $entry.Metadata 'Description')
        $machineName = [string](Get-WinPrivObjectValue $entry.Metadata 'MachineName')
        if (-not $isIntent -and [string]::IsNullOrWhiteSpace($machineName)) { $machineName = [Environment]::MachineName }
        $expectedPrefix = if ($type -eq 'group') { 'WPTG' } elseif ($type -eq 'user') { 'WPTU' } else { $null }
        $sid = $null
        if ($isIntent) {
            $existedValue = Get-WinPrivObjectValue $entry.OriginalState 'Existed'
            $valid = ($existedValue -is [bool]) -and (-not [bool]$existedValue)
        } else {
            try { $sid = [Security.Principal.SecurityIdentifier]::new([string](Get-WinPrivObjectValue $entry.Metadata 'Sid')).Value } catch { }
            $valid = -not [string]::IsNullOrWhiteSpace($sid)
        }
        if (-not $valid -or $null -eq $expectedPrefix -or $name -notmatch "^$expectedPrefix[0-9A-Fa-f]{12}$" -or
            $machineName -ne [Environment]::MachineName -or $description -cne "WinPriv test fixture $name") {
            [void]$errors.Add([pscustomobject]@{ Kind = $entry.Kind; Identifier = $name; Reason = 'Machine, name/type pairing, marker evidence, or exact description is invalid.' })
            continue
        }
        if (-not $isIntent -and $lsaRepairFailed -and $lsaEntries.Count -gt 0) {
            [void]$errors.Add([pscustomobject]@{ Kind = 'LocalPrincipal'; Identifier = $name; Reason = 'The fixture principal was retained because its LSA-right restoration did not complete.' })
            continue
        }
        try {
            $identity = Get-WinPrivLocalPrincipalIdentity -MachineName $machineName -Name $name -Type $type
            if (-not $identity.Exists) {
                $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
                if (-not $isIntent -and $type -eq 'user' -and (Test-Path -LiteralPath $profileKey)) {
                    throw 'The fixture principal is absent but a profile remains; automatic removal was refused without live SID/description verification.'
                }
                continue
            }
            if ($identity.Description -cne $description -or (-not $isIntent -and $identity.Sid -ne $sid)) {
                throw 'The current principal SID or description does not match the fixture marker.'
            }
            if (-not $isIntent -and $type -eq 'user' -and (Remove-WinPrivUserProfileBySid -Sid $sid -ExpectedName $name)) {
                [void]$deltas.Add([pscustomobject]@{ Kind = 'LocalPrincipal'; Identifier = $name; Action = 'RemovedFixtureProfile'; Sid = $sid })
            }
            $computer = [ADSI]"WinNT://$machineName,computer"
            [void]$computer.Delete($type, $name)
            [void]$deltas.Add([pscustomobject]@{
                Kind = $entry.Kind; Identifier = $name
                Action = if ($isIntent) { 'RemovedIncompleteFixturePrincipal' } else { 'RemovedFixturePrincipal' }
                Sid = if ($isIntent) { $identity.Sid } else { $sid }
            })
        }
        catch { [void]$errors.Add([pscustomobject]@{ Kind = $entry.Kind; Identifier = $name; Reason = $_.Exception.Message }) }
    }

    foreach ($entry in @($entries | Where-Object { $_.Kind -notin @('Process', 'Registry', 'Acl', 'LsaRight', 'LocalPrincipal', 'LocalPrincipalIntent') })) {
        [void]$errors.Add([pscustomobject]@{ Kind = [string]$entry.Kind; Identifier = [string]$entry.Identifier; Reason = 'This journal kind has no conservative automatic reconciliation handler.' })
    }

    $status = if ($errors.Count -gt 0) { 'RepairFailed' } elseif ($deltas.Count -gt 0) { 'RecoveredUnexpectedDelta' } else { 'JournalVerified' }
    $result = [pscustomobject]@{
        MarkerId = $Sandbox.MarkerId; Path = $root; Status = $status
        Reason = if ($status -eq 'JournalVerified') { 'All journaled external state matched its baseline.' } else { 'Journal reconciliation detected unexpected test state.' }
        Deltas = $deltas.ToArray(); Errors = $errors.ToArray(); TimestampUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-WinPrivCleanupResult -Result $result
    if (-not ($AllowRecovery -or $NoThrow) -and $errors.Count -gt 0) {
        throw "Sandbox journal reconciliation failed for '$root': $(($errors | ForEach-Object { "$($_.Kind) $($_.Identifier): $($_.Reason)" }) -join '; ')"
    }
    if (-not ($AllowRecovery -or $NoThrow) -and $deltas.Count -gt 0) {
        throw "Sandbox cleanup recovered $($deltas.Count) unexpected machine-state delta(s); the test is not clean."
    }
    return $result
}

function Invoke-WinPrivCurrentRunReconciliation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RunRoot)

    $root = [IO.Path]::GetFullPath($RunRoot)
    $sandboxes = [Collections.Generic.List[object]]::new()
    $unexpected = [Collections.Generic.List[object]]::new()
    $manual = [Collections.Generic.List[object]]::new()
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        return [pscustomobject][ordered]@{
            SchemaVersion = 1; RunRoot = $root; Status = 'RunRootAbsent'
            Sandboxes = @(); UnexpectedDeltas = @(); ManualRecovery = @(); HasFailures = $false; HasManualRecovery = $false
        }
    }

    try { [void](Assert-WinPrivRunMarker -Root $root) }
    catch { [void]$manual.Add([pscustomobject]@{ Kind = 'RunRoot'; Identifier = $root; Reason = $_.Exception.Message }) }

    $sandboxesRoot = Join-Path $root 'sandboxes'
    if ($manual.Count -eq 0 -and (Test-Path -LiteralPath $sandboxesRoot -PathType Container)) {
        foreach ($directory in Get-ChildItem -LiteralPath $sandboxesRoot -Directory -Force -ErrorAction SilentlyContinue) {
            $sandboxRoot = [IO.Path]::GetFullPath($directory.FullName)
            $record = [ordered]@{ MarkerId = $null; Path = $sandboxRoot; Status = 'Unknown'; Reason = $null; Deltas = @(); Errors = @() }
            try {
                $marker = Assert-WinPrivSandboxMarker -Root $sandboxRoot -Parent $sandboxesRoot -MatchDirectoryName
                $record.MarkerId = [Guid]::Parse([string]$marker.MarkerId).ToString('D')
                $sandbox = [pscustomobject]@{ MarkerId = [string]$marker.MarkerId; Root = $sandboxRoot; Journal = Join-Path $sandboxRoot 'cleanup-journal.jsonl' }
                $repair = Repair-WinPrivSandboxJournal -Sandbox $sandbox -NoThrow
                if ($null -eq $repair) {
                    $record.Status = 'NoExternalStateJournal'
                    $record.Reason = 'The sandbox recorded no external machine-state mutations.'
                } else {
                    $record.Status = [string]$repair.Status; $record.Reason = [string]$repair.Reason
                    $record.Deltas = @($repair.Deltas); $record.Errors = @($repair.Errors)
                    if ($repair.Status -eq 'RecoveredUnexpectedDelta') {
                        foreach ($delta in @($repair.Deltas)) {
                            [void]$unexpected.Add([pscustomobject]@{ MarkerId = $record.MarkerId; Kind = $delta.Kind; Identifier = $delta.Identifier; Action = $delta.Action })
                        }
                    } elseif ($repair.Status -eq 'RepairFailed') {
                        [void]$manual.Add([pscustomobject]@{ Kind = 'Sandbox'; Identifier = $sandboxRoot; Reason = (($repair.Errors | ForEach-Object { "$($_.Kind) $($_.Identifier): $($_.Reason)" }) -join '; ') })
                    }
                }
            }
            catch {
                $record.Status = 'ValidationFailed'; $record.Reason = $_.Exception.Message
                [void]$manual.Add([pscustomobject]@{ Kind = 'Sandbox'; Identifier = $sandboxRoot; Reason = $_.Exception.Message })
            }
            [void]$sandboxes.Add([pscustomobject]$record)
        }
    }

    return [pscustomobject][ordered]@{
        SchemaVersion = 1; RunRoot = $root
        Status = if ($manual.Count -gt 0) { 'ManualRecoveryRequired' } elseif ($unexpected.Count -gt 0) { 'RecoveredUnexpectedDelta' } else { 'Verified' }
        Sandboxes = $sandboxes.ToArray(); UnexpectedDeltas = $unexpected.ToArray(); ManualRecovery = $manual.ToArray()
        HasFailures = $unexpected.Count -gt 0 -or $manual.Count -gt 0; HasManualRecovery = $manual.Count -gt 0
    }
}

function Invoke-WinPrivContainedProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$WorkingDirectory,
        [hashtable]$Environment,
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 30,
        $Sandbox,
        [switch]$CreateHiddenConsole,
        [switch]$CreateNoWindow
    )

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'The WinPriv test harness process helpers require Windows.' }
    $startedUtc = [DateTime]::UtcNow
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $stdout = ''; $stderr = ''; $nativeResult = $null; $startError = $null; $renderedCommandLine = $FilePath
    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $WorkingDirectory = if ($null -ne $Sandbox) { $Sandbox.Working } else { [Environment]::CurrentDirectory }
    }
    [void][IO.Directory]::CreateDirectory($WorkingDirectory)

    # CreateProcessW launches suspended so the process joins its kill-on-close Job Object before executing.
    # For WinPrivCmd, CREATE_NEW_CONSOLE ensures GetConsoleWindow() is non-null despite redirected handles.
    $stem = '{0:yyyyMMddTHHmmssfff}-{1}' -f $startedUtc, ([Guid]::NewGuid().ToString('N'))
    $deleteLogsAfterRead = $null -eq $Sandbox
    $logDirectory = if ($deleteLogsAfterRead) { [IO.Path]::GetTempPath() } else { $Sandbox.Logs }
    $stdoutPath = Join-Path $logDirectory ($stem + '.stdout.log')
    $stderrPath = Join-Path $logDirectory ($stem + '.stderr.log')

    $mergedEnvironment = @{}
    foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) { $mergedEnvironment[[string]$entry.Key] = [string]$entry.Value }
    if ($null -ne $Sandbox) { $mergedEnvironment['TEMP'] = $Sandbox.Temp; $mergedEnvironment['TMP'] = $Sandbox.Temp; $mergedEnvironment['TMPDIR'] = $Sandbox.Temp }
    if ($null -ne $Environment) {
        foreach ($key in $Environment.Keys) {
            if ($null -eq $Environment[$key]) { [void]$mergedEnvironment.Remove([string]$key) }
            else { $mergedEnvironment[[string]$key] = [string]$Environment[$key] }
        }
    }
    $environmentEntries = [string[]]@($mergedEnvironment.GetEnumerator() | Sort-Object Key | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value })

    try {
        Initialize-WinPrivSupportType 'WinPrivTests.ProcessContainment' 'WinPriv.ProcessContainment.cs'
        $renderedCommandLine = [WinPrivTests.ProcessContainment]::JoinCommandLine($FilePath, [string[]]$ArgumentList)
        $nativeResult = [WinPrivTests.ProcessContainment]::RunContainedProcess(
            $FilePath, $renderedCommandLine, $WorkingDirectory, $environmentEntries,
            $stdoutPath, $stderrPath, $TimeoutSeconds * 1000, [bool]$CreateHiddenConsole, [bool]$CreateNoWindow)
    }
    catch { $startError = $_.Exception.Message }
    finally {
        $stopwatch.Stop()
        if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
            try { $stdout = [IO.File]::ReadAllText($stdoutPath) } catch { $stderr += "Unable to read stdout log: $($_.Exception.Message)" }
        }
        if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            try { $stderr += [IO.File]::ReadAllText($stderrPath) } catch { $stderr += "Unable to read stderr log: $($_.Exception.Message)" }
        }
        if ($deleteLogsAfterRead) {
            Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
            $stdoutPath = $null; $stderrPath = $null
        }
    }

    $processId = if ($null -ne $nativeResult) { $nativeResult.ProcessId } else { $null }
    $exitCode = if ($null -ne $nativeResult) { $nativeResult.ExitCode } else { $null }
    $timedOut = $null -ne $nativeResult -and $nativeResult.TimedOut
    $jobAssigned = $null -ne $nativeResult -and $nativeResult.JobAssigned
    $childIds = if ($null -ne $nativeResult) { @($nativeResult.ProcessIds | Where-Object { $_ -ne $processId }) } else { @() }
    $result = [pscustomobject]@{
        FilePath = $FilePath; ArgumentList = @($ArgumentList); CommandLine = $renderedCommandLine
        WorkingDirectory = $WorkingDirectory; ProcessId = $processId; ChildProcessIds = @($childIds)
        ExitCode = $exitCode; TimedOut = $timedOut; StartError = $startError; StdOut = $stdout; StdErr = $stderr
        StdOutPath = $stdoutPath; StdErrPath = $stderrPath; StartedUtc = $startedUtc.ToString('o')
        Duration = $stopwatch.Elapsed; DurationMilliseconds = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
        JobAssigned = $jobAssigned; ContainmentMode = 'JobObject'
        Succeeded = -not $timedOut -and $null -eq $startError -and $exitCode -eq 0
    }
    $eventsPath = [Environment]::GetEnvironmentVariable('WINPRIV_TEST_PROCESS_EVENTS_PATH')
    if (-not [string]::IsNullOrWhiteSpace($eventsPath)) {
        Write-WinPrivJsonLine -Path $eventsPath -Value ([pscustomobject]@{
            SchemaVersion = 1; TimestampUtc = [DateTime]::UtcNow.ToString('o'); FilePath = $FilePath
            WorkingDirectory = $WorkingDirectory; ProcessId = $processId; ChildProcessIds = @($childIds)
            ProcessIds = @((@($processId) + @($childIds)) | Where-Object { $null -ne $_ } | Select-Object -Unique)
            ExitCode = $exitCode; TimedOut = $timedOut; StartError = $startError; JobAssigned = $jobAssigned
            ContainmentMode = 'JobObject'; DurationMilliseconds = $result.DurationMilliseconds
        })
    }
    return $result
}

function Invoke-WinPriv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture,
        [string[]]$Arguments = @(),
        [ValidateSet('WinPrivCmd', 'WinPriv')][string]$Launcher = 'WinPrivCmd',
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $true)]$Sandbox,
        [hashtable]$Environment,
        [string]$WorkingDirectory
    )

    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) { $WorkingDirectory = $Sandbox.Working }
    $architectureProperty = $Sandbox.Launchers.PSObject.Properties[$Architecture]
    $launcherProperty = if ($null -ne $architectureProperty) { $architectureProperty.Value.PSObject.Properties[$Launcher] } else { $null }
    if ($null -eq $launcherProperty -or -not (Test-Path -LiteralPath $launcherProperty.Value -PathType Leaf)) {
        throw "Sandbox '$($Sandbox.Root)' has no $Architecture $Launcher launcher."
    }
    $launcherPath = [string]$launcherProperty.Value
    $result = Invoke-WinPrivContainedProcess -FilePath $launcherPath -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory -Environment $Environment -TimeoutSeconds $TimeoutSeconds `
        -Sandbox $Sandbox -CreateHiddenConsole:($Launcher -eq 'WinPrivCmd')
    $result | Add-Member -NotePropertyMembers @{
        Architecture = $Architecture; Launcher = $Launcher; LauncherPath = $launcherPath; SandboxRoot = $Sandbox.Root
    }
    return $result
}

function Invoke-WinPrivProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture,
        [ValidateSet('x86', 'x64', 'ARM64')][string]$ProbeArchitecture,
        [string[]]$WinPrivArguments = @(),
        [Parameter(Mandatory = $true)][string]$Operation,
        [hashtable]$Arguments = @{},
        [string[]]$RemainingArguments = @(),
        [ValidateSet('WinPrivCmd', 'WinPriv')][string]$Launcher = 'WinPrivCmd',
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 30,
        [Parameter(Mandatory = $true)]$Sandbox,
        [hashtable]$Environment,
        [string]$WorkingDirectory,
        [string]$OutputPath
    )

    $probePath = if ([string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_PROBE_PATH)) {
        [IO.Path]::GetFullPath((Join-Path $script:ModuleRoot '..\..\Probes\Invoke-WinPrivProbe.ps1'))
    } else { $env:WINPRIV_TEST_PROBE_PATH }
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) { throw "WinPriv probe script was not found at '$probePath'." }
    if ([string]::IsNullOrWhiteSpace($ProbeArchitecture)) { $ProbeArchitecture = $Architecture }
    $hostDetail = Get-WinPrivTestHost -Architecture $ProbeArchitecture -Detailed
    if (-not $hostDetail.Available) { throw $hostDetail.Reason }
    $hostPath = $hostDetail.Path

    $probeOutputPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Join-Path $Sandbox.Artifacts ("probe-{0}-{1}.json" -f $Operation, [Guid]::NewGuid().ToString('N'))
    } else { [IO.Path]::GetFullPath($OutputPath) }
    $argumentsJson = $Arguments | ConvertTo-Json -Depth 30 -Compress
    $argumentsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($argumentsJson))
    $allArguments = @($WinPrivArguments) + @(
        $hostPath, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $probePath, '-Operation', $Operation, '-ArgumentsBase64', $argumentsBase64, '-OutputPath', $probeOutputPath
    ) + @($RemainingArguments)
    $childEnvironment = @{}
    if ($null -ne $Environment) { foreach ($key in $Environment.Keys) { $childEnvironment[$key] = $Environment[$key] } }
    $childEnvironment['WINPRIV_PROBE_ARGUMENTS_JSON'] = $argumentsJson
    $childEnvironment['WINPRIV_PROBE_OUTPUT_PATH'] = $probeOutputPath
    $childEnvironment['WINPRIV_PROBE_OPERATION'] = $Operation

    $result = Invoke-WinPriv -Architecture $Architecture -Arguments $allArguments -Launcher $Launcher `
        -TimeoutSeconds $TimeoutSeconds -Sandbox $Sandbox -Environment $childEnvironment -WorkingDirectory $WorkingDirectory
    $probeResult = $null; $parseError = $null
    if (Test-Path -LiteralPath $probeOutputPath -PathType Leaf) {
        try { $probeResult = Get-Content -LiteralPath $probeOutputPath -Raw | ConvertFrom-Json -ErrorAction Stop }
        catch { $parseError = $_.Exception.Message }
    }
    if ($null -eq $probeResult) {
        $probeResult = ConvertFrom-WinPrivProbeOutput -Text $result.StdOut
        if ($null -eq $probeResult -and $null -eq $parseError) { $parseError = 'The probe produced no parseable JSON output.' }
    }
    $result | Add-Member -NotePropertyMembers @{
        ProbeArchitecture = $ProbeArchitecture; Operation = $Operation; ProbeHost = $hostPath
        ProbeResult = $probeResult; ProbeOutputPath = $probeOutputPath; ProbeParseError = $parseError
    }
    if ($null -ne $parseError) { $result.Succeeded = $false }
    return $result
}

function Test-WinPrivElevated {
    [CmdletBinding()]
    param()
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { return $false }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { return ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    finally { $identity.Dispose() }
}

function Test-WinPrivProcessIdentity {
    param([int]$ProcessId, [string]$ExpectedPath, [string]$ExpectedStartUtc)
    try { $process = Get-Process -Id $ProcessId -ErrorAction Stop } catch { return $false }
    try {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedPath) -and
            [IO.Path]::GetFullPath($process.Path) -ne [IO.Path]::GetFullPath($ExpectedPath)) { return $false }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedStartUtc)) {
            $expected = [DateTime]::Parse($ExpectedStartUtc).ToUniversalTime()
            if ([Math]::Abs(($process.StartTime.ToUniversalTime() - $expected).TotalSeconds) -gt 1) { return $false }
        }
        return $true
    }
    catch { return $false }
    finally { $process.Dispose() }
}

function Invoke-WinPrivStaleRunReconciliation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SuiteRoot, [string]$CurrentRunRoot, [string]$ReportPath)

    $suitePath = [IO.Path]::GetFullPath($SuiteRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    [void][IO.Directory]::CreateDirectory($suitePath)
    $currentPath = if ([string]::IsNullOrWhiteSpace($CurrentRunRoot)) { $null } else { [IO.Path]::GetFullPath($CurrentRunRoot) }
    $runs = [Collections.Generic.List[object]]::new()
    $manualRecovery = [Collections.Generic.List[object]]::new()

    foreach ($directory in Get-ChildItem -LiteralPath $suitePath -Directory -Force -ErrorAction SilentlyContinue) {
        $root = [IO.Path]::GetFullPath($directory.FullName)
        if ($null -ne $currentPath -and $root -eq $currentPath) { continue }
        $runRecord = [ordered]@{ Root = $root; Status = 'Unknown'; Actions = @(); Reason = $null }

        try { $marker = Assert-WinPrivRunMarker -Root $root -Parent $suitePath }
        catch {
            $runRecord.Status = 'Unvalidated'; $runRecord.Reason = $_.Exception.Message
            [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'RunRoot'; Identifier = $root; Reason = $runRecord.Reason })
            [void]$runs.Add([pscustomobject]$runRecord)
            continue
        }

        $ownerId = [int](Get-WinPrivObjectValue $marker.Owner 'ProcessId')
        if ($ownerId -gt 0 -and (Test-WinPrivProcessIdentity -ProcessId $ownerId `
                -ExpectedPath ([string](Get-WinPrivObjectValue $marker.Owner 'Path')) `
                -ExpectedStartUtc ([string](Get-WinPrivObjectValue $marker.Owner 'StartTimeUtc')))) {
            $runRecord.Status = 'Active'; $runRecord.Reason = 'The marker owner process is still running with the recorded identity.'
            [void]$runs.Add([pscustomobject]$runRecord)
            continue
        }

        $reparsePoints = @(Get-WinPrivReparsePoints -Root $root)
        if ($reparsePoints.Count -gt 0) {
            foreach ($reparsePoint in $reparsePoints) {
                [void]$manualRecovery.Add([pscustomobject]@{
                    Kind = 'ReparsePoint'; Identifier = $reparsePoint.FullName
                    Reason = 'A stale run contains a reparse point; reconciliation and recursive deletion were refused.'; StaleRunRoot = $root
                })
            }
            $runRecord.Status = 'ManualRecoveryRequired'; $runRecord.Reason = 'The stale run contains one or more reparse points.'
            [void]$runs.Add([pscustomobject]$runRecord)
            continue
        }

        $manualStartCount = $manualRecovery.Count
        $actions = [Collections.Generic.List[object]]::new()
        $sandboxesRoot = Join-Path $root 'sandboxes'
        if (Test-Path -LiteralPath $sandboxesRoot -PathType Container) {
            foreach ($sandboxDirectory in Get-ChildItem -LiteralPath $sandboxesRoot -Directory -Force -ErrorAction SilentlyContinue) {
                $sandboxRoot = [IO.Path]::GetFullPath($sandboxDirectory.FullName)
                try {
                    $sandboxMarker = Assert-WinPrivSandboxMarker -Root $sandboxRoot -Parent $sandboxesRoot
                    $sandbox = [pscustomobject]@{ MarkerId = [string]$sandboxMarker.MarkerId; Root = $sandboxRoot; Journal = Join-Path $sandboxRoot 'cleanup-journal.jsonl' }
                    $repair = Repair-WinPrivSandboxJournal -Sandbox $sandbox -AllowRecovery
                    if ($null -ne $repair) {
                        foreach ($delta in @($repair.Deltas)) {
                            [void]$actions.Add([pscustomobject]@{ Kind = [string]$delta.Kind; Identifier = [string]$delta.Identifier; Status = [string]$delta.Action })
                        }
                        foreach ($itemError in @($repair.Errors)) {
                            [void]$manualRecovery.Add([pscustomobject]@{ Kind = [string]$itemError.Kind; Identifier = [string]$itemError.Identifier; Reason = [string]$itemError.Reason; StaleRunRoot = $root })
                        }
                    }
                }
                catch { [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'Sandbox'; Identifier = $sandboxRoot; Reason = $_.Exception.Message }) }
            }
        }

        if ($manualRecovery.Count -eq $manualStartCount) {
            try { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop; $runRecord.Status = 'Reconciled' }
            catch {
                $runRecord.Status = 'ManualRecoveryRequired'; $runRecord.Reason = $_.Exception.Message
                [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'RunRoot'; Identifier = $root; Reason = $_.Exception.Message; StaleRunRoot = $root })
            }
        } else {
            $runRecord.Status = 'ManualRecoveryRequired'
            $runRecord.Reason = 'One or more journal entries could not be restored conservatively; evidence was retained.'
        }
        $runRecord.Actions = $actions.ToArray()
        [void]$runs.Add([pscustomobject]$runRecord)
    }

    $report = [ordered]@{
        SchemaVersion = 1; GeneratedUtc = [DateTime]::UtcNow.ToString('o'); SuiteRoot = $suitePath
        Runs = $runs.ToArray(); ManualRecovery = $manualRecovery.ToArray()
        HasFailures = $manualRecovery.Count -gt 0; ManualRecoveryCount = $manualRecovery.Count
    }
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) { Write-WinPrivJson -Path $ReportPath -Value $report -Depth 50 }
    return [pscustomobject]$report
}

function Add-WinPrivCapabilityResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64', 'All')][string]$Architecture,
        [Parameter(Mandatory = $true)][ValidateSet('Verified', 'Failed', 'PartiallyVerified', 'Unavailable')][string]$Status,
        [string]$Reason,
        $Evidence
    )
    if ($Status -ne 'Verified' -and [string]::IsNullOrWhiteSpace($Reason)) { throw "Capability '$Id' status '$Status' requires a reason." }
    $result = [pscustomobject]@{
        SchemaVersion = 1; Id = $Id; Architecture = $Architecture; Status = $Status; Reason = $Reason
        Evidence = $Evidence; Profile = $env:WINPRIV_TEST_PROFILE; TimestampUtc = [DateTime]::UtcNow.ToString('o'); ProcessId = $PID
    }
    [void]$script:CapabilityResults.Add($result)
    if (-not [string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_CAPABILITY_RESULTS_PATH)) {
        Write-WinPrivJsonLine -Path $env:WINPRIV_TEST_CAPABILITY_RESULTS_PATH -Value $result
    }
    if ($Status -in @('Unavailable', 'PartiallyVerified') -and -not [string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_EXPECTED_SKIP_EVENTS_PATH)) {
        $skipFrame = Get-PSCallStack | Where-Object Command -eq 'Skip-WinPrivCapability' | Select-Object -First 1
        if ($null -ne $skipFrame) {
            Write-WinPrivJsonLine -Path $env:WINPRIV_TEST_EXPECTED_SKIP_EVENTS_PATH -Value ([pscustomobject]@{
                Id = $Id; Architecture = $Architecture; Status = $Status; Reason = $Reason
                ScriptName = $skipFrame.ScriptName; ScriptLineNumber = $skipFrame.ScriptLineNumber
                TimestampUtc = [DateTime]::UtcNow.ToString('o')
            })
        }
    }
    return $result
}

function Clear-WinPrivCapabilityResults {
    [CmdletBinding()]
    param()
    $script:CapabilityResults.Clear()
    $path = $env:WINPRIV_TEST_CAPABILITY_RESULTS_PATH
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) { Remove-Item -LiteralPath $path -Force }
}

function Complete-WinPrivCapabilityReport {
    [CmdletBinding()]
    param(
        [string]$ManifestPath = $env:WINPRIV_TEST_CAPABILITY_MANIFEST,
        [string]$OutputPath = $env:WINPRIV_TEST_COVERAGE_PATH,
        [string[]]$Architecture,
        [ValidateSet('Safe', 'Admin', 'Full')][string]$Profile = $env:WINPRIV_TEST_PROFILE
    )
    if ([string]::IsNullOrWhiteSpace($ManifestPath)) { $ManifestPath = [IO.Path]::GetFullPath((Join-Path $script:ModuleRoot '..\..\Capabilities.psd1')) }
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { throw 'OutputPath was not supplied and WINPRIV_TEST_COVERAGE_PATH is not set.' }
    if ($null -eq $Architecture -or $Architecture.Count -eq 0) { $Architecture = @($env:WINPRIV_TEST_ARCHITECTURES -split '[,;]' | Where-Object { $_ }) }
    if ([string]::IsNullOrWhiteSpace($Profile)) { $Profile = 'Safe' }

    $capabilities = @()
    if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
        $manifest = if ($ManifestPath.EndsWith('.psd1', [StringComparison]::OrdinalIgnoreCase)) {
            Import-PowerShellDataFile -LiteralPath $ManifestPath
        } else { Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json }
        $capabilities = @((Get-WinPrivObjectValue $manifest 'Capabilities') | Where-Object {
            $capProfile = [string](Get-WinPrivObjectValue $_ 'Profile')
            [string]::IsNullOrWhiteSpace($capProfile) -or ($Profile -eq 'Full' -and $capProfile -in @('Safe', 'Admin')) -or
                $capProfile -eq $Profile -or -not [string]::IsNullOrWhiteSpace([string](Get-WinPrivObjectValue $_ 'DefaultStatus'))
        })
    }

    $rawResults = if (-not [string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_CAPABILITY_RESULTS_PATH) -and
        (Test-Path -LiteralPath $env:WINPRIV_TEST_CAPABILITY_RESULTS_PATH -PathType Leaf)) {
        @(Read-WinPrivJsonLines -Path $env:WINPRIV_TEST_CAPABILITY_RESULTS_PATH)
    } else { $script:CapabilityResults.ToArray() }
    $results = @($rawResults | Group-Object { "$($_.Id)`0$($_.Architecture)" } | ForEach-Object { $_.Group | Sort-Object TimestampUtc | Select-Object -Last 1 })

    $coverage = [Collections.Generic.List[object]]::new()
    $missing = [Collections.Generic.List[object]]::new()
    $unexpectedNonVerified = [Collections.Generic.List[object]]::new()

    foreach ($capability in $capabilities) {
        $id = [string](Get-WinPrivObjectValue $capability 'Id')
        $defaultStatus = [string](Get-WinPrivObjectValue $capability 'DefaultStatus')
        $gate = [string](Get-WinPrivObjectValue $capability 'Gate')
        $gateValue = if ([string]::IsNullOrWhiteSpace($gate)) { $null } else { $gate }
        $explicitArchitecture = Get-WinPrivObjectValue $capability 'Architecture'
        $capabilityArchitectures = if ($null -ne $explicitArchitecture) { @($explicitArchitecture) } else { @($Architecture) }

        foreach ($item in $capabilityArchitectures) {
            $result = $results | Where-Object { $_.Id -eq $id -and ($_.Architecture -eq $item -or $_.Architecture -eq 'All') } | Select-Object -Last 1
            $seeded = $false
            if ($null -eq $result -and -not [string]::IsNullOrWhiteSpace($defaultStatus)) {
                $result = [pscustomobject]@{
                    Id = $id; Architecture = $item; Status = $defaultStatus; Reason = [string](Get-WinPrivObjectValue $capability 'Reason')
                    Evidence = $null; Profile = $Profile; TimestampUtc = [DateTime]::UtcNow.ToString('o')
                }
                $seeded = $true
            }
            if ($null -eq $result) {
                $requiredValue = Get-WinPrivObjectValue $capability 'Required'
                [void]$missing.Add([pscustomobject]@{ Id = $id; Architecture = $item; Required = $null -eq $requiredValue -or [bool]$requiredValue; Test = Get-WinPrivObjectValue $capability 'Test' })
                [void]$coverage.Add([pscustomobject]@{ Id = $id; Architecture = $item; Status = 'Failed'; Reason = 'No capability evidence event was emitted; this manifest capability is missing test evidence.'; Seeded = $false; Gate = $gateValue })
                continue
            }
            [void]$coverage.Add([pscustomobject]@{ Id = $id; Architecture = $item; Status = $result.Status; Reason = $result.Reason; Seeded = $seeded; Evidence = $result.Evidence; Gate = $gateValue })
            if ($result.Status -eq 'Failed' -or ($result.Status -in @('PartiallyVerified', 'Unavailable') -and [string]::IsNullOrWhiteSpace($gate) -and [string]::IsNullOrWhiteSpace($defaultStatus))) {
                [void]$unexpectedNonVerified.Add($result)
            }
        }
    }

    $manifestIds = @($capabilities | ForEach-Object { [string](Get-WinPrivObjectValue $_ 'Id') } | Select-Object -Unique)
    $unmanifested = if ($manifestIds.Count -gt 0) { @($results | Where-Object { $_.Id -notin $manifestIds }) } else { @() }
    $requiredMissing = @($missing | Where-Object Required)
    $report = [ordered]@{
        SchemaVersion = 1; GeneratedUtc = [DateTime]::UtcNow.ToString('o'); ManifestPath = $ManifestPath; Profile = $Profile
        Architectures = @($Architecture); ManifestCapabilityCount = $capabilities.Count; ResultCount = $results.Count
        Coverage = $coverage.ToArray(); Missing = $missing.ToArray(); RequiredMissing = @($requiredMissing)
        UnexpectedNonVerified = $unexpectedNonVerified.ToArray(); UnmanifestedResults = @($unmanifested)
        HasFailures = $requiredMissing.Count -gt 0 -or $unexpectedNonVerified.Count -gt 0 -or $unmanifested.Count -gt 0
    }
    Write-WinPrivJson -Path $OutputPath -Value $report -Depth 40
    return [pscustomobject]$report
}

Export-ModuleMember -Function @(
    'Add-WinPrivCapabilityResult', 'Add-WinPrivCleanupJournalEntry', 'Clear-WinPrivCapabilityResults', 'Complete-WinPrivCapabilityReport',
    'Get-WinPrivPeArchitecture', 'Get-WinPrivTestArchitectures', 'Get-WinPrivTestHost', 'Invoke-WinPriv',
    'Invoke-WinPrivContainedProcess', 'Invoke-WinPrivProbe', 'Invoke-WinPrivCurrentRunReconciliation', 'Invoke-WinPrivStaleRunReconciliation',
    'New-WinPrivSandbox', 'Repair-WinPrivSandboxJournal', 'Remove-WinPrivSandbox', 'Test-WinPrivElevated'
)
