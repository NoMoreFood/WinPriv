Set-StrictMode -Version 3.0

function Get-PeMachine {
    param([Parameter(Mandatory)] [string] $Path)

    $stream = [IO.File]::OpenRead($Path)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "$Path is not a PE image." }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "$Path has no PE signature." }
        return $reader.ReadUInt16()
    }
    finally {
        $stream.Dispose()
    }
}

function Convert-PhysicalAddressText {
    param([AllowNull()] [string] $Value)

    if ($null -eq $Value) { return '' }
    return ($Value -replace '[-:\s]', '').ToUpperInvariant()
}

function Get-WinPrivRegistryQueryResults {
    param([Parameter(Mandatory)] $Invocation)

    return @('win32', 'ntPartial', 'ntPartialAlign64', 'ntFull', 'ntFullAlign64') |
        ForEach-Object {
            [pscustomobject]@{ Name = $_; Value = $Invocation.ProbeResult.result.$_ }
        }
}

function Get-WinPrivLocalComputerEntry {
    param([Parameter(Mandatory)] [string] $MachineName)

    return [ADSI]"WinNT://$MachineName,computer"
}

function Get-WinPrivLocalPrincipalEntry {
    param(
        [Parameter(Mandatory)] [string] $MachineName,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [ValidateSet('group', 'user')] [string] $Type
    )

    return [ADSI]"WinNT://$MachineName/$Name,$Type"
}

function Get-WinPrivBuiltinUsersGroupEntry {
    param([Parameter(Mandatory)] [string] $MachineName)

    $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $usersAccount = $usersSid.Translate([Security.Principal.NTAccount]).Value
    $separator = $usersAccount.IndexOf('\')
    $groupName = if ($separator -ge 0) { $usersAccount.Substring($separator + 1) } else { $usersAccount }
    return [ADSI]"WinNT://$MachineName/$groupName,group"
}

function New-WinPrivLocalPrincipal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateSet('group', 'user')] [string] $Type,
        [Parameter(Mandatory)] $Sandbox
    )

    $machineName = [Environment]::MachineName
    $prefix = if ($Type -eq 'group') { 'WPTG' } else { 'WPTU' }
    $name = $prefix + [guid]::NewGuid().ToString('N').Substring(0, 12)
    $description = "WinPriv test fixture $name"
    $password = $null
    $computer = $null
    $entry = $null

    # Record an absent-before creation intent before touching the local SAM.  If
    # the process stops between SetInfo and SID resolution, reconciliation can
    # still identify the exact random-name/description pair and remove it.
    Add-WinPrivCleanupJournalEntry -Sandbox $Sandbox -Kind LocalPrincipalIntent -Identifier $name `
        -OriginalState @{ Existed = $false } -Metadata @{
            MachineName = $machineName; Type = $Type; Description = $description
        } | Out-Null

    try {
        $computer = Get-WinPrivLocalComputerEntry -MachineName $machineName
        $entry = $computer.Create($Type, $name)
        if ($Type -eq 'user') {
            $password = 'Wp!' + [guid]::NewGuid().ToString('N') + 'aA9'
            # Commit the ownership marker while the account is disabled.  Any
            # interruption after this first SetInfo leaves a non-logon-capable
            # object that the pre-creation journal can identify exactly.
            [void]$entry.Put('UserFlags', 0x0203) # UF_NORMAL_ACCOUNT | UF_SCRIPT | UF_ACCOUNTDISABLE
        }
        [void]$entry.Put('Description', $description)
        [void]$entry.SetInfo()

        $resolved = Get-WinPrivLocalPrincipalEntry -MachineName $machineName -Name $name -Type $Type
        $sidBytes = [byte[]]$resolved.Properties['objectSid'].Value
        if ($null -eq $sidBytes -or $sidBytes.Count -eq 0) {
            throw "The local $Type '$name' did not expose an object SID after creation."
        }
        $sid = [Security.Principal.SecurityIdentifier]::new($sidBytes, 0).Value

        Add-WinPrivCleanupJournalEntry -Sandbox $Sandbox -Kind LocalPrincipal -Identifier $name `
            -OriginalState @{ Existed = $false } -Metadata @{
                MachineName = $machineName; Sid = $sid; Type = $Type; Description = $description
            } | Out-Null
        Add-WinPrivCleanupJournalEntry -Sandbox $Sandbox -Kind LsaRight -Identifier "$machineName\$name" `
            -OriginalState @{ Rights = @() } -Metadata @{
                Sid = $sid; PrincipalName = $name
            } | Out-Null

        if ($Type -eq 'user') {
            # A raw WinNT-provider user has no alias membership.  Add the
            # locale-independent builtin Users alias so an ordinary standalone
            # workstation grants the fixture the same logon boundary as a
            # normal non-administrator local user.
            [void]$resolved.SetPassword($password)
            $usersGroup = Get-WinPrivBuiltinUsersGroupEntry -MachineName $machineName
            [void]$usersGroup.Add("WinNT://$machineName/$name,user")
            [void]$resolved.Put('UserFlags', 0x0201) # UF_NORMAL_ACCOUNT | UF_SCRIPT
            [void]$resolved.SetInfo()
        }

        return [pscustomobject]@{
            Name = $name; Type = $Type; Password = $password; Sid = $sid
            Account = "$machineName\$name"; MachineName = $machineName
        }
    }
    catch {
        $setupError = $_
        if ($null -ne $computer -and $null -ne $entry) {
            try { [void]$computer.Delete($Type, $name) } catch { }
        }
        throw $setupError
    }
}

function Remove-WinPrivLocalPrincipal {
    param([Parameter(Mandatory)] [AllowNull()] $Principal)

    if ($null -eq $Principal) { return }
    if ($Principal.Type -eq 'user' -and [string]$Principal.Sid -match '^S-1-') {
        try {
            $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($Principal.Sid)"
            if (Test-Path -LiteralPath $profileKey) {
                $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$($Principal.Sid)'" -ErrorAction SilentlyContinue
                if ($profile -and -not $profile.Loaded) {
                    [void](Remove-CimInstance $profile -ErrorAction SilentlyContinue)
                }
            }
        }
        catch { }
    }
    try {
        $computer = Get-WinPrivLocalComputerEntry -MachineName ([string]$Principal.MachineName)
        [void]$computer.Delete([string]$Principal.Type, [string]$Principal.Name)
    }
    catch { }
}

function Get-WinPrivLsaState {
    param(
        [Parameter(Mandatory)] [string] $Architecture,
        [Parameter(Mandatory)] $Sandbox,
        [string] $Account,
        [string] $Right
    )

    $arguments = @{}
    if ($Account) { $arguments.account = $Account }
    if ($Right) { $arguments.right = $Right }
    $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation lsa -Arguments $arguments `
        -Sandbox $Sandbox -TimeoutSeconds 30
    Assert-WinPrivInvocationSucceeded $result
    return $result.ProbeResult.result
}

function Revoke-WinPrivFixtureRights {
    param([string] $Architecture, $Sandbox, [string] $Account)

    try {
        $state = Get-WinPrivLsaState -Architecture $Architecture -Sandbox $Sandbox -Account $Account
        foreach ($right in @($state.accountRights.rights)) {
            Invoke-WinPriv -Architecture $Architecture -Arguments @('/RevokeRight', [string]$right, $Account) `
                -Launcher WinPrivCmd -Sandbox $Sandbox -TimeoutSeconds 20 | Out-Null
        }
    }
    catch { }
}

function Remove-WinPrivSecurityFixture {
    [CmdletBinding()]
    param(
        [string] $Architecture,
        [AllowNull()] $Sandbox,
        [AllowNull()] $Principal,
        [AllowNull()] $OriginalAcl
    )

    $errors = New-Object 'System.Collections.Generic.List[object]'
    $account = if ($null -ne $Principal -and $Principal.PSObject.Properties['Account']) {
        [string]$Principal.Account
    }
    else { $null }

    if ($null -ne $Sandbox -and -not [string]::IsNullOrWhiteSpace($account)) {
        try {
            Revoke-WinPrivFixtureRights -Architecture $Architecture -Sandbox $Sandbox -Account $account
        }
        catch { [void]$errors.Add($_) }
    }
    if ($null -ne $Sandbox -and $null -ne $OriginalAcl) {
        try { Set-Acl -LiteralPath $Sandbox.Root -AclObject $OriginalAcl -ErrorAction Stop }
        catch { [void]$errors.Add($_) }
    }
    if ($null -ne $Principal) {
        try { Remove-WinPrivLocalPrincipal -Principal $Principal }
        catch { [void]$errors.Add($_) }
    }
    if ($null -ne $Sandbox) {
        try { Remove-WinPrivSandbox -Sandbox $Sandbox | Out-Null }
        catch { [void]$errors.Add($_) }
    }

    if ($errors.Count -gt 0) {
        throw "Security fixture cleanup failed: $(($errors | ForEach-Object { $_.Exception.Message }) -join '; ')"
    }
}

function Get-WinPrivHostPath {
    param([string] $Architecture)

    $hostInfo = Get-WinPrivTestHost -Architecture $Architecture
    if ($hostInfo -is [string]) { return $hostInfo }
    foreach ($property in @('Path', 'HostPath', 'Executable')) {
        if ($hostInfo.PSObject.Properties[$property] -and $hostInfo.$property) { return [string]$hostInfo.$property }
    }
    throw "No executable path was returned for the $Architecture PowerShell host."
}

function Invoke-WinPrivFreshUserProbe {
    param(
        [string] $Architecture,
        $Sandbox,
        $Principal,
        [string[]] $WinPrivArguments,
        [string] $Operation,
        [hashtable] $Arguments = @{}
    )

    if (-not ('WinPrivTests.LogonRunner' -as [type])) {
        $supportRoot = $PSScriptRoot
        Add-Type -Path (Join-Path $supportRoot 'WinPriv.LogonRunner.cs')
    }
    $testsRoot = Split-Path -Parent $PSScriptRoot
    $output = Join-Path $Sandbox.Artifacts ("fresh-{0}.json" -f [guid]::NewGuid().ToString('N'))
    $hostPath = Get-WinPrivHostPath $Architecture
    $sourceProbePath = if ($env:WINPRIV_TEST_PROBE_PATH) {
        $env:WINPRIV_TEST_PROBE_PATH
    }
    else {
        Join-Path $testsRoot 'Probes\Invoke-WinPrivProbe.ps1'
    }
    # The repository may live beneath an administrator-only profile or on a
    # mapped drive that the fresh local user cannot access.  Copy the complete
    # probe directory (the script loads sibling C# files) into its ACL-granted
    # sandbox before launching under that user.
    $probeDirectory = Join-Path $Sandbox.Working 'fresh-user-probe'
    if (-not (Test-Path -LiteralPath $probeDirectory -PathType Container)) {
        Copy-Item -LiteralPath (Split-Path -Parent $sourceProbePath) -Destination $probeDirectory -Recurse -Force
    }
    $probePath = Join-Path $probeDirectory (Split-Path -Leaf $sourceProbePath)
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
        throw "The sandboxed fresh-user probe was not copied to '$probePath'."
    }
    $argumentsJson = $Arguments | ConvertTo-Json -Depth 20 -Compress
    $argumentsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($argumentsJson))
    $probeArguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $probePath, '-Operation', $Operation, '-OutputPath', $output,
        '-ArgumentsBase64', $argumentsBase64
    )
    $argumentsToLauncher = @($WinPrivArguments) + @($hostPath) + $probeArguments
    $launcher = $Sandbox.Launchers.$Architecture.WinPrivCmd
    $processEnvironment = @{}
    foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $processEnvironment[[string]$entry.Key] = [string]$entry.Value
    }
    $profileRoot = Join-Path $Sandbox.Root 'profile'
    $roamingRoot = Join-Path $profileRoot 'AppData\Roaming'
    $localRoot = Join-Path $profileRoot 'AppData\Local'
    [void](New-Item -ItemType Directory -Path $roamingRoot -Force)
    [void](New-Item -ItemType Directory -Path $localRoot -Force)
    $driveRoot = [IO.Path]::GetPathRoot($profileRoot)
    $processEnvironment['TEMP'] = $Sandbox.Temp
    $processEnvironment['TMP'] = $Sandbox.Temp
    $processEnvironment['HOME'] = $profileRoot
    $processEnvironment['USERPROFILE'] = $profileRoot
    $processEnvironment['APPDATA'] = $roamingRoot
    $processEnvironment['LOCALAPPDATA'] = $localRoot
    if (-not [string]::IsNullOrWhiteSpace($driveRoot)) {
        $processEnvironment['HOMEDRIVE'] = $driveRoot.TrimEnd('\', '/')
        $processEnvironment['HOMEPATH'] = $profileRoot.Substring($driveRoot.Length - 1)
    }
    $processEnvironment['USERNAME'] = $Principal.Name
    $processEnvironment['USERDOMAIN'] = $Principal.MachineName
    $processEnvironmentStrings = @($processEnvironment.GetEnumerator() | Sort-Object Key | ForEach-Object {
        '{0}={1}' -f $_.Key, $_.Value
    })
    $run = [WinPrivTests.LogonRunner]::Run(
        $Principal.MachineName, $Principal.Name, $Principal.Password, $launcher,
        $argumentsToLauncher, $Sandbox.Working, $processEnvironmentStrings, 60000
    )
    $probe = $null
    if (Test-Path -LiteralPath $output) {
        $probe = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json -Depth 30
    }
    return [pscustomobject]@{ Run = $run; ProbeResult = $probe; OutputPath = $output }
}

function Invoke-WinPrivDialogProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('x86', 'x64', 'ARM64')] [string] $Architecture,
        [Parameter(Mandatory)] $Sandbox,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $WinPrivArguments,
        [Parameter(Mandatory)] [ValidateSet('WinPrivCmd', 'WinPriv')] [string] $Launcher,
        [Parameter(Mandatory)] [int] $ButtonId,
        [string] $ExpectedTitle = 'Message',
        [string] $Operation = 'marker',
        [hashtable] $Arguments = @{},
        [switch] $NoTarget,
        [ValidateRange(1, 120)] [int] $TimeoutSeconds = 30
    )

    if (-not ('WinPrivTests.DialogAutomation' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'WinPriv.DialogAutomation.cs')
    }
    if (-not (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)) {
        throw 'Start-ThreadJob is required for contained dialog automation.'
    }

    $launcherSet = $Sandbox.Launchers.PSObject.Properties[$Architecture].Value
    $originalLauncher = [string]$launcherSet.PSObject.Properties[$Launcher].Value
    $uniqueName = 'wpd' + [guid]::NewGuid().ToString('N').Substring(0, 9) + '.exe'
    $uniqueLauncher = Join-Path $launcherSet.Root $uniqueName
    Copy-Item -LiteralPath $originalLauncher -Destination $uniqueLauncher
    $launcherSet.PSObject.Properties[$Launcher].Value = $uniqueLauncher

    $testsRoot = Split-Path -Parent $PSScriptRoot
    $modulePath = Join-Path $testsRoot 'Modules\WinPriv.TestHarness\WinPriv.TestHarness.psd1'
    $thread = $null
    $dialogProcess = $null
    try {
        $thread = Start-ThreadJob -ArgumentList @(
            $modulePath, $Architecture, $Sandbox, $WinPrivArguments, $Launcher,
            $Operation, $Arguments, $TimeoutSeconds, [bool]$NoTarget
        ) -ScriptBlock {
            param($ModulePath, $Architecture, $Sandbox, $WinPrivArguments, $Launcher,
                $Operation, $Arguments, $TimeoutSeconds, $NoTarget)
            Import-Module $ModulePath -Force
            if ($NoTarget) {
                Invoke-WinPriv -Architecture $Architecture -Sandbox $Sandbox `
                    -Arguments $WinPrivArguments -Launcher $Launcher -TimeoutSeconds $TimeoutSeconds
            }
            else {
                Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $Sandbox `
                    -WinPrivArguments $WinPrivArguments -Launcher $Launcher -Operation $Operation `
                    -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds
            }
        }

        $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Min(15, $TimeoutSeconds))
        $processName = [IO.Path]::GetFileNameWithoutExtension($uniqueLauncher)
        do {
            $dialogProcess = @(Get-Process -Name $processName -ErrorAction SilentlyContinue | Where-Object {
                try { [IO.Path]::GetFullPath($_.Path) -eq [IO.Path]::GetFullPath($uniqueLauncher) }
                catch { $false }
            } | Select-Object -First 1)
            if ($dialogProcess.Count -eq 0) { Start-Sleep -Milliseconds 50 }
        } while ($dialogProcess.Count -eq 0 -and [DateTime]::UtcNow -lt $deadline)

        if ($dialogProcess.Count -eq 0) {
            throw "The contained $Launcher dialog process did not appear within the PID discovery timeout."
        }
        $dialogPid = [uint32]$dialogProcess[0].Id
        $dialogTitle = [WinPrivTests.DialogAutomation]::Click(
            $dialogPid, $ButtonId, $ExpectedTitle, [Math]::Min(15000, $TimeoutSeconds * 1000)
        )

        if (-not (Wait-Job -Job $thread -Timeout ($TimeoutSeconds + 5))) {
            throw "The contained $Launcher tree did not exit after dialog automation."
        }
        $output = @(Receive-Job -Job $thread -ErrorAction Stop)
        $invocation = @($output | Where-Object {
            $null -ne $_ -and $_.PSObject.Properties['TimedOut'] -and $_.PSObject.Properties['ExitCode']
        } | Select-Object -Last 1)
        if ($invocation.Count -ne 1) {
            throw "Contained dialog execution returned no WinPriv invocation result: $($output | Out-String)"
        }
        $invocation[0] | Add-Member -NotePropertyName DialogProcessId -NotePropertyValue $dialogPid
        $invocation[0] | Add-Member -NotePropertyName DialogTitle -NotePropertyValue $dialogTitle
        return $invocation[0]
    }
    finally {
        if ($null -ne $thread) {
            if ($thread.State -in @('Running', 'NotStarted')) {
                [void](Wait-Job -Job $thread -Timeout ($TimeoutSeconds + 5))
            }
            if ($thread.State -in @('Running', 'NotStarted')) { Stop-Job -Job $thread -ErrorAction SilentlyContinue }
            Remove-Job -Job $thread -Force -ErrorAction SilentlyContinue
        }
        $launcherSet.PSObject.Properties[$Launcher].Value = $originalLauncher
        Remove-Item -LiteralPath $uniqueLauncher -Force -ErrorAction SilentlyContinue
    }
}
