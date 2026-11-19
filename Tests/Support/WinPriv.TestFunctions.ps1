Set-StrictMode -Version 3.0

function Get-PeControlFlowGuard {
    param([Parameter(Mandatory)] [string] $Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    if ([BitConverter]::ToUInt16($bytes, 0) -ne 0x5A4D) { throw "$Path is not a PE image." }
    $peOffset = [BitConverter]::ToUInt32($bytes, 0x3C)
    if ([BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) { throw "$Path has no PE signature." }
    $sectionCount = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
    $optionalSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
    $optionalOffset = $peOffset + 24
    $magic = [BitConverter]::ToUInt16($bytes, $optionalOffset)
    if ($magic -notin @(0x10B, 0x20B)) { throw "$Path has an unsupported PE optional header." }
    $is64Bit = $magic -eq 0x20B
    $directoriesOffset = $optionalOffset + $(if ($is64Bit) { 112 } else { 96 })
    $configRva = [BitConverter]::ToUInt32($bytes, $directoriesOffset + 80)
    $configSize = [BitConverter]::ToUInt32($bytes, $directoriesOffset + 84)
    $characteristics = [BitConverter]::ToUInt16($bytes, $optionalOffset + 70)
    $flagsOffset = if ($is64Bit) { 144 } else { 88 }
    $configOffset = $null
    $configAvailable = 0
    for ($index = 0; $index -lt $sectionCount; ++$index) {
        $sectionOffset = $optionalOffset + $optionalSize + $index * 40
        $sectionRva = [BitConverter]::ToUInt32($bytes, $sectionOffset + 12)
        $rawSize = [BitConverter]::ToUInt32($bytes, $sectionOffset + 16)
        $rawOffset = [BitConverter]::ToUInt32($bytes, $sectionOffset + 20)
        if ($configRva -ge $sectionRva -and $configRva -lt $sectionRva + $rawSize) {
            $configOffset = $rawOffset + $configRva - $sectionRva
            $configAvailable = [Math]::Min(
                [long]$rawSize - ($configRva - $sectionRva), [long]$bytes.LongLength - $configOffset)
            break
        }
    }
    if ($null -eq $configOffset -or $configSize -lt 4 -or $configAvailable -lt 4) {
        throw "$Path has no load configuration."
    }
    $structureSize = [BitConverter]::ToUInt32($bytes, $configOffset)
    if ($structureSize -lt $flagsOffset + 4 -or $structureSize -gt $configAvailable) {
        throw "$Path has no complete CFG load configuration."
    }

    $guardFlags = [BitConverter]::ToUInt32($bytes, $configOffset + $flagsOffset)
    if ($is64Bit) {
        $checkPointer = [BitConverter]::ToUInt64($bytes, $configOffset + 112)
        $functionTable = [BitConverter]::ToUInt64($bytes, $configOffset + 128)
        $functionCount = [BitConverter]::ToUInt64($bytes, $configOffset + 136)
    }
    else {
        $checkPointer = [BitConverter]::ToUInt32($bytes, $configOffset + 72)
        $functionTable = [BitConverter]::ToUInt32($bytes, $configOffset + 80)
        $functionCount = [BitConverter]::ToUInt32($bytes, $configOffset + 84)
    }
    return [pscustomobject]@{
        Path                 = $Path
        GuardCf              = ($characteristics -band 0x4000) -ne 0
        Instrumented         = ($guardFlags -band 0x100) -ne 0
        FunctionTablePresent = ($guardFlags -band 0x400) -ne 0
        CheckPointer         = $checkPointer
        FunctionTable        = $functionTable
        FunctionCount        = $functionCount
    }
}

function Get-WinPrivRegistryQueryResults {
    param([Parameter(Mandatory)] $Invocation)

    return @('win32', 'ntPartial', 'ntPartialAlign64', 'ntFull', 'ntFullAlign64') |
        ForEach-Object { [pscustomobject]@{ Name = $_; Value = $Invocation.ProbeResult.result.$_ } }
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
    $usersAccount = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545').Translate([Security.Principal.NTAccount]).Value
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
    $password = $null; $computer = $null; $entry = $null

    # Journal absent-before creation intent before touching the local SAM so interrupted runs can still reconcile.
    Add-WinPrivCleanupJournalEntry -Sandbox $Sandbox -Kind LocalPrincipalIntent -Identifier $name `
        -OriginalState @{ Existed = $false } -Metadata @{
            MachineName = $machineName; Type = $Type; Description = $description
        } | Out-Null

    try {
        $computer = Get-WinPrivLocalComputerEntry -MachineName $machineName
        $entry = $computer.Create($Type, $name)
        if ($Type -eq 'user') {
            $password = 'Wp!' + [guid]::NewGuid().ToString('N') + 'aA9'
            [void]$entry.Put('UserFlags', 0x0203) # UF_NORMAL_ACCOUNT | UF_SCRIPT | UF_ACCOUNTDISABLE
            [void]$entry.SetPassword($password)
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
            -OriginalState @{ Rights = @() } -Metadata @{ Sid = $sid; PrincipalName = $name } | Out-Null

        if ($Type -eq 'user') {
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
    param([string] $Account, [string] $Right)

    if (-not ('WinPrivTests.LsaPolicy' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'WinPriv.LsaPolicy.cs')
    }
    $accountRights = if ($Account) { @([WinPrivTests.LsaPolicy]::GetRights($Account)) } else { @() }
    $accountsWithRight = if ($Right) {
        @([WinPrivTests.LsaPolicy]::GetAccountSidsWithRight($Right) | ForEach-Object {
            $name = try { [Security.Principal.SecurityIdentifier]::new($_).Translate([Security.Principal.NTAccount]).Value } catch { $_ }
            [pscustomobject]@{ Sid = $_; Account = $name }
        })
    } else { @() }
    return [pscustomobject]@{
        AccountRights       = $accountRights
        AccountsWithRight   = $accountsWithRight
        AvailablePrivileges = @([WinPrivTests.LsaPolicy]::GetAvailablePrivileges())
    }
}

function Revoke-WinPrivFixtureRights {
    param([string] $Architecture, $Sandbox, [string] $Account)

    try {
        if (-not ('WinPrivTests.LsaPolicy' -as [type])) {
            Add-Type -Path (Join-Path $PSScriptRoot 'WinPriv.LsaPolicy.cs')
        }
        [void][WinPrivTests.LsaPolicy]::SetRights($Account, [string[]]@())
    }
    catch { }
}

function Set-WinPrivFixtureAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path, $Acl)

    $restoring = $null -ne $Acl
    if (-not $restoring) { $Acl = Get-Acl -LiteralPath $Path -ErrorAction Stop }
    $expectedSddl = $Acl.Sddl
    # Round-trip new fixtures before journaling so Windows normalizes inherited ACL flags.
    $Acl.SetSecurityDescriptorSddlForm($expectedSddl)
    Set-Acl -LiteralPath $Path -AclObject $Acl -ErrorAction Stop
    $appliedAcl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if ($restoring -and $appliedAcl.Sddl -cne $expectedSddl) {
        throw "ACL restoration did not reproduce the original descriptor for '$Path'."
    }
    return $appliedAcl
}

function Remove-WinPrivSecurityFixture {
    [CmdletBinding()]
    param(
        [string] $Architecture,
        [AllowNull()] $Sandbox,
        [AllowNull()] $Principal,
        [AllowNull()] $OriginalAcl
    )

    $errors = [Collections.Generic.List[object]]::new()
    $account = if ($null -ne $Principal -and $Principal.PSObject.Properties['Account']) { [string]$Principal.Account } else { $null }

    if ($null -ne $Sandbox -and -not [string]::IsNullOrWhiteSpace($account)) {
        try { Revoke-WinPrivFixtureRights -Architecture $Architecture -Sandbox $Sandbox -Account $account }
        catch { [void]$errors.Add($_) }
    }
    if ($null -ne $Sandbox -and $null -ne $OriginalAcl) {
        try { Set-WinPrivFixtureAcl -Path $Sandbox.Root -Acl $OriginalAcl | Out-Null }
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

function Invoke-WinPrivFreshUserProbe {
    param(
        [string] $Architecture,
        $Sandbox,
        $Principal,
        [string[]] $WinPrivArguments,
        [string] $Operation,
        [switch] $BatchLogon
    )

    if (-not ('WinPrivTests.ProcessContainment' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'WinPriv.ProcessContainment.cs')
    }
    $testsRoot = Split-Path -Parent $PSScriptRoot
    $output = Join-Path $Sandbox.Artifacts ("fresh-{0}.json" -f [guid]::NewGuid().ToString('N'))
    $hostPath = Get-WinPrivTestHost -Architecture $Architecture
    if ([string]::IsNullOrWhiteSpace($hostPath)) {
        throw "No executable path was returned for the $Architecture PowerShell host."
    }
    $sourceProbePath = if ($env:WINPRIV_TEST_PROBE_PATH) { $env:WINPRIV_TEST_PROBE_PATH } else { Join-Path $testsRoot 'Probes\Invoke-WinPrivProbe.ps1' }
    # Stage and precompile the probe inside the ACL-granted sandbox so the fresh user needs no repository access.
    $probeDirectory = Join-Path $Sandbox.Working 'fresh-user-probe'
    if (-not (Test-Path -LiteralPath $probeDirectory -PathType Container)) {
        Copy-Item -LiteralPath (Split-Path -Parent $sourceProbePath) -Destination $probeDirectory -Recurse -Force
    }
    $probePath = Join-Path $probeDirectory (Split-Path -Leaf $sourceProbePath)
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
        throw "The sandboxed fresh-user probe was not copied to '$probePath'."
    }
    $assemblyPath = Join-Path $probeDirectory 'WinPrivProbe.dll'
    if (-not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
        $compileScript = @'
$ErrorActionPreference = 'Stop'
$directory = $env:WINPRIV_PROBE_BUILD_DIRECTORY
$sources = [string[]]@(Get-ChildItem -LiteralPath $directory -Filter 'WinPrivProbe.*.cs' | Sort-Object Name | ForEach-Object { $_.FullName })
Add-Type -Path $sources -OutputAssembly (Join-Path $directory 'WinPrivProbe.dll')
'@
        $encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($compileScript))
        $compile = Invoke-WinPrivContainedProcess -FilePath $hostPath -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedScript
        ) -Environment @{ WINPRIV_PROBE_BUILD_DIRECTORY = $probeDirectory } -Sandbox $Sandbox -CreateNoWindow
        if ($compile.TimedOut -or $compile.StartError -or $compile.ExitCode -ne 0 -or
            -not (Test-Path -LiteralPath $assemblyPath -PathType Leaf)) {
            throw "Could not compile the fresh-user probe: $($compile.StartError) $($compile.StdErr)"
        }
    }

    $argumentsToLauncher = @($WinPrivArguments) + @(
        $hostPath, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $probePath, '-Operation', $Operation, '-OutputPath', $output
    )
    $launcher = $Sandbox.Launchers.$Architecture.WinPrivCmd
    $processEnvironment = @{}
    foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $processEnvironment[[string]$entry.Key] = [string]$entry.Value
    }
    $profileRoot = Join-Path $Sandbox.Root 'profile'
    $roamingRoot = Join-Path $profileRoot 'AppData\Roaming'
    $localRoot = Join-Path $profileRoot 'AppData\Local'
    [void][IO.Directory]::CreateDirectory($roamingRoot)
    [void][IO.Directory]::CreateDirectory($localRoot)
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
    $processEnvironmentStrings = [string[]]@($processEnvironment.GetEnumerator() | Sort-Object Key | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value })

    $run = [WinPrivTests.ProcessContainment]::RunAsUser(
        $Principal.MachineName, $Principal.Name, $Principal.Password, $launcher,
        [string[]]$argumentsToLauncher, $Sandbox.Working, $processEnvironmentStrings, 60000, [bool]$BatchLogon
    )
    $probe = if (Test-Path -LiteralPath $output) { Get-Content -LiteralPath $output -Raw | ConvertFrom-Json -Depth 30 } else { $null }
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
    $uniqueLauncher = Join-Path $launcherSet.Root ('wpd' + [guid]::NewGuid().ToString('N').Substring(0, 9) + '.exe')
    Copy-Item -LiteralPath $originalLauncher -Destination $uniqueLauncher
    $launcherSet.PSObject.Properties[$Launcher].Value = $uniqueLauncher

    $modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules\WinPriv.TestHarness\WinPriv.TestHarness.psd1'
    $thread = $null
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
            } else {
                Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $Sandbox `
                    -WinPrivArguments $WinPrivArguments -Launcher $Launcher -Operation $Operation `
                    -Arguments $Arguments -TimeoutSeconds $TimeoutSeconds
            }
        }

        $deadline = [DateTime]::UtcNow.AddSeconds([Math]::Min(15, $TimeoutSeconds))
        $processName = [IO.Path]::GetFileNameWithoutExtension($uniqueLauncher)
        $dialogProcess = @()
        do {
            $dialogProcess = @(Get-Process -Name $processName -ErrorAction SilentlyContinue | Where-Object {
                try { [IO.Path]::GetFullPath($_.Path) -eq [IO.Path]::GetFullPath($uniqueLauncher) } catch { $false }
            } | Select-Object -First 1)
            if ($dialogProcess.Count -eq 0) { Start-Sleep -Milliseconds 50 }
        } while ($dialogProcess.Count -eq 0 -and [DateTime]::UtcNow -lt $deadline)

        if ($dialogProcess.Count -eq 0) {
            throw "The contained $Launcher dialog process did not appear within the PID discovery timeout."
        }
        $dialogPid = [uint32]$dialogProcess[0].Id
        $dialogTitle = [WinPrivTests.DialogAutomation]::Click(
            $dialogPid, $ButtonId, $ExpectedTitle, [Math]::Min(15000, $TimeoutSeconds * 1000))

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
        $invocation[0] | Add-Member -NotePropertyMembers @{ DialogProcessId = $dialogPid; DialogTitle = $dialogTitle }
        return $invocation[0]
    }
    finally {
        if ($null -ne $thread) {
            if ($thread.State -in @('Running', 'NotStarted')) { [void](Wait-Job -Job $thread -Timeout ($TimeoutSeconds + 5)) }
            if ($thread.State -in @('Running', 'NotStarted')) { Stop-Job -Job $thread -ErrorAction SilentlyContinue }
            Remove-Job -Job $thread -Force -ErrorAction SilentlyContinue
        }
        $launcherSet.PSObject.Properties[$Launcher].Value = $originalLauncher
        Remove-Item -LiteralPath $uniqueLauncher -Force -ErrorAction SilentlyContinue
    }
}
