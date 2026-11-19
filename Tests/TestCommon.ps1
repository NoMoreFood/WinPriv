Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$testsRoot = Split-Path -Parent $PSCommandPath
$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$modulePath = Join-Path $testsRoot 'Modules\WinPriv.TestHarness\WinPriv.TestHarness.psd1'
if (-not (Get-Module WinPriv.TestHarness)) {
    Import-Module $modulePath -Force
}

function Get-WinPrivArchitectureCases {
    $architectures = @(Get-WinPrivTestArchitectures)
    if ($architectures.Count -eq 0) {
        throw 'The runner did not select any runnable WinPriv architectures.'
    }
    return @($architectures | ForEach-Object { @{ Architecture = [string]$_ } })
}

function Invoke-WinPrivCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Architecture,
        [Parameter(Mandatory)] [scriptblock] $Body
    )

    try {
        $evidence = & $Body
        Add-WinPrivCapabilityResult -Id $Id -Architecture $Architecture -Status Verified `
            -Reason 'The asserted behavior matched the public contract.' -Evidence $evidence
        return $evidence
    }
    catch {
        Add-WinPrivCapabilityResult -Id $Id -Architecture $Architecture -Status Failed `
            -Reason $_.Exception.Message -Evidence ($_ | Out-String)
        throw
    }
}

function Invoke-WinPrivCapabilityGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Architecture,
        [Parameter(Mandatory)] [hashtable[]] $Cases
    )

    $failures = [Collections.Generic.List[string]]::new()
    foreach ($case in $Cases) {
        try { Invoke-WinPrivCapability -Id $case.Id -Architecture $Architecture -Body $case.Body | Out-Null }
        catch { [void]$failures.Add("$($case.Id): $($_.Exception.Message)") }
    }
    if ($failures.Count -gt 0) { throw ($failures -join "`n") }
}

function Skip-WinPrivCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Architecture,
        [Parameter(Mandatory)] [string] $Reason,
        [ValidateSet('Unavailable', 'PartiallyVerified')] [string] $Status = 'Unavailable'
    )

    Add-WinPrivCapabilityResult -Id $Id -Architecture $Architecture -Status $Status -Reason $Reason -Evidence $null
    Set-ItResult -Skipped -Because $Reason
}

function Skip-WinPrivCapabilities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $Ids,
        [Parameter(Mandatory)] [string] $Architecture,
        [Parameter(Mandatory)] [string] $Reason,
        [ValidateSet('Unavailable', 'PartiallyVerified')] [string] $Status = 'Unavailable'
    )

    # Record secondary IDs directly so only the primary Skip-WinPrivCapability call emits an expected-skip event.
    for ($index = 1; $index -lt $Ids.Count; $index++) {
        Add-WinPrivCapabilityResult -Id $Ids[$index] -Architecture $Architecture -Status $Status `
            -Reason $Reason -Evidence $null | Out-Null
    }
    Skip-WinPrivCapability -Id $Ids[0] -Architecture $Architecture -Reason $Reason -Status $Status
}

function Test-WinPrivProbeSupported {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Invocation,
        [Parameter(Mandatory)] [string[]] $CapabilityIds,
        [Parameter(Mandatory)] [string] $Architecture
    )

    if ($Invocation.ProbeResult.supported) { return $true }
    $reason = [string]$Invocation.ProbeResult.reason
    if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'The probe reported this surface as unavailable.' }
    Skip-WinPrivCapabilities -Ids $CapabilityIds -Architecture $Architecture -Reason $reason
    return $false
}

function Assert-WinPrivInvocationSucceeded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Invocation,
        [int] $ExpectedExitCode = 0
    )

    $Invocation.TimedOut | Should -BeFalse
    $Invocation.StartError | Should -BeNullOrEmpty
    $Invocation.ExitCode | Should -Be $ExpectedExitCode
}

function Assert-WinPrivInvocationFailedCleanly {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Invocation)

    $Invocation.TimedOut | Should -BeFalse
    $Invocation.StartError | Should -BeNullOrEmpty
    $Invocation.ExitCode | Should -Not -Be 0
}

function Resolve-WinPrivNativeFixture {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Sandbox,
        [Parameter(Mandatory)] [string] $Architecture,
        [string] $Name = 'WinPrivHookDynamic.exe'
    )

    $path = Join-Path $Sandbox.Launchers.$Architecture.Root $Name
    if (Test-Path -LiteralPath $path -PathType Leaf) { return $path }
    return $null
}

function Invoke-WinPrivNativeFixtureCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Architecture,
        [Parameter(Mandatory)] $Sandbox,
        [Parameter(Mandatory)] [scriptblock] $Body,
        [string] $FixtureName = 'WinPrivHookDynamic.exe'
    )

    $fixture = Resolve-WinPrivNativeFixture -Sandbox $Sandbox -Architecture $Architecture -Name $FixtureName
    if ($null -eq $fixture) {
        Skip-WinPrivCapability -Id $Id -Architecture $Architecture `
            -Reason "The native $Architecture fixture '$FixtureName' is not present in this build."
        return
    }
    Invoke-WinPrivCapability -Id $Id -Architecture $Architecture -Body { & $Body $fixture } | Out-Null
}

function Get-WinPrivFixturePayloads {
    param([AllowNull()] [string] $Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    return @($Text -split '\r?\n' | Where-Object { $_.TrimStart().StartsWith('{') } | ForEach-Object { $_ | ConvertFrom-Json })
}

function New-WinPrivTestRegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Sandbox,
        [switch] $Policy,
        [string] $CaseId = [guid]::NewGuid().ToString('N'),
        [string] $Suffix = '',
        [hashtable] $Values
    )

    $subKey = if ($Policy) { "Software\Policies\WinPrivTests\$CaseId" }
              else { "Software\WinPrivTests\Case$CaseId$Suffix" }
    $providerPath = "Registry::HKEY_CURRENT_USER\$subKey"
    Add-WinPrivCleanupJournalEntry -Sandbox $Sandbox -Kind Registry -Identifier $providerPath `
        -OriginalState @{ Existed = $false } | Out-Null
    New-Item -Path $providerPath -Force | Out-Null
    if ($null -ne $Values) {
        foreach ($entry in $Values.GetEnumerator()) {
            New-ItemProperty -Path $providerPath -Name $entry.Key -Value $entry.Value -Force | Out-Null
        }
    }
    return [pscustomobject]@{
        CaseId       = $CaseId
        SubKey       = $subKey
        ProviderPath = $providerPath
        FullPath     = "HKEY_CURRENT_USER\$subKey"
    }
}

function Test-WinPrivInteractiveDesktop {
    if (-not [Environment]::UserInteractive) { return $false }
    if ([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { return $false }
    if (-not ('WinPrivTests.DialogAutomation' -as [type])) {
        Add-Type -Path (Join-Path $testsRoot 'Support\WinPriv.DialogAutomation.cs')
    }
    return [WinPrivTests.DialogAutomation]::HasInputDesktop()
}

. (Join-Path $testsRoot 'Support\WinPriv.TestFunctions.ps1')
