Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$testsRoot = Split-Path -Parent $PSCommandPath
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
        [Parameter(Mandatory)] [scriptblock] $Body,
        [string] $VerifiedReason = 'The asserted behavior matched the public contract.'
    )

    try {
        $evidence = & $Body
        Add-WinPrivCapabilityResult -Id $Id -Architecture $Architecture -Status Verified `
            -Reason $VerifiedReason -Evidence $evidence
        return $evidence
    }
    catch {
        Add-WinPrivCapabilityResult -Id $Id -Architecture $Architecture -Status Failed `
            -Reason $_.Exception.Message -Evidence ($_ | Out-String)
        throw
    }
}

function Skip-WinPrivCapability {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Architecture,
        [Parameter(Mandatory)] [string] $Reason,
        [ValidateSet('Unavailable', 'PartiallyVerified')] [string] $Status = 'Unavailable'
    )

    Add-WinPrivCapabilityResult -Id $Id -Architecture $Architecture -Status $Status `
        -Reason $Reason -Evidence $null
    Set-ItResult -Skipped -Because $Reason
}

function Assert-WinPrivInvocationSucceeded {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Invocation)

    $Invocation.TimedOut | Should -BeFalse
    $Invocation.StartError | Should -BeNullOrEmpty
    $Invocation.ExitCode | Should -Be 0
}

function Assert-WinPrivInvocationFailedCleanly {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Invocation)

    $Invocation.TimedOut | Should -BeFalse
    $Invocation.StartError | Should -BeNullOrEmpty
    $Invocation.ExitCode | Should -Not -Be 0
}

function Test-WinPrivInteractiveDesktop {
    if (-not [Environment]::UserInteractive) { return $false }
    if ([Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { return $false }
    if (-not ('WinPrivTests.DialogAutomation' -as [type])) {
        Add-Type -Path (Join-Path $testsRoot 'Support\WinPriv.DialogAutomation.cs')
    }
    return [WinPrivTests.DialogAutomation]::HasInputDesktop()
}

function Get-WinPrivProbeValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Invocation,
        [string] $Property
    )

    $probe = $Invocation.ProbeResult
    if ($null -eq $probe) {
        throw "The probe did not produce structured output. StdOut: $($Invocation.StdOut) StdErr: $($Invocation.StdErr)"
    }
    if ([string]::IsNullOrEmpty($Property)) { return $probe }
    return $probe.$Property
}

. (Join-Path $testsRoot 'Support\WinPriv.TestFunctions.ps1')
