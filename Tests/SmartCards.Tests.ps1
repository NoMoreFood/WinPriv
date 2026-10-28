. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')

    function Assert-LocalSmartCardContext {
        param($Reading, $Baseline)
        $Reading.sessionId | Should -Be $Baseline.sessionId
        $Reading.capabilitySuccess | Should -Be $Baseline.capabilitySuccess
        $Reading.capabilities | Should -Be $Baseline.capabilities
        $Reading.invalidReservedStatus | Should -Be 0x80100011L
        @($Reading.contexts) | Should -HaveCount 2
        foreach ($context in $Reading.contexts) {
            $context.contextStatus | Should -Be 0
            $context.validContextStatus | Should -Be 0
            $context.releaseStatus | Should -Be 0
            $context.listStatus | Should -BeIn @(0, 0x8010002EL)
        }
    }
}

$architectureCases = Get-WinPrivArchitectureCases

Describe 'WinPriv local hardware tokens (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeAll {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
        $baseline = Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $sandbox -Operation smart-cards
        Assert-WinPrivInvocationSucceeded $baseline
    }
    AfterAll { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'adapts signing to local and remote reconnects within the same process' {
        $fixture = Join-Path $sandbox.Launchers.$Architecture.Root 'WinPrivHookDynamic.exe'
        if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
            Skip-WinPrivCapability -Id 'smartcard.session-routing' -Architecture $Architecture `
                -Reason 'The native hook-loading fixture is absent from the supplied binary root.'
            return
        }
        Invoke-WinPrivCapability -Id 'smartcard.session-routing' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivContainedProcess -FilePath $fixture -Sandbox $sandbox `
                -WorkingDirectory $sandbox.Working -TimeoutSeconds 25 -ArgumentList @('--smartcard-session-routing')
            Assert-WinPrivInvocationSucceeded $result
            $payload = $result.StdOut | ConvertFrom-Json -ErrorAction Stop
            $payload.sessionChecks | Should -Be 9
            $payload.signingCalls | Should -Be 10
            return $payload
        }
    }

    It 'preserves software-key signing, silent flags, and invalid-handle errors without prompting' {
        Invoke-WinPrivCapability -Id 'smartcard.signing-pass-through' -Architecture $Architecture -Body {
            $native = Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $sandbox -Operation software-signing
            $local = Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $sandbox -Operation software-signing `
                -WinPrivArguments @('/UseConsoleToken')
            Assert-WinPrivInvocationSucceeded $native
            Assert-WinPrivInvocationSucceeded $local
            $local.ProbeResult.result.invalidHandleStatus | Should -Not -Be 0
            $local.ProbeResult.result.invalidHandleStatus | Should -Be $native.ProbeResult.result.invalidHandleStatus
            foreach ($invocation in @($native, $local)) {
                @($invocation.ProbeResult.result.signatures) | Should -HaveCount 2
                foreach ($signature in $invocation.ProbeResult.result.signatures) {
                    $signature.sizeStatus | Should -Be 0
                    $signature.signStatus | Should -Be 0
                    $signature.verified | Should -BeTrue
                }
            }
            return $local.ProbeResult.result
        }
    }

    It 'uses local contexts while preserving ordinary session queries and WinSCard validation' {
        if ((Get-Service SCardSvr).Status -ne 'Running') {
            Skip-WinPrivCapability -Id 'smartcard.local' -Architecture $Architecture `
                -Reason 'The local Smart Card service is not running.'
            return
        }
        Invoke-WinPrivCapability -Id 'smartcard.local' -Architecture $Architecture -Body {
            foreach ($launcher in @('WinPrivCmd', 'WinPriv')) {
                $local = Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $sandbox -Launcher $launcher `
                    -WinPrivArguments @('/uSeCoNsOlEtOkEn') -Operation smart-cards
                Assert-WinPrivInvocationSucceeded $local
                Assert-LocalSmartCardContext -Reading $local.ProbeResult.result -Baseline $baseline.ProbeResult.result
            }

            $reset = Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $sandbox -Operation smart-cards `
                -Environment @{ _WINPRIV_EV_CONSOLE_TOKEN_ = '1' }
            Assert-WinPrivInvocationSucceeded $reset
            $reset.ProbeResult.result.contexts.contextStatus |
                Should -Be $baseline.ProbeResult.result.contexts.contextStatus
            return $local.ProbeResult.result
        }
    }

    It 'preserves local reader routing in descendants with custom ANSI and Unicode environments' {
        if ((Get-Service SCardSvr).Status -ne 'Running') {
            Skip-WinPrivCapability -Id 'smartcard.propagation' -Architecture $Architecture `
                -Reason 'The local Smart Card service is not running.'
            return
        }
        Invoke-WinPrivCapability -Id 'smartcard.propagation' -Architecture $Architecture -Body {
            foreach ($api in @('A', 'W')) {
                $child = Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $sandbox -TimeoutSeconds 60 `
                    -WinPrivArguments @('/UseConsoleToken') -Operation create-process -Arguments @{
                        api = $api; depth = 2; childOperation = 'smart-cards'; childArguments = @{}
                        customEnvironment = @{}; mergeEnvironment = $false
                    }
                Assert-WinPrivInvocationSucceeded $child
                $child.ProbeResult.result.childResult.success | Should -BeTrue
                $descendant = $child.ProbeResult.result.childResult.result.childResult
                $descendant.success | Should -BeTrue
                Assert-LocalSmartCardContext -Reading $descendant.result -Baseline $baseline.ProbeResult.result
            }
            return @{ CreateProcessApis = @('A', 'W'); Depth = 2; CustomEnvironment = $true }
        }
    }
}
