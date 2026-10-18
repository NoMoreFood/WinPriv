. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')

    function Test-WinPrivDynamicCodeSupport {
        param($Sandbox, [string] $Fixture, [string] $Architecture, [string] $Capability, [switch] $AllowOptOut)

        $mode = if ($AllowOptOut) { 'optout' } else { 'strict' }
        $result = Invoke-WinPrivContainedProcess -FilePath $Fixture -Sandbox $Sandbox `
            -WorkingDirectory $Sandbox.Working -TimeoutSeconds 25 `
            -ArgumentList @('--dynamic-code-capability', $mode)
        Assert-WinPrivInvocationSucceeded $result
        $payload = $result.StdOut | ConvertFrom-Json -ErrorAction Stop
        $payload.capability | Should -Be 'dynamic-code'
        if ($payload.processDynamicCode -eq 0) {
            $payload.allowThreadOptOut | Should -Be 0
            $payload.allocationSucceeded | Should -BeTrue
            $payload.allocationError | Should -Be 0
            $reason = "Windows did not enable ACG in the unhooked $Architecture fixture ($mode): " +
                'the process policy remained disabled and executable allocation succeeded before any Detours call.'
            Skip-WinPrivCapability -Id $Capability -Architecture $Architecture -Reason $reason
            return $false
        }
        $payload.processDynamicCode | Should -Be 1
        $payload.allowThreadOptOut | Should -Be ([int][bool]$AllowOptOut)
        $payload.allocationSucceeded | Should -BeFalse
        $payload.allocationError | Should -Be 1655
        return $true
    }
}

$loadingCases = foreach ($architectureCase in Get-WinPrivArchitectureCases) {
    foreach ($mode in @(
        @{ Name = 'normal-import'; Executable = 'WinPrivHookImport.exe'; Capability = 'detour.load-time-import' },
        @{ Name = 'delay-load'; Executable = 'WinPrivHookDelayLoad.exe'; Capability = 'detour.delay-load-import' },
        @{ Name = 'load-library'; Executable = 'WinPrivHookDynamic.exe'; Capability = 'detour.loadlibrary-getprocaddress' }
    )) {
        @{
            Architecture = [string]$architectureCase.Architecture
            Mode = [string]$mode.Name
            Executable = [string]$mode.Executable
            Capability = [string]$mode.Capability
        }
    }
}

Describe 'WinPriv explicit detour loading paths (<Architecture>, <Mode>)' -Tag 'Safe' -ForEach $loadingCases {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose "hook-loading-$Mode"
        $registryName = "Case$([Guid]::NewGuid().ToString('N'))"
        $subKey = "Software\WinPrivTests\$registryName"
        $providerPath = "Registry::HKEY_CURRENT_USER\$subKey"
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Registry -Identifier $providerPath `
            -OriginalState @{ Existed = $false } -Metadata @{ Purpose = "Hook loading fixture: $Mode" } | Out-Null
        New-Item -Path $providerPath -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction SilentlyContinue
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'intercepts RegQueryValueExW resolved through <Mode>' {
        $fixture = Join-Path $sandbox.Launchers.$Architecture.Root $Executable
        if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
            Skip-WinPrivCapability -Id $Capability -Architecture $Architecture `
                -Reason "The native hook-loading fixture '$Executable' is absent from the supplied binary root."
            return
        }

        Invoke-WinPrivCapability -Id $Capability -Architecture $Architecture -Body {
            $valueName = 'LoadingPathValue'
            $expected = [uint32]0x12345678
            New-ItemProperty -Path $providerPath -Name $valueName -PropertyType DWord -Value 9 -Force | Out-Null

            $result = Invoke-WinPriv -Architecture $Architecture -Sandbox $sandbox -TimeoutSeconds 25 `
                -Arguments @(
                    '/RegOverride', "HKCU\$subKey", $valueName, 'REG_DWORD', $expected.ToString(),
                    $fixture, $subKey, $valueName
                )
            Assert-WinPrivInvocationSucceeded $result

            $jsonLines = @($result.StdOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object {
                $_.StartsWith('{"schemaVersion":1,', [StringComparison]::Ordinal)
            })
            $jsonLines | Should -HaveCount 1
            $payload = $jsonLines[0] | ConvertFrom-Json -ErrorAction Stop
            $payload.mode | Should -Be $Mode
            [uint32]$payload.value | Should -Be $expected

            return [ordered]@{
                Executable = $Executable
                Mode = $payload.mode
                OriginalValue = 9
                DetouredValue = [uint32]$payload.value
            }
        }
    }
}

Describe 'WinPriv process mitigations (<Architecture>)' -Tag 'Safe' -ForEach (Get-WinPrivArchitectureCases) {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose 'process-mitigations'
        $fixture = Join-Path $sandbox.Launchers.$Architecture.Root 'WinPrivHookDynamic.exe'
    }

    AfterEach {
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'loads its hooks and overrides a child registry query under strict CFG' {
        if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
            Skip-WinPrivCapability -Id 'mitigation.strict-cfg' -Architecture $Architecture `
                -Reason 'The native hook-loading fixture is absent from the supplied binary root.'
            return
        }

        Invoke-WinPrivCapability -Id 'mitigation.strict-cfg' -Architecture $Architecture -Body {
            $subKey = "Software\WinPrivTests\Case$([Guid]::NewGuid().ToString('N'))"
            $providerPath = "Registry::HKEY_CURRENT_USER\$subKey"
            Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Registry -Identifier $providerPath `
                -OriginalState @{ Existed = $false } -Metadata @{ Purpose = 'Strict CFG hook loading' } | Out-Null
            try {
                New-Item -Path $providerPath -Force | Out-Null
                New-ItemProperty -Path $providerPath -Name 'MitigationValue' -PropertyType DWord -Value 9 | Out-Null
                foreach ($scope in @('launcher', 'target')) {
                    $launcher = $sandbox.Launchers.$Architecture.WinPrivCmd
                    $overrideArguments = @(
                        '/RegOverride', "HKCU\$subKey", 'MitigationValue', 'REG_DWORD', '305419896'
                    )
                    $queryArguments = @($fixture, $subKey, 'MitigationValue')
                    $filePath = if ($scope -eq 'launcher') { $fixture } else { $launcher }
                    $arguments = if ($scope -eq 'launcher') {
                        @('--launch-mitigation', 'strict-cfg', $launcher) + $overrideArguments + $queryArguments
                    }
                    else {
                        $overrideArguments + @($fixture, '--launch-mitigation', 'strict-cfg') + $queryArguments
                    }
                    $result = Invoke-WinPrivContainedProcess -FilePath $filePath -Sandbox $sandbox `
                        -WorkingDirectory $sandbox.Working -TimeoutSeconds 25 -CreateHiddenConsole `
                        -ArgumentList $arguments
                    Assert-WinPrivInvocationSucceeded $result
                    $payloads = @($result.StdOut -split '\r?\n' | Where-Object {
                        $_.StartsWith('{"schemaVersion":1,', [StringComparison]::Ordinal)
                    } | ConvertFrom-Json -ErrorAction Stop)
                    $payloads | Should -HaveCount 2 -Because $scope
                    $payloads[0].mitigation | Should -Be 'strict-cfg' -Because $scope
                    $payloads[0].enforced | Should -BeTrue -Because $scope
                    $payloads[1].mode | Should -Be 'load-library' -Because $scope
                    [uint32]$payloads[1].value | Should -Be 305419896 -Because $scope
                    (Get-ItemPropertyValue -LiteralPath $providerPath -Name 'MitigationValue') | Should -Be 9
                    @{ Scope = $scope; Policy = $payloads[0]; Registry = $payloads[1] }
                }
            }
            finally {
                Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'keeps process ACG enabled while hooking opted-in launchers, targets, and descendants' {
        if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
            Skip-WinPrivCapability -Id 'mitigation.dynamic-code-optout-propagation' -Architecture $Architecture `
                -Reason 'The native hook-loading fixture is absent from the supplied binary root.'
            return
        }
        if (-not (Test-WinPrivDynamicCodeSupport -Sandbox $sandbox -Fixture $fixture -Architecture $Architecture `
            -Capability 'mitigation.dynamic-code-optout-propagation' -AllowOptOut)) { return }

        Invoke-WinPrivCapability -Id 'mitigation.dynamic-code-optout-propagation' -Architecture $Architecture -Body {
            $subKey = "Software\WinPrivTests\Case$([Guid]::NewGuid().ToString('N'))"
            $providerPath = "Registry::HKEY_CURRENT_USER\$subKey"
            Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Registry -Identifier $providerPath `
                -OriginalState @{ Existed = $false } -Metadata @{ Purpose = 'Scoped ACG hook propagation' } | Out-Null
            try {
                New-Item -Path $providerPath -Force | Out-Null
                New-ItemProperty -Path $providerPath -Name 'MitigationValue' -PropertyType DWord -Value 9 | Out-Null
                foreach ($scope in @('launcher', 'target')) {
                    $launcher = $sandbox.Launchers.$Architecture.WinPrivCmd
                    $launchArguments = @(
                        '/RegOverride', "HKCU\$subKey", 'MitigationValue', 'REG_DWORD', '305419896',
                        $fixture, '--launch-mitigation', 'dynamic-code-optout',
                        $fixture, '--query-descendant', $subKey, 'MitigationValue'
                    )
                    $filePath = if ($scope -eq 'launcher') { $fixture } else { $launcher }
                    $arguments = if ($scope -eq 'launcher') {
                        @('--launch-mitigation', 'dynamic-code-optout', $launcher) + $launchArguments
                    }
                    else { $launchArguments }
                    $result = Invoke-WinPrivContainedProcess -FilePath $filePath -Sandbox $sandbox `
                        -WorkingDirectory $sandbox.Working -TimeoutSeconds 35 -CreateHiddenConsole `
                        -ArgumentList $arguments
                    Assert-WinPrivInvocationSucceeded $result
                    $payloads = @($result.StdOut -split '\r?\n' | Where-Object {
                        $_.StartsWith('{"schemaVersion":1,', [StringComparison]::Ordinal)
                    } | ConvertFrom-Json -ErrorAction Stop)
                    $policies = @($payloads | Where-Object { $_.PSObject.Properties.Name -contains 'mitigation' })
                    $queries = @($payloads | Where-Object { $_.PSObject.Properties.Name -contains 'mode' })
                    $policies | Should -HaveCount $(if ($scope -eq 'launcher') { 3 } else { 2 }) -Because $scope
                    foreach ($policy in $policies) {
                        $policy.mitigation | Should -Be 'dynamic-code-optout' -Because $scope
                        $policy.enforced | Should -BeTrue -Because $scope
                    }
                    $queries | Should -HaveCount 2 -Because $scope
                    foreach ($query in $queries) {
                        $query.mode | Should -Be 'load-library' -Because $scope
                        [uint32]$query.value | Should -Be 305419896 -Because $scope
                        $query.processDynamicCode | Should -Be 1 -Because $scope
                        $query.allowThreadOptOut | Should -Be 1 -Because $scope
                        $query.threadDynamicCode | Should -Be 0 -Because $scope
                    }
                    (Get-ItemPropertyValue -LiteralPath $providerPath -Name 'MitigationValue') | Should -Be 9
                    @{ Scope = $scope; Policies = $policies; Queries = $queries }
                }
            }
            finally {
                Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'restores the caller thread policy across transaction completion and failure paths' {
        if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
            Skip-WinPrivCapability -Id 'mitigation.dynamic-code-optout-transactions' -Architecture $Architecture `
                -Reason 'The native hook-loading fixture is absent from the supplied binary root.'
            return
        }
        if (-not (Test-WinPrivDynamicCodeSupport -Sandbox $sandbox -Fixture $fixture -Architecture $Architecture `
            -Capability 'mitigation.dynamic-code-optout-transactions' -AllowOptOut)) { return }

        Invoke-WinPrivCapability -Id 'mitigation.dynamic-code-optout-transactions' -Architecture $Architecture -Body {
            foreach ($scenario in @('attach', 'abort', 'failed-commit', 'nested', 'preexisting', 'c-bridge')) {
                $result = Invoke-WinPrivContainedProcess -FilePath $fixture -Sandbox $sandbox `
                    -WorkingDirectory $sandbox.Working -TimeoutSeconds 25 `
                    -ArgumentList @('--dynamic-code-optout', $scenario)
                Assert-WinPrivInvocationSucceeded $result
                $payload = $result.StdOut | ConvertFrom-Json -ErrorAction Stop
                $expectedPolicy = if ($scenario -eq 'preexisting') { 1 } else { 0 }
                $payload.scenario | Should -Be $scenario
                $payload.processDynamicCode | Should -Be 1 -Because $scenario
                $payload.allowThreadOptOut | Should -Be 1 -Because $scenario
                $payload.threadBefore | Should -Be $expectedPolicy -Because $scenario
                if ($scenario -ne 'c-bridge') { $payload.threadDuring | Should -Be 1 -Because $scenario }
                $payload.threadAfterScope | Should -Be $expectedPolicy -Because $scenario
                $payload.attachError | Should -Be 0 -Because $scenario
                $payload.trampolineValue | Should -Be 40 -Because $scenario
                $payload.originalPointer | Should -Be ($scenario -in @('abort', 'failed-commit')) -Because $scenario
                if ($scenario -ne 'abort') {
                    $payload.threadAfterCommit | Should -Be $expectedPolicy -Because $scenario
                }
                if ($scenario -eq 'failed-commit') {
                    $payload.invalidApplyError | Should -Be 6
                    $payload.commitError | Should -Be 6
                }
                elseif ($scenario -ne 'abort') {
                    $payload.commitError | Should -Be 0 -Because $scenario
                    $payload.hookedValue | Should -Be 66 -Because $scenario
                }
                if ($scenario -in @('abort', 'failed-commit')) {
                    $payload.hookedValue | Should -Be 40 -Because $scenario
                }
                if ($scenario -eq 'c-bridge') {
                    $payload.invalidApplyError | Should -Be 6
                    $payload.threadAfterInvalid | Should -Be 0
                    $payload.invalidPointerUnchanged | Should -BeTrue
                }
                if ($scenario -eq 'nested') {
                    $payload.nestedActive | Should -BeFalse
                    $payload.nestedCommitError | Should -Be 4317
                    $payload.threadAfterNested | Should -Be 0
                }
                $payload
            }
        }
    }

    It 'identifies a dynamic-code policy that prevents hook installation' {
        if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
            Skip-WinPrivCapability -Id 'mitigation.dynamic-code-diagnostic' -Architecture $Architecture `
                -Reason 'The native hook-loading fixture is absent from the supplied binary root.'
            return
        }
        if (-not (Test-WinPrivDynamicCodeSupport -Sandbox $sandbox -Fixture $fixture -Architecture $Architecture `
            -Capability 'mitigation.dynamic-code-diagnostic')) { return }

        Invoke-WinPrivCapability -Id 'mitigation.dynamic-code-diagnostic' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivContainedProcess -FilePath $fixture -Sandbox $sandbox `
                -WorkingDirectory $sandbox.Working -TimeoutSeconds 25 -CreateHiddenConsole -ArgumentList @(
                    '--launch-mitigation', 'dynamic-code', $sandbox.Launchers.$Architecture.WinPrivCmd,
                    $fixture, 'Software\WinPrivTests', 'AbsentValue'
                )
            Assert-WinPrivInvocationFailedCleanly $result
            $result.ExitCode | Should -Be 1655
            $output = $result.StdOut + $result.StdErr
            $output | Should -Match '"mitigation":"dynamic-code","enforced":true'
            $output | Should -Match 'dynamic-code policy \(ACG\) prohibits WinPriv API hooks \(error 1655\)'
            $output | Should -Not -Match '"mode":"load-library"'
            return @{ ExitCode = $result.ExitCode; Output = $output }
        }
    }

    It 'preserves the dynamic-code allocation error and leaves its target unchanged' {
        if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
            Skip-WinPrivCapability -Id 'mitigation.dynamic-code-allocation' -Architecture $Architecture `
                -Reason 'The native hook-loading fixture is absent from the supplied binary root.'
            return
        }
        if (-not (Test-WinPrivDynamicCodeSupport -Sandbox $sandbox -Fixture $fixture -Architecture $Architecture `
            -Capability 'mitigation.dynamic-code-allocation')) { return }

        Invoke-WinPrivCapability -Id 'mitigation.dynamic-code-allocation' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivContainedProcess -FilePath $fixture -Sandbox $sandbox `
                -WorkingDirectory $sandbox.Working -TimeoutSeconds 25 -ArgumentList @('--dynamic-code-allocation')
            Assert-WinPrivInvocationSucceeded $result
            $payload = $result.StdOut | ConvertFrom-Json -ErrorAction Stop
            $payload.mitigation | Should -Be 'dynamic-code'
            $payload.enforced | Should -BeTrue
            $payload.attachError | Should -Be 1655
            $payload.commitError | Should -Be 1655
            $payload.originalPointer | Should -BeTrue
            $payload.value | Should -Be 40
            return $payload
        }
    }
}

Describe 'WinPriv transaction thread enumeration (<Architecture>)' -Tag 'Safe' -ForEach (Get-WinPrivArchitectureCases) {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose 'thread-enumeration'
        $fixture = Join-Path $sandbox.Launchers.$Architecture.Root 'WinPrivHookDynamic.exe'
    }

    AfterEach {
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'safely completes transactions with <Scenario>' -ForEach @(
        @{ Scenario = 'churn' }, @{ Scenario = 'heap-lock' }, @{ Scenario = 'inaccessible' }
    ) {
        $capability = "detour.thread-$Scenario"
        if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
            Skip-WinPrivCapability -Id $capability -Architecture $Architecture `
                -Reason 'The native transaction fixture is absent from the supplied binary root.'
            return
        }

        Invoke-WinPrivCapability -Id $capability -Architecture $Architecture -Body {
            if ($Scenario -eq 'churn') {
                $result = Invoke-WinPriv -Architecture $Architecture -Sandbox $sandbox -TimeoutSeconds 30 `
                    -Arguments @('/FileRedirect', (Join-Path $sandbox.Working 'source'),
                        (Join-Path $sandbox.Working 'destination'), $fixture, '--thread-enumeration', $Scenario)
            }
            else {
                $result = Invoke-WinPrivContainedProcess -FilePath $fixture -Sandbox $sandbox `
                    -WorkingDirectory $sandbox.Working -TimeoutSeconds 30 -ArgumentList @('--thread-enumeration', $Scenario)
            }
            Assert-WinPrivInvocationSucceeded $result
            $payload = $result.StdOut | ConvertFrom-Json -ErrorAction Stop
            $payload.scenario | Should -Be $Scenario
            $payload.calls | Should -BeGreaterThan 0
            $payload.invalidValues | Should -Be 0
            $payload.originalPointer | Should -Be ($Scenario -eq 'inaccessible')
            $payload.finalValue | Should -Be $(if ($Scenario -eq 'inaccessible') { 40 } else { 66 })
            if ($Scenario -eq 'inaccessible') {
                $payload.commitError | Should -Be 5
                $payload.iterations | Should -Be 0
            }
            else {
                $payload.commitError | Should -Be 0
                $payload.iterations | Should -Be 32
            }
            if ($Scenario -eq 'churn') { $payload.createdThreads | Should -BeGreaterThan 0 }
            return $payload
        }
    }
}

Describe 'WinPriv combined hook installation (<Architecture>)' -Tag 'Safe' -ForEach (Get-WinPrivArchitectureCases) {
    BeforeAll { $sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose 'combined-hooks' }
    AfterAll { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'installs all feature hook groups in a single transaction' {
        $options = @(
            '/MacOverride', '00-11-22-33-44-55', '/MockTime', '+1h',
            '/RegOverride', 'HKCU\Software', 'WinPrivTest', 'REG_DWORD', '1',
            '/AmsiOff', '/ClmOff', '/HostOverride', 'winpriv.invalid', 'localhost',
            '/FileRedirect', (Join-Path $sandbox.Working 'source'), (Join-Path $sandbox.Working 'destination'),
            '/AdminImpersonate', '/ServerEdition', '/RecordCrypto', (Join-Path $sandbox.Root 'records'),
            '/SqlConnectSearchReplace', 'ORIGINAL', 'REPLACED'
        )
        $fixture = Join-Path $sandbox.Launchers.$Architecture.Root 'WinPrivHookDynamic.exe'
        $marker = Join-Path $sandbox.Artifacts 'combined-hooks-started.txt'
        $result = Invoke-WinPriv -Architecture $Architecture -Sandbox $sandbox -TimeoutSeconds 30 `
            -Arguments ($options + @($fixture, '--startup-timestamp', $marker))
        Assert-WinPrivInvocationSucceeded $result
        $marker | Should -Exist
    }
}

Describe 'WinPriv memory image exception handling (<Architecture>)' -Tag 'Safe' -ForEach (Get-WinPrivArchitectureCases) {
    BeforeAll { $sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose 'memory-exceptions' }
    AfterAll { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'recovers from repeated hook exceptions on concurrent threads' {
        $fixture = Join-Path $sandbox.Launchers.$Architecture.Root 'WinPrivHookDynamic.exe'
        $fixture | Should -Exist
        foreach ($pattern in @('[unterminated', '(unclosed', '[z-a]', '*invalid')) {
            $result = Invoke-WinPriv -Architecture $Architecture -Sandbox $sandbox -TimeoutSeconds 30 `
                -Arguments @('/SqlConnectSearchReplace', $pattern, 'replacement', $fixture, '--memory-exceptions')
            Assert-WinPrivInvocationSucceeded $result
            ($result.StdOut | ConvertFrom-Json).completed | Should -Be 100
        }
    }
}

Describe 'WinPriv detour rejection (<Architecture>)' -Tag 'Safe' -ForEach (Get-WinPrivArchitectureCases) {
    BeforeAll { $sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose 'rejected-detours' }
    AfterAll { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'rejects invalid hooks without publishing pending hooks or changing code protections' {
        $fixture = Join-Path $sandbox.Launchers.$Architecture.Root 'WinPrivHookDynamic.exe'
        if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
            Skip-WinPrivCapability -Id 'detour.rejected-hooks' -Architecture $Architecture `
                -Reason 'The native hook-loading fixture is absent from the supplied binary root.'
            return
        }
        Invoke-WinPrivCapability -Id 'detour.rejected-hooks' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivContainedProcess -FilePath $fixture -Sandbox $sandbox `
                -WorkingDirectory $sandbox.Working -TimeoutSeconds 25 -ArgumentList @('--rejected-detours')
            Assert-WinPrivInvocationSucceeded $result
            ($result.StdOut | ConvertFrom-Json).rejectedCases | Should -Be $(if ($Architecture -eq 'ARM64') { 3 } else { 5 })
        }
    }
}
