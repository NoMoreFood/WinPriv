. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')
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
