. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')

    if ([string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_BINARY_ROOT)) {
        $env:WINPRIV_TEST_BINARY_ROOT = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Build'))
    }
    if ([string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT)) {
        $env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT = Join-Path (Join-Path $PSScriptRoot 'Native\Build') 'Release'
    }
}

Describe 'WinPriv Direct Descendant API Import Modes (<Architecture>, <Mode>)' -Tag 'Safe', 'ImportModes' -ForEach @(
    @{ Architecture = 'x64'; Executable = 'WinPrivHookImport.exe'; Mode = 'static-import' },
    @{ Architecture = 'x64'; Executable = 'WinPrivHookImport.exe'; Mode = 'static-import-ansi' },
    @{ Architecture = 'x64'; Executable = 'WinPrivHookDelayLoad.exe'; Mode = 'delay-load' },
    @{ Architecture = 'x64'; Executable = 'WinPrivHookDelayLoad.exe'; Mode = 'delay-load-ansi' },
    @{ Architecture = 'x64'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'load-library' },
    @{ Architecture = 'x64'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'load-library-ansi' },
    @{ Architecture = 'x64'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'get-module-handle' },
    @{ Architecture = 'x64'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'get-module-handle-ansi' },
    @{ Architecture = 'x64'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'reload-library' },
    @{ Architecture = 'x86'; Executable = 'WinPrivHookImport.exe'; Mode = 'static-import' },
    @{ Architecture = 'x86'; Executable = 'WinPrivHookImport.exe'; Mode = 'static-import-ansi' },
    @{ Architecture = 'x86'; Executable = 'WinPrivHookDelayLoad.exe'; Mode = 'delay-load' },
    @{ Architecture = 'x86'; Executable = 'WinPrivHookDelayLoad.exe'; Mode = 'delay-load-ansi' },
    @{ Architecture = 'x86'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'load-library' },
    @{ Architecture = 'x86'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'load-library-ansi' },
    @{ Architecture = 'x86'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'get-module-handle' },
    @{ Architecture = 'x86'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'get-module-handle-ansi' },
    @{ Architecture = 'x86'; Executable = 'WinPrivHookDynamic.exe'; Mode = 'reload-library' }
) {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose "direct-$Architecture-$Mode"
        $registryName = "Case$([Guid]::NewGuid().ToString('N'))"
        $subKey = "Software\WinPrivTests\$registryName"
        $providerPath = "Registry::HKEY_CURRENT_USER\$subKey"
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Registry -Identifier $providerPath `
            -OriginalState @{ Existed = $false } -Metadata @{ Purpose = "Direct import mode test: $Mode" } | Out-Null
        New-Item -Path $providerPath -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction SilentlyContinue
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'intercepts registry API queried via <Mode> in direct <Architecture> descendant' {
        $fixturePath = Join-Path $sandbox.Launchers.$Architecture.Root $Executable
        if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
            $fixturePath = Join-Path (Join-Path $env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT $Architecture) $Executable
        }
        Test-Path -LiteralPath $fixturePath -PathType Leaf | Should -BeTrue

        $valueName = 'TestValue'
        $expected = [uint32]0x12345678
        New-ItemProperty -Path $providerPath -Name $valueName -PropertyType DWord -Value 9 -Force | Out-Null

        $result = Invoke-WinPriv -Architecture $Architecture -Sandbox $sandbox -TimeoutSeconds 25 `
            -Arguments @(
                '/RegOverride', "HKCU\$subKey", $valueName, 'REG_DWORD', $expected.ToString(),
                $fixturePath, '--chain-test', '--mode', $Mode, '--key', $subKey, '--value-name', $valueName, '--expected', $expected.ToString()
            )

        Assert-WinPrivInvocationSucceeded $result

        $jsonLines = @($result.StdOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object {
            $_.StartsWith('{"schemaVersion":1,"event":"chain-verification"', [StringComparison]::Ordinal)
        })
        $jsonLines | Should -HaveCount 1
        $payload = $jsonLines[0] | ConvertFrom-Json -ErrorAction Stop
        $payload.arch | Should -Be $Architecture
        $payload.requestedMode | Should -Be $Mode
        $payload.matched | Should -BeTrue
        [uint32]$payload.queriedValue | Should -Be $expected
        [uint32]$payload.expectedValue | Should -Be $expected
    }
}

Describe 'WinPriv 2-Generation Descendant Cross-Architecture (<ParentArch> -> <ChildArch>, <ParentMode> -> <ChildMode>)' -Tag 'Safe', 'CrossArchitecture' -ForEach @(
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x64'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import'; ChildArch = 'x86'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x64'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import'; ChildArch = 'x86'; ChildExe = 'WinPrivHookDelayLoad.exe'; ChildMode = 'delay-load'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x64'; ParentExe = 'WinPrivHookDynamic.exe'; ParentMode = 'load-library'; ChildArch = 'x86'; ChildExe = 'WinPrivHookImport.exe'; ChildMode = 'static-import'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x64'; ParentExe = 'WinPrivHookDynamic.exe'; ParentMode = 'get-module-handle'; ChildArch = 'x86'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library-ansi'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x64'; ParentExe = 'WinPrivHookDynamic.exe'; ParentMode = 'reload-library'; ChildArch = 'x86'; ChildExe = 'WinPrivHookDelayLoad.exe'; ChildMode = 'delay-load-ansi'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x64'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import'; ChildArch = 'x86'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library'; UseCreateProcessA = $true },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x86'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import'; ChildArch = 'x64'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x86'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import'; ChildArch = 'x64'; ChildExe = 'WinPrivHookDelayLoad.exe'; ChildMode = 'delay-load'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x86'; ParentExe = 'WinPrivHookDynamic.exe'; ParentMode = 'load-library'; ChildArch = 'x64'; ChildExe = 'WinPrivHookImport.exe'; ChildMode = 'static-import'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x86'; ParentExe = 'WinPrivHookDynamic.exe'; ParentMode = 'get-module-handle'; ChildArch = 'x64'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library-ansi'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x86'; ParentExe = 'WinPrivHookDynamic.exe'; ParentMode = 'reload-library'; ChildArch = 'x64'; ChildExe = 'WinPrivHookDelayLoad.exe'; ChildMode = 'delay-load-ansi'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x86'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import'; ChildArch = 'x64'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library'; UseCreateProcessA = $true },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x64'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import'; ChildArch = 'x64'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPrivCmd'; ParentArch = 'x86'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import'; ChildArch = 'x86'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library'; UseCreateProcessA = $false },
    @{ Launcher = 'WinPriv';    ParentArch = 'x64'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import'; ChildArch = 'x86'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library'; UseCreateProcessA = $false }
) {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture @('x86', 'x64') -Purpose "chain-2gen-$ParentArch-$ChildArch"
        $registryName = "Case$([Guid]::NewGuid().ToString('N'))"
        $subKey = "Software\WinPrivTests\$registryName"
        $providerPath = "Registry::HKEY_CURRENT_USER\$subKey"
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Registry -Identifier $providerPath `
            -OriginalState @{ Existed = $false } -Metadata @{ Purpose = "2-gen chain test: $ParentArch to $ChildArch" } | Out-Null
        New-Item -Path $providerPath -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction SilentlyContinue
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'injects and intercepts across <ParentArch> (<ParentMode>) and <ChildArch> (<ChildMode>)' {
        $parentFixture = Join-Path (Join-Path $env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT $ParentArch) $ParentExe
        $childFixture = Join-Path (Join-Path $env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT $ChildArch) $ChildExe
        Test-Path -LiteralPath $parentFixture -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $childFixture -PathType Leaf | Should -BeTrue

        $valueName = 'ChainValue'
        $expected = [uint32]0x55443322
        New-ItemProperty -Path $providerPath -Name $valueName -PropertyType DWord -Value 9 -Force | Out-Null

        $chainArgs = @(
            '/RegOverride', "HKCU\$subKey", $valueName, 'REG_DWORD', $expected.ToString(),
            $parentFixture, '--chain-test', '--mode', $ParentMode, '--key', $subKey, '--value-name', $valueName, '--expected', $expected.ToString()
        )
        if ($UseCreateProcessA) {
            $chainArgs += '--use-createprocess-a'
        }
        $chainArgs += @(
            '--next', $childFixture, '--chain-test', '--mode', $ChildMode, '--key', $subKey, '--value-name', $valueName, '--expected', $expected.ToString()
        )

        $result = Invoke-WinPriv -Architecture $ParentArch -Launcher $Launcher -Sandbox $sandbox -TimeoutSeconds 35 `
            -Arguments $chainArgs

        Assert-WinPrivInvocationSucceeded $result

        if ($Launcher -eq 'WinPrivCmd') {
            $jsonLines = @($result.StdOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object {
                $_.StartsWith('{"schemaVersion":1,"event":"chain-verification"', [StringComparison]::Ordinal)
            })
            $jsonLines | Should -HaveCount 2

            $parentPayload = $jsonLines[0] | ConvertFrom-Json -ErrorAction Stop
            $parentPayload.arch | Should -Be $ParentArch
            $parentPayload.requestedMode | Should -Be $ParentMode
            $parentPayload.matched | Should -BeTrue
            [uint32]$parentPayload.queriedValue | Should -Be $expected

            $childPayload = $jsonLines[1] | ConvertFrom-Json -ErrorAction Stop
            $childPayload.arch | Should -Be $ChildArch
            $childPayload.requestedMode | Should -Be $ChildMode
            $childPayload.matched | Should -BeTrue
            [uint32]$childPayload.queriedValue | Should -Be $expected
        }
    }
}

Describe 'WinPriv 3-Generation Descendant Cross-Architecture (<ParentArch> -> <ChildArch> -> <GrandchildArch>)' -Tag 'Safe', 'CrossArchitecture', 'MultiGeneration' -ForEach @(
    @{
        Description     = 'x64 -> x86 -> x64 round-trip with varied import modes (static -> dynamic -> delay)';
        Launcher        = 'WinPrivCmd';
        ParentArch      = 'x64'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import';
        ChildArch       = 'x86'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library';
        GrandchildArch  = 'x64'; GrandchildExe = 'WinPrivHookDelayLoad.exe'; GrandchildMode = 'delay-load';
        UseCreateProcessA = $false
    },
    @{
        Description     = 'x86 -> x64 -> x86 round-trip with varied import modes (dynamic -> delay -> static)';
        Launcher        = 'WinPrivCmd';
        ParentArch      = 'x86'; ParentExe = 'WinPrivHookDynamic.exe'; ParentMode = 'load-library';
        ChildArch       = 'x64'; ChildExe = 'WinPrivHookDelayLoad.exe'; ChildMode = 'delay-load';
        GrandchildArch  = 'x86'; GrandchildExe = 'WinPrivHookImport.exe'; GrandchildMode = 'static-import';
        UseCreateProcessA = $false
    },
    @{
        Description     = 'x64 -> x86 -> x86 cross-architecture branching';
        Launcher        = 'WinPrivCmd';
        ParentArch      = 'x64'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import';
        ChildArch       = 'x86'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library';
        GrandchildArch  = 'x86'; GrandchildExe = 'WinPrivHookDynamic.exe'; GrandchildMode = 'get-module-handle';
        UseCreateProcessA = $false
    },
    @{
        Description     = 'x86 -> x64 -> x64 cross-architecture branching';
        Launcher        = 'WinPrivCmd';
        ParentArch      = 'x86'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import';
        ChildArch       = 'x64'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library';
        GrandchildArch  = 'x64'; GrandchildExe = 'WinPrivHookDynamic.exe'; GrandchildMode = 'reload-library';
        UseCreateProcessA = $false
    },
    @{
        Description     = 'x64 -> x64 -> x86 branching chain';
        Launcher        = 'WinPrivCmd';
        ParentArch      = 'x64'; ParentExe = 'WinPrivHookDelayLoad.exe'; ParentMode = 'delay-load';
        ChildArch       = 'x64'; ChildExe = 'WinPrivHookImport.exe'; ChildMode = 'static-import';
        GrandchildArch  = 'x86'; GrandchildExe = 'WinPrivHookDynamic.exe'; GrandchildMode = 'load-library';
        UseCreateProcessA = $false
    },
    @{
        Description     = 'x86 -> x86 -> x64 branching chain';
        Launcher        = 'WinPrivCmd';
        ParentArch      = 'x86'; ParentExe = 'WinPrivHookDelayLoad.exe'; ParentMode = 'delay-load';
        ChildArch       = 'x86'; ChildExe = 'WinPrivHookImport.exe'; ChildMode = 'static-import';
        GrandchildArch  = 'x64'; GrandchildExe = 'WinPrivHookDynamic.exe'; GrandchildMode = 'load-library';
        UseCreateProcessA = $false
    },
    @{
        Description     = 'x64 -> x64 -> x64 uniform 3-generation chain';
        Launcher        = 'WinPrivCmd';
        ParentArch      = 'x64'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import';
        ChildArch       = 'x64'; ChildExe = 'WinPrivHookDelayLoad.exe'; ChildMode = 'delay-load';
        GrandchildArch  = 'x64'; GrandchildExe = 'WinPrivHookDynamic.exe'; GrandchildMode = 'load-library';
        UseCreateProcessA = $false
    },
    @{
        Description     = 'x86 -> x86 -> x86 uniform 3-generation chain';
        Launcher        = 'WinPrivCmd';
        ParentArch      = 'x86'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import';
        ChildArch       = 'x86'; ChildExe = 'WinPrivHookDelayLoad.exe'; ChildMode = 'delay-load';
        GrandchildArch  = 'x86'; GrandchildExe = 'WinPrivHookDynamic.exe'; GrandchildMode = 'load-library';
        UseCreateProcessA = $false
    },
    @{
        Description     = 'x64 -> (CreateProcessA) -> x86 -> x64 round-trip chain with ANSI child spawn';
        Launcher        = 'WinPrivCmd';
        ParentArch      = 'x64'; ParentExe = 'WinPrivHookImport.exe'; ParentMode = 'static-import';
        ChildArch       = 'x86'; ChildExe = 'WinPrivHookDynamic.exe'; ChildMode = 'load-library';
        GrandchildArch  = 'x64'; GrandchildExe = 'WinPrivHookDelayLoad.exe'; GrandchildMode = 'delay-load';
        UseCreateProcessA = $true
    }
) {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture @('x86', 'x64') -Purpose "chain-3gen-$ParentArch-$ChildArch-$GrandchildArch"
        $registryName = "Case$([Guid]::NewGuid().ToString('N'))"
        $subKey = "Software\WinPrivTests\$registryName"
        $providerPath = "Registry::HKEY_CURRENT_USER\$subKey"
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Registry -Identifier $providerPath `
            -OriginalState @{ Existed = $false } -Metadata @{ Purpose = "3-gen chain test: $Description" } | Out-Null
        New-Item -Path $providerPath -Force | Out-Null
    }

    AfterEach {
        Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction SilentlyContinue
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It "verifies $Description" {
        $parentFixture = Join-Path (Join-Path $env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT $ParentArch) $ParentExe
        $childFixture = Join-Path (Join-Path $env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT $ChildArch) $ChildExe
        $grandchildFixture = Join-Path (Join-Path $env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT $GrandchildArch) $GrandchildExe
        Test-Path -LiteralPath $parentFixture -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $childFixture -PathType Leaf | Should -BeTrue
        Test-Path -LiteralPath $grandchildFixture -PathType Leaf | Should -BeTrue

        $valueName = 'ThreeGenVal'
        $expected = [uint32]0x44556677
        New-ItemProperty -Path $providerPath -Name $valueName -PropertyType DWord -Value 9 -Force | Out-Null

        $chainArgs = @(
            '/RegOverride', "HKCU\$subKey", $valueName, 'REG_DWORD', $expected.ToString(),
            $parentFixture, '--chain-test', '--mode', $ParentMode, '--key', $subKey, '--value-name', $valueName, '--expected', $expected.ToString()
        )
        if ($UseCreateProcessA) {
            $chainArgs += '--use-createprocess-a'
        }
        $chainArgs += @(
            '--next', $childFixture, '--chain-test', '--mode', $ChildMode, '--key', $subKey, '--value-name', $valueName, '--expected', $expected.ToString(),
            '--next', $grandchildFixture, '--chain-test', '--mode', $GrandchildMode, '--key', $subKey, '--value-name', $valueName, '--expected', $expected.ToString()
        )

        $result = Invoke-WinPriv -Architecture $ParentArch -Launcher $Launcher -Sandbox $sandbox -TimeoutSeconds 45 `
            -Arguments $chainArgs

        Assert-WinPrivInvocationSucceeded $result

        $jsonLines = @($result.StdOut -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object {
            $_.StartsWith('{"schemaVersion":1,"event":"chain-verification"', [StringComparison]::Ordinal)
        })
        $jsonLines | Should -HaveCount 3

        $parentPayload = $jsonLines[0] | ConvertFrom-Json -ErrorAction Stop
        $parentPayload.arch | Should -Be $ParentArch
        $parentPayload.requestedMode | Should -Be $ParentMode
        $parentPayload.matched | Should -BeTrue
        [uint32]$parentPayload.queriedValue | Should -Be $expected

        $childPayload = $jsonLines[1] | ConvertFrom-Json -ErrorAction Stop
        $childPayload.arch | Should -Be $ChildArch
        $childPayload.requestedMode | Should -Be $ChildMode
        $childPayload.matched | Should -BeTrue
        [uint32]$childPayload.queriedValue | Should -Be $expected

        $grandchildPayload = $jsonLines[2] | ConvertFrom-Json -ErrorAction Stop
        $grandchildPayload.arch | Should -Be $GrandchildArch
        $grandchildPayload.requestedMode | Should -Be $GrandchildMode
        $grandchildPayload.matched | Should -BeTrue
        [uint32]$grandchildPayload.queriedValue | Should -Be $expected
    }
}
