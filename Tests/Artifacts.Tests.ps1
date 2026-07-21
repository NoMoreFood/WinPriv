. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')
}

Describe 'WinPriv build artifacts' -Tag 'Safe' {
    BeforeAll {
        $binaryRoot = [IO.Path]::GetFullPath($env:WINPRIV_TEST_BINARY_ROOT)
        $expected = @{
            x86   = @{ Directory = 'x86'; Machine = 0x014C }
            x64   = @{ Directory = 'x64'; Machine = 0x8664 }
            ARM64 = @{ Directory = 'ARM64'; Machine = 0xAA64 }
        }
    }

    It 'contains matching configured launchers for x86' {
        Invoke-WinPrivCapability -Id 'artifact.build-x86' -Architecture x86 -Body {
            $directory = Join-Path $binaryRoot $expected.x86.Directory
            $paths = @((Join-Path $directory 'WinPriv.exe'), (Join-Path $directory 'WinPrivCmd.exe'))
            foreach ($path in $paths) {
                $path | Should -Exist
                (Get-PeMachine $path) | Should -Be $expected.x86.Machine
            }
            ([Diagnostics.FileVersionInfo]::GetVersionInfo($paths[0]).FileVersion) |
                Should -Be ([Diagnostics.FileVersionInfo]::GetVersionInfo($paths[1]).FileVersion)
            return $paths
        }
    }

    It 'contains matching configured launchers for x64' {
        Invoke-WinPrivCapability -Id 'artifact.build-x64' -Architecture x64 -Body {
            $directory = Join-Path $binaryRoot $expected.x64.Directory
            $paths = @((Join-Path $directory 'WinPriv.exe'), (Join-Path $directory 'WinPrivCmd.exe'))
            foreach ($path in $paths) {
                $path | Should -Exist
                (Get-PeMachine $path) | Should -Be $expected.x64.Machine
            }
            ([Diagnostics.FileVersionInfo]::GetVersionInfo($paths[0]).FileVersion) |
                Should -Be ([Diagnostics.FileVersionInfo]::GetVersionInfo($paths[1]).FileVersion)
            return $paths
        }
    }

    It 'contains matching configured launchers for ARM64' {
        Invoke-WinPrivCapability -Id 'artifact.build-arm64' -Architecture ARM64 -Body {
            $directory = Join-Path $binaryRoot $expected.ARM64.Directory
            $paths = @((Join-Path $directory 'WinPriv.exe'), (Join-Path $directory 'WinPrivCmd.exe'))
            foreach ($path in $paths) {
                $path | Should -Exist
                (Get-PeMachine $path) | Should -Be $expected.ARM64.Machine
            }
            ([Diagnostics.FileVersionInfo]::GetVersionInfo($paths[0]).FileVersion) |
                Should -Be ([Diagnostics.FileVersionInfo]::GetVersionInfo($paths[1]).FileVersion)
            return $paths
        }
    }
}

Describe 'WinPriv embedded payloads (<Architecture>)' -Tag 'Safe' -ForEach (Get-WinPrivArchitectureCases) {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
    }

    AfterEach {
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'extracts all three architecture-correct injection libraries beside a copied launcher' {
        $result = Invoke-WinPriv -Architecture $Architecture -Arguments @('/ExtractLibrary') `
            -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 30

        Invoke-WinPrivCapability -Id 'utility.extract-library' -Architecture $Architecture -Body {
            Assert-WinPrivInvocationSucceeded $result
            return @{ ExitCode = $result.ExitCode }
        }

        Invoke-WinPrivCapability -Id 'artifact.embedded-payloads' -Architecture $Architecture -Body {
            $launcherDirectory = Split-Path -Parent $sandbox.Launchers.$Architecture.WinPrivCmd
            $libraries = @(
                @{ File = 'WinPrivLibrary-32.dll'; Architecture = 'x86'; Machine = 0x014C },
                @{ File = 'WinPrivLibrary-64.dll'; Architecture = 'x64'; Machine = 0x8664 },
                @{ File = 'WinPrivLibrary-arm64.dll'; Architecture = 'ARM64'; Machine = 0xAA64 }
            )
            foreach ($library in $libraries) {
                $extracted = Join-Path $launcherDirectory $library.File
                $built = Join-Path (Join-Path $env:WINPRIV_TEST_BINARY_ROOT $library.Architecture) 'WinPrivLibrary.dll'
                $extracted | Should -Exist
                (Get-PeMachine $extracted) | Should -Be $library.Machine
                $built | Should -Exist
                (Get-FileHash $extracted -Algorithm SHA256).Hash | Should -Be `
                    (Get-FileHash $built -Algorithm SHA256).Hash
            }
            return $libraries
        }
    }

    It 'reuses the architecture-matching adjacent library without a temporary extraction' {
        Invoke-WinPrivCapability -Id 'artifact.adjacent-library-reuse' -Architecture $Architecture -Body {
            $extract = Invoke-WinPriv -Architecture $Architecture -Arguments @('/ExtractLibrary') `
                -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $extract
            $expectedName = switch ($Architecture) {
                'x86' { 'WinPrivLibrary-32.dll' }
                'x64' { 'WinPrivLibrary-64.dll' }
                'ARM64' { 'WinPrivLibrary-arm64.dll' }
            }
            $expectedPath = [IO.Path]::GetFullPath((Join-Path $sandbox.Launchers.$Architecture.Root $expectedName))
            $probe = Invoke-WinPrivProbe -Architecture $Architecture -Operation state -Arguments @{} `
                -Sandbox $sandbox -Environment @{ TEMP = $sandbox.Temp; TMP = $sandbox.Temp } -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $probe
            @($probe.ProbeResult.result.winPrivLibraryModules | ForEach-Object { [IO.Path]::GetFullPath([string]$_) }) |
                Should -Contain $expectedPath
            @(Get-ChildItem -LiteralPath $sandbox.Temp -Filter '*.dll' -File -ErrorAction SilentlyContinue) |
                Should -HaveCount 0
            return @{ LibraryPath = $expectedPath }
        }
    }

    It 'removes temporary resource DLLs after a normal injected launch' {
        Invoke-WinPrivCapability -Id 'artifact.temp-library-cleanup' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation state -Arguments @{} `
                -Sandbox $sandbox -Environment @{ TEMP = $sandbox.Temp; TMP = $sandbox.Temp } -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            @(Get-ChildItem -LiteralPath $sandbox.Temp -Filter '*.dll' -File -ErrorAction SilentlyContinue) |
                Should -HaveCount 0
            return @{ Temp = $sandbox.Temp }
        }
    }
}

Describe 'WinPriv release package' -Tag 'Safe' {
    It 'packages six launchers, the license, and complete hash entries in an isolated tree' {
        $runtimeArchitecture = @(Get-WinPrivTestArchitectures)[0]
        $sandbox = New-WinPrivSandbox -Architecture $runtimeArchitecture -Purpose 'package-staging'
        try {
            Invoke-WinPrivCapability -Id 'artifact.package' -Architecture All -Body {
                $hashSuffix = '\Build\ARM64\WinPrivCmd.exe'
                $paddingLength = [Math]::Max(0, 180 - ($sandbox.Root.Length + 16 + $hashSuffix.Length))
                $root = Join-Path $sandbox.Root ('package-source-' + ('x' * $paddingLength))
                $build = Join-Path $root 'Build'
                New-Item -ItemType Directory -Path $build -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $env:WINPRIV_TEST_SOURCE_ROOT 'Build\build.cmd') -Destination $build
                Copy-Item -LiteralPath (Join-Path $env:WINPRIV_TEST_SOURCE_ROOT 'LICENSE') -Destination $root
                foreach ($architecture in @('x86', 'x64', 'ARM64')) {
                    $destination = Join-Path $build $architecture
                    New-Item -ItemType Directory -Path $destination -Force | Out-Null
                    Copy-Item -LiteralPath (Join-Path $env:WINPRIV_TEST_BINARY_ROOT "$architecture\WinPriv.exe") -Destination $destination
                    Copy-Item -LiteralPath (Join-Path $env:WINPRIV_TEST_BINARY_ROOT "$architecture\WinPrivCmd.exe") -Destination $destination
                }

                $packaging = Invoke-WinPrivContainedProcess -FilePath $env:ComSpec `
                    -ArgumentList @('/d', '/c', (Join-Path $build 'build.cmd')) `
                    -WorkingDirectory $build -Sandbox $sandbox -TimeoutSeconds 120
                Assert-WinPrivInvocationSucceeded $packaging

                $zipPath = Join-Path $build 'WinPriv.zip'
                $hashPath = Join-Path $build 'WinPriv-hash.txt'
                $zipPath | Should -Exist
                $hashPath | Should -Exist
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
                try {
                    $entries = @($archive.Entries.FullName -replace '\\', '/')
                    $expectedEntries = @()
                    foreach ($architecture in @('x86', 'x64', 'ARM64')) {
                        $expectedEntries += "$architecture/WinPriv.exe", "$architecture/WinPrivCmd.exe"
                    }
                    $expectedEntries += 'licenses/WinPriv-LICENSE'
                    @($entries | Where-Object { -not $_.EndsWith('/') } | Sort-Object) |
                        Should -Be @($expectedEntries | Sort-Object)
                }
                finally {
                    $archive.Dispose()
                }

                $hashText = Get-Content -LiteralPath $hashPath -Raw
                $hashedFiles = @($zipPath)
                foreach ($architecture in @('x86', 'x64', 'ARM64')) {
                    $hashedFiles += Join-Path $build "$architecture\WinPriv.exe"
                    $hashedFiles += Join-Path $build "$architecture\WinPrivCmd.exe"
                }
                foreach ($file in $hashedFiles) {
                    foreach ($algorithm in @('SHA256', 'SHA1', 'MD5')) {
                        $hash = (Get-FileHash -LiteralPath $file -Algorithm $algorithm).Hash
                        $hashText | Should -Match ("(?m)^{0}[ \t]+{1}[ \t]+{2}[ \t]*\r?$" -f $algorithm, $hash, [regex]::Escape([IO.Path]::GetRelativePath($build, $file)))
                    }
                }
                @([regex]::Matches($hashText, '(?m)^(?:SHA256|SHA1|MD5)\s+[0-9A-F]+\s+.+$')) |
                    Should -HaveCount ($hashedFiles.Count * 3)
                return @{ Entries = $entries.Count; Hashes = $hashedFiles.Count * 3 }
            }
        }
        finally {
            Remove-WinPrivSandbox -Sandbox $sandbox | Out-Null
        }
    }
}
