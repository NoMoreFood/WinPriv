. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')
}

Describe 'WinPriv file and directory rules (<Architecture>)' -Tag 'Safe' -ForEach (Get-WinPrivArchitectureCases) {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose 'file-rules'
        $source = Join-Path $sandbox.Working 'source path'
        $destination = Join-Path $sandbox.Working 'destination path'
    }

    AfterEach {
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'redirects file reads, attributes, writes, and deletion without touching the source' {
        Invoke-WinPrivCapability -Id 'filesystem.redirect-file' -Architecture $Architecture -Body {
            [IO.File]::WriteAllText($source, 'original')
            [IO.File]::WriteAllText($destination, 'replacement')
            [IO.File]::WriteAllText($source + '-sibling', 'sibling')
            $requests = @(
                @{ action = 'read'; path = $source },
                @{ action = 'NtOpenFile'; path = $source },
                @{ action = 'NtCreateFile'; path = $source },
                @{ action = 'read'; path = '\\?\' + $source.ToUpperInvariant() },
                @{ action = 'attributes'; path = $source },
                @{ action = 'attributes-ex'; path = $source },
                @{ action = 'NtQueryAttributesFile'; path = $source },
                @{ action = 'NtQueryFullAttributesFile'; path = $source },
                @{ action = 'read'; path = $source + '-sibling' },
                @{ action = 'write'; path = $source; target = 'changed' },
                @{ action = 'read'; path = $source }
            )
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                -WinPrivArguments @('/fIlErEdIrEcT', $source, $destination, '/BreakRemoteLocks') `
                -Arguments @{ requests = $requests } -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            $rows = @($result.ProbeResult.result)
            $rows | Should -HaveCount $requests.Count
            foreach ($row in $rows) { $row.success | Should -BeTrue -Because ($row | ConvertTo-Json -Compress) }
            foreach ($index in 0..3) { $rows[$index].content | Should -Be 'replacement' }
            $rows[8].content | Should -Be 'sibling'
            $rows[10].content | Should -Be 'changed'
            [IO.File]::ReadAllText($source) | Should -Be 'original'
            [IO.File]::ReadAllText($destination) | Should -Be 'changed'

            $deleted = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                -WinPrivArguments @('/FileRedirect', $source, $destination) `
                -Arguments @{ requests = @(@{ action = 'NtDeleteFile'; path = $source }) } `
                -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $deleted
            $deleted.ProbeResult.result[0].success | Should -BeTrue
            [IO.File]::Exists($destination) | Should -BeFalse
            [IO.File]::ReadAllText($source) | Should -Be 'original'
        }
    }

    It 'redirects a missing directory tree and applies nested redirects through relative and duplicated handles' {
        Invoke-WinPrivCapability -Id 'filesystem.redirect-directory' -Architecture $Architecture -Body {
            [void][IO.Directory]::CreateDirectory($destination)
            [IO.File]::WriteAllText((Join-Path $destination 'visible.txt'), 'visible')
            [IO.File]::WriteAllText((Join-Path $destination 'special.txt'), 'original')
            $override = Join-Path $sandbox.Working 'override.txt'
            [IO.File]::WriteAllText($override, 'nested')
            $requests = @(
                @{ action = 'attributes'; path = $source },
                @{ action = 'read'; path = Join-Path $source 'visible.txt' },
                @{ action = 'NtOpenFile'; root = $source; path = 'visible.txt' },
                @{ action = 'NtCreateFile'; root = $source; path = 'visible.txt'; duplicateRoot = $true },
                @{ action = 'NtOpenFile'; root = $source; path = 'special.txt'; duplicateRoot = $true },
                @{ action = 'list'; path = $source },
                @{ action = 'mkdir'; path = Join-Path $source 'new directory' },
                @{ action = 'write'; path = Join-Path $source 'new directory\new.txt'; target = 'created' },
                @{ action = 'read'; path = Join-Path $source 'new directory\new.txt' },
                @{ action = 'delete'; path = Join-Path $source 'new directory\new.txt' },
                @{ action = 'rmdir'; path = Join-Path $source 'new directory' }
            )
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                -WinPrivArguments @('/FileRedirect', ($source + '\'), ($destination + '\'),
                    '/FileRedirect', (Join-Path $source 'special.txt'), $override) `
                -Arguments @{ requests = $requests } -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            $rows = @($result.ProbeResult.result)
            foreach ($row in $rows) { $row.success | Should -BeTrue -Because ($row | ConvertTo-Json -Compress) }
            foreach ($index in 1..3) { $rows[$index].content | Should -Be 'visible' }
            $rows[4].content | Should -Be 'nested'
            @($rows[5].entries | Split-Path -Leaf | Sort-Object) | Should -Be @('special.txt', 'visible.txt')
            $rows[8].content | Should -Be 'created'
            [IO.Directory]::Exists($source) | Should -BeFalse
            [IO.Directory]::Exists((Join-Path $destination 'new directory')) | Should -BeFalse
            [IO.File]::ReadAllText((Join-Path $destination 'special.txt')) | Should -Be 'original'
        }
    }

    It 'uses specific and last matching rules, resolves relative paths in configuration, and avoids redirect loops' {
        Invoke-WinPrivCapability -Id 'filesystem.rule-order' -Architecture $Architecture -Body {
            [void][IO.Directory]::CreateDirectory($destination)
            [IO.File]::WriteAllText((Join-Path $destination 'ordinary.txt'), 'destination')
            $override = Join-Path $sandbox.Working 'override.txt'
            [IO.File]::WriteAllText($override, 'override')
            $config = Join-Path $sandbox.Root 'files.cfg'
            [IO.File]::WriteAllText($config, '/FileRedirect "source path" "unused destination"' + "`r`n" +
                '/FileRedirect "source path" "destination path"', [Text.UTF8Encoding]::new($false))
            $requests = @(
                @{ action = 'read'; path = Join-Path $source 'ordinary.txt' },
                @{ action = 'read'; path = Join-Path $source 'special.txt' }
            )
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                -WinPrivArguments @('/FileRedirect', (Join-Path $source 'special.txt'), $override,
                    '/LoadCommands', $config, '/FileRedirect', $destination, $source) `
                -Arguments @{ requests = $requests } -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            $result.ProbeResult.result[0].content | Should -Be 'destination'
            $result.ProbeResult.result[1].content | Should -Be 'override'
        }
    }

    It 'resolves relative, device, UNC, extended, and long rule paths' {
        Invoke-WinPrivCapability -Id 'filesystem.path-syntax' -Architecture $Architecture -Body {
            [IO.File]::WriteAllText($destination, 'resolved')
            $rooted = Join-Path $sandbox.Working 'rooted'
            $device = Join-Path $sandbox.Working 'device'
            $extended = Join-Path $sandbox.Working 'extended'
            $long = Join-Path $sandbox.Working (('segment\' * 40) + 'long')
            $cases = @(
                @{ rule = 'unused/../relative'; path = Join-Path $sandbox.Working 'relative' },
                @{ rule = $rooted.Substring(2); path = $rooted },
                @{ rule = $source.Substring(0, 2) + 'drive-relative';
                    path = Join-Path $sandbox.Working 'drive-relative' },
                @{ rule = '\\.\' + $device; path = $device },
                @{ rule = '\\?\' + $extended; path = $extended },
                @{ rule = '\\winpriv.invalid\share\alias'; path = '\\winpriv.invalid\share\alias' },
                @{ rule = '\\?\UNC\winpriv.invalid\share\extended';
                    path = '\\winpriv.invalid\share\extended' },
                @{ rule = $long; path = '\\?\' + $long }
            )
            $switches = @(foreach ($case in $cases) { '/FileRedirect'; $case.rule; '\\?\' + $destination })
            $requests = @(foreach ($case in $cases) { @{ action = 'NtOpenFile'; path = $case.path } })
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                -WinPrivArguments $switches -Arguments @{ requests = $requests } -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            $rows = @($result.ProbeResult.result)
            $rows | Should -HaveCount $cases.Count
            foreach ($row in $rows) {
                $row.success | Should -BeTrue -Because ($row | ConvertTo-Json -Compress)
                $row.content | Should -Be 'resolved'
            }
        }
    }

    It 'redirects rename and hard-link destinations' {
        Invoke-WinPrivCapability -Id 'filesystem.redirect-mutation' -Architecture $Architecture -Body {
            [void][IO.Directory]::CreateDirectory($destination)
            $outside = Join-Path $sandbox.Working 'outside.txt'
            [IO.File]::WriteAllText($outside, 'move me')
            $requests = @(
                @{ action = 'move'; path = $outside; target = Join-Path $source 'renamed.txt' },
                @{ action = 'link'; path = Join-Path $source 'renamed.txt'; target = Join-Path $source 'linked.txt' },
                @{ action = 'read'; path = Join-Path $source 'linked.txt' },
                @{ action = 'move'; path = Join-Path $source 'renamed.txt'; target = $outside }
            )
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                -WinPrivArguments @('/FileRedirect', $source, $destination) `
                -Arguments @{ requests = $requests } -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            $rows = @($result.ProbeResult.result)
            foreach ($row in $rows) { $row.success | Should -BeTrue -Because ($row | ConvertTo-Json -Compress) }
            $rows[2].content | Should -Be 'move me'
            [IO.File]::ReadAllText($outside) | Should -Be 'move me'
            [IO.File]::ReadAllText((Join-Path $destination 'linked.txt')) | Should -Be 'move me'
            [IO.Directory]::Exists($source) | Should -BeFalse
        }
    }

    It 'retains directory rules on an open handle after its directory is renamed' {
        Invoke-WinPrivCapability -Id 'filesystem.redirect-rename-handle' -Architecture $Architecture -Body {
            [void][IO.Directory]::CreateDirectory((Join-Path $destination 'old'))
            [IO.File]::WriteAllText((Join-Path $destination 'old\child.txt'), 'original')
            $override = Join-Path $sandbox.Working 'override.txt'
            [IO.File]::WriteAllText($override, 'redirected after rename')
            $request = @{ action = 'relative-rename'; path = 'child.txt'
                root = Join-Path $source 'old'; target = Join-Path $source 'new' }
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                -WinPrivArguments @('/FileRedirect', $source, $destination,
                    '/FileRedirect', (Join-Path $source 'new\child.txt'), $override) `
                -Arguments @{ requests = @($request) } -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            $result.ProbeResult.result[0].content | Should -Be 'redirected after rename'
            [IO.Directory]::Exists((Join-Path $destination 'old')) | Should -BeFalse
            [IO.File]::ReadAllText((Join-Path $destination 'new\child.txt')) | Should -Be 'original'
        }
    }

    It 'preserves nested rules through junction destinations and directory renames' {
        Invoke-WinPrivCapability -Id 'filesystem.redirect-junction' -Architecture $Architecture -Body {
            $physical = Join-Path $sandbox.Working 'physical'
            [void][IO.Directory]::CreateDirectory((Join-Path $physical 'old'))
            [IO.File]::WriteAllText((Join-Path $physical 'child.txt'), 'original')
            [IO.File]::WriteAllText((Join-Path $physical 'old\child.txt'), 'original after rename')
            $override = Join-Path $sandbox.Working 'override.txt'
            [IO.File]::WriteAllText($override, 'override')
            [void](New-Item -ItemType Junction -Path $destination -Target $physical)
            try {
                $requests = @(
                    @{ action = 'read'; path = Join-Path $source 'child.txt' },
                    @{ action = 'NtOpenFile'; root = $source; path = 'child.txt' },
                    @{ action = 'NtCreateFile'; root = $source; path = 'child.txt'; duplicateRoot = $true },
                    @{ action = 'relative-rename'; root = Join-Path $source 'old'
                        path = 'child.txt'; target = Join-Path $source 'new' }
                )
                $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                    -WinPrivArguments @('/FileRedirect', $source, $destination,
                        '/FileRedirect', (Join-Path $source 'child.txt'), $override,
                        '/FileRedirect', (Join-Path $source 'new\child.txt'), $override) `
                    -Arguments @{ requests = $requests } -Sandbox $sandbox -TimeoutSeconds 30
                Assert-WinPrivInvocationSucceeded $result
                $rows = @($result.ProbeResult.result)
                $rows | Should -HaveCount $requests.Count
                foreach ($row in $rows) {
                    $row.success | Should -BeTrue -Because ($row | ConvertTo-Json -Compress)
                    $row.content | Should -Be 'override'
                }
                [IO.File]::ReadAllText((Join-Path $physical 'child.txt')) | Should -Be 'original'
                [IO.File]::ReadAllText((Join-Path $physical 'new\child.txt')) | Should -Be 'original after rename'
                [IO.Directory]::Exists((Join-Path $physical 'old')) | Should -BeFalse
            }
            finally {
                [IO.Directory]::Delete($destination)
            }
        }
    }

    It 'renames a redirected data stream within its destination file' {
        Invoke-WinPrivCapability -Id 'filesystem.redirect-stream' -Architecture $Architecture -Body {
            [void][IO.Directory]::CreateDirectory($source)
            [void][IO.Directory]::CreateDirectory($destination)
            $sourceFile = Join-Path $source 'file.txt'
            $destinationFile = Join-Path $destination 'file.txt'
            [IO.File]::WriteAllText($sourceFile, 'source')
            [IO.File]::WriteAllText($destinationFile, 'destination')
            [IO.File]::WriteAllText($sourceFile + ':old', 'source stream')
            [IO.File]::WriteAllText($destinationFile + ':old', 'destination stream')
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                -WinPrivArguments @('/FileRedirect', $source, $destination) `
                -Arguments @{ requests = @(
                    @{ action = 'native-rename'; path = $sourceFile + ':old'; target = ':new' }
                ) } -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            $result.ProbeResult.result[0].statusHex | Should -Be '0x00000000'
            [IO.File]::ReadAllText($sourceFile + ':old') | Should -Be 'source stream'
            [IO.File]::ReadAllText($destinationFile + ':new') | Should -Be 'destination stream'
            [IO.File]::Exists($destinationFile + ':old') | Should -BeFalse
            [IO.File]::Exists($sourceFile + ':new') | Should -BeFalse
            [IO.File]::ReadAllText($sourceFile) | Should -Be 'source'
            [IO.File]::ReadAllText($destinationFile) | Should -Be 'destination'
        }
    }

    It 'retains nested rules when process handles grant only duplication access' {
        Invoke-WinPrivCapability -Id 'filesystem.redirect-duplicate' -Architecture $Architecture -Body {
            [void][IO.Directory]::CreateDirectory($destination)
            [IO.File]::WriteAllText((Join-Path $destination 'child.txt'), 'original')
            $override = Join-Path $sandbox.Working 'override.txt'
            [IO.File]::WriteAllText($override, 'override')
            $requests = @(foreach ($process in 'source', 'target', 'both') {
                foreach ($close in $false, $true) {
                    @{ action = 'NtOpenFile'; root = $source; path = 'child.txt'
                        duplicateRoot = $true; duplicateProcess = $process; closeSource = $close }
                }
            })
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation file-paths `
                -WinPrivArguments @('/FileRedirect', $source, $destination,
                    '/FileRedirect', (Join-Path $source 'child.txt'), $override) `
                -Arguments @{ requests = $requests } -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            $rows = @($result.ProbeResult.result)
            $rows | Should -HaveCount $requests.Count
            foreach ($row in $rows) {
                $row.success | Should -BeTrue -Because ($row | ConvertTo-Json -Compress)
                $row.content | Should -Be 'override'
            }
        }
    }

    It 'preserves file rules through two generations with replacement A and W environments' {
        Invoke-WinPrivCapability -Id 'filesystem.rule-propagation' -Architecture $Architecture -Body {
            [IO.File]::WriteAllText($destination, 'inherited')
            foreach ($api in 'A', 'W') {
                $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation create-process `
                    -WinPrivArguments @('/FileRedirect', $source, $destination) `
                    -Arguments @{ api = $api; depth = 2; customEnvironment = @{}; mergeEnvironment = $false
                        childOperation = 'file-paths'; childArguments = @{ requests = @(
                            @{ action = 'read'; path = $source }
                        ) } } -Sandbox $sandbox -TimeoutSeconds 60
                Assert-WinPrivInvocationSucceeded $result
                $child = $result.ProbeResult.result.childResult.result.childResult
                $child.result[0].content | Should -Be 'inherited'
            }
        }
    }
}
