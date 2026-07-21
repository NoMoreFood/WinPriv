. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')
    $documentedSwitches = @(
        '/AdminImpersonate', '/AskMessage', '/BreakRemoteLocks', '/BypassFileSecurity',
        '/ClearDenyRights', '/DisableAmsi', '/ExtractLibrary', '/FipsOff', '/FipsOn',
        '/GrantAllRights', '/GrantRight', '/Help', '/HostOverride', '/KillProcess',
        '/ListPrivileges', '/LoadCommands', '/MacOverride', '/MeasureTime', '/MediumPlus',
        '/PolicyBlock', '/RecordCrypto', '/RegBlock', '/RegOverride', '/RevokeRight',
        '/RunAsConsoleUser', '/RunAsConsoleUserNoWait', '/RunAsUser', '/RunAsUserNoWait',
        '/ServerEdition', '/ShowMessage', '/SqlConnectSearchReplace', '/SqlConnectShow',
        '/UseShellExecute', '/WindowStyle', '/WithAllPrivs', '/WithPrivs'
    )
}

$architectureCases = Get-WinPrivArchitectureCases

Describe 'WinPriv command-line contract (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeAll {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
    }

    AfterAll {
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'shows complete help for /Help, /?, no target, and a detached console launcher' {
        Invoke-WinPrivCapability -Id 'cli.help' -Architecture $Architecture -Body {
            $helpCases = @(
                @{ Arguments = [string[]]@('/Help') },
                @{ Arguments = [string[]]@('/?') },
                @{ Arguments = [string[]]@() }
            )
            foreach ($case in $helpCases) {
                $result = Invoke-WinPriv -Architecture $Architecture -Arguments $case.Arguments `
                    -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 15
                Assert-WinPrivInvocationSucceeded $result
                $result.StdOut | Should -Match 'WinPrivCmd'
                $result.StdOut | Should -Match '/RegOverride'
            }

            $detachedHelp = Invoke-WinPrivContainedProcess `
                -FilePath $sandbox.Launchers.$Architecture.WinPrivCmd -ArgumentList @('/Help') `
                -WorkingDirectory $sandbox.Working -Sandbox $sandbox -TimeoutSeconds 15 -CreateNoWindow
            Assert-WinPrivInvocationSucceeded $detachedHelp
            $detachedHelp.StdOut | Should -Match 'Optional Switches'

            $help = (Invoke-WinPriv -Architecture $Architecture -Arguments @('/Help') `
                -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 15).StdOut
            $missingSwitches = @($documentedSwitches | Where-Object {
                $help -notmatch ([regex]::Escape($_))
            })
            @($missingSwitches) | Should -HaveCount 0 -Because `
                ("the help output is missing these advertised switches: {0}" -f ($missingSwitches -join ', '))
            return @{ SwitchCount = $documentedSwitches.Count }
        }
    }

    It 'accepts the documented /ListPrivileges spelling' {
        Invoke-WinPrivCapability -Id 'cli.list-privileges' -Architecture $Architecture -Body {
            $result = Invoke-WinPriv -Architecture $Architecture -Arguments @('/ListPrivileges') `
                -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            $result.StdOut | Should -Match 'Privilege Constant'
            $result.StdOut | Should -Match 'Se[A-Za-z]+Privilege'
            return @{ ExitCode = $result.ExitCode }
        }
    }

    It 'treats switch names and enumerated values case-insensitively' {
        Invoke-WinPrivCapability -Id 'cli.case-insensitive' -Architecture $Architecture -Body {
            $help = Invoke-WinPriv -Architecture $Architecture -Arguments @('/hElP') `
                -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 15
            Assert-WinPrivInvocationSucceeded $help
            $help.StdOut | Should -Match 'Optional Switches'

            $window = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/wInDoWsTyLe', 'hIdDeN') -Operation window -Arguments @{} `
                -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $window
            $window.ProbeResult.result.showWindow | Should -Be 0
            return @{ HelpExitCode = $help.ExitCode; ShowWindow = $window.ProbeResult.result.showWindow }
        }
    }

    It 'rejects invalid switches and required-argument omissions without hanging' {
        Invoke-WinPrivCapability -Id 'cli.argument-errors' -Architecture $Architecture -Body {
            $recordingFile = Join-Path $sandbox.Root 'not-a-recording-directory'
            [IO.File]::WriteAllText($recordingFile, 'sentinel')
            $configDirectory = Join-Path $sandbox.Root 'not-a-config-file.cfg'
            [void](New-Item -ItemType Directory -Path $configDirectory)
            $cases = @(
                @{ Arguments = [string[]]@('/DefinitelyNotAWinPrivSwitch') },
                @{ Arguments = [string[]]@('/LoadCommands') },
                @{ Arguments = [string[]]@('/LoadCommands', $configDirectory) },
                @{ Arguments = [string[]]@('/WithPrivs') },
                @{ Arguments = [string[]]@('/KillProcess') },
                @{ Arguments = [string[]]@('/MacOverride') },
                @{ Arguments = [string[]]@('/RegOverride', 'HKCU\Software') },
                @{ Arguments = [string[]]@('/RegBlock') },
                @{ Arguments = [string[]]@('/WindowStyle') },
                @{ Arguments = [string[]]@('/HostOverride', 'source.invalid') },
                @{ Arguments = [string[]]@('/RecordCrypto') },
                @{ Arguments = [string[]]@('/RecordCrypto', $recordingFile) },
                @{ Arguments = [string[]]@('/SqlConnectSearchReplace', 'find') },
                @{ Arguments = [string[]]@('/GrantRight') },
                @{ Arguments = [string[]]@('/RevokeRight', 'SeDebugPrivilege') },
                @{ Arguments = [string[]]@('/GrantAllRights') },
                @{ Arguments = [string[]]@('/ShowMessage') },
                @{ Arguments = [string[]]@('/AskMessage') },
                @{ Arguments = [string[]]@('/RunAsUser') },
                @{ Arguments = [string[]]@('/RunAsUserNoWait') }
            )
            foreach ($case in $cases) {
                $result = Invoke-WinPriv -Architecture $Architecture -Arguments $case.Arguments `
                    -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 10
                Assert-WinPrivInvocationFailedCleanly $result
            }
            return @{ NegativeCases = $cases.Count }
        }
    }

    It 'round-trips exit codes, cwd, environment, Unicode, empty, whitespace, quote, and slash arguments' {
        Invoke-WinPrivCapability -Id 'cli.argument-roundtrip' -Architecture $Architecture -Body {
            $exit = Invoke-WinPrivProbe -Architecture $Architecture -Operation exit `
                -Arguments @{ exitCode = 37 } -Sandbox $sandbox -TimeoutSeconds 15
            $exit.TimedOut | Should -BeFalse
            $exit.ExitCode | Should -Be 37

            $values = @('', 'two words', 'embedded"quote', 'trailing\', 'Zażółć gęślą jaźń', '日本語')
            $argumentsProbe = Invoke-WinPrivProbe -Architecture $Architecture -Operation args `
                -Arguments @{} -RemainingArguments $values -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $argumentsProbe
            @($argumentsProbe.ProbeResult.result.remainingArguments) | Should -Be $values

            $state = Invoke-WinPrivProbe -Architecture $Architecture -Operation state `
                -Arguments @{ values = $values; environmentNames = @('WINPRIV_TEST_ROUNDTRIP') } `
                -Environment @{ WINPRIV_TEST_ROUNDTRIP = 'snowman-☃' } `
                -WorkingDirectory $sandbox.Working -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $state
            $probe = Get-WinPrivProbeValue $state
            $probe.success | Should -BeTrue
            $probe.result.cwd | Should -Be ([IO.Path]::GetFullPath($sandbox.Working).TrimEnd('\'))
            $probe.result.environment.WINPRIV_TEST_ROUNDTRIP | Should -Be 'snowman-☃'
            @($probe.result.argumentsJson.values) | Should -Be $values
            return @{ ExitCode = 37; Values = $values }
        }
    }

    It 'launches a matching-architecture probe through the console launcher' {
        Invoke-WinPrivCapability -Id 'launcher.console' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation state `
                -Arguments @{} -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            $result.ProbeResult.success | Should -BeTrue
            $result.ProbeResult.result.architecture | Should -Be $Architecture
            return $result.ProbeResult.result
        }
    }

    It 'launches a matching-architecture probe through the GUI launcher' {
        Invoke-WinPrivCapability -Id 'launcher.gui' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation state `
                -Arguments @{} -Launcher WinPriv -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            $result.ProbeResult.success | Should -BeTrue
            $result.ProbeResult.result.architecture | Should -Be $Architecture
            return $result.ProbeResult.result
        }
    }

    It 'propagates target exit codes through the GUI launcher' {
        Invoke-WinPrivCapability -Id 'launcher.gui-exit-code' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation exit `
                -Arguments @{ exitCode = 29 } -Launcher WinPriv -Sandbox $sandbox -TimeoutSeconds 20
            $result.TimedOut | Should -BeFalse
            $result.StartError | Should -BeNullOrEmpty
            $result.ExitCode | Should -Be 29
            return @{ ExitCode = $result.ExitCode }
        }
    }

    It 'applies explicit configuration through the GUI launcher' {
        Invoke-WinPrivCapability -Id 'launcher.gui-config' -Architecture $Architecture -Body {
            $config = Join-Path $sandbox.Root 'gui.cfg'
            [IO.File]::WriteAllText($config, "/WindowStyle`r`nHidden`r`n", [Text.UTF8Encoding]::new($false))
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/LoadCommands', $config) -Operation window -Arguments @{} `
                -Launcher WinPriv -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            $result.ProbeResult.result.showWindow | Should -Be 0
            return @{ Config = $config; ShowWindow = $result.ProbeResult.result.showWindow }
        }
    }

    It 'extracts all embedded libraries through the GUI launcher' {
        Invoke-WinPrivCapability -Id 'launcher.gui-extract' -Architecture $Architecture -Body {
            $result = Invoke-WinPriv -Architecture $Architecture -Arguments @('/ExtractLibrary') `
                -Launcher WinPriv -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            foreach ($name in @('WinPrivLibrary-32.dll', 'WinPrivLibrary-64.dll', 'WinPrivLibrary-arm64.dll')) {
                Join-Path $sandbox.Launchers.$Architecture.Root $name | Should -Exist
            }
            return @{ Launcher = $result.LauncherPath }
        }
    }
}

Describe 'WinPriv configuration files (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
    }

    AfterEach {
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'loads and merges an explicit UTF-8 configuration with blank lines and environment expansion' {
        Invoke-WinPrivCapability -Id 'config.load-commands' -Architecture $Architecture -Body {
            $config = Join-Path $sandbox.Root 'explicit config.cfg'
            $utf8Bom = [Text.UTF8Encoding]::new($true)
            [IO.File]::WriteAllText($config, "/WindowStyle`r`n%WINPRIV_CFG_STYLE%`r`n`r`n", $utf8Bom)
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/LoadCommands', $config) -Operation window -Arguments @{} `
                -Environment @{ WINPRIV_CFG_STYLE = 'Hidden' } -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            $result.ProbeResult.result.showWindow | Should -Be 0
            return @{ Config = $config; ShowWindow = $result.ProbeResult.result.showWindow }
        }
    }

    It 'loads a complete automatic sibling configuration in place of the real command line' {
        Invoke-WinPrivCapability -Id 'config.automatic' -Architecture $Architecture -Body {
            $launcherSet = $sandbox.Launchers.PSObject.Properties[$Architecture].Value
            $launcher = Join-Path $launcherSet.Root 'WINPRIVCMD-CONFIG.EXE'
            Copy-Item -LiteralPath $launcherSet.WinPrivCmd -Destination $launcher
            $launcherSet.WinPrivCmd = $launcher
            $config = [IO.Path]::ChangeExtension($launcher, '.cfg')
            $configArguments = @('/MeasureTime', '%ComSpec%', '/d', '/c', 'exit', '/b', '0')
            [IO.File]::WriteAllText(
                $config,
                (($configArguments -join "`r`n") + "`r`n"),
                [Text.UTF8Encoding]::new($false))
            $result = Invoke-WinPriv -Architecture $Architecture `
                -Arguments @('/DefinitelyNotAWinPrivSwitch') -Launcher WinPrivCmd `
                -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            $result.StdOut | Should -Match 'Execution Time In Seconds:'
            return @{ Config = $config; ExitCode = $result.ExitCode }
        }
    }

    It 'preserves order across repeated explicit command-file loads' {
        Invoke-WinPrivCapability -Id 'config.merge-order' -Architecture $Architecture -Body {
            $first = Join-Path $sandbox.Root 'first.cfg'
            $second = Join-Path $sandbox.Root 'second.cfg'
            [IO.File]::WriteAllText($first, "/WindowStyle`r`nMaximized`r`n", [Text.UTF8Encoding]::new($false))
            [IO.File]::WriteAllText($second, "/WindowStyle`r`nHidden`r`n", [Text.UTF8Encoding]::new($false))
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/LoadCommands', $first, '/LoadCommands', $first, '/LoadCommands', $second) `
                -Operation window -Arguments @{} -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            $result.ProbeResult.result.showWindow | Should -Be 0
            return @{ Loads = @($first, $first, $second); ShowWindow = $result.ProbeResult.result.showWindow }
        }
    }

    It 'fails a missing explicit command file cleanly' {
        Invoke-WinPrivCapability -Id 'config.missing-file' -Architecture $Architecture -Body {
            $missing = Join-Path $sandbox.Root 'missing.cfg'
            $result = Invoke-WinPriv -Architecture $Architecture `
                -Arguments @('/LoadCommands', $missing) -Launcher WinPrivCmd `
                -Sandbox $sandbox -TimeoutSeconds 10
            Assert-WinPrivInvocationFailedCleanly $result
            $result.StdOut | Should -Match 'Cfg file not found'
            return @{ MissingPath = $missing; ExitCode = $result.ExitCode }
        }
    }

    It 'fails a recursive /LoadCommands cycle cleanly instead of looping' {
        Invoke-WinPrivCapability -Id 'config.recursion-guard' -Architecture $Architecture -Body {
            $config = Join-Path $sandbox.Root 'recursive.cfg'
            [IO.File]::WriteAllText($config, "/LoadCommands`r`n`"$config`"`r`n", [Text.UTF8Encoding]::new($false))
            $result = Invoke-WinPriv -Architecture $Architecture `
                -Arguments @('/LoadCommands', $config) -Launcher WinPrivCmd `
                -Sandbox $sandbox -TimeoutSeconds 5
            $result.TimedOut | Should -BeFalse
            $result.ExitCode | Should -Not -Be 0
            return @{ ExitCode = $result.ExitCode }
        }
    }
}
