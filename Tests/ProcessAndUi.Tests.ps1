. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')
}

$architectureCases = Get-WinPrivArchitectureCases

Describe 'WinPriv process control (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
    }

    AfterEach {
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'kills only same-name processes in the current session before launching the target' {
        Invoke-WinPrivCapability -Id 'process.kill' -Architecture $Architecture -Body {
            $killName = "wpk-$([guid]::NewGuid().ToString('N').Substring(0, 10)).exe"
            $keepName = "wps-$([guid]::NewGuid().ToString('N').Substring(0, 10)).exe"
            $killPath = Join-Path $sandbox.Root $killName
            $keepPath = Join-Path $sandbox.Root $keepName
            Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\ping.exe') -Destination $killPath
            Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\ping.exe') -Destination $keepPath
            $owned = @()
            try {
                $owned += Start-Process -FilePath $killPath -ArgumentList @('127.0.0.1', '-n', '30', '-w', '1000') -PassThru
                $owned += Start-Process -FilePath $killPath -ArgumentList @('127.0.0.1', '-n', '30', '-w', '1000') -PassThru
                $sentinel = Start-Process -FilePath $keepPath -ArgumentList @('127.0.0.1', '-n', '30', '-w', '1000') -PassThru
                $owned += $sentinel
                foreach ($process in $owned) {
                    Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Process -Identifier ([string]$process.Id) `
                        -OriginalState $null -Metadata @{
                            Path = $process.Path; StartTimeUtc = $process.StartTime.ToUniversalTime().ToString('o')
                        } | Out-Null
                }
                Start-Sleep -Milliseconds 300
                @($owned | Where-Object HasExited) | Should -HaveCount 0

                $result = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/KillProcess', $killName) -Operation marker `
                    -Arguments @{ path = (Join-Path $sandbox.Root 'launched.marker'); content = 'launched' } `
                    -Sandbox $sandbox -TimeoutSeconds 20
                Assert-WinPrivInvocationSucceeded $result
                $owned[0].Refresh(); $owned[1].Refresh(); $sentinel.Refresh()
                $owned[0].HasExited | Should -BeTrue
                $owned[1].HasExited | Should -BeTrue
                $sentinel.HasExited | Should -BeFalse

                $noMatch = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/KillProcess', 'wp-no-match-do-not-create.exe') `
                    -Operation state -Arguments @{} -Sandbox $sandbox -TimeoutSeconds 20
                Assert-WinPrivInvocationSucceeded $noMatch
                return @{ Killed = @($owned[0].Id, $owned[1].Id); Preserved = $sentinel.Id }
            }
            finally {
                foreach ($process in $owned) {
                    try {
                        $process.Refresh()
                        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
                    }
                    catch { }
                    $process.Dispose()
                }
            }
        }
    }

    It 'passes every documented /WindowStyle value to STARTUPINFO' {
        Invoke-WinPrivCapability -Id 'process.window-style' -Architecture $Architecture -Body {
            $styles = @{
                NoActive          = 4
                Hidden            = 0
                Maximized         = 3
                Minimized         = 2
                MinimizedNoActive = 7
            }
            foreach ($entry in $styles.GetEnumerator()) {
                $result = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/WindowStyle', $entry.Key) -Operation window `
                    -Arguments @{} -Sandbox $sandbox -TimeoutSeconds 20
                Assert-WinPrivInvocationSucceeded $result
                $result.ProbeResult.result.showWindow | Should -Be $entry.Value
                ($result.ProbeResult.result.flags -band 1) | Should -Be 1
            }
            return $styles
        }
    }

    It 'reports plausible elapsed time after the target exits' {
        Invoke-WinPrivCapability -Id 'process.measure-time' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/MeasureTime') -Operation sleep -Arguments @{ milliseconds = 250 } `
                -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            $match = [regex]::Match($result.StdOut, 'Execution Time In Seconds:\s+([0-9]+(?:\.[0-9]+)?)')
            $match.Success | Should -BeTrue
            $seconds = [double]$match.Groups[1].Value
            $seconds | Should -BeGreaterOrEqual 0.15
            $seconds | Should -BeLessThan 10
            return @{ Seconds = $seconds }
        }
    }

    It 'uses ShellExecute and still injects the target' {
        Invoke-WinPrivCapability -Id 'propagation.shell-execute' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/UseShellExecute') -Operation state -Arguments @{} `
                -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            @($result.ProbeResult.result.winPrivLibraryModules).Count | Should -BeGreaterThan 0
            return $result.ProbeResult.result.winPrivLibraryModules
        }
    }

    It 'fails a missing target executable without hanging' {
        Invoke-WinPrivCapability -Id 'process.launch-failure' -Architecture $Architecture -Body {
            $missing = Join-Path $sandbox.Root 'does-not-exist.exe'
            $result = Invoke-WinPriv -Architecture $Architecture -Arguments @($missing) `
                -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 15
            Assert-WinPrivInvocationFailedCleanly $result
            return @{ Path = $missing; ExitCode = $result.ExitCode }
        }
    }

    It 'leaves an ordinary local file operation untouched with /BreakRemoteLocks' {
        Invoke-WinPrivCapability -Id 'filesystem.break-locks-pass-through' -Architecture $Architecture -Body {
            $path = Join-Path $sandbox.Root 'local-lock-pass-through.txt'
            [IO.File]::WriteAllText($path, 'local-data')
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/BreakRemoteLocks') -Operation file `
                -Arguments @{ action = 'read'; path = $path } -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $result
            [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.ProbeResult.result.bytesBase64)) |
                Should -Be 'local-data'
            $native = @{}
            foreach ($api in @('NtOpenFile', 'NtCreateFile')) {
                $probe = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/BreakRemoteLocks') -Operation native-file `
                    -Arguments @{ api = $api; path = $path } -Sandbox $sandbox -TimeoutSeconds 20
                Assert-WinPrivInvocationSucceeded $probe
                $probe.ProbeResult.result.success | Should -BeTrue
                $native[$api] = $probe.ProbeResult.result.statusHex
            }
            return @{ Length = $result.ProbeResult.result.length; NativeApis = $native }
        }
    }
}

Describe 'WinPriv interactive messages (<Architecture>)' -Tag 'Safe', 'Interactive' -ForEach $architectureCases {
    BeforeAll {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
        $dialogSource = Join-Path $PSScriptRoot 'Support\WinPriv.DialogAutomation.cs'
        if (-not ('WinPrivTests.DialogAutomation' -as [type])) {
            Add-Type -Path $dialogSource
        }
    }

    AfterAll {
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'shows GUI-launcher help for /Help, /?, and no arguments' {
        if (-not (Test-WinPrivInteractiveDesktop)) {
            Skip-WinPrivCapability -Id 'cli.gui-help' -Architecture $Architecture `
                -Reason 'No interactive input desktop is available.'
            return
        }
        Invoke-WinPrivCapability -Id 'cli.gui-help' -Architecture $Architecture -Body {
            $evidence = @()
            $helpCases = @(
                @{ Arguments = [string[]]@('/Help') },
                @{ Arguments = [string[]]@('/?') },
                @{ Arguments = [string[]]@() }
            )
            foreach ($case in $helpCases) {
                $result = Invoke-WinPrivDialogProbe -Architecture $Architecture -Sandbox $sandbox `
                    -WinPrivArguments $case.Arguments -Launcher WinPriv -ButtonId 1 `
                    -ExpectedTitle 'WinPriv Message' -NoTarget
                Assert-WinPrivInvocationSucceeded $result
                $result.JobAssigned | Should -BeTrue
                $evidence += @{ Arguments = $case.Arguments; DialogPid = $result.DialogProcessId }
            }
            return $evidence
        }
    }

    It 'acknowledges /ShowMessage and then launches the target' {
        if (-not (Test-WinPrivInteractiveDesktop)) {
            Skip-WinPrivCapability -Id 'utility.show-message' -Architecture $Architecture `
                -Reason 'No interactive input desktop is available.'
            return
        }
        Invoke-WinPrivCapability -Id 'utility.show-message' -Architecture $Architecture -Body {
            $marker = Join-Path $sandbox.Root 'show-message.marker'
            $result = Invoke-WinPrivDialogProbe -Architecture $Architecture -Sandbox $sandbox `
                -WinPrivArguments @('/ShowMessage', 'WinPriv test message') -Launcher WinPrivCmd `
                -ButtonId 1 -Operation marker -Arguments @{ path = $marker; content = 'shown' }
            Assert-WinPrivInvocationSucceeded $result
            $result.JobAssigned | Should -BeTrue
            $result.DialogTitle | Should -Be 'Message'
            $marker | Should -Exist
            return @{ DialogPid = $result.DialogProcessId; Containment = $result.ContainmentMode }
        }
    }

    It 'continues after the Yes branch of /AskMessage' {
        if (-not (Test-WinPrivInteractiveDesktop)) {
            Skip-WinPrivCapability -Id 'utility.ask-message-yes' -Architecture $Architecture `
                -Reason 'No interactive input desktop is available.'
            return
        }
        Invoke-WinPrivCapability -Id 'utility.ask-message-yes' -Architecture $Architecture -Body {
            $marker = Join-Path $sandbox.Root 'ask-yes.marker'
            $result = Invoke-WinPrivDialogProbe -Architecture $Architecture -Sandbox $sandbox `
                -WinPrivArguments @('/AskMessage', 'Continue WinPriv test?') -Launcher WinPrivCmd `
                -ButtonId 6 -Operation marker -Arguments @{ path = $marker; content = 'yes' }
            Assert-WinPrivInvocationSucceeded $result
            $result.JobAssigned | Should -BeTrue
            $marker | Should -Exist
            return @{ DialogPid = $result.DialogProcessId; Containment = $result.ContainmentMode }
        }
    }

    It 'cancels the No branch of /AskMessage without launching the target' {
        if (-not (Test-WinPrivInteractiveDesktop)) {
            Skip-WinPrivCapability -Id 'utility.ask-message-no' -Architecture $Architecture `
                -Reason 'No interactive input desktop is available.'
            return
        }
        Invoke-WinPrivCapability -Id 'utility.ask-message-no' -Architecture $Architecture -Body {
            $marker = Join-Path $sandbox.Root 'ask-no.marker'
            $result = Invoke-WinPrivDialogProbe -Architecture $Architecture -Sandbox $sandbox `
                -WinPrivArguments @('/AskMessage', 'Cancel WinPriv test?') -Launcher WinPrivCmd `
                -ButtonId 7 -Operation marker -Arguments @{ path = $marker; content = 'no' }
            $result.TimedOut | Should -BeFalse
            $result.StartError | Should -BeNullOrEmpty
            $result.JobAssigned | Should -BeTrue
            $result.ExitCode | Should -Not -Be 0
            $marker | Should -Not -Exist
            return @{ DialogPid = $result.DialogProcessId; ExitCode = $result.ExitCode; Containment = $result.ContainmentMode }
        }
    }

    It 'provides message-dialog parity through the GUI launcher' {
        if (-not (Test-WinPrivInteractiveDesktop)) {
            Skip-WinPrivCapability -Id 'utility.dialog-gui-parity' -Architecture $Architecture `
                -Reason 'No interactive input desktop is available.'
            return
        }
        Invoke-WinPrivCapability -Id 'utility.dialog-gui-parity' -Architecture $Architecture -Body {
            $marker = Join-Path $sandbox.Root 'gui-message.marker'
            $result = Invoke-WinPrivDialogProbe -Architecture $Architecture -Sandbox $sandbox `
                -WinPrivArguments @('/ShowMessage', 'WinPriv GUI parity') -Launcher WinPriv `
                -ButtonId 1 -Operation marker -Arguments @{ path = $marker; content = 'gui' }
            Assert-WinPrivInvocationSucceeded $result
            $result.JobAssigned | Should -BeTrue
            $result.DialogTitle | Should -Be 'Message'
            $marker | Should -Exist
            return @{ DialogPid = $result.DialogProcessId; Containment = $result.ContainmentMode }
        }
    }
}
