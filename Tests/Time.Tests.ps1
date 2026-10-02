. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')

    function Assert-MockedClock {
        param($Clock, [long]$Offset)
        $Clock.ntStatus | Should -Be 0
        $Clock.timeOfDayStatus | Should -Be 0
        $Clock.timeBStatus | Should -Be 0
        $Clock.timeSpecStatus | Should -Be 1
        $Clock.invalidNtStatus | Should -Be ([int]-1073741819)
        foreach ($reading in $Clock.clocks.PSObject.Properties) {
            $tolerance = if ($reading.Name -in @('ucrtTime', 'msvcrtTime')) { 10000000L } else { 300000L }
            [long]$reading.Value | Should -BeGreaterOrEqual ([long]$Clock.rawBefore + $Offset - $tolerance)
            [long]$reading.Value | Should -BeLessOrEqual ([long]$Clock.rawAfter + $Offset + $tolerance)
        }
        foreach ($name in @('formattedDate', 'formattedDateA', 'formattedDateW', 'formattedDateBase')) {
            $Clock.$name | Should -BeIn @($Clock.localDate, $Clock.localDateAfter)
        }
        foreach ($name in @('formattedTime', 'formattedTimeA', 'formattedTimeW', 'formattedTimeBase')) {
            $Clock.$name | Should -BeIn @($Clock.localTime, $Clock.localTimeAfter)
        }
        $Clock.explicitDate | Should -Be '1975-06-15'
        $Clock.explicitTime | Should -Be '12:34:56'
        foreach ($name in @('fileTimeLastError', 'preciseLastError', 'systemLastError', 'localLastError')) {
            $Clock.$name | Should -Be 0x1234
        }
        [Math]::Abs([long]$Clock.interruptTime - [long]$Clock.rawInterrupt) | Should -BeLessThan 1000000
        [Math]::Abs([long]$Clock.uptimeMilliseconds - [long]$Clock.rawInterrupt / 10000) | Should -BeLessThan 100
        [Math]::Abs([long]$Clock.clocks.timeOfDay - [long]$Clock.bootTime - [long]$Clock.rawInterrupt) |
            Should -BeLessThan 10000000
        [Math]::Abs([long]$Clock.performance - [long]$Clock.nativePerformance) |
            Should -BeLessThan $Clock.performanceFrequency
        $Clock.elapsedMilliseconds | Should -BeGreaterOrEqual 100
        $Clock.elapsedMilliseconds | Should -BeLessThan 3000
        $Clock.tickElapsedMilliseconds | Should -BeGreaterOrEqual 100
        $Clock.tickElapsedMilliseconds | Should -BeLessThan 3000
    }
}

$architectureCases = Get-WinPrivArchitectureCases

Describe 'WinPriv wall clock mocking (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeAll { $sandbox = New-WinPrivSandbox -Architecture $Architecture }
    AfterAll { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'shifts native, Win32, CRT, and managed wall clocks while preserving elapsed clocks' {
        Invoke-WinPrivCapability -Id 'time.mock-clock' -Architecture $Architecture -Body {
            foreach ($launcher in @('WinPrivCmd', 'WinPriv')) {
                foreach ($case in @(
                    @{ Delta = '+2d'; Ticks = 1728000000000L }
                    @{ Delta = '-180d'; Ticks = -155520000000000L }
                    @{ Delta = '+0s'; Ticks = 0L }
                )) {
                    $result = Invoke-WinPrivProbe -Architecture $Architecture -Launcher $launcher `
                        -WinPrivArguments @('/MockTime', $case.Delta) -Operation clock -Sandbox $sandbox
                    Assert-WinPrivInvocationSucceeded $result
                    Assert-MockedClock -Clock $result.ProbeResult.result -Offset $case.Ticks
                }
            }
            $plain = Invoke-WinPrivProbe -Architecture $Architecture -Operation clock -Sandbox $sandbox `
                -Environment @{ _WINPRIV_EV_MOCK_TIME_ = '864000000000' }
            Assert-WinPrivInvocationSucceeded $plain
            Assert-MockedClock -Clock $plain.ProbeResult.result -Offset 0
            return @{ Launchers = 2; Offsets = 3; InheritedOffsetCleared = $true }
        }
    }

    It 'accepts abbreviated compound, fractional, calendar, and repeated deltas' {
        Invoke-WinPrivCapability -Id 'time.mock-deltas' -Architecture $Architecture -Body {
            $cases = @(
                @{ Delta = '+1w2d-30mins'; Ticks = 7758000000000L }
                @{ Delta = '-1d 2hr 3min 4sec'; Ticks = -937840000000L }
                @{ Delta = '1.5H'; Ticks = 54000000000L }
                @{ Delta = '250ms500us'; Ticks = 2505000L }
                @{ Delta = '0.0000001s'; Ticks = 1L }
                @{ Delta = '0.1us'; Ticks = 1L }
                @{ Delta = '+1yr'; Months = 12 }
                @{ Delta = '-2MO'; Months = -2 }
                @{ Delta = '+1y2mon-3d'; Years = 1; Months = 2; Days = -3 }
            )
            foreach ($calendar in @(
                @{ Date = '2023-01-31T12:00:00Z'; Delta = '+1mo'; Days = 28 }
                @{ Date = '2024-01-31T12:00:00Z'; Delta = '+1mo'; Days = 29 }
                @{ Date = '2024-02-29T12:00:00Z'; Delta = '+1y'; Days = 365 }
                @{ Date = '2024-02-29T12:00:00Z'; Delta = '+1y2mo'; Days = 424 }
                @{ Date = '2024-03-31T12:00:00Z'; Delta = '-1mo'; Days = -31 }
            )) {
                $target = [DateTime]::Parse($calendar.Date).ToUniversalTime()
                $seconds = [long][Math]::Truncate(($target - [DateTime]::UtcNow).TotalSeconds)
                $cases += @{ Delta = "${seconds}s$($calendar.Delta)"; Ticks = $seconds * 10000000L +
                    $calendar.Days * 864000000000L }
            }
            foreach ($case in $cases) {
                $result = Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $sandbox `
                    -WinPrivArguments @('/MockTime', $case.Delta) -Operation clock
                Assert-WinPrivInvocationSucceeded $result
                $clock = $result.ProbeResult.result
                $offset = [long]$clock.offset
                if ($case.ContainsKey('Ticks')) { $offset | Should -Be $case.Ticks }
                else {
                    $before = [DateTime]::FromFileTimeUtc([long]$clock.rawBefore)
                    $expected = if ($case.ContainsKey('Years')) { $before.AddYears($case.Years) } else { $before }
                    $expected = $expected.AddMonths($case.Months)
                    if ($case.ContainsKey('Days')) { $expected = $expected.AddDays($case.Days) }
                    $offset | Should -Be ($expected - $before).Ticks
                }
                Assert-MockedClock -Clock $clock -Offset $offset
            }
            $config = Join-Path $sandbox.Working 'mock-time.cfg'
            [IO.File]::WriteAllText($config, '/MockTime +1d', [Text.UTF8Encoding]::new($false))
            $last = Invoke-WinPrivProbe -Architecture $Architecture -Operation clock -Sandbox $sandbox `
                -WinPrivArguments @('/LoadCommands', $config, '/mOcKtImE', '-2h')
            Assert-WinPrivInvocationSucceeded $last
            Assert-MockedClock -Clock $last.ProbeResult.result -Offset -72000000000L
            return @{ Deltas = $cases.Count; LastSwitchWins = $true }
        }
    }

    It 'rejects malformed, sub-tick, and out-of-range deltas before launching the target' {
        Invoke-WinPrivCapability -Id 'time.mock-errors' -Architecture $Architecture -Body {
            $marker = Join-Path $sandbox.Working 'invalid-delta.marker'
            $cases = @('', '+', '1', '1month', '1.5y', '0.01us', '1.00000001s', '1s junk', '1s+',
                '1e3s', '+-1s', '9999999999999999999999d', '9223372036854775807s', '-10000y', '+40000y')
            foreach ($delta in $cases) {
                $result = Invoke-WinPrivProbe -Architecture $Architecture -WinPrivArguments @('/MockTime', $delta) `
                    -Operation marker -Arguments @{ path = $marker; content = 'unexpected' } -Sandbox $sandbox
                Assert-WinPrivInvocationFailedCleanly $result
                $result.StdOut | Should -Match 'Invalid /MockTime delta'
                Test-Path -LiteralPath $marker | Should -BeFalse
            }
            return @{ RejectedDeltas = $cases.Count }
        }
    }

    It 'keeps one offset through descendants with custom ANSI and Unicode environments' {
        Invoke-WinPrivCapability -Id 'time.mock-propagation' -Architecture $Architecture -Body {
            foreach ($api in @('A', 'W')) {
                $result = Invoke-WinPrivProbe -Architecture $Architecture -Sandbox $sandbox -TimeoutSeconds 60 `
                    -WinPrivArguments @('/MockTime', '+1y2mo') -Operation create-process -Arguments @{
                        api = $api; depth = 2; childOperation = 'clock'; childArguments = @{}
                        customEnvironment = @{ WINPRIV_CLOCK_MARKER = 'custom' }; mergeEnvironment = $false
                    }
                Assert-WinPrivInvocationSucceeded $result
                $child = $result.ProbeResult.result.childResult
                $child.success | Should -BeTrue
                $clock = $child.result.childResult.result
                [long]$clock.offset | Should -BeGreaterThan (365L * 864000000000L)
                Assert-MockedClock -Clock $clock -Offset ([long]$clock.offset)
                $child.result.parentState.mockTimeOffset | Should -Be $clock.offset
                $result.ProbeResult.result.parentState.mockTimeOffset | Should -Be $clock.offset
            }
            return @{ CreateProcessApis = @('A', 'W'); Depth = 2; CustomEnvironment = $true }
        }
    }
}
