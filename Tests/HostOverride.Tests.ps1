. (Join-Path $PSScriptRoot 'TestCommon.ps1')

$architectureCases = Get-WinPrivArchitectureCases

Describe 'WinPriv host overrides (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestCommon.ps1')
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
        $addressApis = @('addrWide', 'addrAnsi', 'addrEx', 'addrExAnsi', 'addrExAsync')
        $dnsApis = @('dnsWide', 'dnsAnsi', 'dnsUtf8', 'dnsEx', 'dnsExAsync', 'dnsEx3')
    }
    AfterAll { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'redirects address and DNS APIs for an unresolved source' {
        Invoke-WinPrivCapability -Id 'network.host-resolvers' -Architecture $Architecture -Body {
            $name = 'winpriv-' + [Guid]::NewGuid().ToString('N') + '.invalid'
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation hosts -Sandbox $sandbox `
                -WinPrivArguments @('/HostOverride', $name, '127.0.0.2') -Arguments @{ name = $name }
            Assert-WinPrivInvocationSucceeded $result
            foreach ($api in $addressApis) {
                $value = $result.ProbeResult.result.$api
                $value.success | Should -BeTrue
                $value.canonicalName | Should -Be '127.0.0.2'
                foreach ($address in $value.addresses) { $address.address | Should -Be '127.0.0.2' }
            }
            foreach ($api in $dnsApis) {
                $value = $result.ProbeResult.result.$api
                $value.success | Should -BeTrue
                @($value.records).Count | Should -BeGreaterThan 0
                foreach ($record in $value.records) { $record.address | Should -Be '127.0.0.2' }
                $value.contextPreserved | Should -BeTrue
            }
            return $result.ProbeResult.result
        }
    }

    It 'supports native IPv6 replacements and IPv6-only lookups' {
        Invoke-WinPrivCapability -Id 'network.host-ipv6' -Architecture $Architecture -Body {
            $name = 'winpriv-' + [Guid]::NewGuid().ToString('N') + '.invalid'
            $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation hosts -Sandbox $sandbox `
                -WinPrivArguments @('/HostOverride', $name, '::1') `
                -Arguments @{ name = $name; family = 23; type = 28 }
            Assert-WinPrivInvocationSucceeded $result
            foreach ($api in $addressApis) {
                $value = $result.ProbeResult.result.$api
                $value.success | Should -BeTrue
                @($value.addresses).Count | Should -BeGreaterThan 0
                foreach ($address in $value.addresses) {
                    $address.family | Should -Be 23
                    $address.address | Should -Be '::1'
                }
            }
            foreach ($api in $dnsApis) {
                $value = $result.ProbeResult.result.$api
                $value.success | Should -BeTrue
                foreach ($record in $value.records) { $record.address | Should -Be '::1' }
            }
            return $result.ProbeResult.result
        }
    }

    It 'preserves replacement address sets and canonical names without following another rule' {
        Invoke-WinPrivCapability -Id 'network.host-destination' -Architecture $Architecture -Body {
            $name = 'winpriv-' + [Guid]::NewGuid().ToString('N') + '.invalid'
            $baseline = Invoke-WinPrivProbe -Architecture $Architecture -Operation hosts -Sandbox $sandbox `
                -Arguments @{ name = 'localhost.' }
            $hooked = Invoke-WinPrivProbe -Architecture $Architecture -Operation hosts -Sandbox $sandbox `
                -WinPrivArguments @('/HostOverride', $name, 'localhost.', '/HostOverride', 'localhost', '127.0.0.3') `
                -Arguments @{ name = $name }
            Assert-WinPrivInvocationSucceeded $baseline
            Assert-WinPrivInvocationSucceeded $hooked
            foreach ($api in $addressApis) {
                $expected = $baseline.ProbeResult.result.$api
                $actual = $hooked.ProbeResult.result.$api
                $actual.success | Should -BeTrue
                $actual.canonicalName | Should -Be $expected.canonicalName
                ($actual.addresses.address | Sort-Object) -join ',' |
                    Should -Be (($expected.addresses.address | Sort-Object) -join ',')
            }
            foreach ($api in $dnsApis) {
                $expected = $baseline.ProbeResult.result.$api
                $actual = $hooked.ProbeResult.result.$api
                $actual.success | Should -BeTrue
                ($actual.records.address | Sort-Object) -join ',' |
                    Should -Be (($expected.records.address | Sort-Object) -join ',')
                $actual.records[0].name | Should -Be $expected.records[0].name
            }
            return $hooked.ProbeResult.result
        }
    }

    It 'matches case, terminal dots, and Unicode or Punycode hostnames' {
        Invoke-WinPrivCapability -Id 'network.host-names' -Architecture $Architecture -Body {
            $unicodeName = 'b' + [char]0x00FC + 'cher-' + [Guid]::NewGuid().ToString('N') + '.invalid'
            $asciiName = [Globalization.IdnMapping]::new().GetAscii($unicodeName)
            foreach ($case in @(
                @{ Target = 'localhost'; Query = 'LOCALHOST.' },
                @{ Target = $unicodeName; Query = $asciiName.ToUpperInvariant() + '.' },
                @{ Target = $asciiName; Query = $unicodeName + '.'; Unicode = $true },
                @{ Target = $asciiName; Query = $unicodeName + [char]0x3002; Unicode = $true }
            )) {
                $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation hosts -Sandbox $sandbox `
                    -WinPrivArguments @('/HostOverride', $case.Target, '127.0.0.2') -Arguments @{ name = $case.Query }
                Assert-WinPrivInvocationSucceeded $result
                $caseAddressApis = $addressApis
                $caseDnsApis = $dnsApis
                if ($case.ContainsKey('Unicode')) {
                    $caseAddressApis = @('addrWide', 'addrEx', 'addrExAsync')
                    $caseDnsApis = @('dnsWide', 'dnsUtf8', 'dnsEx', 'dnsExAsync', 'dnsEx3')
                }
                foreach ($api in $caseAddressApis) {
                    $result.ProbeResult.result.$api.success | Should -BeTrue
                    foreach ($address in $result.ProbeResult.result.$api.addresses) {
                        $address.address | Should -Be '127.0.0.2'
                    }
                }
                foreach ($api in $caseDnsApis) {
                    $result.ProbeResult.result.$api.success | Should -BeTrue
                    foreach ($record in $result.ProbeResult.result.$api.records) {
                        $record.address | Should -Be '127.0.0.2'
                    }
                }
            }
            return @{ Unicode = $unicodeName; Ascii = $asciiName }
        }
    }

    It 'keeps unrelated DNS names and non-address record queries unchanged' {
        foreach ($case in @(
            @{ name = 'localhost'; type = 1; target = 'unrelated.invalid' },
            @{ name = 'localhost'; type = 16; target = 'localhost' }
        )) {
            $arguments = @{ name = $case.name; type = $case.type }
            $baseline = Invoke-WinPrivProbe -Architecture $Architecture -Operation hosts `
                -Sandbox $sandbox -Arguments $arguments
            $hooked = Invoke-WinPrivProbe -Architecture $Architecture -Operation hosts `
                -Sandbox $sandbox -Arguments $arguments `
                -WinPrivArguments @('/HostOverride', $case.target, '127.0.0.2')
            Assert-WinPrivInvocationSucceeded $baseline
            Assert-WinPrivInvocationSucceeded $hooked
            foreach ($api in $dnsApis) {
                $hooked.ProbeResult.result.$api.status | Should -Be $baseline.ProbeResult.result.$api.status
                ($hooked.ProbeResult.result.$api.records | ConvertTo-Json -Compress) |
                    Should -Be ($baseline.ProbeResult.result.$api.records | ConvertTo-Json -Compress)
            }
        }
    }

    It 'reports the replacement hostname and resolver error on launch failure' {
        Invoke-WinPrivCapability -Id 'network.host-diagnostics' -Architecture $Architecture -Body {
            $missing = 'winpriv-' + [Guid]::NewGuid().ToString('N') + '.invalid'
            $result = Invoke-WinPriv -Architecture $Architecture -Sandbox $sandbox `
                -Arguments @('/HostOverride', 'localhost', $missing, 'cmd.exe', '/c', 'exit', '0')
            Assert-WinPrivInvocationFailedCleanly $result
            $result.StdOut | Should -Match ([regex]::Escape($missing))
            $result.StdOut | Should -Match 'error \d+'
            return @{ ExitCode = $result.ExitCode; Message = $result.StdOut }
        }
    }
}
