. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')
}

$architectureCases = Get-WinPrivArchitectureCases

Describe 'WinPriv registry hooks (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
        $registryName = "Case$([guid]::NewGuid().ToString('N'))"
        $subKey = "Software\WinPrivTests\$registryName"
        $providerPath = "Registry::HKEY_CURRENT_USER\$subKey"
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Registry -Identifier $providerPath `
            -OriginalState @{ Existed = $false } -Metadata @{ Purpose = 'Registry hook fixture' } | Out-Null
        New-Item -Path $providerPath -Force | Out-Null
    }

    AfterEach {
        Remove-Item -Path "Registry::HKEY_CURRENT_USER\Software\WinPrivTests\$registryName" `
            -Recurse -Force -ErrorAction SilentlyContinue
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'overrides REG_DWORD through every supported query information class' {
        $valueName = 'DwordValue'
        New-ItemProperty -Path $providerPath -Name $valueName -PropertyType DWord -Value 9 -Force | Out-Null
        $result = Invoke-WinPrivProbe -Architecture $Architecture `
            -WinPrivArguments @('/RegOverride', "HKCU\$subKey", $valueName, 'REG_DWORD', '305419896') `
            -Operation registry -Arguments @{ root = 'HKCU'; key = $subKey; valueName = $valueName; view = 'default' } `
            -Sandbox $sandbox -TimeoutSeconds 25
        Assert-WinPrivInvocationSucceeded $result

        $failures = New-Object 'Collections.Generic.List[string]'
        try {
            Invoke-WinPrivCapability -Id 'registry.override-dword' -Architecture $Architecture -Body {
                foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                    $query.Value.success | Should -BeTrue
                    $query.Value.type | Should -Be 4
                    [BitConverter]::ToUInt32([Convert]::FromBase64String($query.Value.dataBase64), 0) |
                        Should -Be 0x12345678
                }
                return $result.ProbeResult.result.win32
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('registry.override-dword: {0}' -f $_.Exception.Message))
        }
        try {
            Invoke-WinPrivCapability -Id 'registry.ntquery-partial' -Architecture $Architecture -Body {
                foreach ($method in @('ntPartial', 'ntPartialAlign64')) {
                    $result.ProbeResult.result.$method.success | Should -BeTrue
                    $result.ProbeResult.result.$method.type | Should -Be 4
                }
                $result.ProbeResult.result.ntPartial.invalidHandleStatusHex | Should -Be '0xC0000008'
                return @{ Partial = $result.ProbeResult.result.ntPartial.statusHex; Align64 = $result.ProbeResult.result.ntPartialAlign64.statusHex }
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('registry.ntquery-partial: {0}' -f $_.Exception.Message))
        }
        try {
            Invoke-WinPrivCapability -Id 'registry.ntquery-full' -Architecture $Architecture -Body {
                foreach ($method in @('ntFull', 'ntFullAlign64')) {
                    $result.ProbeResult.result.$method.success | Should -BeTrue
                    $result.ProbeResult.result.$method.type | Should -Be 4
                }
                return @{ Full = $result.ProbeResult.result.ntFull.statusHex; Align64 = $result.ProbeResult.result.ntFullAlign64.statusHex }
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('registry.ntquery-full: {0}' -f $_.Exception.Message))
        }
        try {
            Invoke-WinPrivCapability -Id 'registry.enumerate' -Architecture $Architecture -Body {
                $result.ProbeResult.result.ntEnumerate.supported | Should -BeTrue
                $enumerated = @($result.ProbeResult.result.ntEnumerate.values | Where-Object name -EQ $valueName)
                $enumerated | Should -HaveCount 1
                $enumerated[0].type | Should -Be 4
                [BitConverter]::ToUInt32([Convert]::FromBase64String($enumerated[0].dataBase64), 0) |
                    Should -Be 0x12345678
                return @{ Values = @($result.ProbeResult.result.ntEnumerate.values).Count }
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('registry.enumerate: {0}' -f $_.Exception.Message))
        }
        if ($failures.Count -gt 0) {
            throw ($failures -join [Environment]::NewLine)
        }
    }

    It 'overrides REG_QWORD without truncating the value' {
        Invoke-WinPrivCapability -Id 'registry.override-qword' -Architecture $Architecture -Body {
            $valueName = 'QwordValue'
            New-ItemProperty -Path $providerPath -Name $valueName -PropertyType QWord -Value 1 -Force | Out-Null
            $expected = [uint64]81985529216486895
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/RegOverride', "HKCU\$subKey", $valueName, 'REG_QWORD', $expected.ToString()) `
                -Operation registry -Arguments @{ root = 'HKCU'; key = $subKey; valueName = $valueName } `
                -Sandbox $sandbox -TimeoutSeconds 25
            Assert-WinPrivInvocationSucceeded $result
            foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                $query.Value.success | Should -BeTrue
                $query.Value.type | Should -Be 11
                [BitConverter]::ToUInt64([Convert]::FromBase64String($query.Value.dataBase64), 0) |
                    Should -Be $expected
            }
            $enumerated = @($result.ProbeResult.result.ntEnumerate.values | Where-Object name -EQ $valueName)
            $enumerated | Should -HaveCount 1
            [BitConverter]::ToUInt64([Convert]::FromBase64String($enumerated[0].dataBase64), 0) |
                Should -Be $expected
            return $result.ProbeResult.result.win32
        }
    }

    It 'overrides REG_SZ with Windows-compatible terminating-NUL length semantics' {
        Invoke-WinPrivCapability -Id 'registry.override-string' -Architecture $Architecture -Body {
            $valueName = 'StringValue'
            $expected = 'James Bond'
            New-ItemProperty -Path $providerPath -Name $valueName -PropertyType String -Value 'real' -Force | Out-Null
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/RegOverride', "HKCU\$subKey", $valueName, 'REG_SZ', $expected) `
                -Operation registry -Arguments @{ root = 'HKCU'; key = $subKey; valueName = $valueName } `
                -Sandbox $sandbox -TimeoutSeconds 25
            Assert-WinPrivInvocationSucceeded $result
            foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                $query.Value.success | Should -BeTrue
                $query.Value.type | Should -Be 1
                $bytes = [Convert]::FromBase64String($query.Value.dataBase64)
                [Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0) | Should -Be $expected
                $query.Value.dataLength | Should -Be (($expected.Length + 1) * 2)
                $bytes[-2] | Should -Be 0
                $bytes[-1] | Should -Be 0
            }
            $enumerated = @($result.ProbeResult.result.ntEnumerate.values | Where-Object name -EQ $valueName)
            $enumerated | Should -HaveCount 1
            $enumerated[0].displayValue | Should -Be $expected
            return $result.ProbeResult.result.win32
        }
    }

    It 'overrides REG_BINARY byte-for-byte' {
        Invoke-WinPrivCapability -Id 'registry.override-binary' -Architecture $Architecture -Body {
            $valueName = 'BinaryValue'
            New-ItemProperty -Path $providerPath -Name $valueName -PropertyType Binary -Value ([byte[]](1, 2)) -Force | Out-Null
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/RegOverride', "HKCU\$subKey", $valueName, 'REG_BINARY', '00A17FFF') `
                -Operation registry -Arguments @{ root = 'HKCU'; key = $subKey; valueName = $valueName } `
                -Sandbox $sandbox -TimeoutSeconds 25
            Assert-WinPrivInvocationSucceeded $result
            foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                $query.Value.success | Should -BeTrue
                $query.Value.type | Should -Be 3
                @([Convert]::FromBase64String($query.Value.dataBase64)) |
                    Should -Be ([byte[]](0x00, 0xA1, 0x7F, 0xFF))
            }
            $enumerated = @($result.ProbeResult.result.ntEnumerate.values | Where-Object name -EQ $valueName)
            $enumerated | Should -HaveCount 1
            @([Convert]::FromBase64String($enumerated[0].dataBase64)) |
                Should -Be ([byte[]](0x00, 0xA1, 0x7F, 0xFF))
            return $result.ProbeResult.result.win32
        }
    }

    It 'applies overrides consistently through explicit 32-bit and 64-bit registry views' {
        Invoke-WinPrivCapability -Id 'registry.views' -Architecture $Architecture -Body {
            $valueName = 'ViewValue'
            New-ItemProperty -Path $providerPath -Name $valueName -PropertyType DWord -Value 7 -Force | Out-Null
            $evidence = @{}
            foreach ($view in @('32', '64')) {
                $result = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/RegOverride', "HKCU\$subKey", $valueName, 'REG_DWORD', '99') `
                    -Operation registry -Arguments @{ root = 'HKCU'; key = $subKey; valueName = $valueName; view = $view } `
                    -Sandbox $sandbox -TimeoutSeconds 25
                Assert-WinPrivInvocationSucceeded $result
                foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                    $query.Value.success | Should -BeTrue
                    [BitConverter]::ToUInt32([Convert]::FromBase64String($query.Value.dataBase64), 0) |
                        Should -Be 99
                }
                $evidence[$view] = $result.ProbeResult.result.win32
            }
            return $evidence
        }
    }

    It 'ignores a malformed override rule without corrupting an unrelated real value' {
        Invoke-WinPrivCapability -Id 'registry.malformed-rules' -Architecture $Architecture -Body {
            $valueName = 'MalformedValue'
            New-ItemProperty -Path $providerPath -Name $valueName -PropertyType DWord -Value 73 -Force | Out-Null
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/RegOverride', "HKCU\$subKey", $valueName, 'REG_NOT_REAL', 'not-data') `
                -Operation registry -Arguments @{ root = 'HKCU'; key = $subKey; valueName = $valueName } `
                -Sandbox $sandbox -TimeoutSeconds 25
            Assert-WinPrivInvocationSucceeded $result
            foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                $query.Value.success | Should -BeTrue
                [BitConverter]::ToUInt32([Convert]::FromBase64String($query.Value.dataBase64), 0) |
                    Should -Be 73
            }
            return $result.ProbeResult.result.win32
        }
    }

    It 'processes multiple ordered rules without an earlier invalid rule suppressing later valid rules' {
        Invoke-WinPrivCapability -Id 'registry.multiple-rules' -Architecture $Architecture -Body {
            $valueName = 'OrderedValue'
            New-ItemProperty -Path $providerPath -Name $valueName -PropertyType DWord -Value 1 -Force | Out-Null
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @(
                    '/RegOverride', 'HKCU\Software\WinPrivTests\DoesNotExist', 'Bad', 'REG_DWORD', '2',
                    '/RegOverride', "HKCU\$subKey", $valueName, 'REG_DWORD', '42'
                ) -Operation registry -Arguments @{ root = 'HKCU'; key = $subKey; valueName = $valueName } `
                -Sandbox $sandbox -TimeoutSeconds 25
            Assert-WinPrivInvocationSucceeded $result
            foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                $query.Value.success | Should -BeTrue
                [BitConverter]::ToUInt32([Convert]::FromBase64String($query.Value.dataBase64), 0) |
                    Should -Be 42
            }
            return $result.ProbeResult.result.win32
        }
    }

    It 'blocks the selected key and descendants' {
        Invoke-WinPrivCapability -Id 'registry.block' -Architecture $Architecture -Body {
            $child = "$subKey\Child"
            $childPath = "Registry::HKEY_CURRENT_USER\$child"
            New-Item -Path $childPath -Force | Out-Null
            New-ItemProperty -Path $childPath -Name Blocked -PropertyType String -Value real -Force | Out-Null
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/RegBlock', "HKCU\$subKey") -Operation registry `
                -Arguments @{ root = 'HKCU'; key = $child; valueName = 'Blocked' } `
                -Sandbox $sandbox -TimeoutSeconds 25
            $result.TimedOut | Should -BeFalse
            foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                $query.Value.success | Should -BeFalse
            }
            $result.ProbeResult.result.ntEnumerate.success | Should -BeFalse
            return $result.ProbeResult.result.win32
        }
    }

    It 'does not block a sibling whose name merely shares the same prefix' {
        Invoke-WinPrivCapability -Id 'registry.block-boundary' -Architecture $Architecture -Body {
            $sibling = "${subKey}Sibling"
            $siblingPath = "Registry::HKEY_CURRENT_USER\$sibling"
            Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Registry -Identifier $siblingPath `
                -OriginalState @{ Existed = $false } -Metadata @{ Purpose = 'Registry sibling-boundary fixture' } | Out-Null
            New-Item -Path $siblingPath -Force | Out-Null
            New-ItemProperty -Path $siblingPath -Name Value -PropertyType String -Value sibling -Force | Out-Null
            try {
                $result = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/RegBlock', "HKCU\$subKey") -Operation registry `
                    -Arguments @{ root = 'HKCU'; key = $sibling; valueName = 'Value' } `
                    -Sandbox $sandbox -TimeoutSeconds 25
                Assert-WinPrivInvocationSucceeded $result
                foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                    $query.Value.success | Should -BeTrue
                    $query.Value.displayValue | Should -Be 'sibling'
                }
                @($result.ProbeResult.result.ntEnumerate.values | Where-Object name -eq 'Value') |
                    Should -HaveCount 1
                return $result.ProbeResult.result.win32
            }
            finally {
                Remove-Item -Path $siblingPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Describe 'WinPriv registry convenience switches (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeEach { $sandbox = New-WinPrivSandbox -Architecture $Architecture }
    AfterEach { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'forces FIPS enabled' {
        Invoke-WinPrivCapability -Id 'registry.fips-on' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivProbe -Architecture $Architecture -WinPrivArguments @('/FipsOn') `
                -Operation registry -Arguments @{ root = 'HKLM'; key = 'SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'; valueName = 'Enabled' } `
                -Sandbox $sandbox -TimeoutSeconds 25
            Assert-WinPrivInvocationSucceeded $result
            foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                [BitConverter]::ToUInt32([Convert]::FromBase64String($query.Value.dataBase64), 0) | Should -Be 1
            }
            return $result.ProbeResult.result.win32
        }
    }

    It 'forces FIPS disabled' {
        Invoke-WinPrivCapability -Id 'registry.fips-off' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivProbe -Architecture $Architecture -WinPrivArguments @('/FipsOff') `
                -Operation registry -Arguments @{ root = 'HKLM'; key = 'SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'; valueName = 'Enabled' } `
                -Sandbox $sandbox -TimeoutSeconds 25
            Assert-WinPrivInvocationSucceeded $result
            foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                [BitConverter]::ToUInt32([Convert]::FromBase64String($query.Value.dataBase64), 0) | Should -Be 0
            }
            return $result.ProbeResult.result.win32
        }
    }

    It 'blocks user policy registry reads' {
        Invoke-WinPrivCapability -Id 'registry.policy-block' -Architecture $Architecture -Body {
            $key = "Software\Policies\WinPrivTests\$([guid]::NewGuid().ToString('N'))"
            $path = "Registry::HKEY_CURRENT_USER\$key"
            Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Registry -Identifier $path `
                -OriginalState @{ Existed = $false } -Metadata @{ Purpose = 'Policy-block fixture' } | Out-Null
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name Enabled -PropertyType DWord -Value 1 -Force | Out-Null
            try {
                $result = Invoke-WinPrivProbe -Architecture $Architecture -WinPrivArguments @('/PolicyBlock') `
                    -Operation registry -Arguments @{ root = 'HKCU'; key = $key; valueName = 'Enabled' } `
                    -Sandbox $sandbox -TimeoutSeconds 25
                $result.TimedOut | Should -BeFalse
                foreach ($query in Get-WinPrivRegistryQueryResults $result) {
                    $query.Value.success | Should -BeFalse
                }
                $result.ProbeResult.result.ntEnumerate.success | Should -BeFalse
                return $result.ProbeResult.result.win32
            }
            finally { Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'WinPriv network and AMSI hooks (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeEach { $sandbox = New-WinPrivSandbox -Architecture $Architecture }
    AfterEach { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'spoofs GetAdaptersInfo, GetAdaptersAddresses, and NetWkstaTransportEnum' {
        $expected = '021122334455'
        $result = Invoke-WinPrivProbe -Architecture $Architecture `
            -WinPrivArguments @('/MacOverride', '02-11-22-33-44-55') -Operation adapters `
            -Arguments @{} -Sandbox $sandbox -TimeoutSeconds 30
        Assert-WinPrivInvocationSucceeded $result
        $methods = @(
            @{ Name = 'getAdaptersInfo'; Id = 'network.mac-adapters-info'; Collection = 'adapters' },
            @{ Name = 'getAdaptersAddresses'; Id = 'network.mac-adapters-addresses'; Collection = 'adapters' },
            @{ Name = 'netWkstaTransportEnum'; Id = 'network.mac-workstation'; Collection = 'transports' }
        )
        foreach ($method in $methods) {
            $value = $result.ProbeResult.result.($method.Name)
            if (-not $value.supported) {
                Add-WinPrivCapabilityResult -Id $method.Id -Architecture $Architecture -Status Unavailable `
                    -Reason $value.reason -Evidence $value
                continue
            }
            $items = @($value.($method.Collection))
            if ($items.Count -eq 0) {
                Add-WinPrivCapabilityResult -Id $method.Id -Architecture $Architecture -Status Unavailable `
                    -Reason "The $($method.Name) probe returned no local adapter/transport records." -Evidence $value
                continue
            }
            Invoke-WinPrivCapability -Id $method.Id -Architecture $Architecture -Body {
                foreach ($item in $items) {
                    $actualAddress = if ($method.Collection -eq 'transports') { $item.transportAddress } else { $item.addressHex }
                    (Convert-PhysicalAddressText $actualAddress) | Should -Be $expected
                }
                return @{ Count = $items.Count }
            }
        }
    }

	It 'rejects an oversized malformed MAC override without corrupting API-owned buffers' {
		$result = Invoke-WinPrivProbe -Architecture $Architecture `
			-WinPrivArguments @('/MacOverride', ('AA' * 64)) -Operation adapters `
			-Arguments @{} -Sandbox $sandbox -TimeoutSeconds 30
		Assert-WinPrivInvocationSucceeded $result
		foreach ($method in @('getAdaptersInfo', 'getAdaptersAddresses', 'netWkstaTransportEnum')) {
			$value = $result.ProbeResult.result.$method
			if ($value.supported) { $value.success | Should -BeTrue }
		}
	}

    It 'overrides ANSI and Unicode Winsock lookups without changing unrelated names' {
        $result = Invoke-WinPrivProbe -Architecture $Architecture `
            -WinPrivArguments @('/HostOverride', 'localhost', '127.0.0.2') -Operation wsa `
            -Arguments @{ name = 'localhost' } -Sandbox $sandbox -TimeoutSeconds 30
        Assert-WinPrivInvocationSucceeded $result
        $failures = New-Object 'Collections.Generic.List[string]'
        try {
            Invoke-WinPrivCapability -Id 'network.host-wide' -Architecture $Architecture -Body {
                $result.ProbeResult.result.unicode.success | Should -BeTrue
                $result.ProbeResult.result.unicode.address | Should -Be '127.0.0.2'
				foreach ($address in @($result.ProbeResult.result.unicode.addresses)) {
					if ($address.family -eq 2) { $address.address | Should -Be '127.0.0.2' }
					elseif ($address.family -eq 23) { $address.address | Should -Be '::ffff:127.0.0.2' }
				}
                return $result.ProbeResult.result.unicode
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('network.host-wide: {0}' -f $_.Exception.Message))
        }
        try {
            Invoke-WinPrivCapability -Id 'network.host-ansi' -Architecture $Architecture -Body {
                $result.ProbeResult.result.ansi.success | Should -BeTrue
                $result.ProbeResult.result.ansi.address | Should -Be '127.0.0.2'
				foreach ($address in @($result.ProbeResult.result.ansi.addresses)) {
					if ($address.family -eq 2) { $address.address | Should -Be '127.0.0.2' }
					elseif ($address.family -eq 23) { $address.address | Should -Be '::ffff:127.0.0.2' }
				}
                return $result.ProbeResult.result.ansi
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('network.host-ansi: {0}' -f $_.Exception.Message))
        }
        if ($failures.Count -gt 0) {
            throw ($failures -join [Environment]::NewLine)
        }
    }

    It 'passes an unrelated Winsock lookup through unchanged' {
        Invoke-WinPrivCapability -Id 'network.host-pass-through' -Architecture $Architecture -Body {
            $arguments = @{ name = '127.0.0.1' }
            $baseline = Invoke-WinPrivProbe -Architecture $Architecture -Operation wsa `
                -Arguments $arguments -Sandbox $sandbox -TimeoutSeconds 25
            $hooked = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/HostOverride', 'localhost', '127.0.0.2') -Operation wsa `
                -Arguments $arguments -Sandbox $sandbox -TimeoutSeconds 25
            Assert-WinPrivInvocationSucceeded $baseline
            Assert-WinPrivInvocationSucceeded $hooked
            foreach ($api in @('unicode', 'ansi')) {
                $baseline.ProbeResult.result.$api.success | Should -BeTrue
                $hooked.ProbeResult.result.$api.success | Should -BeTrue
                $hooked.ProbeResult.result.$api.address | Should -Be $baseline.ProbeResult.result.$api.address
            }
            return @{ Baseline = $baseline.ProbeResult.result; Hooked = $hooked.ProbeResult.result }
        }
    }

    It 'returns S_OK and CLEAN for AmsiScanString and AmsiScanBuffer' {
        $result = Invoke-WinPrivProbe -Architecture $Architecture -WinPrivArguments @('/DisableAmsi') `
            -Operation amsi -Arguments @{ content = 'WinPriv synthetic AMSI content'; contentName = 'WinPriv.Tests' } `
            -Sandbox $sandbox -TimeoutSeconds 25
        $supportedProperty = if ($null -ne $result.ProbeResult) {
            $result.ProbeResult.PSObject.Properties['supported']
        }
        if ($null -ne $supportedProperty -and -not [bool]$supportedProperty.Value) {
            $reasonProperty = $result.ProbeResult.PSObject.Properties['reason']
            $reason = if ($null -ne $reasonProperty -and
                -not [string]::IsNullOrWhiteSpace([string]$reasonProperty.Value)) {
                [string]$reasonProperty.Value
            }
            else { 'The AMSI probe explicitly reported that the operation is unavailable.' }
            Skip-WinPrivCapability -Id 'amsi.scan-string' -Architecture $Architecture -Reason $reason
            Add-WinPrivCapabilityResult -Id 'amsi.scan-buffer' -Architecture $Architecture `
                -Status Unavailable -Reason $reason
            return
        }

        $failures = New-Object 'Collections.Generic.List[string]'
        foreach ($case in @(
            @{ Capability = 'amsi.scan-string'; Calls = @('stringValid', 'stringInvalid') },
            @{ Capability = 'amsi.scan-buffer'; Calls = @('bufferValid', 'bufferInvalid') }
        )) {
            try {
                Invoke-WinPrivCapability -Id $case.Capability -Architecture $Architecture -Body {
                    Assert-WinPrivInvocationSucceeded $result
                    foreach ($callName in $case.Calls) {
                        $call = $result.ProbeResult.result.$callName
                        $call.hresult | Should -Be 0
                        $call.result | Should -Be 0
                    }
                    return $result.ProbeResult.result.($case.Calls[-1])
                } | Out-Null
            }
            catch {
                [void]$failures.Add(('{0}: {1}' -f $case.Capability, $_.Exception.Message))
            }
        }
        if ($failures.Count -gt 0) {
            throw ($failures -join [Environment]::NewLine)
        }
    }
}

Describe 'WinPriv OS version hooks (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeEach { $sandbox = New-WinPrivSandbox -Architecture $Architecture }
    AfterEach { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'reports Server through GetVersionExW, GetVersionExA, and VerifyVersionInfoW' {
        $result = Invoke-WinPrivProbe -Architecture $Architecture -WinPrivArguments @('/ServerEdition') `
            -Operation version -Arguments @{} -Sandbox $sandbox -TimeoutSeconds 25
        Assert-WinPrivInvocationSucceeded $result
        $failures = New-Object 'Collections.Generic.List[string]'
        try {
            Invoke-WinPrivCapability -Id 'os.get-version-wide' -Architecture $Architecture -Body {
                $result.ProbeResult.result.getVersionExW.productTypeName | Should -Be 'server'
                return $result.ProbeResult.result.getVersionExW
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('os.get-version-wide: {0}' -f $_.Exception.Message))
        }
        try {
            Invoke-WinPrivCapability -Id 'os.get-version-ansi' -Architecture $Architecture -Body {
                $result.ProbeResult.result.getVersionExA.productTypeName | Should -Be 'server'
                return $result.ProbeResult.result.getVersionExA
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('os.get-version-ansi: {0}' -f $_.Exception.Message))
        }
        try {
            Invoke-WinPrivCapability -Id 'os.verify-version' -Architecture $Architecture -Body {
                $result.ProbeResult.result.verifyServer.verified | Should -BeTrue
                $result.ProbeResult.result.verifyWorkstation.verified | Should -BeFalse
				$result.ProbeResult.result.verifyServer.postCallProductType | Should -Be 3
				$result.ProbeResult.result.verifyWorkstation.postCallProductType | Should -Be 1
				$result.ProbeResult.result.verifyServerCombined.verified | Should -BeTrue
				$result.ProbeResult.result.verifyServerCombined.postCallProductType | Should -Be 3
                return @{ Server = $result.ProbeResult.result.verifyServer; Workstation = $result.ProbeResult.result.verifyWorkstation }
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('os.verify-version: {0}' -f $_.Exception.Message))
        }
        if ($failures.Count -gt 0) {
            throw ($failures -join [Environment]::NewLine)
        }
    }
}

Describe 'WinPriv crypto and SQL hooks (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeEach { $sandbox = New-WinPrivSandbox -Architecture $Architecture }
    AfterEach { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'records plaintext from all six crypto hooks, including separate-buffer BCrypt decryption' {
        $plaintext = [Text.Encoding]::ASCII.GetBytes('WinPrivCrypto123')
        $directory = Join-Path $sandbox.Root 'crypto records'
        $result = Invoke-WinPrivProbe -Architecture $Architecture `
            -WinPrivArguments @('/RecordCrypto', $directory) -Operation crypto `
            -Arguments @{ plaintextBase64 = [Convert]::ToBase64String($plaintext) } `
            -Sandbox $sandbox -TimeoutSeconds 30
        Assert-WinPrivInvocationSucceeded $result
		$result.ProbeResult.result.cryptoApi.sizeQuerySuccess | Should -BeTrue
        $recordingProcessId = '{0:D5}' -f [uint32]$result.ProbeResult.result.processId
        $recordingThreadId = '{0:D5}' -f [uint32]$result.ProbeResult.result.threadId
        $functions = @{
            'crypto.bcrypt-encrypt' = 'BCryptEncrypt'
            'crypto.bcrypt-decrypt' = 'BCryptDecrypt'
            'crypto.crypt-encrypt'   = 'CryptEncrypt'
            'crypto.crypt-decrypt'   = 'CryptDecrypt'
            'crypto.rtl-encrypt'     = 'RtlEncryptMemory'
            'crypto.rtl-decrypt'     = 'RtlDecryptMemory'
        }
        $failures = New-Object 'Collections.Generic.List[string]'
        foreach ($entry in $functions.GetEnumerator()) {
            try {
                Invoke-WinPrivCapability -Id $entry.Key -Architecture $Architecture -Body {
                    $files = @(Get-ChildItem -LiteralPath $directory -Filter "*-$($entry.Value).bin" -File)
                    $files.Count | Should -BeGreaterThan 0
                    foreach ($file in $files) {
                        $file.Name | Should -Match ("^[0-9]{{5}}-PID{0}-TID{1}-{2}\.bin$" -f `
                            [regex]::Escape($recordingProcessId),
                            [regex]::Escape($recordingThreadId),
                            [regex]::Escape($entry.Value))
                        [Linq.Enumerable]::SequenceEqual(
                            [byte[]][IO.File]::ReadAllBytes($file.FullName), [byte[]]$plaintext) | Should -BeTrue
                    }
                    return @($files.FullName)
                } | Out-Null
            }
            catch {
                [void]$failures.Add(('{0}: {1}' -f $entry.Key, $_.Exception.Message))
            }
        }
        if ($failures.Count -gt 0) {
            throw ($failures -join [Environment]::NewLine)
        }
    }

    It 'prints synthetic crypto plaintext in SHOW mode' {
        Invoke-WinPrivCapability -Id 'crypto.show' -Architecture $Architecture -Body {
            $plaintext = [Text.Encoding]::ASCII.GetBytes('WinPrivCrypto123')
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/RecordCrypto', 'SHOW') -Operation crypto `
                -Arguments @{ plaintextBase64 = [Convert]::ToBase64String($plaintext) } `
                -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $result
            $result.StdOut | Should -Match 'Function:\s+BCryptEncrypt'
            $result.StdOut | Should -Match 'WinPrivCrypto123'
            return @{ OutputLength = $result.StdOut.Length }
        }
    }

    It 'shows and rewrites ODBC ANSI and Unicode connection strings before a local expected failure' {
        $connection = 'Driver={WinPrivMissing};Server=ORIGINAL;Uid=synthetic;Pwd=synthetic;'
        $result = Invoke-WinPrivProbe -Architecture $Architecture `
            -WinPrivArguments @('/SqlConnectShow', '/SqlConnectSearchReplace', 'ORIGINAL', 'REPLACED') `
            -Operation odbc -Arguments @{ connectionString = $connection } -Sandbox $sandbox -TimeoutSeconds 30
        $supportedProperty = if ($null -ne $result.ProbeResult) {
            $result.ProbeResult.PSObject.Properties['supported']
        }
        if ($null -ne $supportedProperty -and -not [bool]$supportedProperty.Value) {
            $reasonProperty = $result.ProbeResult.PSObject.Properties['reason']
            $reason = if ($null -ne $reasonProperty -and
                -not [string]::IsNullOrWhiteSpace([string]$reasonProperty.Value)) {
                [string]$reasonProperty.Value
            }
            else { 'The ODBC probe explicitly reported that the operation is unavailable.' }
            Skip-WinPrivCapability -Id 'sql.odbc-wide' -Architecture $Architecture -Reason $reason
            Add-WinPrivCapabilityResult -Id 'sql.odbc-ansi' -Architecture $Architecture `
                -Status Unavailable -Reason $reason
            return
        }

        $emptyReplacement = Invoke-WinPrivProbe -Architecture $Architecture `
            -WinPrivArguments @('/SqlConnectShow', '/SqlConnectSearchReplace', 'ORIGINAL', '') `
            -Operation odbc -Arguments @{ connectionString = $connection } -Sandbox $sandbox -TimeoutSeconds 30
        Assert-WinPrivInvocationSucceeded $emptyReplacement
        $emptyReplacement.StdOut | Should -Match 'Server=;'
        $emptyReplacement.StdOut | Should -Not -Match 'Server=ORIGINAL'

        $failures = New-Object 'Collections.Generic.List[string]'
        foreach ($case in @(
            @{ Capability = 'sql.odbc-wide'; ResultName = 'unicode' },
            @{ Capability = 'sql.odbc-ansi'; ResultName = 'ansi' }
        )) {
            try {
                Invoke-WinPrivCapability -Id $case.Capability -Architecture $Architecture -Body {
                    Assert-WinPrivInvocationSucceeded $result
                    $result.ProbeResult.result.($case.ResultName).supported | Should -BeTrue
                    $result.StdOut | Should -Match 'Server=REPLACED'
                    return $result.ProbeResult.result.($case.ResultName)
                } | Out-Null
            }
            catch {
                [void]$failures.Add(('{0}: {1}' -f $case.Capability, $_.Exception.Message))
            }
        }
        if ($failures.Count -gt 0) {
            throw ($failures -join [Environment]::NewLine)
        }
    }

    It 'shows and rewrites an ADO connection string without contacting an external database' {
        $marker = [Guid]::NewGuid().ToString('N')
        $cases = @(
            [pscustomobject]@{
                Initializer = 'legacy'; Capability = 'sql.com-initialize'; ApiName = 'CoInitialize'
                HresultProperty = 'coInitializeLegacyHresult'
                AbsentHresultProperty = 'coInitializeHresult'
            }
            [pscustomobject]@{
                Initializer = 'ex'; Capability = 'sql.com-initialize-ex'; ApiName = 'CoInitializeEx'
                HresultProperty = 'coInitializeHresult'
                AbsentHresultProperty = 'coInitializeLegacyHresult'
            }
        )
        $records = @()
        foreach ($case in $cases) {
            $original = 'ORIGINAL_{0}_{1}' -f $case.Initializer.ToUpperInvariant(), $marker
            $replacement = 'REPLACED_{0}_{1}' -f $case.Initializer.ToUpperInvariant(), $marker
            $connection = 'Provider=WinPrivMissing.{0};Data Source=none;' -f $original
            $expected = 'Provider=WinPrivMissing.{0};Data Source=none;' -f $replacement
            $invocation = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/SqlConnectShow', '/SqlConnectSearchReplace', $original, $replacement) `
                -Operation ado -Arguments @{ connectionString = $connection; initializer = $case.Initializer } `
                -Sandbox $sandbox -TimeoutSeconds 30
            $records += [pscustomobject]@{
                Case = $case; Invocation = $invocation; Original = $connection; Expected = $expected
            }
        }

        $unsupported = @($records | Where-Object {
            $probe = $_.Invocation.ProbeResult
            $supportedProperty = if ($null -ne $probe) { $probe.PSObject.Properties['supported'] }
            $null -ne $supportedProperty -and -not [bool]$supportedProperty.Value
        })
        if ($unsupported.Count -gt 0) {
            $reason = ($unsupported | ForEach-Object {
                $reasonProperty = $_.Invocation.ProbeResult.PSObject.Properties['reason']
                $detail = if ($null -ne $reasonProperty -and
                    -not [string]::IsNullOrWhiteSpace([string]$reasonProperty.Value)) {
                    [string]$reasonProperty.Value
                }
                else { 'The ADO probe explicitly reported that the operation is unavailable.' }
                '{0}: {1}' -f $_.Case.ApiName, $detail
            }) -join '; '
            Skip-WinPrivCapability -Id 'sql.ado' -Architecture $Architecture -Reason $reason
            Add-WinPrivCapabilityResult -Id 'sql.com-initialize' -Architecture $Architecture `
                -Status Unavailable -Reason $reason
            Add-WinPrivCapabilityResult -Id 'sql.com-initialize-ex' -Architecture $Architecture `
                -Status Unavailable -Reason $reason
            return
        }

        $emptyOriginal = 'EMPTY_{0}' -f $marker
        $emptyConnection = 'Provider=WinPrivMissing.{0};Data Source=none;' -f $emptyOriginal
        $emptyExpected = 'Provider=WinPrivMissing.;Data Source=none;'
        $emptyReplacement = Invoke-WinPrivProbe -Architecture $Architecture `
            -WinPrivArguments @('/SqlConnectShow', '/SqlConnectSearchReplace', $emptyOriginal, '') `
            -Operation ado -Arguments @{ connectionString = $emptyConnection; initializer = 'legacy' } `
            -Sandbox $sandbox -TimeoutSeconds 30
        Assert-WinPrivInvocationSucceeded $emptyReplacement
        $emptyReplacement.ProbeResult.success | Should -BeTrue
        $emptyReplacement.StdOut | Should -Match ([regex]::Escape($emptyExpected))
        $emptyReplacement.StdOut | Should -Not -Match ([regex]::Escape($emptyConnection))

        $assertShowEvidence = {
            param($Record)
            $shownConnections = @([regex]::Matches(
                [string]$Record.Invocation.StdOut,
                'SQL Connection String:[ \t]*([^\r\n]*)') | ForEach-Object {
                    $_.Groups[1].Value.Trim()
                })
            $shownConnections.Count | Should -BeGreaterThan 0
            $shownConnections | Should -Contain $Record.Expected
            $shownConnections | Should -Not -Contain $Record.Original
            return $shownConnections
        }

        $failures = New-Object 'Collections.Generic.List[string]'
        foreach ($record in $records) {
            try {
                Invoke-WinPrivCapability -Id $record.Case.Capability -Architecture $Architecture -Body {
                    Assert-WinPrivInvocationSucceeded $record.Invocation
                    $record.Invocation.ProbeResult.success | Should -BeTrue
                    $record.Invocation.ProbeResult.result.initializer | Should -Be $record.Case.ApiName
                    $record.Invocation.ProbeResult.result.($record.Case.HresultProperty) | Should -BeIn @(0, 1)
                    $record.Invocation.ProbeResult.result.PSObject.Properties[$record.Case.AbsentHresultProperty] |
                        Should -BeNullOrEmpty
                    $shownConnections = & $assertShowEvidence $record
                    return @{
                        Initializer = $record.Invocation.ProbeResult.result.initializer
                        Hresult = $record.Invocation.ProbeResult.result.initializerHresultHex
                        ShownConnections = $shownConnections
                    }
                } | Out-Null
            }
            catch {
                [void]$failures.Add(('{0}: {1}' -f $record.Case.ApiName, $_.Exception.Message))
            }
        }

        try {
            Invoke-WinPrivCapability -Id 'sql.ado' -Architecture $Architecture -Body {
                foreach ($record in $records) {
                    Assert-WinPrivInvocationSucceeded $record.Invocation
                    $record.Invocation.ProbeResult.result.openSucceeded | Should -BeFalse
                    $record.Invocation.ProbeResult.result.openError | Should -Not -BeNullOrEmpty
                    [void](& $assertShowEvidence $record)
                }
                return @($records | ForEach-Object { $_.Invocation.ProbeResult.result })
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('ADO Open: {0}' -f $_.Exception.Message))
        }

        if ($failures.Count -gt 0) {
            throw ($failures -join [Environment]::NewLine)
        }
    }

    It 'bounds a malformed SQL regex without hanging the suite' {
        Invoke-WinPrivCapability -Id 'sql.malformed-regex' -Architecture $Architecture -Body {
            $result = Invoke-WinPrivProbe -Architecture $Architecture `
                -WinPrivArguments @('/SqlConnectSearchReplace', '[unterminated', 'x') `
                -Operation odbc -Arguments @{ connectionString = 'Driver={WinPrivMissing};Marker=value;' } `
                -Sandbox $sandbox -TimeoutSeconds 10
            Assert-WinPrivInvocationSucceeded $result
            $result.ProbeResult.result.unicode.success | Should -BeTrue
            $result.ProbeResult.result.ansi.success | Should -BeTrue
            return $result.ProbeResult.result
        }
    }
}

$crossArchitectureCases = @(
    @{
        LauncherArchitecture = 'x86'
        ParentArchitecture = 'x64'
        ChildArchitecture = 'x86'
        Api = 'W'
        ApiName = 'CreateProcessW'
        Chain = 'x86-x64-x86'
        Capability = 'propagation.cross-x86-x64-x86-wide'
    },
    @{
        LauncherArchitecture = 'x86'
        ParentArchitecture = 'x64'
        ChildArchitecture = 'x86'
        Api = 'A'
        ApiName = 'CreateProcessA'
        Chain = 'x86-x64-x86'
        Capability = 'propagation.cross-x86-x64-x86-ansi'
    },
    @{
        LauncherArchitecture = 'x64'
        ParentArchitecture = 'x86'
        ChildArchitecture = 'x64'
        Api = 'W'
        ApiName = 'CreateProcessW'
        Chain = 'x64-x86-x64'
        Capability = 'propagation.cross-x64-x86-x64-wide'
    },
    @{
        LauncherArchitecture = 'x64'
        ParentArchitecture = 'x86'
        ChildArchitecture = 'x64'
        Api = 'A'
        ApiName = 'CreateProcessA'
        Chain = 'x64-x86-x64'
        Capability = 'propagation.cross-x64-x86-x64-ansi'
    }
)

Describe 'WinPriv cross-architecture descendant propagation (<Chain>, <ApiName>)' `
    -Tag 'Safe', 'CrossArchitecture' -ForEach $crossArchitectureCases {

    It 'injects the architecture-matching payload into the parent and child' {
        $selectedArchitectures = @(
            $env:WINPRIV_TEST_ARCHITECTURES -split '[,;]' |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($selectedArchitectures -notcontains 'x86' -or
            $selectedArchitectures -notcontains 'x64') {
            Skip-WinPrivCapability -Id $Capability -Architecture All -Reason `
                'The cross-architecture matrix requires both x86 and x64 test architectures.'
            return
        }

        $parentHost = Get-WinPrivTestHost -Architecture $ParentArchitecture -Detailed
        $childHost = Get-WinPrivTestHost -Architecture $ChildArchitecture -Detailed
        $unavailableHosts = @(@($parentHost, $childHost) | Where-Object { -not $_.Available })
        if ($unavailableHosts.Count -gt 0) {
            $reason = @($unavailableHosts | ForEach-Object {
                '{0}: {1}' -f $_.Architecture, $_.Reason
            }) -join '; '
            Skip-WinPrivCapability -Id $Capability -Architecture All -Reason $reason
            return
        }

        $sandbox = $null
        try {
            $sandbox = New-WinPrivSandbox -Architecture @('x86', 'x64') `
                -Purpose "cross-$Chain-$Api"

            Invoke-WinPrivCapability -Id $Capability -Architecture All -Body {
                $result = Invoke-WinPrivProbe -Architecture $LauncherArchitecture `
                    -ProbeArchitecture $ParentArchitecture `
                    -Operation create-process -Arguments @{
                        api = $Api
                        depth = 1
                        timeoutMilliseconds = 60000
                        childOperation = 'state'
                        childArguments = @{}
                        powerShellPath = $childHost.Path
                    } -Sandbox $sandbox -TimeoutSeconds 90

                Assert-WinPrivInvocationSucceeded $result
                $result.ProbeResult.success | Should -BeTrue
                $result.ProbeResult.result.success | Should -BeTrue
                $result.ProbeResult.result.created | Should -BeTrue
                $result.ProbeResult.result.api | Should -Be $ApiName
                $result.ProbeResult.result.customEnvironment | Should -BeFalse
                (Get-WinPrivPeArchitecture -Path $result.LauncherPath) |
                    Should -Be $LauncherArchitecture

                $parentState = $result.ProbeResult.result.parentState
                $childEnvelope = $result.ProbeResult.result.childResult
                $childEnvelope.success | Should -BeTrue
                $childState = $childEnvelope.result
                $result.ProbeResult.result.processId | Should -Be $childState.processId

                $assertInjectedState = {
                    param(
                        $State,
                        [string] $ExpectedArchitecture,
                        [string] $ExpectedProcessPath,
                        [string] $Role)

                    $expectedPointerSize = if ($ExpectedArchitecture -eq 'x64') { 8 } else { 4 }
                    $expectedSuffix = if ($ExpectedArchitecture -eq 'x64') { '-64.dll' } else { '-32.dll' }
                    $unexpectedSuffix = if ($ExpectedArchitecture -eq 'x64') { '-32.dll' } else { '-64.dll' }

                    $State.success | Should -BeTrue
                    $State.architecture | Should -Be $ExpectedArchitecture
                    $State.pointerSize | Should -Be $expectedPointerSize
                    $State.is64BitProcess | Should -Be ($ExpectedArchitecture -eq 'x64')
                    (Get-WinPrivPeArchitecture -Path ([string]$State.processPath)) |
                        Should -Be $ExpectedArchitecture
                    [IO.Path]::GetFullPath([string]$State.processPath) |
                        Should -Be ([IO.Path]::GetFullPath($ExpectedProcessPath))
                    $State.winPrivLibraryLoaded | Should -BeTrue
                    $State.PSObject.Properties['loadedModulesError'] | Should -BeNullOrEmpty

                    $modulePaths = @($State.winPrivLibraryModules)
                    $modulePaths | Should -HaveCount 1
                    $expectedModules = @($modulePaths | Where-Object {
                        [IO.Path]::GetFileName([string]$_) -like "*$expectedSuffix"
                    })
                    $unexpectedModules = @($modulePaths | Where-Object {
                        [IO.Path]::GetFileName([string]$_) -like "*$unexpectedSuffix"
                    })
                    $expectedModules | Should -HaveCount 1
                    $unexpectedModules | Should -HaveCount 0

                    return [ordered]@{
                        Role = $Role
                        Architecture = $State.architecture
                        PointerSize = $State.pointerSize
                        ProcessPath = $State.processPath
                        WinPrivLibraryModules = $modulePaths
                    }
                }

                $parentEvidence = & $assertInjectedState `
                    $parentState $ParentArchitecture $parentHost.Path 'parent'
                $childEvidence = & $assertInjectedState `
                    $childState $ChildArchitecture $childHost.Path 'child'

                return [ordered]@{
                    Chain = $Chain
                    Api = $ApiName
                    LauncherArchitecture = $LauncherArchitecture
                    LauncherPath = $result.LauncherPath
                    Parent = $parentEvidence
                    Child = $childEvidence
                }
            } | Out-Null
        }
        finally {
            if ($null -ne $sandbox) {
                Remove-WinPrivSandbox -Sandbox $sandbox
            }
        }
    }
}

Describe 'WinPriv descendant propagation (<Architecture>)' -Tag 'Safe' -ForEach $architectureCases {
    BeforeEach { $sandbox = New-WinPrivSandbox -Architecture $Architecture }
    AfterEach { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'injects CreateProcessW children and grandchildren' {
        $failures = New-Object 'Collections.Generic.List[string]'
        $one = Invoke-WinPrivProbe -Architecture $Architecture -Operation create-process `
            -Arguments @{ api = 'W'; depth = 1; childOperation = 'state'; childArguments = @{} } `
            -Sandbox $sandbox -TimeoutSeconds 35
        try {
            Invoke-WinPrivCapability -Id 'propagation.create-process-wide' -Architecture $Architecture -Body {
                Assert-WinPrivInvocationSucceeded $one
                $one.ProbeResult.result.childResult.success | Should -BeTrue
                @($one.ProbeResult.result.childResult.result.winPrivLibraryModules).Count | Should -BeGreaterThan 0
                return $one.ProbeResult.result.childResult.result.winPrivLibraryModules
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('CreateProcessW child: {0}' -f $_.Exception.Message))
        }

        $two = Invoke-WinPrivProbe -Architecture $Architecture -Operation create-process `
            -Arguments @{ api = 'W'; depth = 2; childOperation = 'state'; childArguments = @{} } `
            -Sandbox $sandbox -TimeoutSeconds 45
        try {
            Invoke-WinPrivCapability -Id 'propagation.grandchild' -Architecture $Architecture -Body {
                Assert-WinPrivInvocationSucceeded $two
                $two.ProbeResult.result.childResult.success | Should -BeTrue
                $two.ProbeResult.result.childResult.result.success | Should -BeTrue
                $two.ProbeResult.result.childResult.result.childResult.success | Should -BeTrue
                @($two.ProbeResult.result.childResult.result.childResult.result.winPrivLibraryModules).Count | Should -BeGreaterThan 0
                return $two.ProbeResult.result.childResult.result.childResult.result.winPrivLibraryModules
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('CreateProcessW grandchild: {0}' -f $_.Exception.Message))
        }
        if ($failures.Count -gt 0) {
            throw ($failures -join [Environment]::NewLine)
        }
    }

    It 'injects CreateProcessA children and grandchildren' {
        $failures = New-Object 'Collections.Generic.List[string]'
        $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation create-process `
            -Arguments @{ api = 'A'; depth = 1; childOperation = 'state'; childArguments = @{} } `
            -Sandbox $sandbox -TimeoutSeconds 35
        try {
            Invoke-WinPrivCapability -Id 'propagation.create-process-ansi' -Architecture $Architecture -Body {
                Assert-WinPrivInvocationSucceeded $result
                $result.ProbeResult.result.childResult.success | Should -BeTrue
                @($result.ProbeResult.result.childResult.result.winPrivLibraryModules).Count | Should -BeGreaterThan 0
                return $result.ProbeResult.result.childResult.result.winPrivLibraryModules
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('CreateProcessA child: {0}' -f $_.Exception.Message))
        }

        $grandchild = Invoke-WinPrivProbe -Architecture $Architecture -Operation create-process `
            -Arguments @{ api = 'A'; depth = 2; childOperation = 'state'; childArguments = @{} } `
            -Sandbox $sandbox -TimeoutSeconds 45
        try {
            Invoke-WinPrivCapability -Id 'propagation.grandchild-ansi' -Architecture $Architecture -Body {
                Assert-WinPrivInvocationSucceeded $grandchild
                $grandchild.ProbeResult.result.childResult.success | Should -BeTrue
                $grandchild.ProbeResult.result.childResult.result.success | Should -BeTrue
                $grandchild.ProbeResult.result.childResult.result.childResult.success | Should -BeTrue
                @($grandchild.ProbeResult.result.childResult.result.childResult.result.winPrivLibraryModules).Count |
                    Should -BeGreaterThan 0
                return $grandchild.ProbeResult.result.childResult.result.childResult.result.winPrivLibraryModules
            } | Out-Null
        }
        catch {
            [void]$failures.Add(('CreateProcessA grandchild: {0}' -f $_.Exception.Message))
        }
        if ($failures.Count -gt 0) {
            throw ($failures -join [Environment]::NewLine)
        }
    }

    It 'uses a nested WinPriv launcher configuration for its descendants' {
        $innerLauncher = $sandbox.Launchers.PSObject.Properties[$Architecture].Value.WinPrivCmd
        $result = Invoke-WinPrivProbe -Architecture $Architecture `
            -WinPrivArguments @($innerLauncher, '/ServerEdition') `
            -Operation version -Arguments @{} -Sandbox $sandbox -TimeoutSeconds 45
        Assert-WinPrivInvocationSucceeded $result
        $result.ProbeResult.success | Should -BeTrue
        $result.ProbeResult.result.getVersionExW.productTypeName | Should -Be 'server'
    }

    It 'preserves WinPriv propagation through custom-environment children and grandchildren' {
        $customValue = 'caf{0}-{1}' -f [char]0x00E9, [char]0x00A3
        $records = @()
        foreach ($api in @('A', 'W')) {
            $invocation = Invoke-WinPrivProbe -Architecture $Architecture -WinPrivArguments @('/ServerEdition') `
                -Operation create-process -Arguments @{
                    api = $api; depth = 2; childOperation = 'version'
                    childArguments = @{ environmentNames = @('WINPRIV_CUSTOM_ENV') }
                    timeoutMilliseconds = 90000
                    customEnvironment = @{
                        WINPRIV_CUSTOM_ENV = $customValue; TEMP = $sandbox.Temp; TMP = $sandbox.Temp
                        SystemRoot = $env:SystemRoot; WINDIR = $env:WINDIR; ComSpec = $env:ComSpec
                        _WINPRIV_EV_SERVER_EDITION_ = '0'
                    }
                    mergeEnvironment = $false
                } -Sandbox $sandbox -TimeoutSeconds 95
            $records += [pscustomobject]@{ Api = $api; Invocation = $invocation }
        }

        Invoke-WinPrivCapability -Id 'propagation.custom-environment' -Architecture $Architecture -Body {
            $failures = New-Object 'Collections.Generic.List[string]'
            $evidence = [ordered]@{}
            foreach ($record in $records) {
                try {
                    $result = $record.Invocation
                    Assert-WinPrivInvocationSucceeded $result
                    $child = $result.ProbeResult.result.childResult
                    $grandchild = $child.result.childResult
                    $child.success | Should -BeTrue
                    $grandchild.success | Should -BeTrue
                    $grandchild.result.getVersionExW.productTypeName | Should -Be 'server'
                    $grandchild.result.environment.WINPRIV_CUSTOM_ENV | Should -Be $customValue
                    if ($record.Api -eq 'W') {
                        $result.ProbeResult.result.environmentCodePage | Should -Be 1200
                        $child.result.environmentCodePage | Should -Be 1200
                    }
                    else {
                        $result.ProbeResult.result.environmentCodePage | Should -BeGreaterThan 0
                        $result.ProbeResult.result.environmentCodePage | Should -Not -Be 1200
                        $child.result.environmentCodePage | Should -BeGreaterThan 0
                        $child.result.environmentCodePage | Should -Not -Be 1200
                    }
                    $evidence[$record.Api] = @{
                        EnvironmentCodePages = @(
                            $result.ProbeResult.result.environmentCodePage,
                            $child.result.environmentCodePage)
                        EnvironmentValue = $grandchild.result.environment.WINPRIV_CUSTOM_ENV
                        Version = $grandchild.result.getVersionExW
                    }
                }
                catch {
                    [void]$failures.Add(('CreateProcess{0}: {1}' -f $record.Api, $_.Exception.Message))
                }
            }
            if ($failures.Count -gt 0) {
                throw ($failures -join [Environment]::NewLine)
            }
            return $evidence
        }
    }

}
