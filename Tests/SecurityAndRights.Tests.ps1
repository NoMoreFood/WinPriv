. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')
    $denyRights = @(
        'SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyBatchLogonRight',
        'SeDenyServiceLogonRight', 'SeDenyRemoteInteractiveLogonRight'
    )
    $allowLogonRights = @(
        'SeNetworkLogonRight', 'SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight',
        'SeBatchLogonRight', 'SeServiceLogonRight'
    )
}

$architectureCases = Get-WinPrivArchitectureCases

Describe 'WinPriv LSA account-right operations (<Architecture>)' -Tag 'Admin' -ForEach $architectureCases {
    BeforeEach {
        $sandbox = $null
        $principal = $null
        if (-not (Test-WinPrivElevated)) { throw 'The Admin profile requires an elevated administrator token.' }
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
        $principalOutput = @(New-WinPrivLocalPrincipal -Type group -Sandbox $sandbox)
        if ($principalOutput.Count -ne 1) {
            throw "New-WinPrivLocalPrincipal returned $($principalOutput.Count) objects; exactly one is required."
        }
        $principal = $principalOutput[0]
    }

    AfterEach {
        Remove-WinPrivSecurityFixture -Architecture $Architecture -Sandbox $sandbox -Principal $principal
    }

    It 'enumerates global LSA assignments for automatic journal recovery' {
        if (-not ('WinPrivTests.LsaPolicy' -as [type])) {
            Add-Type -Path (Join-Path $PSScriptRoot 'Support\WinPriv.LsaPolicy.cs')
        }

        { [void][WinPrivTests.LsaPolicy]::GetAccountSidsWithRight('SeDenyBatchLogonRight') } |
            Should -Not -Throw
    }

    It 'grants and idempotently re-grants one named right' {
        Invoke-WinPrivCapability -Id 'rights.grant' -Architecture $Architecture -Body {
            foreach ($iteration in 1..2) {
                $result = Invoke-WinPriv -Architecture $Architecture `
                    -Arguments @('/GrantRight', 'SeBatchLogonRight', $principal.Account) `
                    -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 20
                Assert-WinPrivInvocationSucceeded $result
            }
            $state = Get-WinPrivLsaState -Architecture $Architecture -Sandbox $sandbox -Account $principal.Account
            @($state.accountRights.rights | Where-Object { $_ -eq 'SeBatchLogonRight' }) | Should -HaveCount 1
            return $state.accountRights.rights
        }
    }

    It 'revokes a present right and leaves it absent on a repeated revoke' {
        Invoke-WinPrivCapability -Id 'rights.revoke' -Architecture $Architecture -Body {
            Invoke-WinPriv -Architecture $Architecture `
                -Arguments @('/GrantRight', 'SeBatchLogonRight', $principal.Account) `
                -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 20 | Out-Null
            foreach ($iteration in 1..2) {
                $result = Invoke-WinPriv -Architecture $Architecture `
                    -Arguments @('/RevokeRight', 'SeBatchLogonRight', $principal.Account) `
                    -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 20
                Assert-WinPrivInvocationSucceeded $result
            }
            $state = Get-WinPrivLsaState -Architecture $Architecture -Sandbox $sandbox -Account $principal.Account
            $state.accountRights.rights | Should -Not -Contain 'SeBatchLogonRight'
            return $state.accountRights.rights
        }
    }

    It 'clears all five deny-logon rights from only the named fixture group' {
        Invoke-WinPrivCapability -Id 'rights.clear-deny-named' -Architecture $Architecture -Body {
            $missingAccount = "WinPrivMissing-$([Guid]::NewGuid().ToString('N'))"
            $missing = Invoke-WinPriv -Architecture $Architecture `
                -Arguments @('/ClearDenyRights', $missingAccount) -Launcher WinPrivCmd `
                -Sandbox $sandbox -TimeoutSeconds 30
            $missing.ExitCode | Should -Not -Be 0

            foreach ($right in $denyRights) {
                $grant = Invoke-WinPriv -Architecture $Architecture `
                    -Arguments @('/GrantRight', $right, $principal.Account) `
                    -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 20
                Assert-WinPrivInvocationSucceeded $grant
            }
            $clear = Invoke-WinPriv -Architecture $Architecture `
                -Arguments @('/ClearDenyRights', $principal.Account) -Launcher WinPrivCmd `
                -Sandbox $sandbox -TimeoutSeconds 30
            Assert-WinPrivInvocationSucceeded $clear
            $state = Get-WinPrivLsaState -Architecture $Architecture -Sandbox $sandbox -Account $principal.Account
            foreach ($right in $denyRights) { $state.accountRights.rights | Should -Not -Contain $right }
            return $state.accountRights.rights
        }
    }

    It 'grants every available non-deny privilege and allow-logon right' {
        Invoke-WinPrivCapability -Id 'rights.grant-all' -Architecture $Architecture -Body {
            $grant = Invoke-WinPriv -Architecture $Architecture `
                -Arguments @('/GrantAllRights', $principal.Account) -Launcher WinPrivCmd `
                -Sandbox $sandbox -TimeoutSeconds 60
            Assert-WinPrivInvocationSucceeded $grant
            $state = Get-WinPrivLsaState -Architecture $Architecture -Sandbox $sandbox -Account $principal.Account
            $expected = @($state.availableRights.rights.name) + $allowLogonRights
            foreach ($right in $expected) { $state.accountRights.rights | Should -Contain $right }
            foreach ($right in $denyRights) { $state.accountRights.rights | Should -Not -Contain $right }
            return @{ Expected = $expected.Count; Actual = @($state.accountRights.rights).Count }
        }
    }

    It 'clears and restores global deny rights only when explicitly enabled' {
        if ($env:WINPRIV_TEST_ALLOW_GLOBAL_POLICY_MUTATION -ne '1') {
            Skip-WinPrivCapability -Id 'rights.clear-deny-global' -Architecture $Architecture `
                -Reason 'The runner was not given -AllowGlobalPolicyMutation.'
            return
        }
        Invoke-WinPrivCapability -Id 'rights.clear-deny-global' -Architecture $Architecture -Body {
            $snapshot = @()
            foreach ($right in $denyRights) {
                $state = Get-WinPrivLsaState -Architecture $Architecture -Sandbox $sandbox -Right $right
                foreach ($account in @($state.accountsWithRight.accounts)) {
                    $snapshot += [pscustomobject]@{ Right = $right; Account = ($account.account ?? $account.sid) }
                }
            }
            Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind LsaRight `
                -Identifier 'global-deny-rights-snapshot' `
                -OriginalState @{ Assignments = @($snapshot); Rights = @($denyRights) } `
                -Metadata @{ Operation = 'ClearDenyRightsGlobal' } | Out-Null
            $seed = Invoke-WinPriv -Architecture $Architecture `
                -Arguments @('/GrantRight', 'SeDenyBatchLogonRight', $principal.Account) `
                -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 20
            Assert-WinPrivInvocationSucceeded $seed
            try {
                $clear = Invoke-WinPriv -Architecture $Architecture -Arguments @('/ClearDenyRights') `
                    -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 60
                Assert-WinPrivInvocationSucceeded $clear
                foreach ($right in $denyRights) {
                    $after = Get-WinPrivLsaState -Architecture $Architecture -Sandbox $sandbox -Right $right
                    @($after.accountsWithRight.accounts) | Should -HaveCount 0
                }
            }
            finally {
                foreach ($assignment in $snapshot | Sort-Object Right, Account -Unique) {
                    if ($assignment.Account) {
                        Invoke-WinPriv -Architecture $Architecture `
                            -Arguments @('/GrantRight', $assignment.Right, $assignment.Account) `
                            -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 30 | Out-Null
                    }
                }
            }
            return @{ RestoredAssignments = @($snapshot).Count }
        }
    }
}

Describe 'WinPriv privilege and identity behavior (<Architecture>)' -Tag 'Admin' -ForEach $architectureCases {
    BeforeEach {
        $sandbox = $null
        $principal = $null
        $originalAcl = $null
        if (-not (Test-WinPrivElevated)) { throw 'The Admin profile requires an elevated administrator token.' }
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
        $principalOutput = @(New-WinPrivLocalPrincipal -Type user -Sandbox $sandbox)
        if ($principalOutput.Count -ne 1) {
            throw "New-WinPrivLocalPrincipal returned $($principalOutput.Count) objects; exactly one is required."
        }
        $principal = $principalOutput[0]
        $originalAcl = Get-Acl -LiteralPath $sandbox.Root
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Acl -Identifier $sandbox.Root `
            -OriginalState @{ Sddl = $originalAcl.Sddl } -Metadata @{ Sid = $principal.Sid } | Out-Null
        $acl = Get-Acl -LiteralPath $sandbox.Root
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $principal.Sid, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule) | Out-Null
        Set-Acl -LiteralPath $sandbox.Root -AclObject $acl
    }

    AfterEach {
        Remove-WinPrivSecurityFixture -Architecture $Architecture -Sandbox $sandbox -Principal $principal `
            -OriginalAcl $originalAcl
    }

    It 'makes both administrator-membership APIs report true for a non-administrator token' {
        $baseline = Invoke-WinPrivFreshUserProbe -Architecture $Architecture -Sandbox $sandbox `
            -Principal $principal -WinPrivArguments @() -Operation admin
        $baseline.Run.Started | Should -BeTrue
        $baseline.Run.TimedOut | Should -BeFalse
        $baseline.Run.JobAssigned | Should -BeTrue
        @($baseline.Run.ProcessIds) | Should -Contain $baseline.Run.ProcessId
        $baseline.ProbeResult.result.isUserAnAdmin | Should -BeFalse
        $baseline.ProbeResult.result.adminMembership.isMember | Should -BeFalse

        $hooked = Invoke-WinPrivFreshUserProbe -Architecture $Architecture -Sandbox $sandbox `
            -Principal $principal -WinPrivArguments @('/AdminImpersonate') -Operation admin
        $hooked.Run.Started | Should -BeTrue
        $hooked.Run.TimedOut | Should -BeFalse
        $hooked.Run.JobAssigned | Should -BeTrue
        @($hooked.Run.ProcessIds) | Should -Contain $hooked.Run.ProcessId
        Invoke-WinPrivCapability -Id 'identity.is-user-admin' -Architecture $Architecture -Body {
            $hooked.ProbeResult.result.isUserAnAdmin | Should -BeTrue
            return $hooked.ProbeResult.result.isUserAnAdmin
        }
        Invoke-WinPrivCapability -Id 'identity.check-token-membership' -Architecture $Architecture -Body {
            $hooked.ProbeResult.result.adminMembership.isMember | Should -BeTrue
            $hooked.ProbeResult.result.everyoneMembership.isMember | Should -BeTrue
            return $hooked.ProbeResult.result.adminMembership
        }
    }

    It 'enables a requested privilege in a fresh token' {
        $grant = Invoke-WinPriv -Architecture $Architecture `
            -Arguments @('/GrantRight', 'SeDebugPrivilege', $principal.Account) `
            -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 20
        Assert-WinPrivInvocationSucceeded $grant
        Invoke-WinPrivCapability -Id 'privilege.with-privs' -Architecture $Architecture -Body {
            $probe = Invoke-WinPrivFreshUserProbe -Architecture $Architecture -Sandbox $sandbox `
                -Principal $principal -WinPrivArguments @('/WithPrivs', 'SeDebugPrivilege,SeDebugPrivilege') `
                -Operation token
            $probe.Run.Started | Should -BeTrue
            $probe.Run.TimedOut | Should -BeFalse
            $probe.Run.JobAssigned | Should -BeTrue
            @($probe.Run.ProcessIds) | Should -Contain $probe.Run.ProcessId
            $probe.Run.ExitCode | Should -Be 0
            $debug = @($probe.ProbeResult.result.privileges | Where-Object name -EQ 'SeDebugPrivilege')
            $debug | Should -HaveCount 1
            $debug[0].enabled | Should -BeTrue
            return $debug[0]
        }
    }

    It 'enables every available privilege in a fresh token after GrantAllRights' {
        $grant = Invoke-WinPriv -Architecture $Architecture `
            -Arguments @('/GrantAllRights', $principal.Account) -Launcher WinPrivCmd `
            -Sandbox $sandbox -TimeoutSeconds 60
        Assert-WinPrivInvocationSucceeded $grant
        Invoke-WinPrivCapability -Id 'privilege.with-all' -Architecture $Architecture -Body {
            $probe = Invoke-WinPrivFreshUserProbe -Architecture $Architecture -Sandbox $sandbox `
                -Principal $principal -WinPrivArguments @('/WithAllPrivs') -Operation token
            $probe.Run.Started | Should -BeTrue
            $probe.Run.TimedOut | Should -BeFalse
            $probe.Run.JobAssigned | Should -BeTrue
            @($probe.Run.ProcessIds) | Should -Contain $probe.Run.ProcessId
            $probe.Run.ExitCode | Should -Be 0
            $privileges = @($probe.ProbeResult.result.privileges)
            $privileges.Count | Should -BeGreaterThan 0
            @($privileges | Where-Object { -not $_.enabled }) | Should -HaveCount 0
            return @{ Privileges = $privileges.Count }
        }
    }
}

Describe 'WinPriv ACL bypass (<Architecture>)' -Tag 'Admin' -ForEach $architectureCases {
    BeforeEach {
        if (-not (Test-WinPrivElevated)) { throw 'The Admin profile requires an elevated administrator token.' }
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
    }
    AfterEach { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'bypasses an explicit read/write denial only for the injected target' {
        $token = Invoke-WinPrivProbe -Architecture $Architecture -Operation token -Arguments @{} `
            -Sandbox $sandbox -TimeoutSeconds 20
        Assert-WinPrivInvocationSucceeded $token
        $required = @('SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege', 'SeChangeNotifyPrivilege')
        $present = @($token.ProbeResult.result.privileges.name)
        $missing = @($required | Where-Object { $_ -notin $present })
        $driveFormat = try { [IO.DriveInfo]::new([IO.Path]::GetPathRoot($sandbox.Root)).DriveFormat } catch { $null }
        if ($missing.Count -gt 0 -or $driveFormat -ne 'NTFS') {
            $reason = if ($missing.Count -gt 0) {
                "The elevated token does not contain: $($missing -join ', ')."
            }
            else {
                "The suite root is on '$driveFormat', not NTFS."
            }
            Skip-WinPrivCapability -Id 'filesystem.bypass-read' -Architecture $Architecture -Reason $reason
            Add-WinPrivCapabilityResult -Id 'filesystem.bypass-write' -Architecture $Architecture -Status Unavailable -Reason $reason
            Add-WinPrivCapabilityResult -Id 'filesystem.nt-open-file' -Architecture $Architecture -Status Unavailable -Reason $reason
            Add-WinPrivCapabilityResult -Id 'filesystem.nt-create-file' -Architecture $Architecture -Status Unavailable -Reason $reason
            return
        }

        $path = Join-Path $sandbox.Root 'acl-fixture.bin'
        $original = [Text.Encoding]::UTF8.GetBytes('denied-original')
        [IO.File]::WriteAllBytes($path, $original)
        $originalAcl = Get-Acl -LiteralPath $path
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind Acl -Identifier $path `
            -OriginalState @{ Sddl = $originalAcl.Sddl } -Metadata @{
                ContentSha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
                ContentBase64 = [Convert]::ToBase64String($original)
            } | Out-Null
        $denyAcl = Get-Acl -LiteralPath $path
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $deny = [Security.AccessControl.FileSystemAccessRule]::new(
            $currentSid, 'ReadData,WriteData', 'None', 'None', 'Deny')
        $denyAcl.AddAccessRule($deny) | Out-Null
        Set-Acl -LiteralPath $path -AclObject $denyAcl
        try {
            $baseline = Invoke-WinPrivProbe -Architecture $Architecture -Operation file `
                -Arguments @{ action = 'read'; path = $path } -Sandbox $sandbox -TimeoutSeconds 20
            $baseline.ProbeResult.result.success | Should -BeFalse
            foreach ($api in @('NtOpenFile', 'NtCreateFile')) {
                $nativeBaseline = Invoke-WinPrivProbe -Architecture $Architecture -Operation native-file `
                    -Arguments @{ api = $api; path = $path } -Sandbox $sandbox -TimeoutSeconds 20
                $nativeBaseline.TimedOut | Should -BeFalse
                $nativeBaseline.ProbeResult.result.success | Should -BeFalse
            }

            Invoke-WinPrivCapability -Id 'filesystem.bypass-read' -Architecture $Architecture -Body {
                $read = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/BypassFileSecurity') -Operation file `
                    -Arguments @{ action = 'read'; path = $path } -Sandbox $sandbox -TimeoutSeconds 30
                Assert-WinPrivInvocationSucceeded $read
                @([Convert]::FromBase64String($read.ProbeResult.result.bytesBase64)) | Should -Be $original
                return $read.ProbeResult.result
            }
            Invoke-WinPrivCapability -Id 'filesystem.nt-open-file' -Architecture $Architecture -Body {
                $read = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/BypassFileSecurity') -Operation native-file `
                    -Arguments @{ api = 'NtOpenFile'; path = $path } -Sandbox $sandbox -TimeoutSeconds 30
                Assert-WinPrivInvocationSucceeded $read
                $read.ProbeResult.result.success | Should -BeTrue
                return $read.ProbeResult.result
            }
            Invoke-WinPrivCapability -Id 'filesystem.nt-create-file' -Architecture $Architecture -Body {
                $read = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/BypassFileSecurity') -Operation native-file `
                    -Arguments @{ api = 'NtCreateFile'; path = $path } -Sandbox $sandbox -TimeoutSeconds 30
                Assert-WinPrivInvocationSucceeded $read
                $read.ProbeResult.result.success | Should -BeTrue
                return $read.ProbeResult.result
            }
            Invoke-WinPrivCapability -Id 'filesystem.bypass-write' -Architecture $Architecture -Body {
                $replacement = [Text.Encoding]::UTF8.GetBytes('bypass-replacement')
                $write = Invoke-WinPrivProbe -Architecture $Architecture `
                    -WinPrivArguments @('/BypassFileSecurity') -Operation file `
                    -Arguments @{ action = 'write'; path = $path; dataBase64 = [Convert]::ToBase64String($replacement) } `
                    -Sandbox $sandbox -TimeoutSeconds 30
                Assert-WinPrivInvocationSucceeded $write
                return $write.ProbeResult.result
            }
        }
        finally {
            Set-Acl -LiteralPath $path -AclObject $originalAcl
            [IO.File]::WriteAllBytes($path, $original)
        }
    }
}

Describe 'WinPriv local-admin run-as boundaries (<Architecture>)' -Tag 'Admin' -ForEach $architectureCases {
    BeforeEach { $sandbox = New-WinPrivSandbox -Architecture $Architecture }
    AfterEach { Remove-WinPrivSandbox -Sandbox $sandbox }

    It 'bounds the four SYSTEM/WTS run-as switches and MediumPlus without claiming a positive verification' {
        $cases = @(
            @{ Id = 'runas.console-wait'; Args = @('/RunAsConsoleUser', $env:ComSpec, '/d', '/c', 'exit 0') },
            @{ Id = 'runas.console-nowait'; Args = @('/RunAsConsoleUserNoWait', $env:ComSpec, '/d', '/c', 'exit 0') },
            @{ Id = 'runas.user-wait'; Args = @('/RunAsUser', '__WinPrivMissingUser__', $env:ComSpec, '/d', '/c', 'exit 0') },
            @{ Id = 'runas.user-nowait'; Args = @('/RunAsUserNoWait', '__WinPrivMissingUser__', $env:ComSpec, '/d', '/c', 'exit 0') },
            @{ Id = 'runas.medium-plus'; Args = @('/MediumPlus', '/RunAsUser', '__WinPrivMissingUser__', $env:ComSpec, '/d', '/c', 'exit 0') }
        )
        foreach ($case in $cases) {
            $result = Invoke-WinPriv -Architecture $Architecture -Arguments $case.Args `
                -Launcher WinPrivCmd -Sandbox $sandbox -TimeoutSeconds 15
            $result.TimedOut | Should -BeFalse
            $result.ExitCode | Should -Not -Be 0
            Add-WinPrivCapabilityResult -Id $case.Id -Architecture $Architecture -Status PartiallyVerified `
                -Reason 'Parser and local-admin failure path verified; positive behavior requires LocalSystem and a WTS session.' `
                -Evidence @{ ExitCode = $result.ExitCode }
        }
    }
}
