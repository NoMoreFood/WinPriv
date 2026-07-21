. (Join-Path $PSScriptRoot 'TestCommon.ps1')

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestCommon.ps1')

    function New-FakeWinPrivDirectoryContext {
        $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-1-2-3-1001')
        $sidBytes = [byte[]]::new($sid.BinaryLength)
        [void]$sid.GetBinaryForm($sidBytes, 0)

        $events = [Collections.Generic.List[object]]::new()
        $entry = [pscustomobject]@{
            Properties = @{ objectSid = [pscustomobject]@{ Value = $sidBytes } }
            PasswordCalls = 0
            PutCalls = 0
            SetInfoCalls = 0
            Events = $events
        }
        $entry | Add-Member -MemberType ScriptMethod -Name SetPassword -Value {
            param($Value)
            $this.PasswordCalls++
            [void]$this.Events.Add([pscustomobject]@{ Method = 'SetPassword'; Name = $null; Value = $Value })
            return 'set-password-noise'
        }
        $entry | Add-Member -MemberType ScriptMethod -Name Put -Value {
            param($Name, $Value)
            $this.PutCalls++
            [void]$this.Events.Add([pscustomobject]@{ Method = 'Put'; Name = $Name; Value = $Value })
            return 'put-noise'
        }
        $entry | Add-Member -MemberType ScriptMethod -Name SetInfo -Value {
            $this.SetInfoCalls++
            [void]$this.Events.Add([pscustomobject]@{ Method = 'SetInfo'; Name = $null; Value = $null })
            return 'set-info-noise'
        }

        $computer = [pscustomobject]@{
            Entry = $entry
            CreatedName = $null
            CreatedType = $null
            CreateError = $null
            DeleteCalls = [Collections.Generic.List[object]]::new()
        }
        $computer | Add-Member -MemberType ScriptMethod -Name Create -Value {
            param($Type, $Name)
            if ($null -ne $this.CreateError) { throw $this.CreateError }
            $this.CreatedType = $Type
            $this.CreatedName = $Name
            return $this.Entry
        }
        $computer | Add-Member -MemberType ScriptMethod -Name Delete -Value {
            param($Type, $Name)
            $this.DeleteCalls.Add([pscustomobject]@{ Type = $Type; Name = $Name })
            return 'delete-noise'
        }

        $usersGroup = [pscustomobject]@{
            AddCalls = [Collections.Generic.List[string]]::new()
            Events = $events
        }
        $usersGroup | Add-Member -MemberType ScriptMethod -Name Add -Value {
            param($Path)
            [void]$this.AddCalls.Add([string]$Path)
            [void]$this.Events.Add([pscustomobject]@{ Method = 'GroupAdd'; Name = $null; Value = $Path })
            return 'group-add-noise'
        }

        return [pscustomobject]@{
            Sid = $sid.Value; Entry = $entry; Computer = $computer; UsersGroup = $usersGroup; Events = $events
        }
    }
}

Describe 'WinPriv local-principal fixture contract' -Tag 'Safe', 'Admin' {
    BeforeEach {
        $script:fakeDirectory = New-FakeWinPrivDirectoryContext
        Mock Get-WinPrivLocalComputerEntry { return $script:fakeDirectory.Computer }
        Mock Get-WinPrivLocalPrincipalEntry { return $script:fakeDirectory.Entry }
        Mock Get-WinPrivBuiltinUsersGroupEntry { return $script:fakeDirectory.UsersGroup }
        Mock Add-WinPrivCleanupJournalEntry { return [pscustomobject]@{ Recorded = $true } }
        $script:sandbox = [pscustomobject]@{ MarkerId = [Guid]::NewGuid().ToString('D') }
    }

    It 'returns exactly one user object even when every ADSI mutator emits output' {
        $result = @(New-WinPrivLocalPrincipal -Type user -Sandbox $script:sandbox)

        $result | Should -HaveCount 1
        $result[0].Name | Should -Match '^WPTU[0-9a-f]{12}$'
        $result[0].Type | Should -Be 'user'
        $result[0].Sid | Should -Be $script:fakeDirectory.Sid
        $result[0].Account | Should -Be "$([Environment]::MachineName)\$($result[0].Name)"
        $script:fakeDirectory.Entry.PasswordCalls | Should -Be 1
        $script:fakeDirectory.Entry.PutCalls | Should -Be 3
        $script:fakeDirectory.Entry.SetInfoCalls | Should -Be 2
        $script:fakeDirectory.UsersGroup.AddCalls | Should -HaveCount 1
        $script:fakeDirectory.UsersGroup.AddCalls[0] | Should -Be `
            "WinNT://$([Environment]::MachineName)/$($result[0].Name),user"
        @($script:fakeDirectory.Events.Method) | Should -Be @(
            'Put', 'Put', 'SetInfo', 'SetPassword', 'GroupAdd', 'Put', 'SetInfo'
        )
        $script:fakeDirectory.Events[0].Name | Should -Be 'UserFlags'
        $script:fakeDirectory.Events[0].Value | Should -Be 0x0203
        $script:fakeDirectory.Events[1].Name | Should -Be 'Description'
        $script:fakeDirectory.Events[5].Name | Should -Be 'UserFlags'
        $script:fakeDirectory.Events[5].Value | Should -Be 0x0201
        $script:fakeDirectory.Computer.DeleteCalls | Should -HaveCount 0
        Should -Invoke Add-WinPrivCleanupJournalEntry -Times 1 -ParameterFilter { $Kind -eq 'LocalPrincipalIntent' }
        Should -Invoke Add-WinPrivCleanupJournalEntry -Times 1 -ParameterFilter { $Kind -eq 'LocalPrincipal' }
        Should -Invoke Add-WinPrivCleanupJournalEntry -Times 1 -ParameterFilter { $Kind -eq 'LsaRight' }
    }

    It 'rolls back the random local account if post-commit SID resolution fails' {
        Mock Get-WinPrivLocalPrincipalEntry { throw 'injected SID resolution failure' }

        { New-WinPrivLocalPrincipal -Type group -Sandbox $script:sandbox } |
            Should -Throw '*injected SID resolution failure*'
        $script:fakeDirectory.Computer.DeleteCalls | Should -HaveCount 1
        $script:fakeDirectory.Computer.DeleteCalls[0].Type | Should -Be 'group'
        $script:fakeDirectory.Computer.DeleteCalls[0].Name | Should -Match '^WPTG[0-9a-f]{12}$'
    }

    It 'does not delete by random name when the ADSI Create call itself fails' {
        $script:fakeDirectory.Computer.CreateError = 'injected create failure'

        { New-WinPrivLocalPrincipal -Type group -Sandbox $script:sandbox } |
            Should -Throw '*injected create failure*'
        $script:fakeDirectory.Computer.DeleteCalls | Should -HaveCount 0
    }
}

Describe 'WinPriv partial security-fixture teardown' -Tag 'Safe', 'Admin' {
    BeforeEach {
        Mock Revoke-WinPrivFixtureRights { }
        Mock Set-Acl { }
        Mock Remove-WinPrivLocalPrincipal { }
        Mock Remove-WinPrivSandbox { }
    }

    It 'still removes a sandbox when principal setup did not complete' {
        $sandbox = [pscustomobject]@{ Root = $TestDrive }
        Remove-WinPrivSecurityFixture -Architecture x64 -Sandbox $sandbox -Principal $null

        Should -Invoke Remove-WinPrivSandbox -Times 1
        Should -Invoke Remove-WinPrivLocalPrincipal -Times 0
        Should -Invoke Revoke-WinPrivFixtureRights -Times 0
    }

    It 'attempts every later cleanup stage after rights and ACL restoration fail' {
        Mock Revoke-WinPrivFixtureRights { throw 'injected rights cleanup failure' }
        Mock Set-Acl { throw 'injected ACL cleanup failure' }
        $sandbox = [pscustomobject]@{ Root = $TestDrive }
        $principal = [pscustomobject]@{
            Account = 'MACHINE\WPTU000000000000'; Name = 'WPTU000000000000'
            Type = 'user'; Sid = 'S-1-5-21-1-2-3-1001'; MachineName = 'MACHINE'
        }

        { Remove-WinPrivSecurityFixture -Architecture x64 -Sandbox $sandbox -Principal $principal `
                -OriginalAcl ([pscustomobject]@{}) } | Should -Throw '*Security fixture cleanup failed*'
        Should -Invoke Revoke-WinPrivFixtureRights -Times 1
        Should -Invoke Set-Acl -Times 1
        Should -Invoke Remove-WinPrivLocalPrincipal -Times 1
        Should -Invoke Remove-WinPrivSandbox -Times 1
    }
}

Describe 'WinPriv standalone sandbox placement' -Tag 'Safe', 'Admin' {
    It 'does not create an unmarked child beneath the suite run root' {
        $savedRunRoot = $env:WINPRIV_TEST_RUN_ROOT
        $savedCleanupEventsPath = $env:WINPRIV_TEST_CLEANUP_EVENTS_PATH
        $sandbox = $null
        try {
            $env:WINPRIV_TEST_RUN_ROOT = $null
            $env:WINPRIV_TEST_CLEANUP_EVENTS_PATH = $null
            $architecture = @($env:WINPRIV_TEST_ARCHITECTURES -split '[,;]' | Where-Object { $_ })[0]
            $sandbox = New-WinPrivSandbox -Architecture $architecture -Purpose 'standalone-root-contract'

            [IO.Path]::GetDirectoryName($sandbox.Root).TrimEnd('\') |
                Should -Be ([IO.Path]::GetTempPath().TrimEnd('\'))
            [IO.Path]::GetFileName($sandbox.Root) | Should -Match '^WinPrivSandbox-[0-9a-f-]{36}$'
        }
        finally {
            if ($null -ne $sandbox) { Remove-WinPrivSandbox -Sandbox $sandbox -Force | Out-Null }
            $env:WINPRIV_TEST_RUN_ROOT = $savedRunRoot
            $env:WINPRIV_TEST_CLEANUP_EVENTS_PATH = $savedCleanupEventsPath
        }
    }
}

Describe 'WinPriv long-path probe output (<Architecture>)' -Tag 'Safe' -ForEach (Get-WinPrivArchitectureCases) {
    BeforeEach {
        $sandbox = New-WinPrivSandbox -Architecture $Architecture
    }

    AfterEach {
        Remove-WinPrivSandbox -Sandbox $sandbox
    }

    It 'atomically persists results beyond the legacy MAX_PATH limit' {
        $longDirectory = $sandbox.Artifacts
        while ((Join-Path $longDirectory 'probe.json').Length -le 270) {
            $longDirectory = Join-Path $longDirectory ('p' * 48)
        }
        [void][IO.Directory]::CreateDirectory($longDirectory)
        $outputPath = Join-Path $longDirectory 'probe.json'

        $result = Invoke-WinPrivProbe -Architecture $Architecture -Operation state -Arguments @{} `
            -Sandbox $sandbox -OutputPath $outputPath -TimeoutSeconds 20
        Assert-WinPrivInvocationSucceeded $result
        $result.ProbeOutputPath.Length | Should -BeGreaterThan 260
        $result.ProbeOutputPath | Should -Exist
    }
}

Describe 'WinPriv local-principal journal reconciliation' -Tag 'Safe', 'Admin' {
    BeforeEach {
        $script:savedCleanupEventsPath = $env:WINPRIV_TEST_CLEANUP_EVENTS_PATH
        $env:WINPRIV_TEST_CLEANUP_EVENTS_PATH = $null
    }

    AfterEach {
        $env:WINPRIV_TEST_CLEANUP_EVENTS_PATH = $script:savedCleanupEventsPath
    }

    It 'treats an already absent completed local user as clean' {
        $name = 'WPTU' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
        $root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root | Out-Null
        $sandbox = [pscustomobject]@{
            MarkerId = [Guid]::NewGuid().ToString('D')
            Root = $root
            Journal = Join-Path $root 'cleanup-journal.jsonl'
        }
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind LocalPrincipal -Identifier $name `
            -OriginalState @{ Existed = $false } -Metadata @{
                MachineName = [Environment]::MachineName; Sid = 'S-1-5-21-1-2-3-424242'
                Type = 'user'; Description = "WinPriv test fixture $name"
            } | Out-Null

        $repair = Repair-WinPrivSandboxJournal -Sandbox $sandbox -NoThrow
        $repair.Status | Should -Be 'JournalVerified'
        @($repair.Errors) | Should -HaveCount 0
    }

    It 'treats an absent pre-creation intent as clean without requiring a SID' {
        $name = 'WPTG' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
        $root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root | Out-Null
        $sandbox = [pscustomobject]@{
            MarkerId = [Guid]::NewGuid().ToString('D')
            Root = $root
            Journal = Join-Path $root 'cleanup-journal.jsonl'
        }
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind LocalPrincipalIntent -Identifier $name `
            -OriginalState @{ Existed = $false } -Metadata @{
                MachineName = [Environment]::MachineName; Type = 'group'
                Description = "WinPriv test fixture $name"
            } | Out-Null

        $repair = Repair-WinPrivSandboxJournal -Sandbox $sandbox -NoThrow
        $repair.Status | Should -Be 'JournalVerified'
        @($repair.Errors) | Should -HaveCount 0
    }

    It 'rejects a creation intent that omits explicit absent-before evidence' {
        $name = 'WPTG' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
        $root = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $root | Out-Null
        $sandbox = [pscustomobject]@{
            MarkerId = [Guid]::NewGuid().ToString('D')
            Root = $root
            Journal = Join-Path $root 'cleanup-journal.jsonl'
        }
        Add-WinPrivCleanupJournalEntry -Sandbox $sandbox -Kind LocalPrincipalIntent -Identifier $name `
            -OriginalState @{} -Metadata @{
                MachineName = [Environment]::MachineName; Type = 'group'
                Description = "WinPriv test fixture $name"
            } | Out-Null

        $repair = Repair-WinPrivSandboxJournal -Sandbox $sandbox -NoThrow
        $repair.Status | Should -Be 'RepairFailed'
        @($repair.Errors | Where-Object Kind -eq 'LocalPrincipalIntent') | Should -HaveCount 1
    }
}
