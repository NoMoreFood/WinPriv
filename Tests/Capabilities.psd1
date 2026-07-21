@{
    SchemaVersion = 1
    StatusValues  = @('Verified', 'Failed', 'PartiallyVerified', 'Unavailable')
    Capabilities  = @(
        # Launchers, command-line contract, and configuration.
        @{ Id = 'launcher.console'; Surface = 'WinPrivCmd.exe'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'launcher.gui'; Surface = 'WinPriv.exe'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'launcher.gui-exit-code'; Surface = 'WinPriv.exe target exit-code propagation'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'launcher.gui-config'; Surface = 'WinPriv.exe explicit configuration'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'launcher.gui-extract'; Surface = 'WinPriv.exe /ExtractLibrary'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'cli.help'; Surface = '/Help, /?, no arguments'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'cli.gui-help'; Surface = 'WinPriv.exe /Help, /?, and no arguments'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop'; Required = $true }
        @{ Id = 'cli.list-privileges'; Surface = '/ListPrivileges'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'cli.case-insensitive'; Surface = 'case-insensitive switches and values'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'cli.argument-errors'; Surface = 'unknown and incomplete switches'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'cli.argument-roundtrip'; Surface = 'target argv, cwd, environment, Unicode'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'config.automatic'; Surface = 'automatic sibling .cfg'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'config.load-commands'; Surface = '/LoadCommands'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'config.merge-order'; Surface = 'ordered repeated /LoadCommands merging'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'config.missing-file'; Surface = '/LoadCommands missing file'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'config.recursion-guard'; Surface = 'recursive /LoadCommands'; Profile = 'Safe'; Test = 'CliAndConfig'; Required = $true }
        @{ Id = 'utility.extract-library'; Surface = '/ExtractLibrary'; Profile = 'Safe'; Test = 'Artifacts'; Required = $true }
        @{ Id = 'utility.show-message'; Surface = '/ShowMessage'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop'; Required = $true }
        @{ Id = 'utility.ask-message-yes'; Surface = '/AskMessage Yes'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop'; Required = $true }
        @{ Id = 'utility.ask-message-no'; Surface = '/AskMessage No'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop'; Required = $true }
        @{ Id = 'utility.dialog-gui-parity'; Surface = 'WinPriv.exe message dialog parity'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop'; Required = $true }

        # Injected registry behavior.
        @{ Id = 'registry.override-dword'; Surface = '/RegOverride REG_DWORD'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.override-qword'; Surface = '/RegOverride REG_QWORD'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.override-string'; Surface = '/RegOverride REG_SZ'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.override-binary'; Surface = '/RegOverride REG_BINARY'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.views'; Surface = '/RegOverride explicit 32-bit and 64-bit views'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.malformed-rules'; Surface = 'malformed /RegOverride pass-through'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.ntquery-partial'; Surface = 'NtQueryValueKey partial/align64'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.ntquery-full'; Surface = 'NtQueryValueKey full/align64'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.enumerate'; Surface = 'NtEnumerateValueKey'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.block'; Surface = '/RegBlock exact key and descendants'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.block-boundary'; Surface = '/RegBlock sibling boundary'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.multiple-rules'; Surface = 'ordered repeated registry rules'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.fips-on'; Surface = '/FipsOn'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.fips-off'; Surface = '/FipsOff'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'registry.policy-block'; Surface = '/PolicyBlock'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }

        # Explicit native caller loading paths for an inline detour.
        @{ Id = 'detour.load-time-import'; Surface = 'RegQueryValueExW through a normal PE import'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture'; Required = $true }
        @{ Id = 'detour.delay-load-import'; Surface = 'RegQueryValueExW through an MSVC delay-load import'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture'; Required = $true }
        @{ Id = 'detour.loadlibrary-getprocaddress'; Surface = 'RegQueryValueExW through LoadLibraryW/GetProcAddress'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture'; Required = $true }

        # Network, identity, OS, AMSI, crypto, and SQL hooks.
        @{ Id = 'network.mac-adapters-info'; Surface = '/MacOverride GetAdaptersInfo'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'NetworkAdapter'; Required = $true }
        @{ Id = 'network.mac-adapters-addresses'; Surface = '/MacOverride GetAdaptersAddresses'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'NetworkAdapter'; Required = $true }
        @{ Id = 'network.mac-workstation'; Surface = '/MacOverride NetWkstaTransportEnum'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'WorkstationService'; Required = $true }
        @{ Id = 'network.host-wide'; Surface = '/HostOverride WSALookupServiceNextW'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'network.host-ansi'; Surface = '/HostOverride WSALookupServiceNextA'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'network.host-pass-through'; Surface = '/HostOverride unrelated lookup pass-through'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'amsi.scan-string'; Surface = '/DisableAmsi AmsiScanString'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Amsi'; Required = $true }
        @{ Id = 'amsi.scan-buffer'; Surface = '/DisableAmsi AmsiScanBuffer'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Amsi'; Required = $true }
        @{ Id = 'identity.is-user-admin'; Surface = '/AdminImpersonate IsUserAnAdmin'; Profile = 'Admin'; Test = 'SecurityAndRights'; Required = $true }
        @{ Id = 'identity.check-token-membership'; Surface = '/AdminImpersonate CheckTokenMembership'; Profile = 'Admin'; Test = 'SecurityAndRights'; Required = $true }
        @{ Id = 'os.get-version-wide'; Surface = '/ServerEdition GetVersionExW'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'os.get-version-ansi'; Surface = '/ServerEdition GetVersionExA'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'os.verify-version'; Surface = '/ServerEdition VerifyVersionInfoW'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'crypto.bcrypt-encrypt'; Surface = '/RecordCrypto BCryptEncrypt'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'crypto.bcrypt-decrypt'; Surface = '/RecordCrypto BCryptDecrypt'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'crypto.crypt-encrypt'; Surface = '/RecordCrypto CryptEncrypt'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'crypto.crypt-decrypt'; Surface = '/RecordCrypto CryptDecrypt'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'crypto.rtl-encrypt'; Surface = '/RecordCrypto RtlEncryptMemory'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'crypto.rtl-decrypt'; Surface = '/RecordCrypto RtlDecryptMemory'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'crypto.show'; Surface = '/RecordCrypto SHOW'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'sql.odbc-wide'; Surface = '/SqlConnectShow and replace SQLDriverConnectW'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Odbc'; Required = $true }
        @{ Id = 'sql.odbc-ansi'; Surface = '/SqlConnectShow and replace SQLDriverConnectA'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Odbc'; Required = $true }
        @{ Id = 'sql.ado'; Surface = '/SqlConnectShow and replace ADO Connection.Open'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Ado'; Required = $true }
        @{ Id = 'sql.com-initialize'; Surface = 'ADO support hook CoInitialize'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Ado'; Required = $true }
        @{ Id = 'sql.com-initialize-ex'; Surface = 'ADO support hook CoInitializeEx'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Ado'; Required = $true }
        @{ Id = 'sql.malformed-regex'; Surface = '/SqlConnectSearchReplace malformed regular expression'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }

        # Propagation and process-control behavior.
        @{ Id = 'propagation.create-process-wide'; Surface = 'CreateProcessW descendants'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'propagation.create-process-ansi'; Surface = 'CreateProcessA descendants'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'propagation.grandchild'; Surface = 'grandchild injection'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'propagation.grandchild-ansi'; Surface = 'CreateProcessA grandchild injection'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'propagation.custom-environment'; Surface = 'child custom environment'; Profile = 'Safe'; Test = 'Hooks'; Required = $true }
        @{ Id = 'propagation.cross-x86-x64-x86-wide'; Surface = 'x86 launcher to x64 parent to x86 CreateProcessW child'; Profile = 'Safe'; Test = 'Hooks'; Architecture = 'All'; Gate = 'X86X64CrossArchitecture'; Required = $true }
        @{ Id = 'propagation.cross-x86-x64-x86-ansi'; Surface = 'x86 launcher to x64 parent to x86 CreateProcessA child'; Profile = 'Safe'; Test = 'Hooks'; Architecture = 'All'; Gate = 'X86X64CrossArchitecture'; Required = $true }
        @{ Id = 'propagation.cross-x64-x86-x64-wide'; Surface = 'x64 launcher to x86 parent to x64 CreateProcessW child'; Profile = 'Safe'; Test = 'Hooks'; Architecture = 'All'; Gate = 'X86X64CrossArchitecture'; Required = $true }
        @{ Id = 'propagation.cross-x64-x86-x64-ansi'; Surface = 'x64 launcher to x86 parent to x64 CreateProcessA child'; Profile = 'Safe'; Test = 'Hooks'; Architecture = 'All'; Gate = 'X86X64CrossArchitecture'; Required = $true }
        @{ Id = 'propagation.shell-execute'; Surface = '/UseShellExecute'; Profile = 'Safe'; Test = 'ProcessAndUi'; Required = $true }
        @{ Id = 'filesystem.bypass-read'; Surface = '/BypassFileSecurity read'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'NtfsAndTokenPrivileges'; Required = $true }
        @{ Id = 'filesystem.bypass-write'; Surface = '/BypassFileSecurity write'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'NtfsAndTokenPrivileges'; Required = $true }
        @{ Id = 'filesystem.nt-open-file'; Surface = '/BypassFileSecurity NtOpenFile'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'NtfsAndTokenPrivileges'; Required = $true }
        @{ Id = 'filesystem.nt-create-file'; Surface = '/BypassFileSecurity NtCreateFile'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'NtfsAndTokenPrivileges'; Required = $true }
        @{ Id = 'filesystem.break-locks-pass-through'; Surface = '/BreakRemoteLocks local pass-through'; Profile = 'Safe'; Test = 'ProcessAndUi'; Required = $true }
        @{ Id = 'filesystem.break-locks-remote'; Surface = '/BreakRemoteLocks remote close/retry'; Profile = 'External'; Test = 'Scope'; Gate = 'RemoteSmbFixture'; DefaultStatus = 'Unavailable'; Reason = 'Requires a second SMB host and is outside the local-admin profile.'; Required = $true }
        @{ Id = 'process.kill'; Surface = '/KillProcess'; Profile = 'Safe'; Test = 'ProcessAndUi'; Required = $true }
        @{ Id = 'process.window-style'; Surface = '/WindowStyle all documented values'; Profile = 'Safe'; Test = 'ProcessAndUi'; Required = $true }
        @{ Id = 'process.measure-time'; Surface = '/MeasureTime'; Profile = 'Safe'; Test = 'ProcessAndUi'; Required = $true }
        @{ Id = 'process.launch-failure'; Surface = 'target executable launch failure'; Profile = 'Safe'; Test = 'ProcessAndUi'; Required = $true }

        # Token privileges and LSA account-right management.
        @{ Id = 'privilege.with-privs'; Surface = '/WithPrivs'; Profile = 'Admin'; Test = 'SecurityAndRights'; Required = $true }
        @{ Id = 'privilege.with-all'; Surface = '/WithAllPrivs'; Profile = 'Admin'; Test = 'SecurityAndRights'; Required = $true }
        @{ Id = 'privilege.interactive-relaunch'; Surface = 'RtlExitUserProcess credential/UAC relaunch'; Profile = 'Interactive'; Test = 'Scope'; Gate = 'InteractiveCredentials'; DefaultStatus = 'Unavailable'; Reason = 'Interactive credential and UAC relaunch is outside the selected profile.'; Required = $true }
        @{ Id = 'rights.grant'; Surface = '/GrantRight'; Profile = 'Admin'; Test = 'SecurityAndRights'; Required = $true }
        @{ Id = 'rights.revoke'; Surface = '/RevokeRight'; Profile = 'Admin'; Test = 'SecurityAndRights'; Required = $true }
        @{ Id = 'rights.clear-deny-named'; Surface = '/ClearDenyRights <account>'; Profile = 'Admin'; Test = 'SecurityAndRights'; Required = $true }
        @{ Id = 'rights.clear-deny-global'; Surface = '/ClearDenyRights'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'AllowGlobalPolicyMutation'; Required = $true }
        @{ Id = 'rights.grant-all'; Surface = '/GrantAllRights'; Profile = 'Admin'; Test = 'SecurityAndRights'; Required = $true }

        # SYSTEM-only launch paths remain visible in the report rather than silently absent.
        @{ Id = 'runas.console-wait'; Surface = '/RunAsConsoleUser'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Positive WTSQueryUserToken path requires LocalSystem and a logged-on session.'; Required = $true }
        @{ Id = 'runas.console-nowait'; Surface = '/RunAsConsoleUserNoWait'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Positive WTSQueryUserToken path requires LocalSystem and a logged-on session.'; Required = $true }
        @{ Id = 'runas.user-wait'; Surface = '/RunAsUser'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Positive WTSQueryUserToken path requires LocalSystem and a logged-on session.'; Required = $true }
        @{ Id = 'runas.user-nowait'; Surface = '/RunAsUserNoWait'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Positive WTSQueryUserToken path requires LocalSystem and a logged-on session.'; Required = $true }
        @{ Id = 'runas.medium-plus'; Surface = '/MediumPlus'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Medium Plus is consumed only by the SYSTEM/WTS run-as path.'; Required = $true }

        # Build and release artifacts.
        @{ Id = 'artifact.build-x86'; Surface = 'Release x86 build'; Profile = 'Safe'; Test = 'Artifacts'; Required = $true }
        @{ Id = 'artifact.build-x64'; Surface = 'Release x64 build'; Profile = 'Safe'; Test = 'Artifacts'; Required = $true }
        @{ Id = 'artifact.build-arm64'; Surface = 'Release ARM64 build'; Profile = 'Safe'; Test = 'Artifacts'; Required = $true }
        @{ Id = 'artifact.embedded-payloads'; Surface = 'embedded x86/x64/ARM64 DLL payloads'; Profile = 'Safe'; Test = 'Artifacts'; Required = $true }
        @{ Id = 'artifact.adjacent-library-reuse'; Surface = 'adjacent architecture-matching DLL reuse'; Profile = 'Safe'; Test = 'Artifacts'; Required = $true }
        @{ Id = 'artifact.temp-library-cleanup'; Surface = 'temporary injection DLL cleanup'; Profile = 'Safe'; Test = 'Artifacts'; Required = $true }
        @{ Id = 'artifact.package'; Surface = 'Build/build.cmd ZIP and hash manifest'; Profile = 'Safe'; Test = 'Artifacts'; Architecture = 'All'; Required = $true }
    )
}
