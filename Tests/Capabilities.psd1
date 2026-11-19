@{
    SchemaVersion = 1
    Capabilities  = @(
        # Launchers, command-line contract, and configuration.
        @{ Id = 'launcher.console'; Surface = 'WinPrivCmd.exe'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'launcher.gui'; Surface = 'WinPriv.exe'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'launcher.gui-exit-code'; Surface = 'WinPriv.exe target exit-code propagation'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'launcher.gui-config'; Surface = 'WinPriv.exe explicit configuration'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'launcher.gui-extract'; Surface = 'WinPriv.exe /ExtractLibrary'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'cli.help'; Surface = '/Help, /?, no arguments'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'cli.gui-help'; Surface = 'WinPriv.exe /Help, /?, and no arguments'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop' }
        @{ Id = 'cli.list-privileges'; Surface = '/ListPrivileges'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'cli.privilege-enumeration'; Surface = 'privilege enumeration failure and cleanup'; Profile = 'Safe'; Test = 'CliAndConfig'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'cli.case-insensitive'; Surface = 'case-insensitive switches and values'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'cli.argument-errors'; Surface = 'unknown and incomplete switches'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'cli.argument-roundtrip'; Surface = 'target argv, cwd, environment, Unicode'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'config.automatic'; Surface = 'automatic sibling .cfg'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'config.load-commands'; Surface = '/LoadCommands'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'config.merge-order'; Surface = 'ordered repeated /LoadCommands merging'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'config.missing-file'; Surface = '/LoadCommands missing file'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'config.recursion-guard'; Surface = 'recursive /LoadCommands'; Profile = 'Safe'; Test = 'CliAndConfig' }
        @{ Id = 'utility.extract-library'; Surface = '/ExtractLibrary'; Profile = 'Safe'; Test = 'Artifacts' }
        @{ Id = 'utility.show-message'; Surface = '/ShowMessage'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop' }
        @{ Id = 'utility.ask-message-yes'; Surface = '/AskMessage Yes'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop' }
        @{ Id = 'utility.ask-message-no'; Surface = '/AskMessage No'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop' }
        @{ Id = 'utility.dialog-gui-parity'; Surface = 'WinPriv.exe message dialog parity'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'InteractiveDesktop' }

        # Credentialed process creation from LocalSystem.
        @{ Id = 'process.logon-policy'; Surface = '/AllowCreateProcessAsSystem logon policy and creation arguments'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture' }

        # Local smart-card access and its process propagation.
        @{ Id = 'smartcard.local'; Surface = '/UseConsoleToken WinSCard reader routing'; Profile = 'Safe'; Test = 'SmartCards'; Gate = 'SmartCardService' }
        @{ Id = 'smartcard.propagation'; Surface = '/UseConsoleToken descendants and custom environments'; Profile = 'Safe'; Test = 'SmartCards'; Gate = 'SmartCardService' }
        @{ Id = 'smartcard.signing-pass-through'; Surface = '/UseConsoleToken software signing and silent requests'; Profile = 'Safe'; Test = 'SmartCards' }
        @{ Id = 'smartcard.session-routing'; Surface = '/UseConsoleToken signing across console and remote reconnects'; Profile = 'Safe'; Test = 'SmartCards'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'smartcard.enrollment'; Surface = '/UseConsoleToken key creation and certificate installation PIN handling'; Profile = 'Safe'; Test = 'SmartCards'; Gate = 'NativeHookLoadingFixture' }

        # Wall clock offsets and their process propagation.
        @{ Id = 'time.mock-clock'; Surface = '/MockTime native, Win32, CRT, and managed wall clocks'; Profile = 'Safe'; Test = 'Time' }
        @{ Id = 'time.mock-deltas'; Surface = '/MockTime signed abbreviated and calendar deltas'; Profile = 'Safe'; Test = 'Time' }
        @{ Id = 'time.mock-errors'; Surface = '/MockTime malformed and out-of-range deltas'; Profile = 'Safe'; Test = 'Time' }
        @{ Id = 'time.mock-propagation'; Surface = '/MockTime descendants and custom environments'; Profile = 'Safe'; Test = 'Time' }

        # Injected registry behavior.
        @{ Id = 'registry.override-dword'; Surface = '/RegOverride REG_DWORD'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.override-qword'; Surface = '/RegOverride REG_QWORD'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.override-string'; Surface = '/RegOverride REG_SZ'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.override-binary'; Surface = '/RegOverride REG_BINARY'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.views'; Surface = '/RegOverride explicit 32-bit and 64-bit views'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.malformed-rules'; Surface = 'malformed /RegOverride pass-through'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.ntquery-partial'; Surface = 'NtQueryValueKey partial/align64'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.ntquery-full'; Surface = 'NtQueryValueKey full/align64'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.enumerate'; Surface = 'NtEnumerateValueKey'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.block'; Surface = '/RegBlock exact key and descendants'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.block-boundary'; Surface = '/RegBlock sibling boundary'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.multiple-rules'; Surface = 'ordered repeated registry rules'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.fips-on'; Surface = '/FipsOn'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.fips-off'; Surface = '/FipsOff'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'registry.policy-block'; Surface = '/PolicyBlock'; Profile = 'Safe'; Test = 'Hooks' }

        # Injected file and directory behavior.
        @{ Id = 'filesystem.redirect-file'; Surface = '/FileRedirect file reads, attributes, writes, and deletion'; Profile = 'Safe'; Test = 'FileRules' }
        @{ Id = 'filesystem.redirect-directory'; Surface = '/FileRedirect directory descendants and relative handles'; Profile = 'Safe'; Test = 'FileRules' }
        @{ Id = 'filesystem.path-syntax'; Surface = 'relative, device, UNC, extended, and long file paths'; Profile = 'Safe'; Test = 'FileRules' }
        @{ Id = 'filesystem.rule-order'; Surface = 'file rule precedence and configuration paths'; Profile = 'Safe'; Test = 'FileRules' }
        @{ Id = 'filesystem.redirect-mutation'; Surface = 'file rename and hard-link destinations'; Profile = 'Safe'; Test = 'FileRules' }
        @{ Id = 'filesystem.rule-propagation'; Surface = 'file rules in descendants with replacement environments'; Profile = 'Safe'; Test = 'FileRules' }
        @{ Id = 'filesystem.redirect-rename-handle'; Surface = 'relative directory handles after rename'; Profile = 'Safe'; Test = 'FileRules' }
        @{ Id = 'filesystem.redirect-junction'; Surface = 'relative directory handles through junction destinations'; Profile = 'Safe'; Test = 'FileRules' }
        @{ Id = 'filesystem.redirect-stream'; Surface = 'native stream renames in redirected files'; Profile = 'Safe'; Test = 'FileRules' }
        @{ Id = 'filesystem.redirect-duplicate'; Surface = 'directory duplication without process query access'; Profile = 'Safe'; Test = 'FileRules' }

        # Explicit native caller loading paths for an inline detour.
        @{ Id = 'detour.rejected-hooks'; Surface = 'atomic rejection of invalid hooks and unsupported instructions'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'detour.load-time-import'; Surface = 'RegQueryValueExW through a normal PE import'; Profile = 'Safe'; Test = 'DescendantHookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'detour.delay-load-import'; Surface = 'RegQueryValueExW through an MSVC delay-load import'; Profile = 'Safe'; Test = 'DescendantHookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'detour.loadlibrary-getprocaddress'; Surface = 'RegQueryValueExW through LoadLibraryW/GetProcAddress'; Profile = 'Safe'; Test = 'DescendantHookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'detour.library-loading'; Surface = 'LoadLibraryEx executable and datafile loads, DLL reload, and file-redirection coexistence'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'detour.optional-hook-libraries'; Surface = 'optional hook libraries load only when their hooks are enabled'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'detour.thread-churn'; Surface = 'transactions during thread creation and exit with file hooks active'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'detour.thread-heap-lock'; Surface = 'transactions while a peer holds the process heap lock'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'detour.thread-inaccessible'; Surface = 'transaction rollback when a peer cannot be suspended'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'detour.descendant-import-modes'; Surface = 'native descendant API import modes and multi-generation injection'; Profile = 'Safe'; Test = 'DescendantHookLoading'; Gate = 'NativeHookLoadingFixture' }

        @{ Id = 'mitigation.strict-cfg'; Surface = 'strict CFG hook loading and child registry interception'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'mitigation.dynamic-code-diagnostic'; Surface = 'ACG launcher error and policy diagnosis'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixtureAndDynamicCodePolicy' }
        @{ Id = 'mitigation.unhookable-descendants'; Surface = 'Microsoft-signed-only and AppContainer descendants launch without hooks'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'mitigation.dynamic-code-allocation'; Surface = 'ACG trampoline allocation error and rollback'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixtureAndDynamicCodePolicy' }
        @{ Id = 'mitigation.dynamic-code-optout-propagation'; Surface = 'ACG opt-out launchers, injected targets, descendants, and restored thread policy'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixtureAndDynamicCodePolicy' }
        @{ Id = 'mitigation.dynamic-code-optout-transactions'; Surface = 'ACG scoped opt-out attach, abort, failed commit, nesting, and existing permission'; Profile = 'Safe'; Test = 'HookLoading'; Gate = 'NativeHookLoadingFixtureAndDynamicCodePolicy' }

        # Network, identity, OS, AMSI, crypto, and SQL hooks.
        @{ Id = 'network.mac-adapters-info'; Surface = '/MacOverride GetAdaptersInfo'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'NetworkAdapter' }
        @{ Id = 'network.mac-adapters-addresses'; Surface = '/MacOverride GetAdaptersAddresses'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'NetworkAdapter' }
        @{ Id = 'network.mac-workstation'; Surface = '/MacOverride NetWkstaTransportEnum'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'WorkstationService' }
        @{ Id = 'network.host-wide'; Surface = '/HostOverride WSALookupServiceNextW'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'network.host-ansi'; Surface = '/HostOverride WSALookupServiceNextA'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'network.host-pass-through'; Surface = '/HostOverride unrelated lookup pass-through'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'network.host-resolvers'; Surface = '/HostOverride address and DNS resolver APIs'; Profile = 'Safe'; Test = 'HostOverride' }
        @{ Id = 'network.host-ipv6'; Surface = '/HostOverride native IPv6 and family restrictions'; Profile = 'Safe'; Test = 'HostOverride' }
        @{ Id = 'network.host-destination'; Surface = '/HostOverride replacement address sets and canonical names'; Profile = 'Safe'; Test = 'HostOverride' }
        @{ Id = 'network.host-names'; Surface = '/HostOverride normalized DNS and IDN names'; Profile = 'Safe'; Test = 'HostOverride' }
        @{ Id = 'network.host-diagnostics'; Surface = '/HostOverride resolver failure diagnostics'; Profile = 'Safe'; Test = 'HostOverride' }
        @{ Id = 'powershell.clm'; Surface = '/ClmOn, /ClmOff language mode, scripts, and descendants'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'amsi.on'; Surface = '/AmsiOn native scanning and switch precedence'; Profile = 'Safe'; Test = 'CliAndConfig'; Gate = 'Amsi' }
        @{ Id = 'amsi.scan-string'; Surface = '/AmsiOff AmsiScanString'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Amsi' }
        @{ Id = 'amsi.scan-buffer'; Surface = '/AmsiOff AmsiScanBuffer'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Amsi' }
        @{ Id = 'identity.is-user-admin'; Surface = '/AdminImpersonate IsUserAnAdmin'; Profile = 'Admin'; Test = 'SecurityAndRights' }
        @{ Id = 'identity.check-token-membership'; Surface = '/AdminImpersonate CheckTokenMembership'; Profile = 'Admin'; Test = 'SecurityAndRights' }
        @{ Id = 'os.get-version-wide'; Surface = '/ServerEdition GetVersionExW'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'os.get-version-ansi'; Surface = '/ServerEdition GetVersionExA'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'os.verify-version'; Surface = '/ServerEdition VerifyVersionInfoW'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'crypto.bcrypt-encrypt'; Surface = '/RecordCrypto BCryptEncrypt'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'crypto.bcrypt-decrypt'; Surface = '/RecordCrypto BCryptDecrypt'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'crypto.crypt-encrypt'; Surface = '/RecordCrypto CryptEncrypt'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'crypto.crypt-decrypt'; Surface = '/RecordCrypto CryptDecrypt'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'crypto.rtl-encrypt'; Surface = '/RecordCrypto RtlEncryptMemory'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'crypto.rtl-decrypt'; Surface = '/RecordCrypto RtlDecryptMemory'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'crypto.show'; Surface = '/RecordCrypto SHOW'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'sql.odbc-wide'; Surface = '/SqlConnectShow and replace SQLDriverConnectW'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Odbc' }
        @{ Id = 'sql.odbc-ansi'; Surface = '/SqlConnectShow and replace SQLDriverConnectA'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Odbc' }
        @{ Id = 'sql.ado'; Surface = '/SqlConnectShow and replace ADO Connection.Open'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Ado' }
        @{ Id = 'sql.com-initialize'; Surface = 'ADO support hook CoInitialize'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Ado' }
        @{ Id = 'sql.com-initialize-ex'; Surface = 'ADO support hook CoInitializeEx'; Profile = 'Safe'; Test = 'Hooks'; Gate = 'Ado' }
        @{ Id = 'sql.malformed-regex'; Surface = '/SqlConnectSearchReplace malformed regular expression'; Profile = 'Safe'; Test = 'Hooks' }

        # Propagation and process-control behavior.
        @{ Id = 'propagation.create-process-wide'; Surface = 'CreateProcessW descendants'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'propagation.create-process-ansi'; Surface = 'CreateProcessA descendants'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'propagation.grandchild'; Surface = 'grandchild injection'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'propagation.grandchild-ansi'; Surface = 'CreateProcessA grandchild injection'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'propagation.custom-environment'; Surface = 'child custom environment'; Profile = 'Safe'; Test = 'Hooks' }
        @{ Id = 'propagation.cross-x86-x64-x86-wide'; Surface = 'x86 launcher to x64 parent to x86 CreateProcessW child'; Profile = 'Safe'; Test = 'Hooks'; Architecture = 'All'; Gate = 'X86X64CrossArchitecture' }
        @{ Id = 'propagation.cross-x86-x64-x86-ansi'; Surface = 'x86 launcher to x64 parent to x86 CreateProcessA child'; Profile = 'Safe'; Test = 'Hooks'; Architecture = 'All'; Gate = 'X86X64CrossArchitecture' }
        @{ Id = 'propagation.cross-x64-x86-x64-wide'; Surface = 'x64 launcher to x86 parent to x64 CreateProcessW child'; Profile = 'Safe'; Test = 'Hooks'; Architecture = 'All'; Gate = 'X86X64CrossArchitecture' }
        @{ Id = 'propagation.cross-x64-x86-x64-ansi'; Surface = 'x64 launcher to x86 parent to x64 CreateProcessA child'; Profile = 'Safe'; Test = 'Hooks'; Architecture = 'All'; Gate = 'X86X64CrossArchitecture' }
        @{ Id = 'propagation.orphan-cross-architecture'; Surface = 'surviving descendants launch another architecture after the root exits'; Profile = 'Safe'; Test = 'ProcessAndUi'; Architecture = 'All'; Gate = 'X86X64CrossArchitecture' }
        @{ Id = 'propagation.shell-execute'; Surface = '/UseShellExecute'; Profile = 'Safe'; Test = 'ProcessAndUi' }
        @{ Id = 'filesystem.bypass-read'; Surface = '/BypassFileSecurity read'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'NtfsAndTokenPrivileges' }
        @{ Id = 'filesystem.bypass-write'; Surface = '/BypassFileSecurity write'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'NtfsAndTokenPrivileges' }
        @{ Id = 'filesystem.nt-open-file'; Surface = '/BypassFileSecurity NtOpenFile'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'NtfsAndTokenPrivileges' }
        @{ Id = 'filesystem.nt-create-file'; Surface = '/BypassFileSecurity NtCreateFile'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'NtfsAndTokenPrivileges' }
        @{ Id = 'filesystem.break-locks-pass-through'; Surface = '/BreakRemoteLocks local pass-through'; Profile = 'Safe'; Test = 'ProcessAndUi' }
        @{ Id = 'filesystem.break-locks-remote'; Surface = '/BreakRemoteLocks remote close/retry'; Profile = 'External'; Test = 'Scope'; Gate = 'RemoteSmbFixture'; DefaultStatus = 'Unavailable'; Reason = 'Requires a second SMB host and is outside the local-admin profile.' }
        @{ Id = 'process.kill'; Surface = '/KillProcess'; Profile = 'Safe'; Test = 'ProcessAndUi' }
        @{ Id = 'process.kill-identity'; Surface = '/KillProcess process identity revalidation'; Profile = 'Safe'; Test = 'ProcessAndUi'; Gate = 'NativeHookLoadingFixture' }
        @{ Id = 'process.window-style'; Surface = '/WindowStyle all documented values'; Profile = 'Safe'; Test = 'ProcessAndUi' }
        @{ Id = 'process.measure-time'; Surface = '/MeasureTime'; Profile = 'Safe'; Test = 'ProcessAndUi' }
        @{ Id = 'process.launch-failure'; Surface = 'target executable launch failure'; Profile = 'Safe'; Test = 'ProcessAndUi' }

        # Token privileges and LSA account-right management.
        @{ Id = 'privilege.with-privs'; Surface = '/WithPrivs'; Profile = 'Admin'; Test = 'SecurityAndRights' }
        @{ Id = 'privilege.with-all'; Surface = '/WithAllPrivs'; Profile = 'Admin'; Test = 'SecurityAndRights' }
        @{ Id = 'privilege.interactive-relaunch'; Surface = 'RtlExitUserProcess credential/UAC relaunch'; Profile = 'Interactive'; Test = 'Scope'; Gate = 'InteractiveCredentials'; DefaultStatus = 'Unavailable'; Reason = 'Interactive credential and UAC relaunch is outside the selected profile.' }
        @{ Id = 'rights.grant'; Surface = '/GrantRight'; Profile = 'Admin'; Test = 'SecurityAndRights' }
        @{ Id = 'rights.revoke'; Surface = '/RevokeRight'; Profile = 'Admin'; Test = 'SecurityAndRights' }
        @{ Id = 'rights.clear-deny-named'; Surface = '/ClearDenyRights <account>'; Profile = 'Admin'; Test = 'SecurityAndRights' }
        @{ Id = 'rights.clear-deny-global'; Surface = '/ClearDenyRights'; Profile = 'Admin'; Test = 'SecurityAndRights'; Gate = 'AllowGlobalPolicyMutation' }
        @{ Id = 'rights.grant-all'; Surface = '/GrantAllRights'; Profile = 'Admin'; Test = 'SecurityAndRights' }

        # SYSTEM-only launch paths remain visible in the report rather than silently absent.
        @{ Id = 'runas.console-wait'; Surface = '/RunAsConsoleUser'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Positive WTSQueryUserToken path requires LocalSystem and a logged-on session.' }
        @{ Id = 'runas.console-nowait'; Surface = '/RunAsConsoleUserNoWait'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Positive WTSQueryUserToken path requires LocalSystem and a logged-on session.' }
        @{ Id = 'runas.user-wait'; Surface = '/RunAsUser'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Positive WTSQueryUserToken path requires LocalSystem and a logged-on session.' }
        @{ Id = 'runas.user-nowait'; Surface = '/RunAsUserNoWait'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Positive WTSQueryUserToken path requires LocalSystem and a logged-on session.' }
        @{ Id = 'runas.medium-plus'; Surface = '/MediumPlus'; Profile = 'System'; Test = 'Scope'; Gate = 'LocalSystemWithInteractiveSession'; DefaultStatus = 'Unavailable'; Reason = 'Medium Plus is consumed only by the SYSTEM/WTS run-as path.' }

        # Build and release artifacts.
        @{ Id = 'artifact.cfg-metadata'; Surface = 'CFG headers and call-target tables for all launchers and libraries'; Profile = 'Safe'; Test = 'Artifacts'; Architecture = 'All' }
        @{ Id = 'artifact.build-x86'; Surface = 'Release x86 build'; Profile = 'Safe'; Test = 'Artifacts'; Architecture = 'x86' }
        @{ Id = 'artifact.build-x64'; Surface = 'Release x64 build'; Profile = 'Safe'; Test = 'Artifacts'; Architecture = 'x64' }
        @{ Id = 'artifact.build-arm64'; Surface = 'Release ARM64 build'; Profile = 'Safe'; Test = 'Artifacts'; Architecture = 'ARM64' }
        @{ Id = 'artifact.embedded-payloads'; Surface = 'embedded x86/x64/ARM64 DLL payloads'; Profile = 'Safe'; Test = 'Artifacts' }
        @{ Id = 'artifact.sidecar-library-loading'; Surface = 'loading a matching WinPriv DLL from the launcher directory'; Profile = 'Safe'; Test = 'Artifacts' }
        @{ Id = 'artifact.embedded-library-loading'; Surface = 'temporary DLL extraction and native loading'; Profile = 'Safe'; Test = 'Artifacts' }
        @{ Id = 'artifact.temporary-library-cleanup'; Surface = 'temporary DLL cleanup and extraction failure handling'; Profile = 'Safe'; Test = 'Artifacts' }
        @{ Id = 'artifact.package'; Surface = 'Build/build.cmd ZIP and hash manifest'; Profile = 'Safe'; Test = 'Artifacts'; Architecture = 'All' }
    )
}
