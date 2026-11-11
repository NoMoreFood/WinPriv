//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <WinPrivShared.h>

std::wstring GetWinPrivHelp()
{
	// Keep the message box brief and direct readers to the console switch reference.
	if (!WinPrivUsesConsoleSubsystem())
	{
		return std::wstring(PROJECT_NAME) +
			L".exe [optional switches] <Command to execute>\n" +
			L"\n" +
			L"Run WinPrivCmd.exe /Help for the full list of switches.";
	}

	// command line help
	return std::wstring(PROJECT_NAME) +
		LR"(.exe [optional switches] <Command to execute>

WinPriv is a system administration utility that alters the runtime behavior of
the specified process and its child processes. It does this by loading a
supplemental library into memory to intercept and alter the behavior of
common low-level functions such as registry and file system operations.

WinPriv can be used for a variety of purposes, including testing security
settings without altering system-wide policy, implementing security-related
workarounds on a per-process basis instead of altering system-wide policy, and
taking advantage of system privileges to perform file system auditing and
reconfiguration.

WinPriv is available as a GUI application (WinPriv) and a console application
(WinPrivCmd). Both versions apply the same settings to the target process.
Use WinPrivCmd for console programs whose output you need to see. Use WinPriv
for programs that do not need a console window.

Optional Switches
=================

/Help, /?

   Displays this help information and exits. The same help is displayed when
   no target command is supplied.

/LoadCommands <Path>

   Loads command-line parameters from an additional configuration file.
   The switches in the file are merged with any remaining command-line
   arguments and processed as if provided directly on the command line.

   Example:

	  /LoadCommands C:\Config\MySettings.cfg

/WithPrivs <Privilege>[,<Privilege>,...]

   Requests named Windows privileges for the target process. Separate names
   with commas. Missing privileges require local policy access, credentials
   for the current account, and an elevated relaunch. Only account assignments
   added by WinPriv are removed afterward. Console relaunches pause at exit.

   Example:

	  /WithPrivs SeDebugPrivilege,SeBackupPrivilege

/WithAllPrivs

   Requests every privilege defined in local security policy, using the same
   acquisition and relaunch behavior as /WithPrivs.

/RegOverride <Registry Key Path> <Value Name> <Data Type> <Data Value>

   Specifies a registry value to override. Instead of returning the true
   registry value for the specified key path and value name, the value
   specified in this switch is returned.

   Examples:

	  /RegOverride HKCU\Software\Demo Enabled REG_DWORD 1
	  /RegOverride HKLM\Software\Demo UserName REG_SZ "James Bond"

/RegBlock <Registry Key Path>

   Specifies a registry key under which all values will be reported as
   nonexistent. When the application requests a particular value in the
   specified key or one of its subkeys, it will be reported as not found
   regardless of whether it actually exists in the registry.

   Example:

	  /RegBlock HKCU\Software\Demo

/MacOverride <MAC Address>

   Specifies the physical network address returned when the target application
   queries the system for MAC addresses. Calls to GetAdaptersAddresses,
   GetAdaptersInfo, and NetWkstaTransportEnum are intercepted. Hexadecimal
   octets can be separated by dashes or colons, or written without separators.

   Example:

	  /MacOverride 00-11-22-33-44-66

/HostOverride <Target HostName> <Replacement HostName>

   Resolves matching host names through the replacement host or IP address.
   Hooks cover WSALookupServiceBegin, getaddrinfo/GetAddrInfoW, gethostbyname,
   GetAddrInfoEx, and address queries through DnsQuery and DnsQueryEx.
   Matching ignores case and a terminal dot and normalizes internationalized
   names. The first matching rule wins; replacements do not cascade.
   The replacement must resolve before launch. Windows resolves it again for
   each request, preserving IPv4/IPv6 selection and asynchronous behavior.
   Private DNS implementations are outside these hooks.

   Examples:

	  /HostOverride google.com yahoo.com
	  /HostOverride google.com 127.0.0.1

/FipsOn, /FipsOff

   Overrides the Enabled DWORD under the FipsAlgorithmPolicy registry key
   for hooked reads. The machine's FIPS policy is unchanged.

/PolicyBlock

   Applies /RegBlock to Software\Policies and
   Software\Microsoft\Windows\CurrentVersion\Policies under HKCU and HKLM.
   It hides registry values without disabling all Group Policy enforcement.

/FileRedirect <Source Path> <Destination Path>

   Redirects file and directory access from the source to the destination.
   Directory rules also redirect all descendants, including new files.
   Reads and writes use the destination; source contents are not copied.

   This switch can be repeated. Paths are case-insensitive and relative
   paths are resolved from WinPriv's working directory. The longest matching
   path wins; the last rule wins for equal paths. Redirects apply once.

/BypassFileSecurity

   Requests backup, restore, take-ownership, and change-notify privileges and
   adds backup intent to file opens. Access depends on the privileges Windows
   grants; sharing rules and other process or file protections still apply.
   Missing privileges use the acquisition behavior described under /WithPrivs.

   Example:

   Access detailed permissions under 'C:\System Volume Information':
   WinPrivCmd.exe /BypassFileSecurity icacls.exe
	  "C:\System Volume Information" /T
)"
		LR"(
/BreakRemoteLocks

   Tries to close matching SMB server file handles and retries an open that
   failed with sharing-violation or access-denied status. Requires permission
   to enumerate and close files on the server. It can close remote clients'
   handles to locally shared files, but not ordinary local process handles.

/MediumPlus

   Sets the duplicated session-user token to Medium Plus integrity. Place
   this before a /RunAs... switch. It has no effect on normal hooked launches.

/AdminImpersonate

   Makes IsUserAnAdmin report true and successful CheckTokenMembership calls
   report membership in the built-in Administrators group. Other group queries
   retain their normal results. It grants no access and does not change token
   membership. The target also receives the RunAsInvoker compatibility setting.

/ServerEdition

   Makes extended GetVersionExA/W queries report a server product type and
   adjusts VerifyVersionInfoW product-type checks. The installed Windows
   edition is unchanged.

/AmsiOn

   This option preserves normal Antimalware Scan Interface (AMSI) scanning
   for the target process and its child processes. It overrides an earlier
   request to disable scanning without changing the machine configuration.

/AmsiOff

   This option disables Antimalware Scan Interface (AMSI) scanning for the
   target process and its child processes.

/ClmOn, /ClmOff

   These options enable or disable PowerShell Constrained Language Mode (CLM)
   for the target process and its child processes by overriding PowerShell
   policy queries. The last CLM switch wins. The machine policy is unchanged.

/UseConsoleToken

   Uses locally attached smart cards and hardware keys through the Windows
   smart-card APIs, including from a Remote Desktop session. Applies to the
   target and its child processes.
   In remote sessions, key creation, signing, and certificate installation
   through Microsoft's Smart Card Key Storage Provider prompt for a PIN when
   needed. Enter it in the Windows dialog's password field. WinPriv does not
   save the PIN. Explicitly silent requests remain silent.
   The token's normal PIN validation and permissions still apply.

/RecordCrypto <Directory>

   Records plaintext input to BCryptEncrypt, CryptEncrypt, and RtlEncryptMemory,
   and output from their decryption counterparts. Nonempty buffers are written
   to separate files without overwriting existing captures. Size-only queries
   produce no capture. Use SHOW to display text through the target's console
   or message boxes instead.

/SqlConnectShow

   Displays intercepted ODBC and ADO connection strings after any successful
   /SqlConnectSearchReplace rewrite.

/SqlConnectSearchReplace <SearchString> <ReplaceString>

   Rewrites ODBC and ADO connection strings before opening the connection,
   including ADO's stored ConnectionString when Open omits it. The search is
   a case-sensitive regular expression; replacement captures use $1, $2, etc.
   An invalid pattern leaves the original string in use.

   Example:

   WinPrivCmd.exe /SqlConnectSearchReplace
	  Provider=SQLOLEDB Provider=SQLNCLI11 LegacyApplication.exe

/KillProcess <ProcessName>

   Attempts to terminate every matching executable in the caller's session
   before launch, or the selected session when placed before a run-as command.
   Matching ignores case. Termination failures do not stop the target launch.

/ExtractLibrary

   Exports WinPriv-x86.dll, WinPriv-x64.dll, and WinPriv-ARM64.dll beside
   the WinPriv executable. WinPriv uses the matching DLL when present and
   falls back to the embedded library when it is absent.

/WindowStyle <Style>

   This option launches the target process with the specified window style:
   NoActive, Hidden, Maximized, Minimized, or MinimizedNoActive.

/UseShellExecute

   This option launches the target process with ShellExecuteEx() instead of
   CreateProcess(). This is useful for launching an application that is
   registered on the system but not in the system path.

/ShowMessage <Message>

   This option displays a message box with the specified message before
   launching the target process. The caption of the message box is "Message".

/AskMessage <Message>

   This option displays a Yes/No message box with the specified message before
   launching the target process. If you click No, execution is cancelled.
   The caption of the message box is "Message".

/MockTime <Delta>

   Shifts the target's wall clock and its descendants by a signed time delta.
   Units: y/yr, mo/mon, w/wk, d, h/hr, m/min, s/sec, ms, us. Abbreviations are
   case-insensitive; yrs, wks, hrs, mins, and secs are also accepted.
   Combine components, for example +1y2mo-3d or "-2w 4h 30min", applied from
   left to right. A sign applies to following components until changed.
   Unsigned deltas are positive.
   Years and months are whole calendar units, with month-end dates clamped.
   Other units accept decimal fractions down to 100 ns. The resulting offset
   is fixed at launch, and the last /MockTime wins. Uptime, stopwatches, and
   relative waits retain their normal behavior.

/MeasureTime

   This option measures the execution time of the target process and displays
   it to the user.

/ListPrivileges, /ListPrivs

   Lists the privilege names and descriptions defined in local security policy,
   rather than the privileges enabled in the current token, then exits.

/GrantRight <Right> <UserName>

   Grants the specified LSA account right or privilege to the named user or
   group account on the local machine. The right can be any privilege
   constant (e.g., SeDebugPrivilege) or a logon-right constant (e.g.,
   SeInteractiveLogonRight). Administrator rights are required. This
   operation takes effect immediately for new logon sessions.

   Examples:

	  /GrantRight SeDebugPrivilege DOMAIN\JDoe
	  /GrantRight SeBatchLogonRight LocalSvcAccount
	  /GrantRight SeServiceLogonRight "NT SERVICE\MyService"

/RevokeRight <Right> <UserName>

   Revokes the specified LSA account right or privilege from the named user
   or group account on the local machine. All arguments follow the same
   rules as /GrantRight.

   Examples:

	  /RevokeRight SeShutdownPrivilege DOMAIN\JDoe
	  /RevokeRight SeRemoteInteractiveLogonRight LocalSvcAccount

/ClearDenyRights [UserName]

   Removes deny-logon rights assigned directly to the named user or group.
   A user's group assignments remain in effect.
   If no UserName is specified, deny-logon rights are removed from every
   account on the local machine. Accounts that have none of those rights
   are silently skipped. Administrator rights are required.
   The following rights are cleared if present:

	  SeDenyNetworkLogonRight           (Deny access from the network)
	  SeDenyInteractiveLogonRight       (Deny local logon)
	  SeDenyBatchLogonRight             (Deny logon as a batch job)
	  SeDenyServiceLogonRight           (Deny logon as a service)
	  SeDenyRemoteInteractiveLogonRight (Deny Remote Desktop logon)

/GrantAllRights <UserName>

   Grants all system privileges and non-deny logon rights to the named user
   or group account. This includes every privilege enumerated on the local
   machine (e.g., SeDebugPrivilege, SeShutdownPrivilege) as well as all
   allow-logon rights. Deny-logon rights are not granted. Administrator
   rights are required. This operation takes effect immediately for new
   logon sessions.

/AllowCreateProcessAsSystem

   Allows CreateProcessWithLogonW calls from LocalSystem processes using the
   supplied user's credentials. Supports ordinary logon and LOGON_WITH_PROFILE.
   Temporarily grants the user the local interactive-logon right if missing,
   removing it as soon as the logon completes. Explicit deny-logon policy
   still applies. Uses the Default desktop name when none is specified.
   Non-SYSTEM callers retain the native behavior. Network-only logons are
   unsupported by the replacement.

/RunAsConsoleUser, /RunAsConsoleUserNoWait

   Requires LocalSystem. Uses the active console user's token, falling back
   to the first active non-SYSTEM user session. Disconnected sessions are
   not selected. Waits for the target and returns its exit code.
   With /RunAsConsoleUserNoWait, WinPriv returns immediately after the
   process starts.

/RunAsUser <UserName>, /RunAsUserNoWait <UserName>

   Requires LocalSystem. Selects an active session for the named account,
   or a disconnected session if no active one exists. Waits for the target
   and returns its exit code. /RunAsUserNoWait returns zero after creation.

   Run-as launches use the session user's environment and interactive desktop.
   They do not apply hook options, /WithPrivs, /WindowStyle, /UseShellExecute,
   or /MeasureTime. To apply hooks, launch another WinPriv invocation there.

Other Notes
===========
- Multiple switches can be specified in a single command. For example, you
  can combine multiple /RegBlock and /RegOverride switches to block and
  override a set of registry keys and values for the target program.
)";
}
