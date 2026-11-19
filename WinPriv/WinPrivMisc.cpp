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
			L".exe [optional switches] <Command to execute>\n\n"
			L"Run WinPrivCmd.exe /Help for the full list of switches.";
	}

	// Command line help.
	return std::wstring(PROJECT_NAME) +
		LR"(.exe [optional switches] <Command to execute>

WinPriv alters the runtime behavior of a target process and its descendants by
injecting a native helper DLL that intercepts selected low-level Windows APIs.
Use WinPrivCmd for console programs and WinPriv for GUI programs.

Optional Switches
=================

General & Configuration
  /Help, /?                  Show this help and exit.
  /LoadCommands <Path>       Insert switches from a UTF-8 configuration file.
  /ExtractLibrary            Write WinPriv-x86/x64/ARM64.dll beside this executable
                             (used in preference to temporary extraction).
  /WindowStyle <Style>       Set initial window state: NoActive, Hidden, Maximized,
                             Minimized, or MinimizedNoActive.
  /UseShellExecute           Launch the target via ShellExecuteEx() instead of CreateProcess().
  /KillProcess <Name>        Terminate matching executables in the target session before launch.
  /ShowMessage <Message>     Show an OK message box ("Message") before launch.
  /AskMessage <Message>      Show a Yes/No message box ("Message"); No cancels launch.
  /MeasureTime               Display target execution time in seconds after exit.

Privileges & Local Security Policy
  /ListPrivileges, /ListPrivs
                             List privilege constants and descriptions defined in local policy.
  /WithPrivs <Priv>[,...]    Enable named privileges (acquires missing policy rights temporarily).
  /WithAllPrivs              Enable every privilege defined in local security policy.
  /GrantRight <Right> <User> Grant an LSA privilege or logon right on the local machine.
  /RevokeRight <Right> <User>
                             Revoke an LSA privilege or logon right on the local machine.
  /ClearDenyRights [User]    Clear the five SeDeny*LogonRight entries for User, or all accounts.
  /GrantAllRights <User>     Grant all system privileges and non-deny logon rights to User.

Registry, Filesystem & Environment Hooks
  /RegOverride <Key> <Value> <Type> <Data>
                             Override a registry value (REG_DWORD, REG_QWORD, REG_SZ, REG_BINARY).
  /RegBlock <Key>            Report all values under Key and its subkeys as nonexistent.
  /PolicyBlock               Apply /RegBlock to HKCU/HKLM Policy keys.
  /FipsOn, /FipsOff          Override FipsAlgorithmPolicy\Enabled to 1 or 0 for hooked reads.
  /FileRedirect <Src> <Dst>  Redirect file/directory access from Src to Dst (longest, then last wins).
  /BypassFileSecurity        Request backup/restore privileges and add backup intent to file opens.
  /BreakRemoteLocks          Close matching SMB server handles and retry blocked opens.
  /MockTime <Delta>          Shift wall clock by signed delta (y/yr, mo/mon, w/wk, d, h/hr, m/min,
                             s/sec, ms, us; plurals yrs/mons/wks/hrs/mins/secs accepted).

Network, Security & Database Hooks
  /MacOverride <Address>     Override MAC addresses returned by adapter/transport APIs.
  /HostOverride <Src> <Dst>  Resolve Src via Dst across Winsock and DNS address APIs (first match wins).
  /AdminImpersonate          Report admin membership (IsUserAnAdmin/CheckTokenMembership) + RunAsInvoker.
  /ServerEdition             Report server product type in GetVersionExA/W and VerifyVersionInfoW.
  /AmsiOn, /AmsiOff          Preserve or disable AMSI scanning (last switch wins).
  /ClmOn, /ClmOff            Enforce or disable PowerShell Constrained Language Mode (last wins).
  /UseConsoleToken           Route smart-card/hardware-token APIs to local readers (incl. RDP).
  /RecordCrypto <Dir|SHOW>   Capture BCrypt/Crypt/RtlEncryptMemory plaintext to Dir or display it.
  /SqlConnectShow            Display intercepted ODBC and ADO connection strings.
  /SqlConnectSearchReplace <Regex> <Replace>
                             Rewrite ODBC and ADO connection strings using a case-sensitive regex.

Session & LocalSystem Launch
  /AllowCreateProcessAsSystem
                             Enable CreateProcessWithLogonW from LocalSystem targets.
  /MediumPlus                Set duplicated session token to Medium Plus (place before /RunAs...).
  /RunAsConsoleUser, /RunAsConsoleUserNoWait
                             Run in the active console (or first active user) session (LocalSystem).
  /RunAsUser <User>, /RunAsUserNoWait <User>
                             Run in User's active or disconnected session (LocalSystem).
                             Note: /RunAs* launches do not apply hooks or launcher modifiers directly.

Multiple switches may be combined in a single command (e.g. multiple /RegOverride and /FileRedirect).
)";
}
