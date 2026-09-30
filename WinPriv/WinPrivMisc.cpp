//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <Windows.h>
#include <winternl.h>
#include <WinPrivShared.h>

#include <map>
#include <string>

#include <ntlsa.h>

std::map<std::wstring, std::wstring> GetPrivilegeList()
{
	// list of privileges to return
	std::map<std::wstring, std::wstring> tPrivilegeList;

	// object attributes are reserved, so initialize to zeros.
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	// get a handle to the policy object.
	NTSTATUS iResult = 0;
	SmartPointer<LSA_HANDLE> policyHandle(LsaClose, nullptr);
	if ((iResult = LsaOpenPolicy(nullptr, &ObjectAttributes,
		POLICY_VIEW_LOCAL_INFORMATION, &policyHandle)) != STATUS_SUCCESS)
	{
		// return on error - priv list will be empty
		return tPrivilegeList;
	}

	// enumerate the privileges that are settable
	SmartPointer<PPOLICY_PRIVILEGE_DEFINITION> buffer(LsaFreeMemory, nullptr);
	LSA_ENUMERATION_HANDLE enumerationContext = 0;
	ULONG countReturned = 0;
	while (LsaEnumeratePrivileges(policyHandle, &enumerationContext,
		(PVOID *)&buffer, INFINITE, &countReturned) == STATUS_SUCCESS)
	{
		for (ULONG iPrivIndex = 0; iPrivIndex < countReturned; iPrivIndex++)
		{
			const std::wstring sPrivilegeName(buffer[iPrivIndex].Name.Buffer, buffer[iPrivIndex].Name.Length / sizeof(WCHAR));
			tPrivilegeList[sPrivilegeName] = sPrivilegeName;
			DWORD iSize = 0;
			DWORD iIden = 0;

			// return privilege display name -- call lookup once to get string size
			// and then alloc the string on the next call to get the string
			if (LookupPrivilegeDisplayName(nullptr, sPrivilegeName.c_str(), nullptr, &iSize, &iIden) == 0)
			{
				SmartPointer<LPWSTR> sDisplayName(free, static_cast<LPWSTR>(malloc(sizeof(WCHAR) * (++iSize))));
				if (LookupPrivilegeDisplayName(nullptr, sPrivilegeName.c_str(), sDisplayName, &iSize, &iIden) != 0)
				{
					tPrivilegeList[sPrivilegeName] = static_cast<LPWSTR>(sDisplayName);
				}
			}
		}
	}

	return tPrivilegeList;
}

std::wstring GetWinPrivHelp()
{
	// a messagebox will garble this help information so simply the help
	// for the non-commandline version and defer to commandline for help
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

   Enables one or more named Windows privileges for the target process. Use a
   comma-delimited list when enabling multiple privileges.

   Example:

	  /WithPrivs SeDebugPrivilege,SeBackupPrivilege

/WithAllPrivs

   Attempts to enable every privilege available to the current account for
   the target process.

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

   Specifies that any request to obtain the IP address for the specified target
   will instead receive the specified replacement IP address. This is done by
   intercepting calls to WSALookupServiceNext(), through which nearly all
   address lookups ultimately occur. Be aware that, due to special security
   protections, this will not work for Internet Explorer or programs that use
   its libraries, but it should work for most other processes.

   Examples:

	  /HostOverride google.com yahoo.com
	  /HostOverride google.com 127.0.0.1

/FipsOn, /FipsOff

   These options cause the system to report that Federal Information
   Processing Standards (FIPS) enforcement is enabled or disabled, regardless
   of the current system setting. They use /RegOverride on the FIPS-related
   registry key.

/PolicyBlock

   This option will cause all registry queries to HKCU\Software\Policies and
   HKLM\Software\Policies to be blocked. This is a convenience option that
   actually uses the /RegBlock functionality.

/BypassFileSecurity

   This option causes the target process to enable the backup and restore
   privileges and alters the way the program accesses files to take advantage
   of these extra privileges. When these privileges are enabled, all access
   control lists on the file system are ignored. This allows an administrator
   to inspect and alter files without changing permissions or taking ownership.

   Effective uses of this option include using command-line utilities such as
   icacls.exe to inspect or alter permissions. Using this with cmd.exe or
   powershell.exe also provides a means to interact with secured areas.

   Example:

   Access detailed permissions under 'C:\System Volume Information':
   WinPrivCmd.exe /BypassFileSecurity icacls.exe
	  "C:\System Volume Information" /T
)"
		LR"(
/BreakRemoteLocks

   This option attempts to break remote file locks if a file cannot be accessed
   because it is open in a program on a remote system. For example, this can
   allow programs such as robocopy to mirror an area where the destination
   system has a file in use. This option has no effect if the file is in use
   by a program on the same system as WinPriv.

/MediumPlus

   This option launches the target process using the plus variant of the
   current user token's mandatory integrity level. For example, a process
   running at Medium integrity will be launched at Medium Plus integrity.
   This can be useful when an application requires a higher integrity level
   than the current user's token provides without fully elevating to High.

/AdminImpersonate

   This option causes any local administrator check using IsUserAnAdmin() or
   CheckTokenMembership() to unconditionally succeed, regardless of whether
   the user is actually a member of the local Administrators group.

/ServerEdition

   This option causes the most common operating system version information
   functions to indicate that the system is running a server edition of the
   operating system.

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

/RecordCrypto <Directory>

   This option records the input to common Windows encryption functions and
   the output from common Windows decryption functions. A separate file is
   created for each operation in the specified directory. If 'SHOW' is
   specified instead of a directory path, information is output to the
   console or message boxes, depending on the type of application.

/SqlConnectShow

   This option displays the ODBC connection parameters immediately before a
   connection operation occurs.

/SqlConnectSearchReplace <SearchString> <ReplaceString>

   This option searches for and replaces text in an ODBC connection string
   before passing it to the connection's Open() function. The search string
   is parsed as a regular expression.

   Example:

   WinPrivCmd.exe /SqlConnectSearchReplace
	  Provider=SQLOLEDB Provider=SQLNCLI11 LegacyApplication.exe

/KillProcess <ProcessName>

   Terminates the process with the specified name before running the target.
   This is useful when the target prevents multiple instances and an existing
   instance must be stopped before a new instance can run with WinPriv's
   settings.

/ExtractLibrary

   This option extracts the embedded x86, x64, and ARM64 libraries to the
   directory containing the WinPriv executable. The libraries are normally
   extracted to the user's temporary directory. If all three libraries are
   beside the executable, WinPriv uses those copies instead.

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

/MeasureTime

   This option measures the execution time of the target process and displays
   it to the user.

/ListPrivileges

   This option displays a list of available privilege names and descriptions.

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

   Removes all deny-logon rights from the named user or group account,
   lifting any explicit LSA-level blocks on how the account may log on.
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

/RunAsConsoleUser, /RunAsConsoleUserNoWait

   Runs the specified program as the user logged in at the console. If no
   user is logged in at the console, the first active remote user session
   is used. This can be useful when WinPriv runs in a system context, such
   as a scheduled task or system management agent.
   With /RunAsConsoleUserNoWait, WinPriv returns immediately after the
   process starts.

/RunAsUser [UserName], /RunAsUserNoWait [UserName]

   Runs the specified program as the specified user. The user must be logged
   in to the system at the console or remotely. This can be useful when WinPriv
   runs in a system context, such as a scheduled task or system management
   agent. With /RunAsUserNoWait, WinPriv returns immediately after the
   process starts.

Other Notes
===========
- Multiple switches can be specified in a single command. For example, you
  can combine multiple /RegBlock and /RegOverride switches to block and
  override a set of registry keys and values for the target program.
)";
}
