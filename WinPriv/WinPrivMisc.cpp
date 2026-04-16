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
#include <regex>

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
			DWORD iSize = 0;
			DWORD iIden = 0;

			// return privilege display name -- call lookup once to get string size
			// and then alloc the string on the next call to get the string
			if (LookupPrivilegeDisplayName(nullptr, buffer[iPrivIndex].Name.Buffer, nullptr, &iSize, &iIden) == 0)
			{
				SmartPointer<LPWSTR> sDisplayName(free, static_cast<LPWSTR>(malloc(sizeof(WCHAR) * (++iSize))));
				if (LookupPrivilegeDisplayName(nullptr, buffer[iPrivIndex].Name.Buffer, sDisplayName, &iSize, &iIden) != 0)
				{
					tPrivilegeList[buffer[iPrivIndex].Name.Buffer] = static_cast<LPWSTR>(sDisplayName);
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
	if (GetConsoleWindow() == nullptr)
	{
		return std::wstring(PROJECT_NAME) +
			L".exe [optional switches] <Command To Execute> \n" +
			L"\n" +
			L"See WinPrivCmd /Help to view optional switch information.";
	}

	// command line help
	return std::wstring(PROJECT_NAME) +
		LR"(.exe [optional switches] <Command To Execute>

WinPriv is a system administration utility that alters the runtime behavior of
the specified process and its child processes. It does this by loading a
supplemental library into memory to intercept and alter the behavior of
common low-level functions such as registry and file system operations.

WinPriv can be used for a variety of purposes including testing security
settings without altering system-wide policy, implementing security-related
workarounds on a per-process basis instead of altering system-wide policy, and
taking advantage of system privileges to perform file system auditing and
reconfiguration.

WinPriv comes in a normal version (WinPriv) and a console version (WinPrivCmd).
The behavior of the subprocess is the same regardless of which version is used.
These versions are provided in case the target program is a console program,
in which case you will only be able to get its screen output if you use
WinPrivCmd. Similarly, you may not wish to see the console window when
targeting a non-console program, in which case it may be advantageous to use
WinPriv.

Optional Switches
=================

/RegOverride <Registry Key Path> <Value Name> <Data Type> <Data Value>

   Specifies a registry value to override. Instead of returning the true
   registry value for the specified key path and value name, the value
   specified in this switch is returned.

   Examples:

	  /RegOverride HKCU\Software\Demo Enabled REG_DWORD 1
	  /RegOverride HKLM\Software\Demo UserName REG_SZ "James Bond"

/RegBlock <Registry Key Path>

   Specifies a registry key under which all values will be reported as
   non-existent. When the application requests a particular value in the
   specified key or one of its subkeys, it will be reported as not found
   regardless of whether it actually exists in the registry.

   Examples:

	  /RegBlock HKCU\Software\Demo

/MacOverride <MAC Address>

   Specifies a physical network address that will be returned when the target
   application makes a query to the system to provide its MAC addresses. Any
   call to GetAdaptersAddresses, GetAdaptersInfo, and NetWkstaTransportEnum
   is handled. The hex octets can be delimited by dashes, colons, or nothing.

   Examples:

	  /MacOverride 00-11-22-33-44-66

/HostOverride <Target HostName> <Replacement HostName>

   Specifies that any request to obtain the IP address for the specified target
   will instead receive the specified replacement IP address. This is done by
   intercepting calls to WSALookupServiceNext(), through which nearly all
   address lookups ultimately occur. Be aware that due to special security
   protections, this will not work for Internet Explorer and programs that use
   Internet Explorer libraries, but should work for most other processes.

   Examples:

	  /HostOverride google.com yahoo.com
	  /HostOverride google.com 127.0.0.1

/FipsOn & /FipsOff

   This option will cause the system to report that Federal Information
   Processing Standard enforcement is turned on or off, regardless of its
   current setting on the system. This is a convenience option that actually
   uses the /RegOverride functionality on the FIPS-related registry key.

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

   Effective uses of this option include using command line utilities like
   icacls.exe to inspect or alter permissions. Using this with cmd.exe or
   powershell.exe also provides a means to interact with secured areas.

   Examples:

   Access detailed permissions under 'C:\System Volume Information':
   WinPrivCmd.exe /BypassFileSecurity icacls.exe
	  "C:\System Volume Information" /T
)"
		LR"(
/BreakRemoteLocks

   This option attempts to break remote file locks if a file cannot be accessed
   because it is opened by another program remotely. For example, this can be
   used to allow programs like robocopy to mirror an area where the destination
   system has an in-use file. This option will have no effect if the file is
   in-use by a program on the same system where WinPriv is executed.

/MediumPlus

   This option launches the target process using the plus variant of the
   current user token's mandatory integrity level. For example, a process
   running at Medium integrity will be launched at Medium Plus integrity.
   This can be useful when an application requires a higher integrity level
   than the current user's token provides without fully elevating to High.

/AdminImpersonate

   This option causes any local administrator check using IsUserAnAdmin() or
   CheckTokenMembership() to unconditionally succeed regardless of whether the
   user is actually a member of the local administrator group.

/ServerEdition

   This option causes the most common operating system version information
   functions to indicate that the system is running a server edition of the
   operating system.

/RecordCrypto <Directory>

   This option records the data being input to common Windows encryption
   functions and the data being output from common Windows decryption
   functions. A separate file will be created for each operation in the
   specified directory. If 'SHOW' is specified instead of a directory path,
   information is output to the console or message boxes, depending on the
   type of application.

/SqlConnectShow

   This option will display the ODBC connection parameters immediately before
   a connection operation occurs.

/SqlConnectSearchReplace <SearchString> <ReplaceString>

   This option performs a search and replace on an ODBC connection string prior
   to passing it to the connection Open() function. The search string is
   parsed as a regular expression.

   Examples:

   WinPrivCmd.exe /SqlConnectSearchReplace
	  Provider=SQLOLEDB Provider=SQLNCLI11 LegacyApplication.exe

/KillProcess <ProcessName>

   Kills the process with the specified name prior to running the target. This
   is useful if the target has logic to prevent multiple instances from running
   and needs to be terminated before the effects of a WinPriv session can be
   effective.

/ExtractLibrary

   This option extracts the embedded 32-bit and 64-bit libraries to the
   directory where WinPriv is running. These are normally dynamically extracted
   to the user's temporary directory. If WinPriv finds these libraries in the
   directory where it is running, it will use those instead of writing them
   to the temporary directory.

/WindowStyle <Style>

   This option will launch the target process with the specified window style:
   NoActive, Hidden, Maximized, Minimized, MinimizedNoActive

/UseShellExecute

   This option will launch the target process with the ShellExecute() function
   instead of CreateProcess(). This can be useful if launching an application
   that is registered on the system but not in the system path.

/MeasureTime

   This option measures the execution time of the target process and displays
   it to the user.

/ListPrivileges

   This option displays a list of available privileges and permissions.

/RunAsConsoleUser

   Runs the specified program as the user that is logged into the console.
   If no user is logged into the console, the first active remote user
   session is used. This can be useful when WinPriv is running under a system
   context such as a scheduled task or system management agent.

/RunAsConsoleUserNoWait

   Same as /RunAsConsoleUser but does not wait for the launched process to
   complete before returning. WinPriv will return immediately after the
   process is started.

/RunAsUser [UserName]

   Runs the specified program as the specified user. The user must be logged
   into the system at the console or remotely. This can be useful when WinPriv
   is running under a system context such as a scheduled task or system
   management agent.

Other Notes & Limitations
=========================
- Multiple switches can be specified in a single command. For example, one
  can use multiple /RegBlock and /RegOverride switches to block and override
  a specified set of registry keys and values for a target program.
)";
}