#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <windows.h>
#include <winternl.h>

#include <iostream>
#include <map>
#include <string>
#include <regex>

#include <ntlsa.h>

#include "WinPrivShared.h"

std::map<std::wstring, std::wstring> GetPrivilegeList()
{
	// list of privileges to return
	std::map<std::wstring, std::wstring> tPrivilegeList;

	// object attributes are reserved, so initialize to zeros.
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	// get a handle to the policy object.
	NTSTATUS iResult = 0;
	LSA_HANDLE policyHandle;
	if ((iResult = LsaOpenPolicy(NULL, &ObjectAttributes,
		POLICY_VIEW_LOCAL_INFORMATION, &policyHandle)) != STATUS_SUCCESS)
	{
		// return on error - priv list will be empty
		return tPrivilegeList;
	}

	// enumerate the privileges that are settable
	PPOLICY_PRIVILEGE_DEFINITION buffer;
	LSA_ENUMERATION_HANDLE enumerationContext = 0;
	ULONG countReturned = 0;
	while (LsaEnumeratePrivileges(policyHandle, &enumerationContext,
		(PVOID *)&buffer, INFINITE, &countReturned) == STATUS_SUCCESS)
	{
		for (ULONG iPrivIndex = 0; iPrivIndex < countReturned; iPrivIndex++)
		{
			LPWSTR sDisplayName = nullptr;
			DWORD iSize = 0;
			DWORD iIden = 0;

			// return privilege display name -- call lookup once to get string size
			// and then alloc the string on the next call to get the string
			if (LookupPrivilegeDisplayName(NULL, (LPWSTR)buffer[iPrivIndex].Name.Buffer, NULL, &iSize, &iIden) == 0 &&
				LookupPrivilegeDisplayName(NULL, (LPWSTR)buffer[iPrivIndex].Name.Buffer,
					sDisplayName = (LPWSTR)malloc(sizeof(WCHAR) * (++iSize)), &iSize, &iIden) != 0)
			{
				tPrivilegeList[buffer[iPrivIndex].Name.Buffer] = sDisplayName;
			}

			// cleanup
			if (sDisplayName == nullptr) free(sDisplayName);
		}

		// cleanup
		LsaFreeMemory(buffer);
	}

	// rights are not available from any enumerated functions so these are manually added
	// temporarily disabled since they cannot be managed the same way as privileges
	if (false)
	{
		tPrivilegeList[SE_BATCH_LOGON_NAME] = L"Log on as a batch job";
		tPrivilegeList[SE_DENY_BATCH_LOGON_NAME] = L"Deny log on as a batch job";
		tPrivilegeList[SE_DENY_INTERACTIVE_LOGON_NAME] = L"Deny log on locally";
		tPrivilegeList[SE_DENY_NETWORK_LOGON_NAME] = L"Deny access to this computer from the network";
		tPrivilegeList[SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME] = L"Deny log on through Remote Desktop Services";
		tPrivilegeList[SE_DENY_SERVICE_LOGON_NAME] = L"Deny log on as a service";
		tPrivilegeList[SE_INTERACTIVE_LOGON_NAME] = L"Allow log on locally";
		tPrivilegeList[SE_NETWORK_LOGON_NAME] = L"Access this computer from the network";
		tPrivilegeList[SE_REMOTE_INTERACTIVE_LOGON_NAME] = L"Allow log on through Remote Desktop Services";
		tPrivilegeList[SE_SERVICE_LOGON_NAME] = L"Log on as a service";
	}

	// cleanup
	LsaClose(policyHandle);
	return tPrivilegeList;
}

std::wstring GetWinPrivHelp()
{
	// a messagebox will garble this help information so simply the help
	// for the non-commandline version and defer to commandline for help
	if (GetConsoleWindow() == NULL)
	{
		return std::wstring(PROJECT_NAME) +
			L"(.exe [optional switches] <Command To Execute> \n" +
			L"\n" +
			L"See WinPrivCmd /Help to view optional switch information.";
	}

	// command line help
	return std::wstring(PROJECT_NAME) + 
		LR"(.exe [optional switches] <Command To Execute> 

WinPriv is system administration utility that alters the runtime behavior of 
the specified process and its child processes. It does this by loading a
supplemental library into memory to intercept and alter the behavior of 
common low-level functions such as registry and file system operations.

WinPriv can be used for a variety of purposes including testing security 
settings without altering system-wide policy, implementing security-related
workarounds on a per-process basis instead of altering system-wide policy, and
taking advantageous of system privileges to perform file system auditing and
reconfiguration.

WinPriv comes in normal version (WinPriv) and a console version (WinPrivCmd).
The behavior of the subprocess is the same regardless of which version is used.
These versions are provided in case the target program is a console program
in which case you will only be able to get its screen output if you use 
WinPrivCmd. Similarly, you may not wish to see the console windows when 
targeting a non-console program in which case it may be advantageous to use
WinPriv.

Optional Switches
================= 

/RegOverride <Registry Key Path> <Value Name> <Data Type> <Data Value>
   
   Specifies a registry value to override. Instead of returning the true 
   registry value for the specified key path and value name, the value 
   the value specified in this switch is returned. 
   
   Examples:

      /RegOverride HKCU\Software\Demo Enabled REG_DWORD 1
      /RegOverride HKLM\Software\Demo UserName REG_SZ "James Bond"
   
/RegBlock <Registry Key Path>
   
   Specified a registry key under which all values will be reported as 
   non-existent. When the application requests a particular value in the 
   specified key or one of its subkeys, it will be reported as not found
   regardless as to whether it actually exists in the registry.
   
   Examples:
   
      /RegBlock HKCU\Software\Demo 
   
/MacOverride <MAC Address>
   
   Specifies a physical network address that will be returned when the target
   application makes a query to the system to provide its MAC addresses. Any
   call to GetAdaptersAddresses, GetAdaptersInfo, and NetWkstaTransportEnum 
   is handled.  The hex octets can be delimited by dashes, colons, or nothing.
   
   Examples:
   
      /MacOverride 00-11-22-33-44-66 
   
/FipsOn & /FipsOff
   
   This option will turn cause the system to report that Federal Information
   Processing System enforcement is turned on or off, regardless of its current 
   setting on the system. This operation is a convenience option that actually 
   uses the /RegOverride functionality on the FIPS-related registry key.
   
/PolicyBlock

   This option will cause all registry queries to HKCU\Software\Policies and
   HKCU\Software\Policies. This option is convenience option that actually uses
   the /RegBlock functionality.
   
/BypassFileSecurity
   
   This option causes the target process to enable the backup and restore 
   privileges and alters the way the program access files to take advantage of 
   this extra privileges. When these privileges are enabled, all access 
   control lists on the file system are ignored. This allows an administrator
   to inspect and alter files without changing permissions or taking ownership.

   Effective uses of this option include using command line utilities like 
   icacls.exe to inspect/alter permissions. Using this with cmd.exe or 
   powershell.exe also provide a mean to interact with secured areas.
   
   Examples:
   
   Access detailed permissions under 'C:\System Volume Information':
   WinPrivCmd.exe /BypassFileSecurity icacls.exe 
      "C:\System Volume Information" /T
   
/ListPrivileges
      
   This option displays of list of available privileges and permissions.

Other Notes & Limitations
=========================
- Multiple switches can be specified in a single command. For example, one 
  can use multiple /RegBlock and /RegOverride commands to block and override
  the specified set of registry key and values on a specified target program.
)";
}