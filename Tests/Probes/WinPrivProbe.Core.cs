using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace WinPrivProbe
{
    public static partial class Native
    {
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenPrivileges = 3;
        private const int TokenElevationType = 18;
        private const int TokenElevation = 20;
        private const int TokenIntegrityLevel = 25;
        private const int TokenVirtualizationEnabled = 24;
        private const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint SE_PRIVILEGE_REMOVED = 0x00000004;
        private const uint MOVEFILE_REPLACE_EXISTING = 0x00000001;
        private const uint MOVEFILE_WRITE_THROUGH = 0x00000008;
        private const uint WAIT_OBJECT_0 = 0;
        private const uint WAIT_TIMEOUT = 258;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint VER_PRODUCT_TYPE = 0x00000080;
		private const uint VER_MAJORVERSION = 0x00000002;
        private const byte VER_EQUAL = 1;
        private const byte VER_NT_WORKSTATION = 1;
        private const byte VER_NT_DOMAIN_CONTROLLER = 2;
        private const byte VER_NT_SERVER = 3;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINDOWPLACEMENT
        {
            public uint length;
            public uint flags;
            public uint showCmd;
            public int ptMinPositionX;
            public int ptMinPositionY;
            public int ptMaxPositionX;
            public int ptMaxPositionY;
            public int rcNormalPositionLeft;
            public int rcNormalPositionTop;
            public int rcNormalPositionRight;
            public int rcNormalPositionBottom;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct OSVERSIONINFOEXW
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public ushort wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct OSVERSIONINFOEXA
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public ushort wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool MoveFileExW(string existingFileName, string newFileName, uint flags);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern void GetStartupInfoW(ref STARTUPINFO startupInfo);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr window);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetWindowPlacement(IntPtr window, ref WINDOWPLACEMENT placement);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern uint GetACP();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeNameW(string systemName, ref LUID luid, StringBuilder name, ref int nameLength);

        [DllImport("advapi32.dll")]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("advapi32.dll")]
        private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthority);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("shell32.dll", SetLastError = true)]
        private static extern bool IsUserAnAdmin();

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CheckTokenMembership(IntPtr tokenHandle, byte[] sidToCheck, out bool isMember);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVersionExW(ref OSVERSIONINFOEXW versionInfo);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool GetVersionExA(ref OSVERSIONINFOEXA versionInfo);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool VerifyVersionInfoW(ref OSVERSIONINFOEXW versionInfo, uint typeMask, ulong conditionMask);

        [DllImport("kernel32.dll")]
        private static extern ulong VerSetConditionMask(ulong conditionMask, uint typeMask, byte condition);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine,
            IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
            IntPtr environment, string currentDirectory, ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool CreateProcessA(string applicationName, StringBuilder commandLine,
            IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
            IntPtr environment, string currentDirectory, ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        public static Dictionary<string, object> MethodResult(bool supported, bool success, string reason)
        {
            Dictionary<string, object> value = new Dictionary<string, object>();
            value["supported"] = supported;
            value["success"] = success;
            if (!String.IsNullOrEmpty(reason))
            {
                value["reason"] = reason;
            }
            return value;
        }

        private static string Win32Message(int error)
        {
            return new Win32Exception(error).Message;
        }

        private static string Hex32(int value)
        {
            return "0x" + unchecked((uint)value).ToString("X8", CultureInfo.InvariantCulture);
        }

        private static string MachineName(ushort machine)
        {
            if (machine == 0x014c) return "x86";
            if (machine == 0x8664) return "x64";
            if (machine == 0xAA64) return "ARM64";
            if (machine == 0) return IntPtr.Size == 4 ? "x86" : "x64";
            return "0x" + machine.ToString("X4", CultureInfo.InvariantCulture);
        }

        private static string GetProcessArchitecture()
        {
            try
            {
                ushort processMachine;
                ushort nativeMachine;
                if (IsWow64Process2(GetCurrentProcess(), out processMachine, out nativeMachine))
                {
                    return MachineName(processMachine == 0 ? nativeMachine : processMachine);
                }
            }
            catch (EntryPointNotFoundException)
            {
            }
            return IntPtr.Size == 4 ? "x86" : "x64";
        }

        public static bool AtomicMove(string temporaryPath, string destinationPath)
        {
            return MoveFileExW(ExtendedPath(temporaryPath), ExtendedPath(destinationPath),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        }

        private static string ExtendedPath(string path)
        {
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + path.Substring(2);
            return @"\\?\" + Path.GetFullPath(path);
        }

        public static Dictionary<string, object> GetState(string[] remainingArguments, string[] environmentNames)
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            result["processId"] = Process.GetCurrentProcess().Id;
            result["processPath"] = Process.GetCurrentProcess().MainModule.FileName;
            result["architecture"] = GetProcessArchitecture();
            result["pointerSize"] = IntPtr.Size;
            result["is64BitOperatingSystem"] = Environment.Is64BitOperatingSystem;
            result["is64BitProcess"] = Environment.Is64BitProcess;
            result["commandLine"] = Environment.CommandLine;
            result["argv"] = Environment.GetCommandLineArgs();
            result["remainingArguments"] = remainingArguments == null ? new string[0] : remainingArguments;
            result["cwd"] = Environment.CurrentDirectory;
            result["userName"] = WindowsIdentity.GetCurrent().Name;
            result["machineName"] = Environment.MachineName;
            List<string> loadedModules = new List<string>();
            List<string> winPrivLibraryModules = new List<string>();
            try
            {
                foreach (ProcessModule module in Process.GetCurrentProcess().Modules)
                {
                    string modulePath = module.FileName;
                    loadedModules.Add(modulePath);
                    string moduleName = Path.GetFileName(modulePath);
                    bool namedLibrary = moduleName.StartsWith("WinPrivLibrary",
                        StringComparison.OrdinalIgnoreCase);
                    bool extractedLibrary = System.Text.RegularExpressions.Regex.IsMatch(
                        moduleName,
                        "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-(32|64|arm64)\\.dll$",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase |
                        System.Text.RegularExpressions.RegexOptions.CultureInvariant);
                    if (namedLibrary || extractedLibrary)
                    {
                        winPrivLibraryModules.Add(modulePath);
                    }
                }
            }
            catch (Exception moduleError)
            {
                result["loadedModulesError"] = moduleError.GetType().FullName + ": " + moduleError.Message;
            }
            result["loadedModules"] = loadedModules;
            result["winPrivLibraryModules"] = winPrivLibraryModules;
            result["winPrivLibraryLoaded"] = winPrivLibraryModules.Count != 0;
            Dictionary<string, object> process = new Dictionary<string, object>();
            process["id"] = result["processId"];
            process["path"] = result["processPath"];
            process["architecture"] = result["architecture"];
            process["pointerSize"] = result["pointerSize"];
            process["is64Bit"] = result["is64BitProcess"];
            process["loadedModules"] = loadedModules;
            process["winPrivLibraryModules"] = winPrivLibraryModules;
            process["winPrivLibraryLoaded"] = winPrivLibraryModules.Count != 0;
            result["process"] = process;
            result["environment"] = GetSelectedEnvironment(environmentNames);
            result["env"] = result["environment"];
            result["window"] = GetWindowState();
            result["token"] = GetTokenState();
            return result;
        }

        private static Dictionary<string, object> GetSelectedEnvironment(string[] requestedNames)
        {
            Dictionary<string, object> result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            names.Add("TEMP");
            names.Add("TMP");
            names.Add("WINPRIV_PROBE_ARGUMENTS_JSON");
            names.Add("WINPRIV_PROBE_OUTPUT_PATH");
            if (requestedNames != null)
            {
                for (int i = 0; i < requestedNames.Length; i++)
                {
                    if (!String.IsNullOrEmpty(requestedNames[i])) names.Add(requestedNames[i]);
                }
            }
            foreach (string name in names)
            {
                string value = Environment.GetEnvironmentVariable(name);
                if (value != null) result[name] = value;
            }
            return result;
        }

        public static Dictionary<string, object> GetWindowState()
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            IntPtr window = GetConsoleWindow();
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            GetStartupInfoW(ref startup);
            result["flags"] = startup.dwFlags;
            result["showWindow"] = startup.wShowWindow;
            result["usesShowWindow"] = (startup.dwFlags & 0x00000001) != 0;
            result["consoleWindowHandle"] = "0x" + window.ToInt64().ToString("X", CultureInfo.InvariantCulture);
            result["hasConsoleWindow"] = window != IntPtr.Zero;
            if (window != IntPtr.Zero)
            {
                result["visible"] = IsWindowVisible(window);
                WINDOWPLACEMENT placement = new WINDOWPLACEMENT();
                placement.length = (uint)Marshal.SizeOf(typeof(WINDOWPLACEMENT));
                bool ok = GetWindowPlacement(window, ref placement);
                result["placementSuccess"] = ok;
                if (ok) result["showCommand"] = placement.showCmd;
                else result["lastError"] = Marshal.GetLastWin32Error();
            }
            return result;
        }

        private static byte[] SidBytes(WellKnownSidType type)
        {
            SecurityIdentifier sid = new SecurityIdentifier(type, null);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            return bytes;
        }

        public static Dictionary<string, object> GetAdminState()
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            try
            {
                result["isUserAnAdmin"] = IsUserAnAdmin();
                bool admin;
                bool adminCall = CheckTokenMembership(IntPtr.Zero,
                    SidBytes(WellKnownSidType.BuiltinAdministratorsSid), out admin);
                Dictionary<string, object> adminResult = MethodResult(true, adminCall,
                    adminCall ? null : Win32Message(Marshal.GetLastWin32Error()));
                adminResult["isMember"] = admin;
                adminResult["lastError"] = adminCall ? 0 : Marshal.GetLastWin32Error();
                result["adminMembership"] = adminResult;

                bool everyone;
                bool everyoneCall = CheckTokenMembership(IntPtr.Zero,
                    SidBytes(WellKnownSidType.WorldSid), out everyone);
                Dictionary<string, object> everyoneResult = MethodResult(true, everyoneCall,
                    everyoneCall ? null : Win32Message(Marshal.GetLastWin32Error()));
                everyoneResult["isMember"] = everyone;
                everyoneResult["lastError"] = everyoneCall ? 0 : Marshal.GetLastWin32Error();
                result["everyoneMembership"] = everyoneResult;
            }
            catch (Exception error)
            {
                result["success"] = false;
                result["reason"] = error.GetType().FullName + ": " + error.Message;
            }
            return result;
        }

        public static Dictionary<string, object> GetTokenState()
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token))
                {
                    int error = Marshal.GetLastWin32Error();
                    result["reason"] = Win32Message(error);
                    result["lastError"] = error;
                    return result;
                }

                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                result["identity"] = identity.Name;
                result["sid"] = identity.User == null ? null : identity.User.Value;
                result["privileges"] = ReadTokenPrivileges(token);
                result["integrity"] = ReadTokenIntegrity(token);
                result["elevation"] = ReadTokenUInt32(token, TokenElevation);
                result["elevationType"] = ReadTokenUInt32(token, TokenElevationType);
                result["virtualizationEnabled"] = ReadTokenUInt32(token, TokenVirtualizationEnabled);
                result["success"] = true;
                return result;
            }
            catch (Exception error)
            {
                result["reason"] = error.GetType().FullName + ": " + error.Message;
                return result;
            }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
            }
        }

        private static object ReadTokenUInt32(IntPtr token, int informationClass)
        {
            IntPtr buffer = Marshal.AllocHGlobal(4);
            try
            {
                int returned;
                if (!GetTokenInformation(token, informationClass, buffer, 4, out returned))
                {
                    Dictionary<string, object> failure = MethodResult(true, false,
                        Win32Message(Marshal.GetLastWin32Error()));
                    failure["lastError"] = Marshal.GetLastWin32Error();
                    return failure;
                }
                return unchecked((uint)Marshal.ReadInt32(buffer));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static List<Dictionary<string, object>> ReadTokenPrivileges(IntPtr token)
        {
            int required;
            GetTokenInformation(token, TokenPrivileges, IntPtr.Zero, 0, out required);
            if (required <= 0) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr buffer = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(token, TokenPrivileges, buffer, required, out required))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                uint count = unchecked((uint)Marshal.ReadInt32(buffer, 0));
                List<Dictionary<string, object>> values = new List<Dictionary<string, object>>();
                int offset = 4;
                for (uint i = 0; i < count; i++)
                {
                    LUID luid = new LUID();
                    luid.LowPart = unchecked((uint)Marshal.ReadInt32(buffer, offset));
                    luid.HighPart = Marshal.ReadInt32(buffer, offset + 4);
                    uint attributes = unchecked((uint)Marshal.ReadInt32(buffer, offset + 8));
                    int length = 0;
                    LookupPrivilegeNameW(null, ref luid, null, ref length);
                    StringBuilder name = new StringBuilder(Math.Max(length + 1, 64));
                    int capacity = name.Capacity;
                    bool nameResult = LookupPrivilegeNameW(null, ref luid, name, ref capacity);
                    Dictionary<string, object> item = new Dictionary<string, object>();
                    item["name"] = nameResult ? name.ToString() : null;
                    item["luid"] = luid.HighPart.ToString(CultureInfo.InvariantCulture) + ":" +
                        luid.LowPart.ToString(CultureInfo.InvariantCulture);
                    item["attributes"] = attributes;
                    item["enabled"] = (attributes & SE_PRIVILEGE_ENABLED) != 0;
                    item["enabledByDefault"] = (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
                    item["removed"] = (attributes & SE_PRIVILEGE_REMOVED) != 0;
                    values.Add(item);
                    offset += 12;
                }
                return values;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static Dictionary<string, object> ReadTokenIntegrity(IntPtr token)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            int required;
            GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out required);
            if (required <= 0)
            {
                int error = Marshal.GetLastWin32Error();
                result["reason"] = Win32Message(error);
                result["lastError"] = error;
                return result;
            }
            IntPtr buffer = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, required, out required))
                {
                    int error = Marshal.GetLastWin32Error();
                    result["reason"] = Win32Message(error);
                    result["lastError"] = error;
                    return result;
                }
                IntPtr sidPointer = Marshal.ReadIntPtr(buffer, 0);
                SecurityIdentifier sid = new SecurityIdentifier(sidPointer);
                IntPtr countPointer = GetSidSubAuthorityCount(sidPointer);
                byte count = Marshal.ReadByte(countPointer);
                uint rid = count == 0 ? 0 : unchecked((uint)Marshal.ReadInt32(
                    GetSidSubAuthority(sidPointer, (uint)(count - 1))));
                string label = "unknown";
                if (rid < 0x1000) label = "untrusted";
                else if (rid < 0x2000) label = "low";
                else if (rid < 0x3000) label = "medium";
                else if (rid < 0x4000) label = "high";
                else if (rid < 0x5000) label = "system";
                else if (rid >= 0x5000) label = "protected";
                result["sid"] = sid.Value;
                result["rid"] = rid;
                result["label"] = label;
                result["success"] = true;
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static Dictionary<string, object> VersionInfo(uint major, uint minor, uint build,
            uint platform, string servicePack, ushort suiteMask, byte productType, bool success, int error)
        {
            Dictionary<string, object> result = MethodResult(true, success,
                success ? null : Win32Message(error));
            result["major"] = major;
            result["minor"] = minor;
            result["build"] = build;
            result["platformId"] = platform;
            result["servicePack"] = servicePack;
            result["suiteMask"] = suiteMask;
            result["productType"] = productType;
            result["productTypeName"] = productType == VER_NT_WORKSTATION ? "workstation" :
                (productType == VER_NT_DOMAIN_CONTROLLER ? "domainController" :
                (productType == VER_NT_SERVER ? "server" : "unknown"));
            result["lastError"] = success ? 0 : error;
            return result;
        }

        public static Dictionary<string, object> GetVersionState()
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            OSVERSIONINFOEXW wide = new OSVERSIONINFOEXW();
            wide.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOEXW));
            bool wideOk = GetVersionExW(ref wide);
            int wideError = wideOk ? 0 : Marshal.GetLastWin32Error();
            result["getVersionExW"] = VersionInfo(wide.dwMajorVersion, wide.dwMinorVersion,
                wide.dwBuildNumber, wide.dwPlatformId, wide.szCSDVersion, wide.wSuiteMask,
                wide.wProductType, wideOk, wideError);

            OSVERSIONINFOEXA ansi = new OSVERSIONINFOEXA();
            ansi.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOEXA));
            bool ansiOk = GetVersionExA(ref ansi);
            int ansiError = ansiOk ? 0 : Marshal.GetLastWin32Error();
            result["getVersionExA"] = VersionInfo(ansi.dwMajorVersion, ansi.dwMinorVersion,
                ansi.dwBuildNumber, ansi.dwPlatformId, ansi.szCSDVersion, ansi.wSuiteMask,
                ansi.wProductType, ansiOk, ansiError);

            ulong mask = VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL);
            result["verifyWorkstation"] = VerifyProductType(VER_NT_WORKSTATION, mask);
            result["verifyServer"] = VerifyProductType(VER_NT_SERVER, mask);
			ulong combinedMask = VerSetConditionMask(mask, VER_MAJORVERSION, VER_EQUAL);
			result["verifyServerCombined"] = VerifyProductAndMajor(
				VER_NT_SERVER, wide.dwMajorVersion, combinedMask);
            result["success"] = wideOk && ansiOk;
            return result;
        }

        private static Dictionary<string, object> VerifyProductType(byte requested, ulong mask)
        {
            OSVERSIONINFOEXW info = new OSVERSIONINFOEXW();
            info.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOEXW));
            info.wProductType = requested;
            bool verified = VerifyVersionInfoW(ref info, VER_PRODUCT_TYPE, mask);
            int error = verified ? 0 : Marshal.GetLastWin32Error();
            Dictionary<string, object> result = MethodResult(true, true, null);
            result["requestedProductType"] = requested;
            result["postCallProductType"] = info.wProductType;
            result["verified"] = verified;
            result["lastError"] = error;
            return result;
        }

		private static Dictionary<string, object> VerifyProductAndMajor(byte requested, uint major, ulong mask)
		{
			OSVERSIONINFOEXW info = new OSVERSIONINFOEXW();
			info.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOEXW));
			info.dwMajorVersion = major;
			info.wProductType = requested;
			bool verified = VerifyVersionInfoW(ref info, VER_PRODUCT_TYPE | VER_MAJORVERSION, mask);
			int error = verified ? 0 : Marshal.GetLastWin32Error();
			Dictionary<string, object> result = MethodResult(true, true, null);
			result["requestedProductType"] = requested;
			result["postCallProductType"] = info.wProductType;
			result["requestedMajorVersion"] = major;
			result["postCallMajorVersion"] = info.dwMajorVersion;
			result["verified"] = verified;
			result["lastError"] = error;
			return result;
		}

        private static IntPtr BuildEnvironmentBlock(string[] entries, bool unicode,
            out uint creationFlags, out uint codePage)
        {
            creationFlags = unicode ? CREATE_UNICODE_ENVIRONMENT : 0;
            codePage = unicode ? 1200u : GetACP();
            if (entries == null) return IntPtr.Zero;
            string[] copy = (string[])entries.Clone();
            Array.Sort(copy, StringComparer.OrdinalIgnoreCase);
            string joined = String.Join("\0", copy) + "\0\0";
            Encoding encoding = unicode ? Encoding.Unicode : Encoding.GetEncoding((int)codePage);
            byte[] bytes = encoding.GetBytes(joined);
            IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            return pointer;
        }

        public static Dictionary<string, object> RunCreateProcess(string api, string applicationName,
            string commandLine, string currentDirectory, string[] environmentEntries, int timeoutMilliseconds)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            bool unicode = !String.Equals(api, "A", StringComparison.OrdinalIgnoreCase);
            IntPtr environment = IntPtr.Zero;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            try
            {
                uint flags;
                uint environmentCodePage;
                environment = BuildEnvironmentBlock(environmentEntries, unicode, out flags,
                    out environmentCodePage);
                STARTUPINFO startup = new STARTUPINFO();
                startup.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
                StringBuilder mutableCommandLine = new StringBuilder(commandLine);
                bool created;
                if (unicode)
                {
                    created = CreateProcessW(applicationName, mutableCommandLine, IntPtr.Zero,
                        IntPtr.Zero, false, flags, environment, currentDirectory, ref startup, out process);
                }
                else
                {
                    created = CreateProcessA(applicationName, mutableCommandLine, IntPtr.Zero,
                        IntPtr.Zero, false, flags, environment, currentDirectory, ref startup, out process);
                }
                result["api"] = unicode ? "CreateProcessW" : "CreateProcessA";
                result["applicationName"] = applicationName;
                result["commandLine"] = commandLine;
                result["customEnvironment"] = environmentEntries != null;
                result["environmentCodePage"] = environmentCodePage;
                result["created"] = created;
                if (!created)
                {
                    int error = Marshal.GetLastWin32Error();
                    result["lastError"] = error;
                    result["reason"] = Win32Message(error);
                    return result;
                }
                result["processId"] = process.dwProcessId;
                uint wait = WaitForSingleObject(process.hProcess,
                    unchecked((uint)Math.Max(timeoutMilliseconds, 1)));
                result["waitResult"] = wait;
                if (wait == WAIT_TIMEOUT)
                {
                    result["timedOut"] = true;
                    bool terminated = TerminateProcess(process.hProcess, 0xDEAD);
                    result["terminated"] = terminated;
                    WaitForSingleObject(process.hProcess, 5000);
                    result["reason"] = "Child process exceeded the probe timeout.";
                    return result;
                }
                if (wait != WAIT_OBJECT_0)
                {
                    int error = Marshal.GetLastWin32Error();
                    result["lastError"] = error;
                    result["reason"] = Win32Message(error);
                    return result;
                }
                uint exitCode;
                if (!GetExitCodeProcess(process.hProcess, out exitCode))
                {
                    int error = Marshal.GetLastWin32Error();
                    result["lastError"] = error;
                    result["reason"] = Win32Message(error);
                    return result;
                }
                result["timedOut"] = false;
                result["exitCode"] = exitCode;
                result["success"] = true;
                return result;
            }
            catch (EntryPointNotFoundException error)
            {
                result["supported"] = false;
                result["reason"] = error.Message;
                return result;
            }
            finally
            {
                if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
            }
        }
    }
}
