using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace WinPrivProbe
{
    public static partial class Native
    {
        private const uint TOKEN_QUERY = 0x0008;
        private const int TokenPrivileges = 3;
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
        private struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved, lpDesktop, lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MACHINE_INFORMATION { public ushort ProcessMachine, Reserved; public uint MachineAttributes; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct OSVERSIONINFOEXW
        {
            public uint dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szCSDVersion;
            public ushort wServicePackMajor, wServicePackMinor, wSuiteMask;
            public byte wProductType, wReserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct OSVERSIONINFOEXA
        {
            public uint dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szCSDVersion;
            public ushort wServicePackMajor, wServicePackMinor, wSuiteMask;
            public byte wProductType, wReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ClockSystemTime
        {
            public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds;
            public DateTime ToDateTime() { return new DateTime(Year, Month, Day, Hour, Minute, Second, Milliseconds); }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ClockTimeOfDay
        {
            public long BootTime, CurrentTime, TimeZoneBias;
            public uint TimeZoneId, Reserved;
            public ulong BootTimeBias, SleepTimeBias;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ClockTimeB { public long Seconds; public ushort Milliseconds; public short TimeZone, Dst; }

        [StructLayout(LayoutKind.Sequential)]
        private struct ClockTimeSpec { public long Seconds; public int Nanoseconds; }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool MoveFileExW(string existingFileName, string newFileName, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern void GetStartupInfoW(ref STARTUPINFO startupInfo);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll")]
        private static extern uint GetACP();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessInformation(IntPtr process, int informationClass,
            out PROCESS_MACHINE_INFORMATION information, uint informationSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr tokenHandle, int tokenInformationClass,
            IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeNameW(string systemName, ref LUID luid, StringBuilder name, ref int nameLength);

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
            IntPtr environment, string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool CreateProcessA(string applicationName, StringBuilder commandLine,
            IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
            IntPtr environment, string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll")]
        private static extern void GetSystemTimeAsFileTime(out long time);

        [DllImport("kernel32.dll")]
        private static extern void GetSystemTimePreciseAsFileTime(out long time);

        [DllImport("kernel32.dll")]
        private static extern void GetSystemTime(out ClockSystemTime time);

        [DllImport("kernel32.dll")]
        private static extern void GetLocalTime(out ClockSystemTime time);

        [DllImport("kernelbase.dll", EntryPoint = "GetSystemTimeAsFileTime")]
        private static extern void GetBaseSystemTimeAsFileTime(out long time);

        [DllImport("kernelbase.dll", EntryPoint = "GetSystemTime")]
        private static extern void GetBaseSystemTime(out ClockSystemTime time);

        [DllImport("kernelbase.dll", EntryPoint = "GetLocalTime")]
        private static extern void GetBaseLocalTime(out ClockSystemTime time);

        [DllImport("kernel32.dll")]
        private static extern void SetLastError(uint error);

        [DllImport("kernel32.dll")]
        private static extern uint GetLastError();

        [DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();

        [DllImport("kernelbase.dll")]
        private static extern void QueryInterruptTime(out ulong time);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryPerformanceCounter(out long counter, out long frequency);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemTime(out long time);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemTime(IntPtr time);

        [DllImport("ntdll.dll")]
        private static extern long RtlGetSystemTimePrecise();

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int informationClass, out ClockTimeOfDay time,
            int length, out int returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetDateFormatEx(string locale, uint flags, IntPtr time, string format,
            StringBuilder output, int count, string calendar);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetTimeFormatEx(string locale, uint flags, IntPtr time, string format,
            StringBuilder output, int count);

        [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, EntryPoint = "GetDateFormatEx")]
        private static extern int GetBaseDateFormatEx(string locale, uint flags, IntPtr time, string format,
            StringBuilder output, int count, string calendar);

        [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, EntryPoint = "GetTimeFormatEx")]
        private static extern int GetBaseTimeFormatEx(string locale, uint flags, IntPtr time, string format,
            StringBuilder output, int count);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern int GetDateFormatA(uint locale, uint flags, IntPtr time, string format,
            StringBuilder output, int count);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetDateFormatW(uint locale, uint flags, IntPtr time, string format,
            StringBuilder output, int count);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern int GetTimeFormatA(uint locale, uint flags, IntPtr time, string format,
            StringBuilder output, int count);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetTimeFormatW(uint locale, uint flags, IntPtr time, string format,
            StringBuilder output, int count);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetDateFormatEx(string locale, uint flags, ref ClockSystemTime time, string format,
            StringBuilder output, int count, string calendar);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetTimeFormatEx(string locale, uint flags, ref ClockSystemTime time, string format,
            StringBuilder output, int count);

        [DllImport("ucrtbase.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "_time64")]
        private static extern long UcrtTime64(IntPtr time);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "_time64")]
        private static extern long MsvcrtTime64(IntPtr time);

        [DllImport("ucrtbase.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "_ftime64_s")]
        private static extern int UcrtTimeB(out ClockTimeB time);

        [DllImport("ucrtbase.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "_timespec64_get")]
        private static extern int UcrtTimeSpec(out ClockTimeSpec time, int timeBase);

        [DllImport("winsta.dll", SetLastError = true)]
        private static extern byte WinStationGetCurrentSessionCapabilities(uint capability, out uint value);

        [DllImport("winscard.dll")]
        private static extern int SCardEstablishContext(uint scope, IntPtr reserved1, IntPtr reserved2, out UIntPtr context);

        [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
        private static extern int SCardListReadersW(UIntPtr context, string groups, out IntPtr readers, ref uint characters);

        [DllImport("winscard.dll")]
        private static extern int SCardIsValidContext(UIntPtr context);

        [DllImport("winscard.dll")]
        private static extern int SCardFreeMemory(UIntPtr context, IntPtr memory);

        [DllImport("winscard.dll")]
        private static extern int SCardReleaseContext(UIntPtr context);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptSignHash(IntPtr key, IntPtr paddingInfo, byte[] hash, int hashSize,
            byte[] signature, int signatureSize, out int resultSize, uint flags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptFinalizeKey(IntPtr key, uint flags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptSetProperty(IntPtr key, string property, byte[] input, int size, uint flags);

        public static Dictionary<string, object> MethodResult(bool supported, bool success, string reason)
        {
            Dictionary<string, object> value = new Dictionary<string, object>();
            value["supported"] = supported;
            value["success"] = success;
            if (!String.IsNullOrEmpty(reason)) value["reason"] = reason;
            return value;
        }

        private static Dictionary<string, object> FailWin32(Dictionary<string, object> result, int error)
        {
            result["lastError"] = error;
            result["reason"] = Win32Message(error);
            return result;
        }

        private static Dictionary<string, object> RunSafe(Action<Dictionary<string, object>> action)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            try { action(result); }
            catch (DllNotFoundException error) { result["supported"] = false; result["reason"] = error.Message; }
            catch (EntryPointNotFoundException error) { result["supported"] = false; result["reason"] = error.Message; }
            catch (Exception error) { result["reason"] = error.GetType().FullName + ": " + error.Message; }
            return result;
        }

        private static string Win32Message(int error) { return new Win32Exception(error).Message; }

        private static string Hex32(int value)
        {
            return "0x" + unchecked((uint)value).ToString("X8", CultureInfo.InvariantCulture);
        }

        public static bool AtomicMove(string temporaryPath, string destinationPath)
        {
            return MoveFileExW(ExtendedPath(temporaryPath), ExtendedPath(destinationPath),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        }

        public static string ExtendedPath(string path)
        {
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + path.Substring(2);
            return @"\\?\" + Path.GetFullPath(path);
        }

        private static string MachineName(ushort machine)
        {
            if (machine == 0x014c) return "x86";
            if (machine == 0x8664 || machine == 0xA641) return "x64";
            if (machine == 0xAA64) return "ARM64";
            if (machine == 0) return IntPtr.Size == 4 ? "x86" : "x64";
            return "0x" + machine.ToString("X4", CultureInfo.InvariantCulture);
        }

        private static string GetProcessArchitecture()
        {
            try
            {
                ushort processMachine, nativeMachine;
                if (IsWow64Process2(GetCurrentProcess(), out processMachine, out nativeMachine))
                {
                    if (processMachine == 0 && nativeMachine == 0xAA64)
                    {
                        PROCESS_MACHINE_INFORMATION info;
                        if (GetProcessInformation(GetCurrentProcess(), 9, out info,
                            (uint)Marshal.SizeOf(typeof(PROCESS_MACHINE_INFORMATION))) && info.ProcessMachine != 0)
                            return MachineName(info.ProcessMachine);
                    }
                    return MachineName(processMachine == 0 ? nativeMachine : processMachine);
                }
            }
            catch (EntryPointNotFoundException) { }
            return IntPtr.Size == 4 ? "x86" : "x64";
        }

        public static Dictionary<string, object> GetState(string[] remainingArguments, string[] environmentNames)
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            Process current = Process.GetCurrentProcess();
            result["processId"] = current.Id;
            result["processPath"] = current.MainModule.FileName;
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

            List<string> winPrivLibraryModules = new List<string>();
            try
            {
                foreach (ProcessModule module in current.Modules)
                {
                    string moduleName = Path.GetFileName(module.FileName);
                    if (moduleName.StartsWith("WinPrivLibrary", StringComparison.OrdinalIgnoreCase) ||
                        Regex.IsMatch(moduleName,
                            "^WinPriv-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-)?(x86|x64|arm64)\\.dll$",
                            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                        winPrivLibraryModules.Add(module.FileName);
                }
            }
            catch (Exception error)
            {
                result["loadedModulesError"] = error.GetType().FullName + ": " + error.Message;
            }
            result["winPrivLibraryModules"] = winPrivLibraryModules;
            result["winPrivLibraryLoaded"] = winPrivLibraryModules.Count != 0;

            Dictionary<string, object> env = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> names = new HashSet<string>(
                new string[] { "TEMP", "TMP", "WINPRIV_PROBE_ARGUMENTS_JSON", "WINPRIV_PROBE_OUTPUT_PATH" },
                StringComparer.OrdinalIgnoreCase);
            if (environmentNames != null)
                foreach (string name in environmentNames)
                    if (!String.IsNullOrEmpty(name)) names.Add(name);
            foreach (string name in names)
            {
                string value = Environment.GetEnvironmentVariable(name);
                if (value != null) env[name] = value;
            }
            result["environment"] = env;
            return result;
        }

        public static Dictionary<string, object> GetWindowState()
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            GetStartupInfoW(ref startup);
            result["flags"] = startup.dwFlags;
            result["showWindow"] = startup.wShowWindow;
            result["usesShowWindow"] = (startup.dwFlags & 0x00000001) != 0;
            return result;
        }

        private static Dictionary<string, object> CheckMembership(WellKnownSidType sidType)
        {
            SecurityIdentifier sid = new SecurityIdentifier(sidType, null);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            bool isMember;
            bool ok = CheckTokenMembership(IntPtr.Zero, bytes, out isMember);
            int error = ok ? 0 : Marshal.GetLastWin32Error();
            Dictionary<string, object> result = MethodResult(true, ok, ok ? null : Win32Message(error));
            result["isMember"] = isMember;
            result["lastError"] = error;
            return result;
        }

        public static Dictionary<string, object> GetAdminState()
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                result["isUserAnAdmin"] = IsUserAnAdmin();
                result["adminMembership"] = CheckMembership(WellKnownSidType.BuiltinAdministratorsSid);
                result["everyoneMembership"] = CheckMembership(WellKnownSidType.WorldSid);
                result["success"] = true;
            });
        }

        public static Dictionary<string, object> GetTokenState()
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                IntPtr token = IntPtr.Zero;
                try
                {
                    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token))
                    {
                        FailWin32(result, Marshal.GetLastWin32Error());
                        return;
                    }
                    WindowsIdentity identity = WindowsIdentity.GetCurrent();
                    result["identity"] = identity.Name;
                    result["sid"] = identity.User == null ? null : identity.User.Value;
                    result["privileges"] = ReadTokenPrivileges(token);
                    result["success"] = true;
                }
                finally { if (token != IntPtr.Zero) CloseHandle(token); }
            });
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
                for (uint i = 0; i < count; i++)
                {
                    int offset = 4 + (int)(i * 12);
                    LUID luid = new LUID
                    {
                        LowPart = unchecked((uint)Marshal.ReadInt32(buffer, offset)),
                        HighPart = Marshal.ReadInt32(buffer, offset + 4)
                    };
                    uint attributes = unchecked((uint)Marshal.ReadInt32(buffer, offset + 8));
                    int length = 0;
                    LookupPrivilegeNameW(null, ref luid, null, ref length);
                    StringBuilder name = new StringBuilder(Math.Max(length + 1, 64));
                    int capacity = name.Capacity;
                    bool ok = LookupPrivilegeNameW(null, ref luid, name, ref capacity);
                    Dictionary<string, object> item = new Dictionary<string, object>();
                    item["name"] = ok ? name.ToString() : null;
                    item["luid"] = luid.HighPart.ToString(CultureInfo.InvariantCulture) + ":" +
                        luid.LowPart.ToString(CultureInfo.InvariantCulture);
                    item["attributes"] = attributes;
                    item["enabled"] = (attributes & SE_PRIVILEGE_ENABLED) != 0;
                    item["enabledByDefault"] = (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
                    item["removed"] = (attributes & SE_PRIVILEGE_REMOVED) != 0;
                    values.Add(item);
                }
                return values;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static Dictionary<string, object> VersionInfo(uint major, uint minor, uint build,
            uint platform, string servicePack, ushort suiteMask, byte productType, bool success, int error)
        {
            Dictionary<string, object> result = MethodResult(true, success, success ? null : Win32Message(error));
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

        private static Dictionary<string, object> VerifyVersion(byte requested, uint? major, ulong mask)
        {
            OSVERSIONINFOEXW info = new OSVERSIONINFOEXW();
            info.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOEXW));
            info.wProductType = requested;
            uint typeMask = VER_PRODUCT_TYPE;
            if (major.HasValue) { info.dwMajorVersion = major.Value; typeMask |= VER_MAJORVERSION; }
            bool verified = VerifyVersionInfoW(ref info, typeMask, mask);
            Dictionary<string, object> result = MethodResult(true, true, null);
            result["requestedProductType"] = requested;
            result["postCallProductType"] = info.wProductType;
            if (major.HasValue)
            {
                result["requestedMajorVersion"] = major.Value;
                result["postCallMajorVersion"] = info.dwMajorVersion;
            }
            result["verified"] = verified;
            result["lastError"] = verified ? 0 : Marshal.GetLastWin32Error();
            return result;
        }

        public static Dictionary<string, object> GetVersionState()
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            OSVERSIONINFOEXW wide = new OSVERSIONINFOEXW { dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOEXW)) };
            bool wideOk = GetVersionExW(ref wide);
            result["getVersionExW"] = VersionInfo(wide.dwMajorVersion, wide.dwMinorVersion, wide.dwBuildNumber,
                wide.dwPlatformId, wide.szCSDVersion, wide.wSuiteMask, wide.wProductType, wideOk, wideOk ? 0 : Marshal.GetLastWin32Error());

            OSVERSIONINFOEXA ansi = new OSVERSIONINFOEXA { dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOEXA)) };
            bool ansiOk = GetVersionExA(ref ansi);
            result["getVersionExA"] = VersionInfo(ansi.dwMajorVersion, ansi.dwMinorVersion, ansi.dwBuildNumber,
                ansi.dwPlatformId, ansi.szCSDVersion, ansi.wSuiteMask, ansi.wProductType, ansiOk, ansiOk ? 0 : Marshal.GetLastWin32Error());

            ulong mask = VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL);
            result["verifyWorkstation"] = VerifyVersion(VER_NT_WORKSTATION, null, mask);
            result["verifyServer"] = VerifyVersion(VER_NT_SERVER, null, mask);
            result["verifyServerCombined"] = VerifyVersion(VER_NT_SERVER, wide.dwMajorVersion,
                VerSetConditionMask(mask, VER_MAJORVERSION, VER_EQUAL));
            result["success"] = wideOk && ansiOk;
            return result;
        }

        private static long ReadSharedClock(int offset)
        {
            IntPtr address = new IntPtr(0x7FFE0000 + offset);
            int high;
            uint low;
            do
            {
                high = Marshal.ReadInt32(address, 4);
                low = unchecked((uint)Marshal.ReadInt32(address));
            }
            while (high != Marshal.ReadInt32(address, 8));
            return ((long)high << 32) | low;
        }

        private static string FormatClock(Func<StringBuilder, int> formatter)
        {
            StringBuilder buffer = new StringBuilder(64);
            formatter(buffer);
            return buffer.ToString();
        }

        private static uint MeasurePreservedError(Action call)
        {
            SetLastError(0x1234);
            call();
            return GetLastError();
        }

        public static Dictionary<string, object> GetClockState()
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            Dictionary<string, object> clocks = new Dictionary<string, object>();
            long time;
            ClockSystemTime date;
            ClockTimeOfDay timeOfDay;
            ClockTimeB timeB;
            ClockTimeSpec timeSpec;
            int returned;
            long epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();

            result["rawBefore"] = ReadSharedClock(0x14);
            GetSystemTimeAsFileTime(out time); clocks["fileTime"] = time;
            GetSystemTimePreciseAsFileTime(out time); clocks["preciseFileTime"] = time;
            result["ntStatus"] = NtQuerySystemTime(out time); clocks["ntTime"] = time;
            clocks["rtlPrecise"] = RtlGetSystemTimePrecise();
            GetSystemTime(out date); clocks["systemTime"] = DateTime.SpecifyKind(date.ToDateTime(), DateTimeKind.Utc).ToFileTimeUtc();
            GetBaseSystemTimeAsFileTime(out time); clocks["baseFileTime"] = time;
            GetBaseSystemTime(out date); clocks["baseSystemTime"] = DateTime.SpecifyKind(date.ToDateTime(), DateTimeKind.Utc).ToFileTimeUtc();
            GetBaseLocalTime(out date); clocks["baseLocalTime"] = DateTime.SpecifyKind(date.ToDateTime(), DateTimeKind.Local).ToFileTimeUtc();
            GetLocalTime(out date);
            clocks["localTime"] = DateTime.SpecifyKind(date.ToDateTime(), DateTimeKind.Local).ToFileTimeUtc();
            result["localDate"] = date.ToDateTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            result["localTime"] = date.ToDateTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);
            clocks["managedUtc"] = DateTime.UtcNow.ToFileTimeUtc();
            clocks["managedLocal"] = DateTime.Now.ToFileTimeUtc();
            result["timeOfDayStatus"] = NtQuerySystemInformation(3, out timeOfDay, Marshal.SizeOf(typeof(ClockTimeOfDay)), out returned);
            clocks["timeOfDay"] = timeOfDay.CurrentTime;
            result["bootTime"] = timeOfDay.BootTime;
            result["invalidNtStatus"] = NtQuerySystemTime(IntPtr.Zero);
            clocks["ucrtTime"] = epoch + UcrtTime64(IntPtr.Zero) * 10000000;
            clocks["msvcrtTime"] = epoch + MsvcrtTime64(IntPtr.Zero) * 10000000;
            result["timeBStatus"] = UcrtTimeB(out timeB);
            clocks["ucrtTimeB"] = epoch + timeB.Seconds * 10000000 + timeB.Milliseconds * 10000;
            result["timeSpecStatus"] = UcrtTimeSpec(out timeSpec, 1);
            clocks["ucrtTimeSpec"] = epoch + timeSpec.Seconds * 10000000 + timeSpec.Nanoseconds / 100;

            StringBuilder formatted = new StringBuilder(64);
            result["dateFormatStatus"] = GetDateFormatEx("", 0, IntPtr.Zero, "yyyy-MM-dd", formatted, 64, null);
            result["formattedDate"] = formatted.ToString();
            formatted.Length = 0;
            result["timeFormatStatus"] = GetTimeFormatEx("", 0, IntPtr.Zero, "HH:mm:ss", formatted, 64);
            result["formattedTime"] = formatted.ToString();
            result["formattedDateA"] = FormatClock(b => GetDateFormatA(0x7F, 0, IntPtr.Zero, "yyyy-MM-dd", b, b.Capacity));
            result["formattedDateW"] = FormatClock(b => GetDateFormatW(0x7F, 0, IntPtr.Zero, "yyyy-MM-dd", b, b.Capacity));
            result["formattedTimeA"] = FormatClock(b => GetTimeFormatA(0x7F, 0, IntPtr.Zero, "HH:mm:ss", b, b.Capacity));
            result["formattedTimeW"] = FormatClock(b => GetTimeFormatW(0x7F, 0, IntPtr.Zero, "HH:mm:ss", b, b.Capacity));
            result["formattedDateBase"] = FormatClock(b => GetBaseDateFormatEx("", 0, IntPtr.Zero, "yyyy-MM-dd", b, b.Capacity, null));
            result["formattedTimeBase"] = FormatClock(b => GetBaseTimeFormatEx("", 0, IntPtr.Zero, "HH:mm:ss", b, b.Capacity));

            GetLocalTime(out date);
            result["localDateAfter"] = date.ToDateTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            result["localTimeAfter"] = date.ToDateTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);
            result["rawAfter"] = ReadSharedClock(0x14);
            result["clocks"] = clocks;
            result["offset"] = Environment.GetEnvironmentVariable("_WINPRIV_EV_MOCK_TIME_");

            // Formatting an explicit date/time must not add another offset.
            date = new ClockSystemTime { Year = 1975, Month = 6, Day = 15, Hour = 12, Minute = 34, Second = 56 };
            result["explicitDate"] = FormatClock(b => GetDateFormatEx("", 0, ref date, "yyyy-MM-dd", b, b.Capacity, null));
            result["explicitTime"] = FormatClock(b => GetTimeFormatEx("", 0, ref date, "HH:mm:ss", b, b.Capacity));

            // Wall clock mocking must preserve elapsed clocks and relative sleeps.
            ulong interrupt;
            QueryInterruptTime(out interrupt);
            result["interruptTime"] = interrupt;
            result["rawInterrupt"] = ReadSharedClock(0x8);
            result["uptimeMilliseconds"] = GetTickCount64();
            long performance, frequency;
            NtQueryPerformanceCounter(out performance, out frequency);
            result["nativePerformance"] = performance;
            result["performance"] = Stopwatch.GetTimestamp();
            result["performanceFrequency"] = frequency;
            Stopwatch elapsed = Stopwatch.StartNew();
            ulong tickStart = GetTickCount64();
            Thread.Sleep(120);
            result["elapsedMilliseconds"] = elapsed.Elapsed.TotalMilliseconds;
            result["tickElapsedMilliseconds"] = GetTickCount64() - tickStart;

            // Void clock getters must preserve the caller's last-error value.
            GetLastError();
            result["fileTimeLastError"] = MeasurePreservedError(() => { long t; GetSystemTimeAsFileTime(out t); });
            result["preciseLastError"] = MeasurePreservedError(() => { long t; GetSystemTimePreciseAsFileTime(out t); });
            result["systemLastError"] = MeasurePreservedError(() => { ClockSystemTime d; GetSystemTime(out d); });
            result["localLastError"] = MeasurePreservedError(() => { ClockSystemTime d; GetLocalTime(out d); });
            return result;
        }

        public static Dictionary<string, object> RunCreateProcess(string api, string applicationName,
            string commandLine, string currentDirectory, string[] environmentEntries, int timeoutMilliseconds)
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                bool unicode = !String.Equals(api, "A", StringComparison.OrdinalIgnoreCase);
                IntPtr environment = IntPtr.Zero;
                PROCESS_INFORMATION process = new PROCESS_INFORMATION();
                try
                {
                    uint flags = unicode ? CREATE_UNICODE_ENVIRONMENT : 0;
                    uint codePage = unicode ? 1200u : GetACP();
                    if (environmentEntries != null)
                    {
                        string[] copy = (string[])environmentEntries.Clone();
                        Array.Sort(copy, StringComparer.OrdinalIgnoreCase);
                        byte[] bytes = (unicode ? Encoding.Unicode : Encoding.GetEncoding((int)codePage))
                            .GetBytes(String.Join("\0", copy) + "\0\0");
                        environment = Marshal.AllocHGlobal(bytes.Length);
                        Marshal.Copy(bytes, 0, environment, bytes.Length);
                    }
                    STARTUPINFO startup = new STARTUPINFO { cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO)) };
                    StringBuilder mutableCommandLine = new StringBuilder(commandLine);
                    bool created = unicode
                        ? CreateProcessW(applicationName, mutableCommandLine, IntPtr.Zero, IntPtr.Zero, false,
                            flags, environment, currentDirectory, ref startup, out process)
                        : CreateProcessA(applicationName, mutableCommandLine, IntPtr.Zero, IntPtr.Zero, false,
                            flags, environment, currentDirectory, ref startup, out process);
                    result["api"] = unicode ? "CreateProcessW" : "CreateProcessA";
                    result["applicationName"] = applicationName;
                    result["commandLine"] = commandLine;
                    result["customEnvironment"] = environmentEntries != null;
                    result["environmentCodePage"] = codePage;
                    result["created"] = created;
                    if (!created) { FailWin32(result, Marshal.GetLastWin32Error()); return; }

                    result["processId"] = process.dwProcessId;
                    uint wait = WaitForSingleObject(process.hProcess, unchecked((uint)Math.Max(timeoutMilliseconds, 1)));
                    result["waitResult"] = wait;
                    if (wait == WAIT_TIMEOUT)
                    {
                        result["timedOut"] = true;
                        result["terminated"] = TerminateProcess(process.hProcess, 0xDEAD);
                        WaitForSingleObject(process.hProcess, 5000);
                        result["reason"] = "Child process exceeded the probe timeout.";
                        return;
                    }
                    if (wait != WAIT_OBJECT_0) { FailWin32(result, Marshal.GetLastWin32Error()); return; }
                    uint exitCode;
                    if (!GetExitCodeProcess(process.hProcess, out exitCode)) { FailWin32(result, Marshal.GetLastWin32Error()); return; }
                    result["timedOut"] = false;
                    result["exitCode"] = exitCode;
                    result["success"] = true;
                }
                finally
                {
                    if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                    if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
                    if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
                }
            });
        }

        public static Dictionary<string, object> GetSoftwareSigning()
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            byte[] hash = new byte[32];
            int size;
            result["invalidHandleStatus"] = unchecked((uint)NCryptSignHash(IntPtr.Zero, IntPtr.Zero, hash, hash.Length, null, 0, out size, 0));
            result["invalidFinalizeStatus"] = unchecked((uint)NCryptFinalizeKey(IntPtr.Zero, 0));
            result["invalidCertificateStatus"] = unchecked((uint)NCryptSetProperty(IntPtr.Zero, "SmartCardKeyCertificate", new byte[] { 0x30, 0 }, 2, 0));

            // Exercise silent and interactive signing without persisting a key.
            List<Dictionary<string, object>> signatures = new List<Dictionary<string, object>>();
            using (ECDsaCng key = new ECDsaCng(256))
            using (var handle = key.Key.Handle)
            {
                foreach (uint flags in new uint[] { 0, 0x40 })
                {
                    Dictionary<string, object> signing = new Dictionary<string, object>();
                    signing["flags"] = flags;
                    int status = NCryptSignHash(handle.DangerousGetHandle(), IntPtr.Zero, hash, hash.Length, null, 0, out size, flags);
                    signing["sizeStatus"] = unchecked((uint)status);
                    if (status == 0)
                    {
                        byte[] signature = new byte[size];
                        status = NCryptSignHash(handle.DangerousGetHandle(), IntPtr.Zero, hash, hash.Length, signature, signature.Length, out size, flags);
                        signing["signStatus"] = unchecked((uint)status);
                        signing["verified"] = status == 0 && key.VerifyHash(hash, signature);
                    }
                    signatures.Add(signing);
                }
            }
            result["signatures"] = signatures;
            return result;
        }

        public static Dictionary<string, object> GetSmartCardReaders()
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            uint capabilities;
            result["capabilitySuccess"] = WinStationGetCurrentSessionCapabilities(1, out capabilities) != 0;
            result["capabilities"] = capabilities;
            result["sessionId"] = Process.GetCurrentProcess().SessionId;
            UIntPtr context;
            result["invalidReservedStatus"] = unchecked((uint)SCardEstablishContext(2, new IntPtr(1), IntPtr.Zero, out context));

            List<Dictionary<string, object>> contexts = new List<Dictionary<string, object>>();
            foreach (uint scope in new uint[] { 0, 2 })
            {
                Dictionary<string, object> reading = new Dictionary<string, object>();
                reading["scope"] = scope;
                int status = SCardEstablishContext(scope, IntPtr.Zero, IntPtr.Zero, out context);
                reading["contextStatus"] = unchecked((uint)status);
                if (status == 0)
                {
                    try
                    {
                        reading["validContextStatus"] = unchecked((uint)SCardIsValidContext(context));
                        IntPtr readers = IntPtr.Zero;
                        try
                        {
                            uint characters = uint.MaxValue;
                            status = SCardListReadersW(context, null, out readers, ref characters);
                            reading["listStatus"] = unchecked((uint)status);
                            reading["readers"] = status == 0 && characters > 1
                                ? Marshal.PtrToStringUni(readers, checked((int)characters)).TrimEnd('\0').Split('\0')
                                : new string[0];
                        }
                        finally { if (readers != IntPtr.Zero) SCardFreeMemory(context, readers); }
                    }
                    finally { reading["releaseStatus"] = unchecked((uint)SCardReleaseContext(context)); }
                }
                contexts.Add(reading);
            }
            result["contexts"] = contexts;
            return result;
        }
    }
}
