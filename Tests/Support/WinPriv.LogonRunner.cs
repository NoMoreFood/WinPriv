using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace WinPrivTests
{
    public sealed class LogonRunResult
    {
        public bool Started { get; set; }
        public bool TimedOut { get; set; }
        public int ExitCode { get; set; }
        public int ProcessId { get; set; }
        public int Win32Error { get; set; }
        public string Error { get; set; }
        public string CommandLine { get; set; }
        public bool JobAssigned { get; set; }
        public int[] ProcessIds { get; set; }
    }

    public static class LogonRunner
    {
        private const int LOGON_WITHOUT_PROFILE = 0x00000000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint CREATE_NEW_CONSOLE = 0x00000010;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint STARTF_USESHOWWINDOW = 0x00000001;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectExtendedLimitInformation = 9;
        private const int JobObjectBasicProcessIdList = 3;
        private const short SW_HIDE = 0;
        private const uint WAIT_OBJECT_0 = 0;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint DACL_SECURITY_INFORMATION = 4;
        private const int WINSTA_ALL_ACCESS = 0x000F037F;
        private const int DESKTOP_ALL_ACCESS = 0x000F01FF;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
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
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessWithLogonW(string userName, string domain,
            string password, int logonFlags, string applicationName, StringBuilder commandLine,
            uint creationFlags, IntPtr environment, string currentDirectory,
            ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int informationClass,
            ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information, uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int informationClass,
            IntPtr information, uint informationLength, out uint returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("user32.dll")]
        private static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll")]
        private static extern IntPtr GetThreadDesktop(uint threadId);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetUserObjectSecurity(IntPtr handle, ref uint information,
            byte[] descriptor, uint length, out uint needed);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetUserObjectSecurity(IntPtr handle, ref uint information, byte[] descriptor);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        public static LogonRunResult Run(string domain, string userName, string password,
            string executable, string[] arguments, string currentDirectory, string[] environment,
            int timeoutMilliseconds)
        {
            LogonRunResult result = new LogonRunResult();
            string commandLine = Quote(executable);
            if (arguments != null)
            {
                for (int i = 0; i < arguments.Length; i++) commandLine += " " + Quote(arguments[i]);
            }
            result.CommandLine = commandLine;
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = STARTF_USESHOWWINDOW;
            startup.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            IntPtr job = IntPtr.Zero;
            IntPtr environmentBlock = IntPtr.Zero;
            UserObjectAccess stationAccess = null;
            UserObjectAccess desktopAccess = null;
            try
            {
                string account = String.IsNullOrEmpty(domain) ? userName : domain + "\\" + userName;
                SecurityIdentifier sid = (SecurityIdentifier)new NTAccount(account)
                    .Translate(typeof(SecurityIdentifier));
                stationAccess = new UserObjectAccess(GetProcessWindowStation(), sid, WINSTA_ALL_ACCESS);
                desktopAccess = new UserObjectAccess(GetThreadDesktop(GetCurrentThreadId()), sid, DESKTOP_ALL_ACCESS);

                // These probes inspect token state only. Loading HKCU would
                // create a persistent profile for the temporary local user and
                // provides no test coverage benefit.
                environmentBlock = BuildEnvironmentBlock(environment);
                bool created = CreateProcessWithLogonW(userName, domain, password,
                    LOGON_WITHOUT_PROFILE, null, new StringBuilder(commandLine),
                    CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE | CREATE_SUSPENDED, environmentBlock,
                    currentDirectory, ref startup, out process);
                result.Started = created;
                if (!created)
                {
                    result.Win32Error = Marshal.GetLastWin32Error();
                    result.Error = new Win32Exception(result.Win32Error).Message;
                    return result;
                }
                result.ProcessId = unchecked((int)process.dwProcessId);
                job = CreateJobObjectW(IntPtr.Zero, null);
                if (job == IntPtr.Zero)
                {
                    SetError(result);
                    TerminateProcess(process.hProcess, 0xDEAD);
                    return result;
                }
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits =
                    new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits,
                    (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))) ||
                    !AssignProcessToJobObject(job, process.hProcess))
                {
                    SetError(result);
                    TerminateProcess(process.hProcess, 0xDEAD);
                    return result;
                }
                result.JobAssigned = true;
                if (ResumeThread(process.hThread) == UInt32.MaxValue)
                {
                    SetError(result);
                    TerminateProcess(process.hProcess, 0xDEAD);
                    return result;
                }
                HashSet<int> observedProcessIds = new HashSet<int>();
                observedProcessIds.Add(result.ProcessId);
                Stopwatch execution = Stopwatch.StartNew();
                int boundedTimeout = Math.Max(timeoutMilliseconds, 1);
                while (true)
                {
                    int[] activeProcessIds = GetJobProcessIds(job);
                    for (int index = 0; index < activeProcessIds.Length; index++)
                        observedProcessIds.Add(activeProcessIds[index]);
                    if (activeProcessIds.Length == 0) break;
                    long remaining = (long)boundedTimeout - execution.ElapsedMilliseconds;
                    if (remaining <= 0)
                    {
                        result.TimedOut = true;
                        if (!TerminateJobObject(job, 0xDEAD)) SetError(result);
                        Stopwatch cleanup = Stopwatch.StartNew();
                        while (GetJobProcessIds(job).Length != 0 && cleanup.ElapsedMilliseconds < 5000)
                            Thread.Sleep(10);
                        break;
                    }
                    Thread.Sleep((int)Math.Min(25L, remaining));
                }
                result.ProcessIds = new int[observedProcessIds.Count];
                observedProcessIds.CopyTo(result.ProcessIds);
                Array.Sort(result.ProcessIds);
                if (result.TimedOut) WaitForSingleObject(process.hProcess, 5000);
                uint exitCode;
                if (!GetExitCodeProcess(process.hProcess, out exitCode))
                {
                    result.Win32Error = Marshal.GetLastWin32Error();
                    result.Error = new Win32Exception(result.Win32Error).Message;
                    return result;
                }
                result.ExitCode = unchecked((int)exitCode);
                return result;
            }
            finally
            {
                if (environmentBlock != IntPtr.Zero) Marshal.FreeHGlobal(environmentBlock);
                if (job != IntPtr.Zero) CloseHandle(job);
                if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
                try
                {
                    if (desktopAccess != null) desktopAccess.Dispose();
                }
                finally
                {
                    if (stationAccess != null) stationAccess.Dispose();
                }
            }
        }

        private sealed class UserObjectAccess : IDisposable
        {
            private readonly IntPtr handle;
            private readonly byte[] original;
            private bool changed;

            public UserObjectAccess(IntPtr handle, SecurityIdentifier sid, int accessMask)
            {
                this.handle = handle;
                original = ReadSecurity(handle);
                RawSecurityDescriptor security = new RawSecurityDescriptor(original, 0);
                if (security.DiscretionaryAcl == null) return;
                int index = 0;
                while (index < security.DiscretionaryAcl.Count &&
                    (security.DiscretionaryAcl[index].AceFlags & AceFlags.Inherited) == 0) index++;
                security.DiscretionaryAcl.InsertAce(index,
                    new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, accessMask, sid, false, null));
                byte[] descriptor = new byte[security.BinaryLength];
                security.GetBinaryForm(descriptor, 0);
                uint information = DACL_SECURITY_INFORMATION;
                if (!SetUserObjectSecurity(handle, ref information, descriptor))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not grant fixture desktop access.");
                changed = true;
            }

            public void Dispose()
            {
                if (!changed) return;
                uint information = DACL_SECURITY_INFORMATION;
                if (!SetUserObjectSecurity(handle, ref information, original))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not restore fixture desktop access.");
                changed = false;
                string expected = new RawSecurityDescriptor(original, 0).GetSddlForm(AccessControlSections.Access);
                string actual = new RawSecurityDescriptor(ReadSecurity(handle), 0)
                    .GetSddlForm(AccessControlSections.Access);
                if (!String.Equals(expected, actual, StringComparison.Ordinal))
                    throw new InvalidOperationException("Fixture desktop ACL did not match its original descriptor.");
            }

            private static byte[] ReadSecurity(IntPtr handle)
            {
                uint information = DACL_SECURITY_INFORMATION;
                uint needed;
                GetUserObjectSecurity(handle, ref information, null, 0, out needed);
                byte[] descriptor = new byte[needed];
                if (needed == 0 || !GetUserObjectSecurity(handle, ref information, descriptor, needed, out needed))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not read fixture desktop access.");
                return descriptor;
            }
        }

        private static IntPtr BuildEnvironmentBlock(string[] environment)
        {
            if (environment == null) return IntPtr.Zero;
            SortedDictionary<string, string> values =
                new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int index = 0; index < environment.Length; index++)
            {
                string item = environment[index];
                if (String.IsNullOrEmpty(item)) continue;
                int separator = item.IndexOf('=');
                if (separator <= 0) continue;
                values[item.Substring(0, separator)] = item.Substring(separator + 1);
            }
            StringBuilder block = new StringBuilder();
            foreach (KeyValuePair<string, string> pair in values)
            {
                block.Append(pair.Key);
                block.Append('=');
                block.Append(pair.Value ?? String.Empty);
                block.Append('\0');
            }
            block.Append('\0');
            return Marshal.StringToHGlobalUni(block.ToString());
        }

        private static int[] GetJobProcessIds(IntPtr job)
        {
            const int maximumProcessCount = 4096;
            int size = 8 + (IntPtr.Size * maximumProcessCount);
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint returned;
                if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer,
                    (uint)size, out returned))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "QueryInformationJobObject failed");
                int count = Marshal.ReadInt32(buffer, 4);
                if (count < 0 || count > maximumProcessCount)
                    throw new InvalidOperationException("Job Object returned an invalid process count.");
                int[] processIds = new int[count];
                for (int index = 0; index < count; index++)
                {
                    long value = IntPtr.Size == 8
                        ? Marshal.ReadInt64(buffer, 8 + (index * IntPtr.Size))
                        : Marshal.ReadInt32(buffer, 8 + (index * IntPtr.Size));
                    if (value <= 0 || value > Int32.MaxValue)
                        throw new InvalidOperationException("Job Object returned an invalid process identifier.");
                    processIds[index] = (int)value;
                }
                return processIds;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static void SetError(LogonRunResult result)
        {
            result.Win32Error = Marshal.GetLastWin32Error();
            result.Error = new Win32Exception(result.Win32Error).Message;
        }

        private static string Quote(string value)
        {
            if (value == null) return "\"\"";
            if (value.Length != 0 && value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '\"' }) < 0)
                return value;
            StringBuilder output = new StringBuilder();
            output.Append('\"');
            int slashes = 0;
            for (int i = 0; i < value.Length; i++)
            {
                char ch = value[i];
                if (ch == '\\') { slashes++; continue; }
                if (ch == '\"')
                {
                    output.Append('\\', slashes * 2 + 1);
                    output.Append('\"');
                    slashes = 0;
                    continue;
                }
                output.Append('\\', slashes);
                slashes = 0;
                output.Append(ch);
            }
            output.Append('\\', slashes * 2);
            output.Append('\"');
            return output.ToString();
        }
    }
}
