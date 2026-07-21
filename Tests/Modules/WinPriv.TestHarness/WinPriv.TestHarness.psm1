Set-StrictMode -Version 2.0

$script:ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:NativeMethodsLoaded = $false
$script:CapabilityResults = New-Object 'System.Collections.Generic.List[object]'
$script:TestHostProbeCache = @{}

function Test-WinPrivWindows {
    return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

function Initialize-WinPrivNativeMethods {
    if ($script:NativeMethodsLoaded) {
        return
    }

    if (-not (Test-WinPrivWindows)) {
        throw 'The WinPriv test harness process helpers require Windows.'
    }

    if (-not ('WinPriv.TestHarness.NativeMethods' -as [type])) {
        $source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace WinPriv.TestHarness
{
    public sealed class ContainedProcessResult
    {
        public Int32 ProcessId { get; set; }
        public Int32 ExitCode { get; set; }
        public bool TimedOut { get; set; }
        public Int32[] ProcessIds { get; set; }
        public bool JobAssigned { get; set; }
    }

    public static class NativeMethods
    {
        private const UInt32 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const Int32 JobObjectBasicProcessIdList = 3;
        private const Int32 JobObjectExtendedLimitInformation = 9;
        private const UInt32 TOKEN_QUERY = 0x0008;
        private const Int32 TokenElevation = 20;
        private const UInt32 CREATE_SUSPENDED = 0x00000004;
        private const UInt32 CREATE_NEW_CONSOLE = 0x00000010;
        private const UInt32 CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const UInt32 CREATE_NO_WINDOW = 0x08000000;
        private const UInt32 STARTF_USESHOWWINDOW = 0x00000001;
        private const UInt32 STARTF_USESTDHANDLES = 0x00000100;
        private const Int16 SW_HIDE = 0;
        private const UInt32 GENERIC_READ = 0x80000000;
        private const UInt32 GENERIC_WRITE = 0x40000000;
        private const UInt32 FILE_SHARE_READ = 0x00000001;
        private const UInt32 FILE_SHARE_WRITE = 0x00000002;
        private const UInt32 CREATE_ALWAYS = 2;
        private const UInt32 OPEN_EXISTING = 3;
        private const UInt32 FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const UInt32 WAIT_OBJECT_0 = 0x00000000;
        private const UInt32 WAIT_TIMEOUT = 0x00000102;
        private const UInt32 WAIT_FAILED = 0xFFFFFFFF;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public Int64 PerProcessUserTimeLimit;
            public Int64 PerJobUserTimeLimit;
            public UInt32 LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public UInt32 ActiveProcessLimit;
            public UIntPtr Affinity;
            public UInt32 PriorityClass;
            public UInt32 SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public UInt64 ReadOperationCount;
            public UInt64 WriteOperationCount;
            public UInt64 OtherOperationCount;
            public UInt64 ReadTransferCount;
            public UInt64 WriteTransferCount;
            public UInt64 OtherTransferCount;
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

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_ELEVATION
        {
            public UInt32 TokenIsElevated;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public Int32 nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public UInt32 dwX;
            public UInt32 dwY;
            public UInt32 dwXSize;
            public UInt32 dwYSize;
            public UInt32 dwXCountChars;
            public UInt32 dwYCountChars;
            public UInt32 dwFillAttribute;
            public UInt32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
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
            public UInt32 dwProcessId;
            public UInt32 dwThreadId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr job,
            Int32 informationClass,
            IntPtr information,
            UInt32 informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr job, UInt32 exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(
            IntPtr job,
            Int32 informationClass,
            IntPtr information,
            UInt32 informationLength,
            out UInt32 returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AllocConsole();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ShowWindow(IntPtr window, Int32 command);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr process, UInt32 desiredAccess, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr token,
            Int32 informationClass,
            IntPtr information,
            UInt32 informationLength,
            out UInt32 returnLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(
            string fileName,
            UInt32 desiredAccess,
            UInt32 shareMode,
            ref SECURITY_ATTRIBUTES securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(
            string applicationName,
            System.Text.StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
            UInt32 creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UInt32 ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr process, out UInt32 exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, UInt32 exitCode);

        public static IntPtr CreateKillOnCloseJob()
        {
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
            }

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            Int32 size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(limits, buffer, false);
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (UInt32)size))
                {
                    Int32 error = Marshal.GetLastWin32Error();
                    CloseHandle(job);
                    throw new Win32Exception(error, "SetInformationJobObject failed");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
            return job;
        }

        public static bool TryAssignProcess(IntPtr job, IntPtr process, out Int32 error)
        {
            bool result = AssignProcessToJobObject(job, process);
            error = result ? 0 : Marshal.GetLastWin32Error();
            return result;
        }

        public static bool TryTerminateJob(IntPtr job, UInt32 exitCode, out Int32 error)
        {
            bool result = TerminateJobObject(job, exitCode);
            error = result ? 0 : Marshal.GetLastWin32Error();
            return result;
        }

        public static Int32[] GetJobProcessIds(IntPtr job)
        {
            const Int32 maximumProcessCount = 4096;
            Int32 size = 8 + (IntPtr.Size * maximumProcessCount);
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                UInt32 returned;
                if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, (UInt32)size, out returned))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryInformationJobObject failed");
                }
                Int32 count = Marshal.ReadInt32(buffer, 4);
                if (count < 0 || count > maximumProcessCount)
                {
                    throw new InvalidOperationException("Job Object returned an invalid process count.");
                }
                List<Int32> ids = new List<Int32>(count);
                for (Int32 index = 0; index < count; index++)
                {
                    Int64 value = IntPtr.Size == 8
                        ? Marshal.ReadInt64(buffer, 8 + (index * IntPtr.Size))
                        : Marshal.ReadInt32(buffer, 8 + (index * IntPtr.Size));
                    if (value <= 0 || value > Int32.MaxValue)
                        throw new InvalidOperationException("Job Object returned an invalid process identifier.");
                    ids.Add((Int32)value);
                }
                return ids.ToArray();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static bool EnsureHiddenConsole()
        {
            IntPtr window = GetConsoleWindow();
            if (window != IntPtr.Zero)
            {
                return true;
            }
            if (!AllocConsole())
            {
                return false;
            }
            window = GetConsoleWindow();
            if (window != IntPtr.Zero)
            {
                ShowWindow(window, 0);
            }
            return true;
        }

        public static bool IsCurrentTokenElevated()
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token))
            {
                return false;
            }
            try
            {
                Int32 size = Marshal.SizeOf(typeof(TOKEN_ELEVATION));
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    UInt32 returned;
                    if (!GetTokenInformation(token, TokenElevation, buffer, (UInt32)size, out returned))
                    {
                        return false;
                    }
                    TOKEN_ELEVATION elevation = (TOKEN_ELEVATION)Marshal.PtrToStructure(buffer, typeof(TOKEN_ELEVATION));
                    return elevation.TokenIsElevated != 0;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                CloseHandle(token);
            }
        }

        public static ContainedProcessResult RunContainedProcess(
            string applicationName,
            string commandLine,
            string currentDirectory,
            string[] environmentEntries,
            string standardOutputPath,
            string standardErrorPath,
            Int32 timeoutMilliseconds,
            bool createNewConsole,
            bool createNoWindow)
        {
            IntPtr job = IntPtr.Zero;
            IntPtr standardInput = INVALID_HANDLE_VALUE;
            IntPtr standardOutput = INVALID_HANDLE_VALUE;
            IntPtr standardError = INVALID_HANDLE_VALUE;
            IntPtr environment = IntPtr.Zero;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION();
            bool processAssigned = false;
            try
            {
                SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES();
                security.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                security.bInheritHandle = true;
                standardInput = CreateFile("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ref security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                standardOutput = CreateFile(standardOutputPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ref security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                standardError = CreateFile(standardErrorPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ref security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (standardInput == INVALID_HANDLE_VALUE || standardOutput == INVALID_HANDLE_VALUE || standardError == INVALID_HANDLE_VALUE)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create redirected standard handles");
                }

                STARTUPINFO startup = new STARTUPINFO();
                startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startup.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
                startup.wShowWindow = SW_HIDE;
                startup.hStdInput = standardInput;
                startup.hStdOutput = standardOutput;
                startup.hStdError = standardError;

                string environmentBlock = String.Join("\0", environmentEntries) + "\0\0";
                environment = Marshal.StringToHGlobalUni(environmentBlock);
                UInt32 creationFlags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
                if (createNewConsole)
                {
                    creationFlags |= CREATE_NEW_CONSOLE;
                }
                else if (createNoWindow)
                {
                    creationFlags |= CREATE_NO_WINDOW;
                }
                System.Text.StringBuilder mutableCommandLine = new System.Text.StringBuilder(commandLine);
                if (!CreateProcess(applicationName, mutableCommandLine, IntPtr.Zero, IntPtr.Zero, true,
                    creationFlags, environment, currentDirectory, ref startup, out process))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessW failed");
                }

                job = CreateKillOnCloseJob();
                Int32 assignmentError;
                if (!TryAssignProcess(job, process.hProcess, out assignmentError))
                {
                    TerminateProcess(process.hProcess, 0xDEAD);
                    WaitForSingleObject(process.hProcess, 5000);
                    throw new Win32Exception(assignmentError, "AssignProcessToJobObject failed before process resume");
                }
                processAssigned = true;
                if (ResumeThread(process.hThread) == UInt32.MaxValue)
                {
                    Int32 error = Marshal.GetLastWin32Error();
                    TerminateJobObject(job, 0xDEAD);
                    throw new Win32Exception(error, "ResumeThread failed");
                }

                // Waiting for the root handle is insufficient: a launcher can
                // exit successfully while an injected child or grandchild is
                // still running.  Poll the Job Object until its active process
                // list is empty, applying one deadline to the complete tree.
                HashSet<Int32> observedProcessIds = new HashSet<Int32>();
                observedProcessIds.Add(unchecked((Int32)process.dwProcessId));
                System.Diagnostics.Stopwatch execution = System.Diagnostics.Stopwatch.StartNew();
                bool timedOut = false;
                while (true)
                {
                    Int32[] activeProcessIds = GetJobProcessIds(job);
                    for (Int32 index = 0; index < activeProcessIds.Length; index++)
                    {
                        observedProcessIds.Add(activeProcessIds[index]);
                    }
                    if (activeProcessIds.Length == 0)
                    {
                        break;
                    }

                    Int64 remaining = (Int64)timeoutMilliseconds - execution.ElapsedMilliseconds;
                    if (remaining <= 0)
                    {
                        timedOut = true;
                        Int32 terminateError;
                        TryTerminateJob(job, 0xDEAD, out terminateError);

                        // Closing the Job Object is also kill-on-close, but wait
                        // briefly here so callers receive evidence only after the
                        // timed-out tree has actually been torn down.
                        System.Diagnostics.Stopwatch cleanup = System.Diagnostics.Stopwatch.StartNew();
                        while (GetJobProcessIds(job).Length != 0 && cleanup.ElapsedMilliseconds < 5000)
                        {
                            System.Threading.Thread.Sleep(10);
                        }
                        break;
                    }

                    Int32 delay = (Int32)Math.Min((Int64)25, remaining);
                    System.Threading.Thread.Sleep(delay);
                }

                UInt32 nativeExitCode;
                if (!GetExitCodeProcess(process.hProcess, out nativeExitCode))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "GetExitCodeProcess failed");
                }
                Int32[] processIds = new Int32[observedProcessIds.Count];
                observedProcessIds.CopyTo(processIds);
                Array.Sort(processIds);
                return new ContainedProcessResult
                {
                    ProcessId = unchecked((Int32)process.dwProcessId),
                    ExitCode = unchecked((Int32)nativeExitCode),
                    TimedOut = timedOut,
                    ProcessIds = processIds,
                    JobAssigned = true
                };
            }
            finally
            {
                if (process.hProcess != IntPtr.Zero && !processAssigned)
                {
                    TerminateProcess(process.hProcess, 0xDEAD);
                    WaitForSingleObject(process.hProcess, 5000);
                }
                if (job != IntPtr.Zero) CloseHandle(job);
                if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
                if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
                if (standardInput != INVALID_HANDLE_VALUE) CloseHandle(standardInput);
                if (standardOutput != INVALID_HANDLE_VALUE) CloseHandle(standardOutput);
                if (standardError != INVALID_HANDLE_VALUE) CloseHandle(standardError);
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
            }
        }
    }
}
'@
        Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
    }

    $script:NativeMethodsLoaded = $true
}

function Test-WinPrivPathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $childPath = [IO.Path]::GetFullPath($Child)
    $parentPath = [IO.Path]::GetFullPath($Parent).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $prefix = $parentPath + [IO.Path]::DirectorySeparatorChar
    return $childPath.Equals($parentPath, [StringComparison]::OrdinalIgnoreCase) -or
        $childPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-WinPrivCommandLineArgument {
    param([AllowEmptyString()][string]$Value)

    if ($null -eq $Value -or $Value.Length -eq 0) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }

    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Join-WinPrivCommandLine {
    param([string[]]$ArgumentList)
    return (($ArgumentList | ForEach-Object { ConvertTo-WinPrivCommandLineArgument -Value ([string]$_) }) -join ' ')
}

function Get-WinPrivPeArchitecture {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }
    $stream = $null
    $reader = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { return $null }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or $peOffset -gt ($stream.Length - 6)) { return $null }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { return $null }
        switch ($reader.ReadUInt16()) {
            0x014C { return 'x86' }
            0x8664 { return 'x64' }
            0xAA64 { return 'ARM64' }
            default { return 'Unknown' }
        }
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-WinPrivOsArchitecture {
    $architecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')
    }
    switch -Regex ($architecture) {
        'ARM64' { return 'ARM64' }
        'AMD64|x64' { return 'x64' }
        default { return 'x86' }
    }
}

function Get-WinPrivArchitectureDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryRoot,
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture
    )

    $root = [IO.Path]::GetFullPath($BinaryRoot)
    $child = Join-Path $root $Architecture
    if (Test-Path -LiteralPath $child -PathType Container) {
        return $child
    }
    if ((Split-Path -Leaf $root) -ieq $Architecture -and (Test-Path -LiteralPath $root -PathType Container)) {
        return $root
    }
    return $null
}

function Test-WinPrivPowerShellHost {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture
    )

    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    $resolvedPath = $file.FullName
    $cacheKey = '{0}|{1}|{2}|{3}' -f $Architecture, $resolvedPath.ToUpperInvariant(), $file.Length, $file.LastWriteTimeUtc.Ticks
    if ($script:TestHostProbeCache.ContainsKey($cacheKey)) {
        return $script:TestHostProbeCache[$cacheKey]
    }

    $marker = 'WINPRIV_HOST_' + [Guid]::NewGuid().ToString('N')
    $probeScript = @'
$ErrorActionPreference = 'Stop'
try {
    $processArchitecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
}
catch {
    if ([IntPtr]::Size -eq 4) {
        $processArchitecture = 'X86'
    }
    else {
        $processArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')
    }
}
[pscustomobject]@{
    Marker = '__WINPRIV_HOST_MARKER__'
    PSEdition = [string]$PSVersionTable.PSEdition
    PSVersion = $PSVersionTable.PSVersion.ToString()
    ProcessArchitecture = $processArchitecture
    ExecutablePath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    ProcessId = $PID
} | ConvertTo-Json -Compress
'@.Replace('__WINPRIV_HOST_MARKER__', $marker)

    $invocation = $null
    $state = $null
    $reason = $null
    try {
        $invocation = Invoke-WinPrivContainedProcess -FilePath $resolvedPath -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', $probeScript
        ) -WorkingDirectory ([IO.Path]::GetTempPath()) -TimeoutSeconds 5
        if ($invocation.TimedOut) {
            $reason = "Host '$resolvedPath' did not complete the PowerShell identity probe within 5 seconds."
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$invocation.StartError)) {
            $reason = "Host '$resolvedPath' could not execute the PowerShell identity probe: $($invocation.StartError)"
        }
        elseif ($invocation.ExitCode -ne 0) {
            $reason = "Host '$resolvedPath' returned exit code $($invocation.ExitCode) from the PowerShell identity probe."
        }
        else {
            $lines = @([string]$invocation.StdOut -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            for ($index = $lines.Count - 1; $index -ge 0; $index--) {
                try {
                    $candidateState = $lines[$index] | ConvertFrom-Json -ErrorAction Stop
                    if ([string]$candidateState.Marker -ceq $marker) {
                        $state = $candidateState
                        break
                    }
                }
                catch { }
            }
            if ($null -eq $state) {
                $reason = "Host '$resolvedPath' did not emit a valid PowerShell identity record."
            }
        }
    }
    catch {
        $reason = "Host '$resolvedPath' could not execute the PowerShell identity probe: $($_.Exception.Message)"
    }

    $version = $null
    $edition = $null
    $processArchitecture = $null
    $reportedExecutable = $null
    if ($null -ne $state) {
        $edition = [string]$state.PSEdition
        try { $version = [version]([string]$state.PSVersion) } catch { }
        switch (([string]$state.ProcessArchitecture).ToUpperInvariant()) {
            'X86'   { $processArchitecture = 'x86' }
            'X64'   { $processArchitecture = 'x64' }
            'ARM64' { $processArchitecture = 'ARM64' }
        }
        try { $reportedExecutable = [IO.Path]::GetFullPath([string]$state.ExecutablePath) } catch { }

        if ($processArchitecture -ne $Architecture) {
            $reason = "Host '$resolvedPath' reported process architecture '$processArchitecture', not '$Architecture'."
        }
        elseif ([string]::IsNullOrWhiteSpace($reportedExecutable) -or
            -not $reportedExecutable.Equals($resolvedPath, [StringComparison]::OrdinalIgnoreCase)) {
            $reason = "Host '$resolvedPath' executed PowerShell from '$reportedExecutable' instead of the candidate executable."
        }
        elseif ($Architecture -eq 'x86' -and
            ($edition -ne 'Desktop' -or $null -eq $version -or $version.Major -ne 5 -or $version.Minor -ne 1)) {
            $reason = "Host '$resolvedPath' reported PowerShell edition '$edition' version '$version'; x86 probes require Windows PowerShell exactly 5.1."
        }
        elseif ($Architecture -ne 'x86' -and
            ($edition -ne 'Core' -or $null -eq $version -or $version -lt [version]'7.6')) {
            $reason = "Host '$resolvedPath' reported PowerShell edition '$edition' version '$version'; $Architecture probes require PowerShell Core 7.6 or later."
        }
    }

    $result = [pscustomobject]@{
        Valid               = $null -ne $state -and [string]::IsNullOrWhiteSpace($reason)
        Reason              = $reason
        Version             = $version
        PSEdition           = $edition
        ProcessArchitecture = $processArchitecture
        ExecutablePath      = $reportedExecutable
        ProbeProcessId      = if ($null -ne $state) { $state.ProcessId } else { $null }
        Invocation          = $invocation
    }
    $script:TestHostProbeCache[$cacheKey] = $result
    return $result
}

function Get-WinPrivTestHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture,
        [switch]$Detailed
    )

    $path = $null
    $reason = $null
    $engine = if ($Architecture -eq 'x86') { 'WindowsPowerShell' } else { 'PowerShell' }
    $overrideName = 'WINPRIV_TEST_POWERSHELL_' + $Architecture.ToUpperInvariant()
    $internalAliasName = 'WINPRIV_TEST_HOST_' + $Architecture.ToUpperInvariant()
    $override = [Environment]::GetEnvironmentVariable($overrideName)
    if ([string]::IsNullOrWhiteSpace($override)) {
        $override = [Environment]::GetEnvironmentVariable($internalAliasName)
    }

    if (-not [string]::IsNullOrWhiteSpace($override)) {
        $path = $override
    }
    elseif ($Architecture -eq 'x86') {
        $windows = [Environment]::GetEnvironmentVariable('WINDIR')
        $osArchitecture = Get-WinPrivOsArchitecture
        $systemDirectory = if ($osArchitecture -eq 'x86') { 'System32' } else { 'SysWOW64' }
        $path = Join-Path $windows "$systemDirectory\WindowsPowerShell\v1.0\powershell.exe"
    }
    else {
        $currentPath = $null
        try { $currentPath = (Get-Process -Id $PID -ErrorAction Stop).Path } catch { }
        if ($currentPath -and (Get-WinPrivPeArchitecture -Path $currentPath) -eq $Architecture) {
            $path = $currentPath
        }
        else {
            $programRoots = @(
                [Environment]::GetEnvironmentVariable('ProgramW6432'),
                [Environment]::GetEnvironmentVariable('ProgramFiles')
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            foreach ($programRoot in $programRoots) {
                $candidate = Join-Path $programRoot 'PowerShell\7\pwsh.exe'
                if ((Test-Path -LiteralPath $candidate -PathType Leaf) -and
                    (Get-WinPrivPeArchitecture -Path $candidate) -eq $Architecture) {
                    $path = $candidate
                    break
                }
            }
        }
    }

    $version = $null
    $edition = $null
    $processArchitecture = $null
    $probeProcessId = $null
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $reason = "No $Architecture PowerShell host was found. Set $overrideName to override discovery."
        $path = $null
    }
    else {
        try { $path = (Get-Item -LiteralPath $path -ErrorAction Stop).FullName } catch { }
        $actualArchitecture = Get-WinPrivPeArchitecture -Path $path
        if ($actualArchitecture -ne $Architecture) {
            $reason = "Host '$path' is $actualArchitecture, not $Architecture."
            $path = $null
        }
        else {
            try {
                $validation = Test-WinPrivPowerShellHost -Path $path -Architecture $Architecture
                $version = $validation.Version
                $edition = $validation.PSEdition
                $processArchitecture = $validation.ProcessArchitecture
                $probeProcessId = $validation.ProbeProcessId
                if (-not $validation.Valid) {
                    $reason = $validation.Reason
                    $path = $null
                }
            }
            catch {
                $reason = "Host '$path' could not be validated as PowerShell: $($_.Exception.Message)"
                $path = $null
            }
        }
    }

    $result = [pscustomobject]@{
        Architecture = $Architecture
        Path         = $path
        Engine       = $engine
        Version      = $version
        PSEdition    = $edition
        ProcessArchitecture = $processArchitecture
        ProbeProcessId = $probeProcessId
        Available    = $null -ne $path
        Reason       = $reason
        Override     = $overrideName
        InternalAlias = $internalAliasName
    }
    if ($Detailed) { return $result }
    return $result.Path
}

function Get-WinPrivTestArchitectures {
    [CmdletBinding()]
    param(
        [Alias('Architecture')]
        [ValidateSet('Auto', 'x86', 'x64', 'ARM64')]
        [string[]]$Requested = @('Auto'),
        [string]$BinaryRoot = $env:WINPRIV_TEST_BINARY_ROOT,
        [switch]$Detailed
    )

    if (-not $PSBoundParameters.ContainsKey('Requested') -and
        -not [string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_ARCHITECTURES)) {
        $Requested = @($env:WINPRIV_TEST_ARCHITECTURES -split '[,;]' | Where-Object { $_ })
    }
    if ($Requested.Count -gt 1 -and ($Requested -contains 'Auto')) {
        throw "Architecture 'Auto' cannot be combined with an explicit architecture."
    }
    $requestedArchitectures = if ($Requested -contains 'Auto') { @('x86', 'x64', 'ARM64') } else { @($Requested | Select-Object -Unique) }
    $osArchitecture = Get-WinPrivOsArchitecture
    $details = @()

    foreach ($item in $requestedArchitectures) {
        $osCompatible = switch ($item) {
            'x86' { $true }
            'x64' { $osArchitecture -in @('x64', 'ARM64') }
            'ARM64' { $osArchitecture -eq 'ARM64' }
        }
        $reasons = New-Object 'System.Collections.Generic.List[string]'
        if (-not $osCompatible) {
            [void]$reasons.Add("$item processes cannot run on $osArchitecture Windows.")
        }
        $hostInfo = Get-WinPrivTestHost -Architecture $item -Detailed
        if (-not $hostInfo.Available) { [void]$reasons.Add($hostInfo.Reason) }

        $binaryDirectory = $null
        $binariesAvailable = $true
        if (-not [string]::IsNullOrWhiteSpace($BinaryRoot)) {
            $binaryDirectory = Get-WinPrivArchitectureDirectory -BinaryRoot $BinaryRoot -Architecture $item
            $binariesAvailable = $null -ne $binaryDirectory -and
                (Test-Path -LiteralPath (Join-Path $binaryDirectory 'WinPriv.exe') -PathType Leaf) -and
                (Test-Path -LiteralPath (Join-Path $binaryDirectory 'WinPrivCmd.exe') -PathType Leaf)
            if (-not $binariesAvailable) {
                [void]$reasons.Add("WinPriv.exe and WinPrivCmd.exe were not found for $item under '$BinaryRoot'.")
            }
        }

        $details += [pscustomobject]@{
            Architecture    = $item
            OsArchitecture  = $osArchitecture
            Compatible      = $osCompatible -and $hostInfo.Available -and $binariesAvailable
            Host            = $hostInfo.Path
            HostVersion     = $hostInfo.Version
            HostEdition     = $hostInfo.PSEdition
            HostProcessArchitecture = $hostInfo.ProcessArchitecture
            HostProbeProcessId = $hostInfo.ProbeProcessId
            BinaryDirectory = $binaryDirectory
            Reason          = ($reasons -join ' ')
        }
    }

    if ($Detailed) { return $details }
    return @($details | Where-Object Compatible | ForEach-Object Architecture)
}

function Write-WinPrivJsonLine {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }
    $json = $Value | ConvertTo-Json -Depth 30 -Compress
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $stream = $null
        $writer = $null
        try {
            $stream = New-Object IO.FileStream($Path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
            $writer = New-Object IO.StreamWriter($stream, (New-Object Text.UTF8Encoding($false)))
            $writer.WriteLine($json)
            $writer.Flush()
            return
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw }
            Start-Sleep -Milliseconds 50
        }
        finally {
            if ($null -ne $writer) { $writer.Dispose() }
            elseif ($null -ne $stream) { $stream.Dispose() }
        }
    } while ($true)
}

function New-WinPrivSandbox {
    [CmdletBinding()]
    param(
        [ValidateSet('x86', 'x64', 'ARM64')]
        [string[]]$Architecture,
        [string]$BinaryRoot = $env:WINPRIV_TEST_BINARY_ROOT,
        [string]$Root,
        [string]$Purpose = 'test'
    )

    if ([string]::IsNullOrWhiteSpace($BinaryRoot)) {
        throw 'BinaryRoot was not supplied and WINPRIV_TEST_BINARY_ROOT is not set.'
    }
    if ($null -eq $Architecture -or $Architecture.Count -eq 0) {
        $Architecture = @($env:WINPRIV_TEST_ARCHITECTURES -split '[,;]' | Where-Object { $_ })
    }
    if ($Architecture.Count -eq 0) {
        throw 'No sandbox architecture was selected.'
    }

    $markerId = [Guid]::NewGuid().ToString('D')
    if ([string]::IsNullOrWhiteSpace($Root)) {
        $runRoot = $env:WINPRIV_TEST_RUN_ROOT
        if ([string]::IsNullOrWhiteSpace($runRoot)) {
            $Root = Join-Path ([IO.Path]::GetTempPath()) "WinPrivSandbox-$markerId"
        }
        else {
            $Root = Join-Path (Join-Path $runRoot 'sandboxes') $markerId
        }
    }
    $Root = [IO.Path]::GetFullPath($Root)
    if (-not [string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_RUN_ROOT) -and
        -not (Test-WinPrivPathWithin -Child $Root -Parent $env:WINPRIV_TEST_RUN_ROOT)) {
        throw "Sandbox root '$Root' is outside WINPRIV_TEST_RUN_ROOT '$env:WINPRIV_TEST_RUN_ROOT'."
    }
    if (Test-Path -LiteralPath $Root) {
        throw "Sandbox path already exists: '$Root'."
    }

    $temp = Join-Path $Root 'temp'
    $working = Join-Path $Root 'work'
    $artifacts = Join-Path $Root 'artifacts'
    $logs = Join-Path $Root 'logs'
    $bin = Join-Path $Root 'bin'
    foreach ($directory in @($Root, $temp, $working, $artifacts, $logs, $bin)) {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }

    $launchers = [ordered]@{}
    try {
        foreach ($item in ($Architecture | Select-Object -Unique)) {
            $sourceDirectory = Get-WinPrivArchitectureDirectory -BinaryRoot $BinaryRoot -Architecture $item
            if ($null -eq $sourceDirectory) {
                throw "No $item binary directory exists under '$BinaryRoot'."
            }
            foreach ($required in @('WinPriv.exe', 'WinPrivCmd.exe')) {
                if (-not (Test-Path -LiteralPath (Join-Path $sourceDirectory $required) -PathType Leaf)) {
                    throw "Required $item launcher '$required' is missing from '$sourceDirectory'."
                }
            }
            $destinationDirectory = Join-Path $bin $item
            [void](New-Item -ItemType Directory -Path $destinationDirectory -Force)
            Get-ChildItem -LiteralPath $sourceDirectory -File | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $destinationDirectory -Force
            }
            $nativeFixtureRoot = $env:WINPRIV_TEST_NATIVE_FIXTURE_ROOT
            if (-not [string]::IsNullOrWhiteSpace($nativeFixtureRoot)) {
                $nativeFixtureDirectory = Join-Path ([IO.Path]::GetFullPath($nativeFixtureRoot)) $item
                foreach ($fixture in @('WinPrivHookImport.exe', 'WinPrivHookDelayLoad.exe', 'WinPrivHookDynamic.exe')) {
                    $fixturePath = Join-Path $nativeFixtureDirectory $fixture
                    if (Test-Path -LiteralPath $fixturePath -PathType Leaf) {
                        Copy-Item -LiteralPath $fixturePath -Destination $destinationDirectory -Force
                    }
                }
            }
            $launchers[$item] = [pscustomobject]@{
                Root       = $destinationDirectory
                WinPriv    = Join-Path $destinationDirectory 'WinPriv.exe'
                WinPrivCmd = Join-Path $destinationDirectory 'WinPrivCmd.exe'
                Library    = Join-Path $destinationDirectory 'WinPrivLibrary.dll'
            }
        }

        $markerPath = Join-Path $Root '.winpriv-test-sandbox.json'
        $marker = [ordered]@{
            SchemaVersion = 1
            MarkerId      = $markerId
            Root          = $Root
            Purpose       = $Purpose
            CreatedUtc    = [DateTime]::UtcNow.ToString('o')
            ProcessId     = $PID
        }
        [IO.File]::WriteAllText($markerPath, ($marker | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))

        return [pscustomobject]@{
            MarkerId   = $markerId
            Root       = $Root
            Temp       = $temp
            Working    = $working
            Artifacts  = $artifacts
            Logs       = $logs
            Bin        = $bin
            MarkerPath = $markerPath
            Journal    = Join-Path $Root 'cleanup-journal.jsonl'
            Launchers  = [pscustomobject]$launchers
            Purpose    = $Purpose
        }
    }
    catch {
        if (Test-Path -LiteralPath $Root -PathType Container) {
            Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw
    }
}

function Write-WinPrivCleanupResult {
    param($Result)
    $path = $env:WINPRIV_TEST_CLEANUP_EVENTS_PATH
    if (-not [string]::IsNullOrWhiteSpace($path)) {
        Write-WinPrivJsonLine -Path $path -Value $Result
    }
}

function Remove-WinPrivSandbox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]$Sandbox,
        [switch]$Force
    )
    process {
        $root = [IO.Path]::GetFullPath([string]$Sandbox.Root)
        $markerPath = Join-Path $root '.winpriv-test-sandbox.json'
        if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
            throw "Refusing to remove unmarked sandbox '$root'."
        }
        $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
        if ($marker.Root -ne $root -or $marker.MarkerId -ne $Sandbox.MarkerId) {
            throw "Refusing to remove sandbox '$root' because its ownership marker does not match."
        }
        $runRoot = $env:WINPRIV_TEST_RUN_ROOT
        if (-not [string]::IsNullOrWhiteSpace($runRoot) -and -not (Test-WinPrivPathWithin -Child $root -Parent $runRoot)) {
            throw "Refusing to remove sandbox '$root' outside test run root '$runRoot'."
        }

        Repair-WinPrivSandboxJournal -Sandbox $Sandbox | Out-Null

        $keep = -not $Force -and $env:WINPRIV_TEST_KEEP_ARTIFACTS -eq '1'
        if ($keep) {
            $result = [pscustomobject]@{
                MarkerId    = $Sandbox.MarkerId
                Path        = $root
                Status      = 'Preserved'
                Reason      = 'KeepArtifacts was requested.'
                TimestampUtc = [DateTime]::UtcNow.ToString('o')
            }
            Write-WinPrivCleanupResult -Result $result
            return $result
        }
        if (-not $Force -and $env:WINPRIV_TEST_DEFER_SANDBOX_CLEANUP -eq '1') {
            $result = [pscustomobject]@{
                MarkerId     = $Sandbox.MarkerId
                Path         = $root
                Status       = 'Deferred'
                Reason       = 'The runner defers sandbox deletion until the final test outcome is known.'
                TimestampUtc = [DateTime]::UtcNow.ToString('o')
            }
            Write-WinPrivCleanupResult -Result $result
            return $result
        }

        $errorText = $null
        try {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
        }
        catch {
            $errorText = $_.Exception.Message
        }
        $residual = Test-Path -LiteralPath $root
        $result = [pscustomobject]@{
            MarkerId     = $Sandbox.MarkerId
            Path         = $root
            Status       = if ($residual) { 'Residual' } else { 'Clean' }
            Reason       = $errorText
            TimestampUtc = [DateTime]::UtcNow.ToString('o')
        }
        Write-WinPrivCleanupResult -Result $result
        if ($residual) {
            throw "Sandbox cleanup left residual state at '$root': $errorText"
        }
        return $result
    }
}

function Add-WinPrivCleanupJournalEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Sandbox,
        [Parameter(Mandatory = $true)][ValidateSet('Path', 'Process', 'Acl', 'LocalPrincipalIntent', 'LocalPrincipal', 'LsaRight', 'Registry', 'Other')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Identifier,
        $OriginalState,
        [hashtable]$Metadata
    )
    $entry = [pscustomobject]@{
        SchemaVersion = 1
        EntryId       = [Guid]::NewGuid().ToString('D')
        MarkerId      = $Sandbox.MarkerId
        Kind          = $Kind
        Identifier    = $Identifier
        OriginalState = $OriginalState
        Metadata      = $Metadata
        CreatedUtc    = [DateTime]::UtcNow.ToString('o')
        ProcessId     = $PID
    }
    Write-WinPrivJsonLine -Path $Sandbox.Journal -Value $entry
    return $entry
}

function Get-WinPrivCleanupJournal {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Sandbox)
    if (-not (Test-Path -LiteralPath $Sandbox.Journal -PathType Leaf)) { return @() }
    return @(Get-Content -LiteralPath $Sandbox.Journal | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}

function Initialize-WinPrivLsaPolicy {
    if ('WinPrivTests.LsaPolicy' -as [type]) { return }
    $source = [IO.Path]::GetFullPath((Join-Path $script:ModuleRoot '..\..\Support\WinPriv.LsaPolicy.cs'))
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "The LSA cleanup helper is missing: '$source'."
    }
    Add-Type -Path $source -ErrorAction Stop
}

function Test-WinPrivStringSetEqual {
    param([object[]]$Left, [object[]]$Right)
    $leftValues = @($Left | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $rightValues = @($Right | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    return @(Compare-Object -ReferenceObject $leftValues -DifferenceObject $rightValues -CaseSensitive:$false).Count -eq 0
}

function Get-WinPrivExceptionWin32Code {
    param([AllowNull()] $Exception)

    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [ComponentModel.Win32Exception]) {
            return [int]$current.NativeErrorCode
        }
        if ($current -is [Runtime.InteropServices.COMException]) {
            return ([int]$current.ErrorCode -band 0xFFFF)
        }
        $current = $current.InnerException
    }
    return $null
}

function Get-WinPrivLocalPrincipalIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$MachineName,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ValidateSet('user', 'group')][string]$Type
    )

    $path = "WinNT://$MachineName/$Name,$Type"
    try {
        $exists = [DirectoryServices.DirectoryEntry]::Exists($path)
    }
    catch {
        $code = Get-WinPrivExceptionWin32Code -Exception $_.Exception
        if ($code -in @(2220, 2221)) {
            return [pscustomobject]@{ Exists = $false; Sid = $null; Description = $null; Path = $path }
        }
        throw
    }
    if (-not $exists) {
        return [pscustomobject]@{ Exists = $false; Sid = $null; Description = $null; Path = $path }
    }

    $principal = [ADSI]$path
    try {
        $sidBytes = [byte[]]$principal.Properties['objectSid'].Value
        if ($null -eq $sidBytes -or $sidBytes.Count -eq 0) {
            throw "The existing local $Type '$Name' has no readable object SID."
        }
        return [pscustomobject]@{
            Exists = $true
            Sid = [Security.Principal.SecurityIdentifier]::new($sidBytes, 0).Value
            Description = [string]$principal.Properties['Description'].Value
            Path = $path
        }
    }
    finally {
        [void]$principal.Close()
    }
}

function Remove-WinPrivUserProfileBySid {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )

    try { $canonicalSid = [Security.Principal.SecurityIdentifier]::new($Sid).Value }
    catch { throw "Invalid profile SID '$Sid'." }
    if ($ExpectedName -notmatch '^WPTU[0-9A-Fa-f]{12}$') { throw "Invalid fixture profile name '$ExpectedName'." }
    $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$canonicalSid"
    if (-not (Test-Path -LiteralPath $profileKey)) { return $false }
    $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$canonicalSid'" -ErrorAction Stop
    if ($null -eq $profile) { throw "A profile registry entry exists for '$canonicalSid', but Win32_UserProfile did not return it." }
    $profileLeaf = Split-Path -Leaf ([string]$profile.LocalPath)
    if ($profile.Special -or ($profileLeaf -ne $ExpectedName -and -not $profileLeaf.StartsWith("$ExpectedName.", [StringComparison]::OrdinalIgnoreCase))) {
        throw "The profile for '$canonicalSid' is special or its path does not match the fixture name."
    }
    if ($profile.Loaded) { throw "The fixture profile for '$canonicalSid' is still loaded." }
    [void](Remove-CimInstance -InputObject $profile -ErrorAction Stop)
    return $true
}

function Repair-WinPrivSandboxJournal {
    param(
        [Parameter(Mandatory = $true)]$Sandbox,
        [switch]$AllowRecovery,
        [switch]$NoThrow
    )

    $entries = @(Get-WinPrivCleanupJournal -Sandbox $Sandbox)
    if ($entries.Count -eq 0) { return }
    $root = [IO.Path]::GetFullPath([string]$Sandbox.Root)
    $deltas = New-Object 'System.Collections.Generic.List[object]'
    $errors = New-Object 'System.Collections.Generic.List[object]'
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    $reparsePoints = @($rootItem | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }) + @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    })
    if ($reparsePoints.Count -gt 0) {
        [void]$errors.Add([pscustomobject]@{
            Kind = 'ReparsePoint'; Identifier = ($reparsePoints.FullName -join '; ')
            Reason = 'Journal repair was refused because the sandbox contains a reparse point.'
        })
        $entries = @()
    }
    if (-not $AllowRecovery) {
        foreach ($entry in $entries) {
            $entryId = [Guid]::Empty
            if (-not [Guid]::TryParse([string]$entry.EntryId, [ref]$entryId) -or
                [string]$entry.MarkerId -ne [string]$Sandbox.MarkerId) {
                [void]$errors.Add([pscustomobject]@{
                    Kind = 'Journal'; Identifier = [string]$entry.EntryId
                    Reason = 'The journal entry GUID or sandbox marker does not match.'
                })
            }
        }
        if (@($errors | Where-Object Kind -eq 'Journal').Count -gt 0) {
            $entries = @()
        }
    }

    foreach ($entry in @($entries | Where-Object Kind -eq 'Process')) {
        $metadata = $entry.Metadata
        $processId = [int](Get-WinPrivObjectValue -Object $metadata -Name 'ProcessId')
        if ($processId -le 0) { [void][int]::TryParse([string]$entry.Identifier, [ref]$processId) }
        $path = [string](Get-WinPrivObjectValue -Object $metadata -Name 'Path')
        $started = [string](Get-WinPrivObjectValue -Object $metadata -Name 'StartTimeUtc')
        if ($processId -le 0 -or [string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($started)) {
            [void]$errors.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $entry.Identifier; Reason = 'PID, image path, and start time are required.' })
            continue
        }
        if (Test-WinPrivProcessIdentity -ProcessId $processId -ExpectedPath $path -ExpectedStartUtc $started) {
            try {
                Stop-Process -Id $processId -Force -ErrorAction Stop
                [void]$deltas.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $processId; Action = 'TerminatedRecordedProcess' })
            }
            catch { [void]$errors.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $processId; Reason = $_.Exception.Message }) }
        }
    }

    foreach ($entry in @($entries | Where-Object Kind -eq 'Registry')) {
        $path = [string]$entry.Identifier
        $originalExisted = [bool](Get-WinPrivObjectValue -Object $entry.OriginalState -Name 'Existed')
        $allowed = $path -match '^Registry::HKEY_CURRENT_USER\\Software\\WinPrivTests\\Case[0-9A-Fa-f]{32}(Sibling)?$' -or
            $path -match '^Registry::HKEY_CURRENT_USER\\Software\\Policies\\WinPrivTests\\[0-9A-Fa-f]{32}$'
        if ($originalExisted -or -not $allowed) {
            [void]$errors.Add([pscustomobject]@{ Kind = 'Registry'; Identifier = $path; Reason = 'Only absent-before-test GUID HKCU fixture keys can be reconciled automatically.' })
            continue
        }
        if (Test-Path -LiteralPath $path) {
            try {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                [void]$deltas.Add([pscustomobject]@{ Kind = 'Registry'; Identifier = $path; Action = 'RemovedFixtureKey' })
            }
            catch { [void]$errors.Add([pscustomobject]@{ Kind = 'Registry'; Identifier = $path; Reason = $_.Exception.Message }) }
        }
    }

    foreach ($entry in @($entries | Where-Object Kind -eq 'Acl')) {
        $path = [IO.Path]::GetFullPath([string]$entry.Identifier)
        $sddl = [string](Get-WinPrivObjectValue -Object $entry.OriginalState -Name 'Sddl')
        if (-not (Test-WinPrivPathWithin -Child $path -Parent $root) -or [string]::IsNullOrWhiteSpace($sddl)) {
            [void]$errors.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Reason = 'ACL path is outside the sandbox or original SDDL is missing.' })
            continue
        }
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            if ($acl.Sddl -ne $sddl) {
                $acl.SetSecurityDescriptorSddlForm($sddl)
                Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
                [void]$deltas.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Action = 'RestoredSddl' })
            }
            $expectedContent = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'ContentBase64')
            if (-not [string]::IsNullOrWhiteSpace($expectedContent)) {
                $expectedHash = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'ContentSha256')
                $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
                if ($actualHash -ne $expectedHash) {
                    [IO.File]::WriteAllBytes($path, [Convert]::FromBase64String($expectedContent))
                    [void]$deltas.Add([pscustomobject]@{ Kind = 'Path'; Identifier = $path; Action = 'RestoredContent' })
                }
            }
        }
        catch { [void]$errors.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Reason = $_.Exception.Message }) }
    }

    $lsaEntries = @($entries | Where-Object Kind -eq 'LsaRight')
    if ($lsaEntries.Count -gt 0) {
        try { Initialize-WinPrivLsaPolicy }
        catch { [void]$errors.Add([pscustomobject]@{ Kind = 'LsaRight'; Identifier = 'Add-Type'; Reason = $_.Exception.Message }) }
    }
    if ('WinPrivTests.LsaPolicy' -as [type]) {
        foreach ($entry in $lsaEntries) {
            try {
                if ([string]$entry.Identifier -eq 'global-deny-rights-snapshot') {
                    $assignments = @((Get-WinPrivObjectValue -Object $entry.OriginalState -Name 'Assignments'))
                    $rights = @($assignments | ForEach-Object { [string]$_.Right }) +
                        @((Get-WinPrivObjectValue -Object $entry.OriginalState -Name 'Rights'))
                    foreach ($right in @($rights | Where-Object { $_ } | Sort-Object -Unique)) {
                        $desired = @($assignments | Where-Object Right -eq $right | ForEach-Object { [string]$_.Account })
                        $desiredSids = @($desired | ForEach-Object { [WinPrivTests.LsaPolicy]::ResolveSid($_) })
                        $currentSids = @([WinPrivTests.LsaPolicy]::GetAccountSidsWithRight($right))
                        if (-not (Test-WinPrivStringSetEqual $currentSids $desiredSids)) {
                            [WinPrivTests.LsaPolicy]::SetAccountsWithRight($right, $desired)
                            [void]$deltas.Add([pscustomobject]@{ Kind = 'LsaRight'; Identifier = $right; Action = 'RestoredGlobalAssignments' })
                        }
                    }
                    continue
                }
                $sid = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'Sid')
                $name = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'PrincipalName')
                if ($sid -notmatch '^S-1-' -or $name -notmatch '^WPT[GU][0-9A-Fa-f]{12}$' -or
                    -not ([string]$entry.Identifier).EndsWith("\$name", [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'The fixture SID/name/account marker is incomplete or invalid.'
                }
                $desired = @((Get-WinPrivObjectValue -Object $entry.OriginalState -Name 'Rights'))
                $current = @([WinPrivTests.LsaPolicy]::GetRights($sid))
                if (-not (Test-WinPrivStringSetEqual $current $desired)) {
                    [WinPrivTests.LsaPolicy]::SetRights($sid, [string[]]$desired)
                    [void]$deltas.Add([pscustomobject]@{ Kind = 'LsaRight'; Identifier = $sid; Action = 'RestoredAccountRights' })
                }
            }
            catch { [void]$errors.Add([pscustomobject]@{ Kind = 'LsaRight'; Identifier = $entry.Identifier; Reason = $_.Exception.Message }) }
        }
    }

    $lsaRepairFailed = @($errors | Where-Object Kind -eq 'LsaRight').Count -gt 0
    $completedPrincipalEntries = @($entries | Where-Object Kind -eq 'LocalPrincipal')
    foreach ($entry in $completedPrincipalEntries) {
        $name = [string]$entry.Identifier
        $sidText = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'Sid')
        $sid = $null
        try { $sid = [Security.Principal.SecurityIdentifier]::new($sidText).Value } catch { }
        $type = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'Type')
        $description = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'Description')
        $machineName = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'MachineName')
        if ([string]::IsNullOrWhiteSpace($machineName)) { $machineName = [Environment]::MachineName }
        $expectedPrefix = if ($type -eq 'group') { 'WPTG' } elseif ($type -eq 'user') { 'WPTU' } else { $null }
        if ($null -eq $expectedPrefix -or $name -notmatch "^$expectedPrefix[0-9A-Fa-f]{12}$" -or
            [string]::IsNullOrWhiteSpace($sid) -or $machineName -ne [Environment]::MachineName -or
            $description -cne "WinPriv test fixture $name") {
            [void]$errors.Add([pscustomobject]@{
                Kind = 'LocalPrincipal'; Identifier = $name
                Reason = 'Machine, name/type pairing, SID, or exact description marker is invalid.'
            })
            continue
        }
        if ($lsaRepairFailed -and $lsaEntries.Count -gt 0) {
            [void]$errors.Add([pscustomobject]@{
                Kind = 'LocalPrincipal'; Identifier = $name
                Reason = 'The fixture principal was retained because its LSA-right restoration did not complete.'
            })
            continue
        }
        try {
            $identity = Get-WinPrivLocalPrincipalIdentity -MachineName $machineName -Name $name -Type $type
            if (-not $identity.Exists) {
                $profileKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
                if ($type -eq 'user' -and (Test-Path -LiteralPath $profileKey)) {
                    throw 'The fixture principal is absent but a profile remains; automatic removal was refused without live SID/description verification.'
                }
                continue
            }
            if ($identity.Sid -ne $sid -or $identity.Description -cne $description) {
                throw 'The current principal SID or description does not match the fixture marker.'
            }
            if ($type -eq 'user' -and (Remove-WinPrivUserProfileBySid -Sid $sid -ExpectedName $name)) {
                [void]$deltas.Add([pscustomobject]@{
                    Kind = 'LocalPrincipal'; Identifier = $name; Action = 'RemovedFixtureProfile'; Sid = $sid
                })
            }
            $computer = [ADSI]"WinNT://$machineName,computer"
            [void]$computer.Delete($type, $name)
            [void]$deltas.Add([pscustomobject]@{ Kind = 'LocalPrincipal'; Identifier = $name; Action = 'RemovedFixturePrincipal'; Sid = $sid })
        }
        catch {
            [void]$errors.Add([pscustomobject]@{ Kind = 'LocalPrincipal'; Identifier = $name; Reason = $_.Exception.Message })
        }
    }

    $completedPrincipalNames = @($completedPrincipalEntries | ForEach-Object { [string]$_.Identifier })
    foreach ($entry in @($entries | Where-Object Kind -eq 'LocalPrincipalIntent')) {
        $name = [string]$entry.Identifier
        if ($name -in $completedPrincipalNames) { continue }
        $type = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'Type')
        $description = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'Description')
        $machineName = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'MachineName')
        $existedProperty = if ($null -ne $entry.OriginalState) {
            $entry.OriginalState.PSObject.Properties['Existed']
        }
        else { $null }
        $absentBefore = $null -ne $existedProperty -and $existedProperty.Value -is [bool] -and
            -not [bool]$existedProperty.Value
        $expectedPrefix = if ($type -eq 'group') { 'WPTG' } elseif ($type -eq 'user') { 'WPTU' } else { $null }
        if (-not $absentBefore -or $null -eq $expectedPrefix -or
            $name -notmatch "^$expectedPrefix[0-9A-Fa-f]{12}$" -or
            $machineName -ne [Environment]::MachineName -or
            $description -cne "WinPriv test fixture $name") {
            [void]$errors.Add([pscustomobject]@{
                Kind = 'LocalPrincipalIntent'; Identifier = $name
                Reason = 'The absent-before machine, name/type pairing, or exact description marker is invalid.'
            })
            continue
        }
        try {
            $identity = Get-WinPrivLocalPrincipalIdentity -MachineName $machineName -Name $name -Type $type
            if (-not $identity.Exists) { continue }
            if ($identity.Description -cne $description) {
                throw 'The current principal description does not match the creation-intent marker.'
            }
            $computer = [ADSI]"WinNT://$machineName,computer"
            [void]$computer.Delete($type, $name)
            [void]$deltas.Add([pscustomobject]@{
                Kind = 'LocalPrincipalIntent'; Identifier = $name
                Action = 'RemovedIncompleteFixturePrincipal'; Sid = $identity.Sid
            })
        }
        catch {
            [void]$errors.Add([pscustomobject]@{
                Kind = 'LocalPrincipalIntent'; Identifier = $name; Reason = $_.Exception.Message
            })
        }
    }

    $status = if ($errors.Count -gt 0) { 'RepairFailed' } elseif ($deltas.Count -gt 0) { 'RecoveredUnexpectedDelta' } else { 'JournalVerified' }
    $result = [pscustomobject]@{
        MarkerId = $Sandbox.MarkerId; Path = $root; Status = $status
        Reason = if ($status -eq 'JournalVerified') { 'All journaled external state matched its baseline.' } else { 'Journal reconciliation detected unexpected test state.' }
        Deltas = @($deltas | ForEach-Object { $_ }); Errors = @($errors | ForEach-Object { $_ })
        TimestampUtc = [DateTime]::UtcNow.ToString('o')
    }
    Write-WinPrivCleanupResult -Result $result
    if (-not ($AllowRecovery -or $NoThrow) -and $errors.Count -gt 0) {
        throw "Sandbox journal reconciliation failed for '$root': $(($errors | ForEach-Object { "$($_.Kind) $($_.Identifier): $($_.Reason)" }) -join '; ')"
    }
    if (-not ($AllowRecovery -or $NoThrow) -and $deltas.Count -gt 0) {
        throw "Sandbox cleanup recovered $($deltas.Count) unexpected machine-state delta(s); the test is not clean."
    }
    return $result
}

function Invoke-WinPrivCurrentRunReconciliation {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$RunRoot)

    $root = [IO.Path]::GetFullPath($RunRoot)
    $sandboxes = New-Object 'System.Collections.Generic.List[object]'
    $unexpected = New-Object 'System.Collections.Generic.List[object]'
    $manual = New-Object 'System.Collections.Generic.List[object]'

    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        return [pscustomobject][ordered]@{
            SchemaVersion = 1; RunRoot = $root; Status = 'RunRootAbsent'
            Sandboxes = @(); UnexpectedDeltas = @(); ManualRecovery = @()
            HasFailures = $false; HasManualRecovery = $false
        }
    }

    $runMarkerPath = Join-Path $root '.winpriv-test-run.json'
    try {
        $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'The current run root is a reparse point.'
        }
        if (-not (Test-Path -LiteralPath $runMarkerPath -PathType Leaf)) {
            throw 'The current run ownership marker is missing.'
        }
        $runMarker = Get-Content -LiteralPath $runMarkerPath -Raw | ConvertFrom-Json -ErrorAction Stop
        $runGuid = [Guid]::Empty
        if (-not [Guid]::TryParse([string]$runMarker.MarkerId, [ref]$runGuid) -or
            [IO.Path]::GetFullPath([string]$runMarker.Root) -ne $root -or
            [string]$runMarker.RunId -ne (Split-Path -Leaf $root)) {
            throw 'The current run marker identity does not match its directory.'
        }
    }
    catch {
        [void]$manual.Add([pscustomobject]@{
            Kind = 'RunRoot'; Identifier = $root; Reason = $_.Exception.Message
        })
    }

    $sandboxesRoot = Join-Path $root 'sandboxes'
    if ($manual.Count -eq 0 -and (Test-Path -LiteralPath $sandboxesRoot -PathType Container)) {
        foreach ($directory in Get-ChildItem -LiteralPath $sandboxesRoot -Directory -Force -ErrorAction SilentlyContinue) {
            $sandboxRoot = [IO.Path]::GetFullPath($directory.FullName)
            $record = [ordered]@{
                MarkerId = $null; Path = $sandboxRoot; Status = 'Unknown'; Reason = $null
                Deltas = @(); Errors = @()
            }
            try {
                $markerPath = Join-Path $sandboxRoot '.winpriv-test-sandbox.json'
                if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                    -not (Test-WinPrivPathWithin -Child $sandboxRoot -Parent $sandboxesRoot) -or
                    -not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
                    throw 'The sandbox is unmarked, a reparse point, or outside the current run sandboxes directory.'
                }
                $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json -ErrorAction Stop
                $markerGuid = [Guid]::Empty
                $directoryGuid = [Guid]::Empty
                if (-not [Guid]::TryParse([string]$marker.MarkerId, [ref]$markerGuid) -or
                    -not [Guid]::TryParse([string]$directory.Name, [ref]$directoryGuid) -or
                    $markerGuid -ne $directoryGuid -or
                    [IO.Path]::GetFullPath([string]$marker.Root) -ne $sandboxRoot) {
                    throw 'The sandbox marker GUID, root, or directory identity does not match.'
                }
                $record.MarkerId = $markerGuid.ToString('D')
                $sandbox = [pscustomobject]@{
                    MarkerId = [string]$marker.MarkerId
                    Root = $sandboxRoot
                    Journal = Join-Path $sandboxRoot 'cleanup-journal.jsonl'
                }
                $repair = Repair-WinPrivSandboxJournal -Sandbox $sandbox -NoThrow
                if ($null -eq $repair) {
                    $record.Status = 'NoExternalStateJournal'
                    $record.Reason = 'The sandbox recorded no external machine-state mutations.'
                }
                else {
                    $record.Status = [string]$repair.Status
                    $record.Reason = [string]$repair.Reason
                    $record.Deltas = @($repair.Deltas)
                    $record.Errors = @($repair.Errors)
                    if ($repair.Status -eq 'RecoveredUnexpectedDelta') {
                        foreach ($delta in @($repair.Deltas)) {
                            [void]$unexpected.Add([pscustomobject]@{
                                MarkerId = $record.MarkerId; Kind = $delta.Kind
                                Identifier = $delta.Identifier; Action = $delta.Action
                            })
                        }
                    }
                    elseif ($repair.Status -eq 'RepairFailed') {
                        [void]$manual.Add([pscustomobject]@{
                            Kind = 'Sandbox'; Identifier = $sandboxRoot
                            Reason = (($repair.Errors | ForEach-Object { "$($_.Kind) $($_.Identifier): $($_.Reason)" }) -join '; ')
                        })
                    }
                }
            }
            catch {
                $record.Status = 'ValidationFailed'
                $record.Reason = $_.Exception.Message
                [void]$manual.Add([pscustomobject]@{
                    Kind = 'Sandbox'; Identifier = $sandboxRoot; Reason = $_.Exception.Message
                })
            }
            [void]$sandboxes.Add([pscustomobject]$record)
        }
    }

    $hasFailures = $unexpected.Count -gt 0 -or $manual.Count -gt 0
    return [pscustomobject][ordered]@{
        SchemaVersion = 1
        RunRoot = $root
        Status = if ($manual.Count -gt 0) { 'ManualRecoveryRequired' } elseif ($unexpected.Count -gt 0) { 'RecoveredUnexpectedDelta' } else { 'Verified' }
        Sandboxes = @($sandboxes | ForEach-Object { $_ })
        UnexpectedDeltas = @($unexpected | ForEach-Object { $_ })
        ManualRecovery = @($manual | ForEach-Object { $_ })
        HasFailures = $hasFailures
        HasManualRecovery = $manual.Count -gt 0
    }
}

function Get-WinPrivDescendantProcessIds {
    param([int]$RootProcessId)
    $processes = @()
    try { $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | Select-Object ProcessId, ParentProcessId) } catch { return @() }
    $found = New-Object 'System.Collections.Generic.HashSet[int]'
    $queue = New-Object 'System.Collections.Generic.Queue[int]'
    $queue.Enqueue($RootProcessId)
    while ($queue.Count -gt 0) {
        $parent = $queue.Dequeue()
        foreach ($process in $processes) {
            $id = [int]$process.ProcessId
            if ([int]$process.ParentProcessId -eq $parent -and $found.Add($id)) {
                $queue.Enqueue($id)
            }
        }
    }
    return @($found)
}

function Write-WinPrivContainedProcessEvent {
    param([Parameter(Mandatory = $true)]$Result)

    $path = [Environment]::GetEnvironmentVariable('WINPRIV_TEST_PROCESS_EVENTS_PATH')
    if ([string]::IsNullOrWhiteSpace($path)) {
        return
    }
    $processIds = @($Result.ProcessId) + @($Result.ChildProcessIds)
    $event = [pscustomobject]@{
        SchemaVersion        = 1
        TimestampUtc         = [DateTime]::UtcNow.ToString('o')
        FilePath             = $Result.FilePath
        WorkingDirectory     = $Result.WorkingDirectory
        ProcessId            = $Result.ProcessId
        ChildProcessIds      = @($Result.ChildProcessIds)
        ProcessIds           = @($processIds | Where-Object { $null -ne $_ } | Select-Object -Unique)
        ExitCode             = $Result.ExitCode
        TimedOut             = [bool]$Result.TimedOut
        StartError           = $Result.StartError
        JobAssigned          = [bool]$Result.JobAssigned
        JobAssignmentError   = $Result.JobAssignmentError
        ContainmentMode      = $Result.ContainmentMode
        DurationMilliseconds = $Result.DurationMilliseconds
    }
    Write-WinPrivJsonLine -Path $path -Value $event
}

function Invoke-WinPrivContainedProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Alias('Arguments')][string[]]$ArgumentList = @(),
        [string]$WorkingDirectory,
        [hashtable]$Environment,
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 30,
        $Sandbox,
        [switch]$CreateHiddenConsole,
        [switch]$CreateNoWindow
    )

    $startedUtc = [DateTime]::UtcNow
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $stdout = ''
    $stderr = ''
    $exitCode = $null
    $timedOut = $false
    $startError = $null
    $processId = $null
    $childIds = @()
    $jobAssigned = $false
    $jobError = $null
    $job = [IntPtr]::Zero
    $process = $null
    $stdoutTask = $null
    $stderrTask = $null

    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $WorkingDirectory = if ($null -ne $Sandbox) { $Sandbox.Working } else { [Environment]::CurrentDirectory }
    }
    if (-not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $WorkingDirectory -Force)
    }

    # CreateProcessW is used directly on Windows so the process can be created
    # suspended, assigned to its Job Object, and only then allowed to execute.
    # For WinPrivCmd, CREATE_NEW_CONSOLE guarantees that GetConsoleWindow() is
    # non-null even though stdout/stderr are redirected; this prevents the
    # launcher's generic output helper from falling back to a modal message box.
    if (Test-WinPrivWindows) {
        $stem = '{0:yyyyMMddTHHmmssfff}-{1}' -f $startedUtc, ([Guid]::NewGuid().ToString('N'))
        $deleteLogsAfterRead = $false
        if ($null -ne $Sandbox) {
            $stdoutPath = Join-Path $Sandbox.Logs ($stem + '.stdout.log')
            $stderrPath = Join-Path $Sandbox.Logs ($stem + '.stderr.log')
        }
        else {
            $stdoutPath = Join-Path ([IO.Path]::GetTempPath()) ($stem + '.stdout.log')
            $stderrPath = Join-Path ([IO.Path]::GetTempPath()) ($stem + '.stderr.log')
            $deleteLogsAfterRead = $true
        }
        $mergedEnvironment = @{}
        foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
            $mergedEnvironment[[string]$entry.Key] = [string]$entry.Value
        }
        if ($null -ne $Sandbox) {
            $mergedEnvironment['TEMP'] = $Sandbox.Temp
            $mergedEnvironment['TMP'] = $Sandbox.Temp
            $mergedEnvironment['TMPDIR'] = $Sandbox.Temp
            $mergedEnvironment['WINPRIV_TEST_SANDBOX'] = $Sandbox.Root
        }
        if ($null -ne $Environment) {
            foreach ($key in $Environment.Keys) {
                if ($null -eq $Environment[$key]) { [void]$mergedEnvironment.Remove([string]$key) }
                else { $mergedEnvironment[[string]$key] = [string]$Environment[$key] }
            }
        }
        $environmentEntries = @($mergedEnvironment.GetEnumerator() | Sort-Object Key | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value })
        $renderedCommandLine = (ConvertTo-WinPrivCommandLineArgument $FilePath) + $(if ($ArgumentList.Count) { ' ' + (Join-WinPrivCommandLine $ArgumentList) } else { '' })
        try {
            Initialize-WinPrivNativeMethods
            $nativeResult = [WinPriv.TestHarness.NativeMethods]::RunContainedProcess(
                $FilePath,
                $renderedCommandLine,
                $WorkingDirectory,
                [string[]]$environmentEntries,
                $stdoutPath,
                $stderrPath,
                $TimeoutSeconds * 1000,
                [bool]$CreateHiddenConsole,
                [bool]$CreateNoWindow)
            $processId = $nativeResult.ProcessId
            $exitCode = $nativeResult.ExitCode
            $timedOut = $nativeResult.TimedOut
            $jobAssigned = $nativeResult.JobAssigned
            $childIds = @($nativeResult.ProcessIds | Where-Object { $_ -ne $processId })
        }
        catch {
            $startError = $_.Exception.Message
        }
        finally {
            $stopwatch.Stop()
            if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
                try { $stdout = [IO.File]::ReadAllText($stdoutPath) } catch { $stderr += "Unable to read stdout log: $($_.Exception.Message)" }
            }
            if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
                try { $stderr += [IO.File]::ReadAllText($stderrPath) } catch { $stderr += "Unable to read stderr log: $($_.Exception.Message)" }
            }
            if ($deleteLogsAfterRead) {
                Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
                $stdoutPath = $null
                $stderrPath = $null
            }
        }
        $result = [pscustomobject]@{
            FilePath             = $FilePath
            ArgumentList         = @($ArgumentList)
            CommandLine          = $renderedCommandLine
            WorkingDirectory     = $WorkingDirectory
            ProcessId            = $processId
            ChildProcessIds      = @($childIds)
            ExitCode             = $exitCode
            TimedOut             = $timedOut
            StartError           = $startError
            StdOut               = $stdout
            StdErr               = $stderr
            StdOutPath           = $stdoutPath
            StdErrPath           = $stderrPath
            StartedUtc           = $startedUtc.ToString('o')
            Duration             = $stopwatch.Elapsed
            DurationMilliseconds = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
            JobAssigned          = $jobAssigned
            JobAssignmentError   = $jobError
            ContainmentMode      = 'JobObject'
            Succeeded            = -not $timedOut -and $null -eq $startError -and $exitCode -eq 0
        }
        Write-WinPrivContainedProcessEvent -Result $result
        return $result
    }

    try {
        if ($CreateHiddenConsole) {
            Initialize-WinPrivNativeMethods
            [void][WinPriv.TestHarness.NativeMethods]::EnsureHiddenConsole()
        }

        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = Join-WinPrivCommandLine -ArgumentList $ArgumentList
        $startInfo.WorkingDirectory = $WorkingDirectory
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = [bool]$CreateNoWindow
        $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden

        if ($null -ne $Sandbox) {
            $startInfo.EnvironmentVariables['TEMP'] = $Sandbox.Temp
            $startInfo.EnvironmentVariables['TMP'] = $Sandbox.Temp
            $startInfo.EnvironmentVariables['TMPDIR'] = $Sandbox.Temp
            $startInfo.EnvironmentVariables['WINPRIV_TEST_SANDBOX'] = $Sandbox.Root
        }
        if ($null -ne $Environment) {
            foreach ($key in $Environment.Keys) {
                if ($null -eq $Environment[$key]) {
                    [void]$startInfo.EnvironmentVariables.Remove([string]$key)
                }
                else {
                    $startInfo.EnvironmentVariables[[string]$key] = [string]$Environment[$key]
                }
            }
        }

        $process = New-Object Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "Process.Start returned false for '$FilePath'."
        }
        $processId = $process.Id
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        try {
            Initialize-WinPrivNativeMethods
            $job = [WinPriv.TestHarness.NativeMethods]::CreateKillOnCloseJob()
            $nativeError = 0
            $jobAssigned = [WinPriv.TestHarness.NativeMethods]::TryAssignProcess($job, $process.Handle, [ref]$nativeError)
            if (-not $jobAssigned) { $jobError = "AssignProcessToJobObject failed with Win32 error $nativeError." }
        }
        catch {
            $jobError = $_.Exception.Message
        }

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            $childIds = @(Get-WinPrivDescendantProcessIds -RootProcessId $processId)
            if ($jobAssigned -and $job -ne [IntPtr]::Zero) {
                $nativeError = 0
                [void][WinPriv.TestHarness.NativeMethods]::TryTerminateJob($job, 0xDEAD, [ref]$nativeError)
            }
            else {
                foreach ($id in ($childIds | Sort-Object -Descending)) {
                    Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
                }
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            }
            [void]$process.WaitForExit(5000)
        }
        else {
            $process.WaitForExit()
        }

        if ($jobAssigned -and $job -ne [IntPtr]::Zero) {
            $jobIds = @([WinPriv.TestHarness.NativeMethods]::GetJobProcessIds($job))
            $childIds = @($jobIds | Where-Object { $_ -ne $processId })
        }
        elseif ($childIds.Count -eq 0) {
            $childIds = @(Get-WinPrivDescendantProcessIds -RootProcessId $processId)
        }

        if ($job -ne [IntPtr]::Zero) {
            [void][WinPriv.TestHarness.NativeMethods]::CloseHandle($job)
            $job = [IntPtr]::Zero
        }
        if (-not $jobAssigned) {
            foreach ($id in ($childIds | Sort-Object -Descending)) {
                Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
            }
        }

        if ($null -ne $stdoutTask -and $stdoutTask.Wait(5000)) { $stdout = $stdoutTask.Result }
        if ($null -ne $stderrTask -and $stderrTask.Wait(5000)) { $stderr = $stderrTask.Result }
        if ($process.HasExited) { $exitCode = $process.ExitCode }
    }
    catch {
        $startError = $_.Exception.Message
        if ($null -ne $process -and -not $process.HasExited) {
            try { $process.Kill() } catch { }
        }
    }
    finally {
        if ($job -ne [IntPtr]::Zero) {
            try { [void][WinPriv.TestHarness.NativeMethods]::CloseHandle($job) } catch { }
        }
        if ($null -ne $process) { $process.Dispose() }
        $stopwatch.Stop()
    }

    $stdoutPath = $null
    $stderrPath = $null
    if ($null -ne $Sandbox) {
        $stem = '{0:yyyyMMddTHHmmssfff}-{1}' -f $startedUtc, ([Guid]::NewGuid().ToString('N'))
        $stdoutPath = Join-Path $Sandbox.Logs ($stem + '.stdout.log')
        $stderrPath = Join-Path $Sandbox.Logs ($stem + '.stderr.log')
        $encoding = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($stdoutPath, [string]$stdout, $encoding)
        [IO.File]::WriteAllText($stderrPath, [string]$stderr, $encoding)
    }

    $result = [pscustomobject]@{
        FilePath             = $FilePath
        ArgumentList         = @($ArgumentList)
        CommandLine          = (ConvertTo-WinPrivCommandLineArgument $FilePath) + $(if ($ArgumentList.Count) { ' ' + (Join-WinPrivCommandLine $ArgumentList) } else { '' })
        WorkingDirectory     = $WorkingDirectory
        ProcessId            = $processId
        ChildProcessIds      = @($childIds)
        ExitCode             = $exitCode
        TimedOut             = $timedOut
        StartError           = $startError
        StdOut               = $stdout
        StdErr               = $stderr
        StdOutPath           = $stdoutPath
        StdErrPath           = $stderrPath
        StartedUtc           = $startedUtc.ToString('o')
        Duration             = $stopwatch.Elapsed
        DurationMilliseconds = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
        JobAssigned          = $jobAssigned
        JobAssignmentError   = $jobError
        ContainmentMode      = if ($jobAssigned) { 'JobObject' } else { 'ProcessTreeFallback' }
        Succeeded            = -not $timedOut -and $null -eq $startError -and $exitCode -eq 0
    }
    Write-WinPrivContainedProcessEvent -Result $result
    return $result
}

function Get-WinPrivSandboxLauncher {
    param(
        [Parameter(Mandatory = $true)]$Sandbox,
        [Parameter(Mandatory = $true)][string]$Architecture,
        [Parameter(Mandatory = $true)][string]$Launcher
    )
    $architectureProperty = $Sandbox.Launchers.PSObject.Properties[$Architecture]
    if ($null -eq $architectureProperty) {
        throw "Sandbox '$($Sandbox.Root)' has no $Architecture launchers."
    }
    $launcherProperty = $architectureProperty.Value.PSObject.Properties[$Launcher]
    if ($null -eq $launcherProperty -or -not (Test-Path -LiteralPath $launcherProperty.Value -PathType Leaf)) {
        throw "Sandbox '$($Sandbox.Root)' has no $Architecture $Launcher launcher."
    }
    return [string]$launcherProperty.Value
}

function Invoke-WinPriv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture,
        [Alias('ArgumentList')][string[]]$Arguments = @(),
        [ValidateSet('WinPrivCmd', 'WinPriv')][string]$Launcher = 'WinPrivCmd',
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 30,
        $Sandbox,
        [hashtable]$Environment,
        [string]$WorkingDirectory
    )

    $ownedSandbox = $false
    if ($null -eq $Sandbox) {
        $Sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose 'invoke'
        $ownedSandbox = $true
    }
    if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) { $WorkingDirectory = $Sandbox.Working }
    $launcherPath = Get-WinPrivSandboxLauncher -Sandbox $Sandbox -Architecture $Architecture -Launcher $Launcher
    $result = Invoke-WinPrivContainedProcess -FilePath $launcherPath -ArgumentList $Arguments -WorkingDirectory $WorkingDirectory -Environment $Environment -TimeoutSeconds $TimeoutSeconds -Sandbox $Sandbox -CreateHiddenConsole:($Launcher -eq 'WinPrivCmd')
    $result | Add-Member -NotePropertyName Architecture -NotePropertyValue $Architecture
    $result | Add-Member -NotePropertyName Launcher -NotePropertyValue $Launcher
    $result | Add-Member -NotePropertyName LauncherPath -NotePropertyValue $launcherPath
    $result | Add-Member -NotePropertyName SandboxRoot -NotePropertyValue $Sandbox.Root

    if ($ownedSandbox -and $result.Succeeded -and $env:WINPRIV_TEST_KEEP_ARTIFACTS -ne '1') {
        try { [void](Remove-WinPrivSandbox -Sandbox $Sandbox -Force) }
        catch {
            $result.Succeeded = $false
            $result | Add-Member -NotePropertyName CleanupError -NotePropertyValue $_.Exception.Message
        }
    }
    return $result
}

function ConvertFrom-WinPrivProbeOutput {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return $Text | ConvertFrom-Json -ErrorAction Stop } catch { }
    $lines = @($Text -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    for ($index = $lines.Count - 1; $index -ge 0; $index--) {
        try { return $lines[$index] | ConvertFrom-Json -ErrorAction Stop } catch { }
    }
    return $null
}

function Invoke-WinPrivProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64')][string]$Architecture,
        [Alias('ParentArchitecture')]
        [ValidateSet('x86', 'x64', 'ARM64')][string]$ProbeArchitecture,
        [string[]]$WinPrivArguments = @(),
        [Parameter(Mandatory = $true)][string]$Operation,
        [Alias('ProbeArguments')][hashtable]$Arguments = @{},
        [string[]]$RemainingArguments = @(),
        [ValidateSet('WinPrivCmd', 'WinPriv')][string]$Launcher = 'WinPrivCmd',
        [ValidateRange(1, 86400)][int]$TimeoutSeconds = 30,
        $Sandbox,
        [hashtable]$Environment,
        [string]$WorkingDirectory,
        [string]$ProbePath = $env:WINPRIV_TEST_PROBE_PATH,
        [string]$OutputPath
    )

    if ([string]::IsNullOrWhiteSpace($ProbePath)) {
        $ProbePath = [IO.Path]::GetFullPath((Join-Path $script:ModuleRoot '..\..\Probes\Invoke-WinPrivProbe.ps1'))
    }
    if (-not (Test-Path -LiteralPath $ProbePath -PathType Leaf)) {
        throw "WinPriv probe script was not found at '$ProbePath'."
    }
    if ([string]::IsNullOrWhiteSpace($ProbeArchitecture)) {
        $ProbeArchitecture = $Architecture
    }
    $hostPath = Get-WinPrivTestHost -Architecture $ProbeArchitecture
    if ([string]::IsNullOrWhiteSpace($hostPath)) {
        $detail = Get-WinPrivTestHost -Architecture $ProbeArchitecture -Detailed
        throw $detail.Reason
    }

    $ownedSandbox = $false
    if ($null -eq $Sandbox) {
        $Sandbox = New-WinPrivSandbox -Architecture $Architecture -Purpose "probe-$Operation"
        $ownedSandbox = $true
    }
    $probeOutputPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Join-Path $Sandbox.Artifacts ("probe-{0}-{1}.json" -f $Operation, [Guid]::NewGuid().ToString('N'))
    }
    else {
        [IO.Path]::GetFullPath($OutputPath)
    }
    $argumentsJson = $Arguments | ConvertTo-Json -Depth 30 -Compress
    $argumentsBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($argumentsJson))
    $probeHostArguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $ProbePath,
        '-Operation', $Operation,
        '-ArgumentsBase64', $argumentsBase64,
        '-OutputPath', $probeOutputPath
    )
    $probeHostArguments += @($RemainingArguments)
    $allArguments = @($WinPrivArguments) + @($hostPath) + $probeHostArguments
    $childEnvironment = @{}
    if ($null -ne $Environment) {
        foreach ($key in $Environment.Keys) { $childEnvironment[$key] = $Environment[$key] }
    }
    $childEnvironment['WINPRIV_PROBE_ARGUMENTS_JSON'] = $argumentsJson
    $childEnvironment['WINPRIV_PROBE_OUTPUT_PATH'] = $probeOutputPath
    $childEnvironment['WINPRIV_PROBE_OPERATION'] = $Operation

    $result = Invoke-WinPriv -Architecture $Architecture -Arguments $allArguments -Launcher $Launcher -TimeoutSeconds $TimeoutSeconds -Sandbox $Sandbox -Environment $childEnvironment -WorkingDirectory $WorkingDirectory
    $result | Add-Member -NotePropertyName ProbeArchitecture -NotePropertyValue $ProbeArchitecture
    $probeResult = $null
    $parseError = $null
    if (Test-Path -LiteralPath $probeOutputPath -PathType Leaf) {
        try { $probeResult = Get-Content -LiteralPath $probeOutputPath -Raw | ConvertFrom-Json -ErrorAction Stop }
        catch { $parseError = $_.Exception.Message }
    }
    if ($null -eq $probeResult) {
        $probeResult = ConvertFrom-WinPrivProbeOutput -Text $result.StdOut
        if ($null -eq $probeResult -and $null -eq $parseError) {
            $parseError = 'The probe produced no parseable JSON output.'
        }
    }
    $result | Add-Member -NotePropertyName Operation -NotePropertyValue $Operation
    $result | Add-Member -NotePropertyName ProbeHost -NotePropertyValue $hostPath
    $result | Add-Member -NotePropertyName ProbeResult -NotePropertyValue $probeResult
    $result | Add-Member -NotePropertyName ProbeOutputPath -NotePropertyValue $probeOutputPath
    $result | Add-Member -NotePropertyName ProbeParseError -NotePropertyValue $parseError
    if ($null -ne $parseError) { $result.Succeeded = $false }

    if ($ownedSandbox -and $result.Succeeded -and $env:WINPRIV_TEST_KEEP_ARTIFACTS -ne '1') {
        try { [void](Remove-WinPrivSandbox -Sandbox $Sandbox -Force) }
        catch {
            $result.Succeeded = $false
            $result | Add-Member -NotePropertyName CleanupError -NotePropertyValue $_.Exception.Message
        }
    }
    return $result
}

function Test-WinPrivElevated {
    [CmdletBinding()]
    param()
    if (-not (Test-WinPrivWindows)) { return $false }
    try {
        Initialize-WinPrivNativeMethods
        return [WinPriv.TestHarness.NativeMethods]::IsCurrentTokenElevated()
    }
    catch {
        return $false
    }
}

function Get-WinPrivObjectValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}

function Test-WinPrivProcessIdentity {
    param(
        [int]$ProcessId,
        [string]$ExpectedPath,
        [string]$ExpectedStartUtc
    )
    try { $process = Get-Process -Id $ProcessId -ErrorAction Stop } catch { return $false }
    try {
        if (-not [string]::IsNullOrWhiteSpace($ExpectedPath) -and
            [IO.Path]::GetFullPath($process.Path) -ne [IO.Path]::GetFullPath($ExpectedPath)) { return $false }
        if (-not [string]::IsNullOrWhiteSpace($ExpectedStartUtc)) {
            $expected = [DateTime]::Parse($ExpectedStartUtc).ToUniversalTime()
            $actual = $process.StartTime.ToUniversalTime()
            if ([Math]::Abs(($actual - $expected).TotalSeconds) -gt 1) { return $false }
        }
        return $true
    }
    catch { return $false }
    finally { $process.Dispose() }
}

function Invoke-WinPrivStaleRunReconciliation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SuiteRoot,
        [string]$CurrentRunRoot,
        [string]$ReportPath
    )

    $suitePath = [IO.Path]::GetFullPath($SuiteRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (-not (Test-Path -LiteralPath $suitePath -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $suitePath -Force)
    }
    $currentPath = if ([string]::IsNullOrWhiteSpace($CurrentRunRoot)) { $null } else { [IO.Path]::GetFullPath($CurrentRunRoot) }
    $runs = New-Object 'System.Collections.Generic.List[object]'
    $manualRecovery = New-Object 'System.Collections.Generic.List[object]'

    foreach ($directory in Get-ChildItem -LiteralPath $suitePath -Directory -Force -ErrorAction SilentlyContinue) {
        $root = [IO.Path]::GetFullPath($directory.FullName)
        if ($null -ne $currentPath -and $root -eq $currentPath) { continue }
        $runRecord = [ordered]@{ Root = $root; Status = 'Unknown'; Actions = @(); Reason = $null }
        $markerPath = Join-Path $root '.winpriv-test-run.json'
        if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not (Test-WinPrivPathWithin -Child $root -Parent $suitePath) -or
            -not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
            $runRecord.Status = 'Unvalidated'
            $runRecord.Reason = 'Missing marker, reparse point, or path outside the exact WinPrivTests prefix; no action was taken.'
            [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'RunRoot'; Identifier = $root; Reason = $runRecord.Reason })
            [void]$runs.Add([pscustomobject]$runRecord)
            continue
        }

        try {
            $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json -ErrorAction Stop
            $markerGuid = [Guid]::Empty
            if (-not [Guid]::TryParse([string]$marker.MarkerId, [ref]$markerGuid) -or
                [IO.Path]::GetFullPath([string]$marker.Root) -ne $root -or
                [string]$marker.RunId -ne $directory.Name) {
                throw 'Run marker identity does not match its directory.'
            }
        }
        catch {
            $runRecord.Status = 'Unvalidated'
            $runRecord.Reason = $_.Exception.Message
            [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'RunRoot'; Identifier = $root; Reason = $runRecord.Reason })
            [void]$runs.Add([pscustomobject]$runRecord)
            continue
        }

        $ownerId = [int](Get-WinPrivObjectValue -Object $marker.Owner -Name 'ProcessId')
        $ownerPath = [string](Get-WinPrivObjectValue -Object $marker.Owner -Name 'Path')
        $ownerStarted = [string](Get-WinPrivObjectValue -Object $marker.Owner -Name 'StartTimeUtc')
        if ($ownerId -gt 0 -and (Test-WinPrivProcessIdentity -ProcessId $ownerId -ExpectedPath $ownerPath -ExpectedStartUtc $ownerStarted)) {
            $runRecord.Status = 'Active'
            $runRecord.Reason = 'The marker owner process is still running with the recorded identity.'
            [void]$runs.Add([pscustomobject]$runRecord)
            continue
        }

        $manualStartCount = $manualRecovery.Count
        $entries = @()
        $earlyReparsePoints = @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        })
        if ($earlyReparsePoints.Count -gt 0) {
            foreach ($reparsePoint in $earlyReparsePoints) {
                [void]$manualRecovery.Add([pscustomobject]@{
                    Kind = 'ReparsePoint'; Identifier = $reparsePoint.FullName
                    Reason = 'A stale run contains a reparse point; reconciliation and recursive deletion were refused.'
                    StaleRunRoot = $root
                })
            }
            $runRecord.Status = 'ManualRecoveryRequired'
            $runRecord.Reason = 'The stale run contains one or more reparse points.'
            [void]$runs.Add([pscustomobject]$runRecord)
            continue
        }
        $sandboxesRoot = Join-Path $root 'sandboxes'
        if (Test-Path -LiteralPath $sandboxesRoot -PathType Container) {
            foreach ($sandboxDirectory in Get-ChildItem -LiteralPath $sandboxesRoot -Directory -Force -ErrorAction SilentlyContinue) {
                $sandboxRoot = [IO.Path]::GetFullPath($sandboxDirectory.FullName)
                $sandboxMarkerPath = Join-Path $sandboxRoot '.winpriv-test-sandbox.json'
                try {
                    if (($sandboxDirectory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                        -not (Test-WinPrivPathWithin -Child $sandboxRoot -Parent $sandboxesRoot) -or
                        -not (Test-Path -LiteralPath $sandboxMarkerPath -PathType Leaf)) {
                        throw 'Sandbox is unmarked, a reparse point, or outside the expected sandboxes directory.'
                    }
                    $sandboxMarker = Get-Content -LiteralPath $sandboxMarkerPath -Raw | ConvertFrom-Json -ErrorAction Stop
                    $sandboxGuid = [Guid]::Empty
                    if (-not [Guid]::TryParse([string]$sandboxMarker.MarkerId, [ref]$sandboxGuid) -or
                        [IO.Path]::GetFullPath([string]$sandboxMarker.Root) -ne $sandboxRoot) {
                        throw 'Sandbox marker identity does not match its directory.'
                    }
                    $journalPath = Join-Path $sandboxRoot 'cleanup-journal.jsonl'
                    if (Test-Path -LiteralPath $journalPath -PathType Leaf) {
                        $journalEntries = @(Get-Content -LiteralPath $journalPath | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
                        foreach ($journalEntry in $journalEntries) {
                            $entryGuid = [Guid]::Empty
                            if (-not [Guid]::TryParse([string]$journalEntry.EntryId, [ref]$entryGuid) -or
                                [string]$journalEntry.MarkerId -ne [string]$sandboxMarker.MarkerId) {
                                throw 'A cleanup journal entry has an invalid GUID or mismatched sandbox marker.'
                            }
                        }
                        $entries += $journalEntries
                    }
                }
                catch {
                    [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'Sandbox'; Identifier = $sandboxRoot; Reason = $_.Exception.Message })
                }
            }
        }

        $actions = New-Object 'System.Collections.Generic.List[object]'
        if ($entries.Count -gt 0) {
            $recoverySandbox = [pscustomobject]@{
                MarkerId = [string]$marker.MarkerId
                Root = $root
                Journal = $null
            }
            # Reuse the same exact-marker repair logic used by normal teardown,
            # but do not treat recovered state as a new test failure: stale-run
            # recovery is itself the purpose of this pass.
            $combinedJournal = Join-Path $root 'stale-reconciliation-journal.jsonl'
            $recoverySandbox.Journal = $combinedJournal
            $entries | ForEach-Object { Write-WinPrivJsonLine -Path $combinedJournal -Value $_ }
            try {
                $repair = Repair-WinPrivSandboxJournal -Sandbox $recoverySandbox -AllowRecovery
                if ($null -ne $repair) {
                    foreach ($delta in @($repair.Deltas)) {
                        [void]$actions.Add([pscustomobject]@{
                            Kind = [string]$delta.Kind; Identifier = [string]$delta.Identifier
                            Status = [string]$delta.Action
                        })
                    }
                    foreach ($error in @($repair.Errors)) {
                        [void]$manualRecovery.Add([pscustomobject]@{
                            Kind = [string]$error.Kind; Identifier = [string]$error.Identifier
                            Reason = [string]$error.Reason; StaleRunRoot = $root
                        })
                    }
                }
            }
            finally {
                Remove-Item -LiteralPath $combinedJournal -Force -ErrorAction SilentlyContinue
            }
            $entries = @($entries | Where-Object {
                $_.Kind -notin @('Process', 'Registry', 'Acl', 'LsaRight', 'LocalPrincipalIntent', 'LocalPrincipal')
            })
        }
        foreach ($entry in @($entries | Where-Object Kind -eq 'Process')) {
            $metadata = $entry.Metadata
            $processId = [int](Get-WinPrivObjectValue -Object $metadata -Name 'ProcessId')
            if ($processId -le 0) { [void][int]::TryParse([string]$entry.Identifier, [ref]$processId) }
            $expectedPath = [string](Get-WinPrivObjectValue -Object $metadata -Name 'Path')
            $expectedStart = [string](Get-WinPrivObjectValue -Object $metadata -Name 'StartTimeUtc')
            $processExists = $null -ne (Get-Process -Id $processId -ErrorAction SilentlyContinue)
            if (-not $processExists) {
                [void]$actions.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $processId; Status = 'AlreadyAbsent' })
            }
            elseif ($processId -gt 0 -and -not [string]::IsNullOrWhiteSpace($expectedPath) -and
                -not [string]::IsNullOrWhiteSpace($expectedStart) -and
                (Test-WinPrivProcessIdentity -ProcessId $processId -ExpectedPath $expectedPath -ExpectedStartUtc $expectedStart)) {
                try {
                    Stop-Process -Id $processId -Force -ErrorAction Stop
                    [void]$actions.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $processId; Status = 'Terminated' })
                }
                catch { [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $processId; Reason = $_.Exception.Message }) }
            }
            else {
                [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'Process'; Identifier = $processId; Reason = 'PID exists but path/start-time evidence is incomplete or does not match; it was not terminated.' })
            }
        }

        foreach ($entry in @($entries | Where-Object Kind -eq 'Acl')) {
            $path = [string]$entry.Identifier
            $sddl = [string](Get-WinPrivObjectValue -Object $entry.OriginalState -Name 'Sddl')
            if ([string]::IsNullOrWhiteSpace($sddl) -and $entry.OriginalState -is [string]) { $sddl = [string]$entry.OriginalState }
            if (-not (Test-WinPrivPathWithin -Child $path -Parent $root) -or [string]::IsNullOrWhiteSpace($sddl)) {
                [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Reason = 'ACL path is outside the stale run or original SDDL is missing.' })
                continue
            }
            if (-not (Test-Path -LiteralPath $path)) {
                [void]$actions.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Status = 'PathAlreadyAbsent' })
                continue
            }
            try {
                $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
                $acl.SetSecurityDescriptorSddlForm($sddl)
                Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
                [void]$actions.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Status = 'Restored' })
            }
            catch { [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'Acl'; Identifier = $path; Reason = $_.Exception.Message }) }
        }

        $hasLsaEntries = @($entries | Where-Object Kind -eq 'LsaRight').Count -gt 0
        foreach ($entry in @($entries | Where-Object Kind -eq 'LocalPrincipal')) {
            $name = [string]$entry.Identifier
            if ($hasLsaEntries) {
                [void]$actions.Add([pscustomobject]@{ Kind = 'LocalPrincipal'; Identifier = $name; Status = 'RetainedForLsaRecovery' })
                continue
            }
            $sid = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'Sid')
            $type = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'Type')
            $description = [string](Get-WinPrivObjectValue -Object $entry.Metadata -Name 'Description')
            if ($type -notin @('user', 'group') -or [string]::IsNullOrWhiteSpace($name) -or
                [string]::IsNullOrWhiteSpace($sid) -or [string]::IsNullOrWhiteSpace($description)) {
                [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'LocalPrincipal'; Identifier = $name; Reason = 'Name, SID, type, and description marker are all required.' })
                continue
            }
            try {
                $principal = [ADSI]"WinNT://$env:COMPUTERNAME/$name,$type"
                $sidBytes = [byte[]]$principal.Properties['objectSid'].Value
                $actualSid = (New-Object Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                $actualDescription = [string]$principal.Properties['Description'].Value
                if ($actualSid -ne $sid -or $actualDescription -ne $description) {
                    throw 'The current principal SID or description marker does not match the journal.'
                }
                $computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
                [void]$computer.Delete($type, $name)
                [void]$actions.Add([pscustomobject]@{ Kind = 'LocalPrincipal'; Identifier = $name; Status = 'Removed'; Sid = $sid })
            }
            catch {
                $notFound = $_.Exception.Message -match 'not found|unknown user|no such'
                if ($notFound) { [void]$actions.Add([pscustomobject]@{ Kind = 'LocalPrincipal'; Identifier = $name; Status = 'AlreadyAbsent'; Sid = $sid }) }
                else { [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'LocalPrincipal'; Identifier = $name; Reason = $_.Exception.Message; Sid = $sid }) }
            }
        }

        foreach ($entry in @($entries | Where-Object Kind -eq 'LsaRight')) {
            [void]$manualRecovery.Add([pscustomobject]@{
                Kind = 'LsaRight'
                Identifier = [string]$entry.Identifier
                Reason = 'Exact LSA policy restoration requires manual recovery; the original state is retained in this journal entry.'
                OriginalState = $entry.OriginalState
                StaleRunRoot = $root
            })
        }
        foreach ($entry in @($entries | Where-Object Kind -eq 'Path')) {
            $ownedPath = [string]$entry.Identifier
            if (-not (Test-WinPrivPathWithin -Child $ownedPath -Parent $root)) {
                [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'Path'; Identifier = $ownedPath; Reason = 'Journaled path is outside the validated stale run root and was not removed.'; StaleRunRoot = $root })
            }
            else {
                [void]$actions.Add([pscustomobject]@{ Kind = 'Path'; Identifier = $ownedPath; Status = 'CoveredByRunRootCleanup' })
            }
        }
        foreach ($entry in @($entries | Where-Object {
            $_.Kind -notin @('Process', 'Acl', 'LocalPrincipalIntent', 'LocalPrincipal', 'LsaRight', 'Path')
        })) {
            [void]$manualRecovery.Add([pscustomobject]@{ Kind = [string]$entry.Kind; Identifier = [string]$entry.Identifier; Reason = 'This journal kind has no conservative automatic reconciliation handler.' })
        }

        foreach ($reparsePoint in Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        }) {
            [void]$manualRecovery.Add([pscustomobject]@{
                Kind = 'ReparsePoint'; Identifier = $reparsePoint.FullName
                Reason = 'A stale run contains a reparse point; recursive deletion was refused.'; StaleRunRoot = $root
            })
        }
        $hasBlockingJournal = $manualRecovery.Count -gt $manualStartCount
        if (-not $hasBlockingJournal) {
            try {
                Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
                $runRecord.Status = 'Reconciled'
            }
            catch {
                $runRecord.Status = 'ManualRecoveryRequired'
                $runRecord.Reason = $_.Exception.Message
                [void]$manualRecovery.Add([pscustomobject]@{ Kind = 'RunRoot'; Identifier = $root; Reason = $_.Exception.Message; StaleRunRoot = $root })
            }
        }
        else {
            $runRecord.Status = 'ManualRecoveryRequired'
            $runRecord.Reason = 'One or more journal entries could not be restored conservatively; evidence was retained.'
        }
        $runRecord.Actions = @($actions | ForEach-Object { $_ })
        [void]$runs.Add([pscustomobject]$runRecord)
    }

    $report = [ordered]@{
        SchemaVersion          = 1
        GeneratedUtc           = [DateTime]::UtcNow.ToString('o')
        SuiteRoot              = $suitePath
        Runs                   = @($runs | ForEach-Object { $_ })
        ManualRecovery         = @($manualRecovery | ForEach-Object { $_ })
        HasFailures            = $manualRecovery.Count -gt 0
        ManualRecoveryCount    = $manualRecovery.Count
    }
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        $reportDirectory = Split-Path -Parent $ReportPath
        if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) { [void](New-Item -ItemType Directory -Path $reportDirectory -Force) }
        [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 50), (New-Object Text.UTF8Encoding($false)))
    }
    return [pscustomobject]$report
}

function Add-WinPrivCapabilityResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][ValidateSet('x86', 'x64', 'ARM64', 'All')][string]$Architecture,
        [Parameter(Mandatory = $true)][ValidateSet('Verified', 'Failed', 'PartiallyVerified', 'Unavailable')][string]$Status,
        [string]$Reason,
        $Evidence
    )
    if ($Status -ne 'Verified' -and [string]::IsNullOrWhiteSpace($Reason)) {
        throw "Capability '$Id' status '$Status' requires a reason."
    }
    $result = [pscustomobject]@{
        SchemaVersion = 1
        Id            = $Id
        Architecture  = $Architecture
        Status        = $Status
        Reason        = $Reason
        Evidence      = $Evidence
        Profile       = $env:WINPRIV_TEST_PROFILE
        TimestampUtc  = [DateTime]::UtcNow.ToString('o')
        ProcessId     = $PID
    }
    [void]$script:CapabilityResults.Add($result)
    $path = $env:WINPRIV_TEST_CAPABILITY_RESULTS_PATH
    if (-not [string]::IsNullOrWhiteSpace($path)) {
        Write-WinPrivJsonLine -Path $path -Value $result
    }
    if ($Status -in @('Unavailable', 'PartiallyVerified') -and
        -not [string]::IsNullOrWhiteSpace($env:WINPRIV_TEST_EXPECTED_SKIP_EVENTS_PATH)) {
        $skipFrame = Get-PSCallStack | Where-Object Command -eq 'Skip-WinPrivCapability' | Select-Object -First 1
        if ($null -ne $skipFrame) {
            Write-WinPrivJsonLine -Path $env:WINPRIV_TEST_EXPECTED_SKIP_EVENTS_PATH -Value ([pscustomobject]@{
                Id = $Id; Architecture = $Architecture; Status = $Status; Reason = $Reason
                ScriptName = $skipFrame.ScriptName; ScriptLineNumber = $skipFrame.ScriptLineNumber
                TimestampUtc = [DateTime]::UtcNow.ToString('o')
            })
        }
    }
    return $result
}

function Get-WinPrivCapabilityResults {
    [CmdletBinding()]
    param([switch]$Latest)
    $results = @()
    $path = $env:WINPRIV_TEST_CAPABILITY_RESULTS_PATH
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        $results = @(Get-Content -LiteralPath $path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
    }
    else {
        $results = @($script:CapabilityResults | ForEach-Object { $_ })
    }
    if (-not $Latest) { return $results }
    $latestResults = @()
    foreach ($group in ($results | Group-Object { "$($_.Id)`0$($_.Architecture)" })) {
        $latestResults += $group.Group | Sort-Object TimestampUtc | Select-Object -Last 1
    }
    return $latestResults
}

function Clear-WinPrivCapabilityResults {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param()
    $script:CapabilityResults.Clear()
    $path = $env:WINPRIV_TEST_CAPABILITY_RESULTS_PATH
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf) -and
        $PSCmdlet.ShouldProcess($path, 'Remove capability result store')) {
        Remove-Item -LiteralPath $path -Force
    }
}

function Import-WinPrivCapabilityManifest {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path.EndsWith('.psd1', [StringComparison]::OrdinalIgnoreCase)) {
        # PowerShell data files produce Hashtables, whose keys are not exposed via
        # PSObject.Properties.  Normalize once so JSON and PSD1 manifests behave
        # identically throughout the coverage code (including on Windows PS 5.1).
        $data = Import-PowerShellDataFile -LiteralPath $Path
        return $data | ConvertTo-Json -Depth 50 | ConvertFrom-Json
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Test-WinPrivCapabilityProfile {
    param([string]$CapabilityProfile, [string]$RunProfile)
    if ([string]::IsNullOrWhiteSpace($CapabilityProfile)) { return $true }
    switch ($RunProfile) {
        'Safe' { return $CapabilityProfile -eq 'Safe' }
        'Admin' { return $CapabilityProfile -eq 'Admin' }
        'Full' { return $CapabilityProfile -in @('Safe', 'Admin') }
        default { return $CapabilityProfile -eq $RunProfile }
    }
}

function Complete-WinPrivCapabilityReport {
    [CmdletBinding()]
    param(
        [string]$ManifestPath = $env:WINPRIV_TEST_CAPABILITY_MANIFEST,
        [string]$OutputPath = $env:WINPRIV_TEST_COVERAGE_PATH,
        [string[]]$Architecture,
        [ValidateSet('Safe', 'Admin', 'Full')][string]$Profile = $env:WINPRIV_TEST_PROFILE,
        [switch]$FailOnGap
    )
    if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
        $testsRoot = [IO.Path]::GetFullPath((Join-Path $script:ModuleRoot '..\..'))
        foreach ($name in @('Capabilities.psd1', 'CapabilityManifest.psd1', 'Capabilities.json', 'CapabilityManifest.json')) {
            $candidate = Join-Path $testsRoot $name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $ManifestPath = $candidate; break }
        }
    }
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        throw 'OutputPath was not supplied and WINPRIV_TEST_COVERAGE_PATH is not set.'
    }
    if ($null -eq $Architecture -or $Architecture.Count -eq 0) {
        $Architecture = @($env:WINPRIV_TEST_ARCHITECTURES -split '[,;]' | Where-Object { $_ })
    }
    if ([string]::IsNullOrWhiteSpace($Profile)) { $Profile = 'Safe' }

    $manifest = $null
    $capabilities = @()
    if (-not [string]::IsNullOrWhiteSpace($ManifestPath) -and (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        $manifest = Import-WinPrivCapabilityManifest -Path $ManifestPath
        $capabilities = @($manifest.Capabilities | Where-Object {
            (Test-WinPrivCapabilityProfile -CapabilityProfile ([string]$_.Profile) -RunProfile $Profile) -or
            ($_.PSObject.Properties['DefaultStatus'] -and -not [string]::IsNullOrWhiteSpace([string]$_.DefaultStatus))
        })
    }
    $results = @(Get-WinPrivCapabilityResults -Latest)
    $coverage = New-Object 'System.Collections.Generic.List[object]'
    $missing = New-Object 'System.Collections.Generic.List[object]'
    $unexpectedNonVerified = New-Object 'System.Collections.Generic.List[object]'

    foreach ($capability in $capabilities) {
        $capabilityArchitectures = @($Architecture)
        if ($capability.Id -match '^artifact\.build-(x86|x64|arm64)$') {
            $capabilityArchitectures = @(switch ($Matches[1].ToLowerInvariant()) {
                'x86' { 'x86' }
                'x64' { 'x64' }
                'arm64' { 'ARM64' }
            })
        }
        if ($capability.PSObject.Properties['Architectures']) {
            $capabilityArchitectures = @($capability.Architectures)
        }
        elseif ($capability.PSObject.Properties['Architecture']) {
            $capabilityArchitectures = @($capability.Architecture)
        }
        # An explicit All is one global capability result. Unannotated
        # capabilities already use the requested per-architecture scope above.
        foreach ($item in $capabilityArchitectures) {
            $matching = @($results | Where-Object { $_.Id -eq $capability.Id -and ($_.Architecture -eq $item -or $_.Architecture -eq 'All') } | Select-Object -Last 1)
            $result = if ($matching.Count) { $matching[0] } else { $null }
            $seeded = $false
            if ($null -eq $result -and $capability.PSObject.Properties['DefaultStatus'] -and -not [string]::IsNullOrWhiteSpace([string]$capability.DefaultStatus)) {
                $result = [pscustomobject]@{
                    Id           = $capability.Id
                    Architecture = $item
                    Status       = [string]$capability.DefaultStatus
                    Reason       = [string]$capability.Reason
                    Evidence     = $null
                    Profile      = $Profile
                    TimestampUtc = [DateTime]::UtcNow.ToString('o')
                }
                $seeded = $true
            }
            if ($null -eq $result) {
                $required = -not $capability.PSObject.Properties['Required'] -or [bool]$capability.Required
                $entry = [pscustomobject]@{
                    Id           = $capability.Id
                    Architecture = $item
                    Required     = $required
                    Test         = $capability.Test
                }
                [void]$missing.Add($entry)
                [void]$coverage.Add([pscustomobject]@{
                    Id = $capability.Id; Architecture = $item; Status = 'Failed'
                    Reason = 'No capability evidence event was emitted; this manifest capability is missing test evidence.'
                    Seeded = $false
                    Gate = if ($capability.PSObject.Properties['Gate']) { [string]$capability.Gate } else { $null }
                })
                continue
            }
            [void]$coverage.Add([pscustomobject]@{
                Id = $capability.Id; Architecture = $item; Status = $result.Status; Reason = $result.Reason; Seeded = $seeded; Evidence = $result.Evidence
                Gate = if ($capability.PSObject.Properties['Gate']) { [string]$capability.Gate } else { $null }
            })
            $hasGate = $capability.PSObject.Properties['Gate'] -and -not [string]::IsNullOrWhiteSpace([string]$capability.Gate)
            $hasDefault = $capability.PSObject.Properties['DefaultStatus'] -and -not [string]::IsNullOrWhiteSpace([string]$capability.DefaultStatus)
            if ($result.Status -eq 'Failed' -or
                ($result.Status -in @('PartiallyVerified', 'Unavailable') -and -not $hasGate -and -not $hasDefault)) {
                [void]$unexpectedNonVerified.Add($result)
            }
        }
    }

    $manifestIds = @($capabilities | ForEach-Object { [string]$_.Id } | Select-Object -Unique)
    # Keep this as an actual array even when the filter emits no objects.  Assigning
    # the output of an if statement unwraps an empty @() to $null (and a single
    # result to a scalar), which makes .Count fail under Set-StrictMode.
    $unmanifested = @()
    if ($manifestIds.Count -gt 0) {
        $unmanifested = @($results | Where-Object { $_.Id -notin $manifestIds })
    }
    $requiredMissing = @($missing | Where-Object Required)
    $report = [ordered]@{
        SchemaVersion          = 1
        GeneratedUtc           = [DateTime]::UtcNow.ToString('o')
        ManifestPath           = $ManifestPath
        Profile                = $Profile
        Architectures          = @($Architecture)
        ManifestCapabilityCount = $capabilities.Count
        ResultCount            = $results.Count
        Coverage               = @($coverage | ForEach-Object { $_ })
        Missing                = @($missing | ForEach-Object { $_ })
        RequiredMissing        = @($requiredMissing)
        UnexpectedNonVerified  = @($unexpectedNonVerified | ForEach-Object { $_ })
        UnmanifestedResults    = @($unmanifested)
        HasFailures            = $requiredMissing.Count -gt 0 -or $unexpectedNonVerified.Count -gt 0 -or $unmanifested.Count -gt 0
    }
    $directory = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
    [IO.File]::WriteAllText($OutputPath, ($report | ConvertTo-Json -Depth 40), (New-Object Text.UTF8Encoding($false)))
    if ($FailOnGap -and $report.HasFailures) {
        throw "Capability coverage failed: $($requiredMissing.Count) required gaps, $($unexpectedNonVerified.Count) failed/unexpected gated results, and $($unmanifested.Count) unmanifested results."
    }
    return [pscustomobject]$report
}

Export-ModuleMember -Function @(
    'Add-WinPrivCapabilityResult',
    'Add-WinPrivCleanupJournalEntry',
    'Clear-WinPrivCapabilityResults',
    'Complete-WinPrivCapabilityReport',
    'Get-WinPrivCapabilityResults',
    'Get-WinPrivCleanupJournal',
    'Get-WinPrivPeArchitecture',
    'Get-WinPrivTestArchitectures',
    'Get-WinPrivTestHost',
    'Invoke-WinPriv',
    'Invoke-WinPrivContainedProcess',
    'Invoke-WinPrivProbe',
    'Invoke-WinPrivCurrentRunReconciliation',
    'Invoke-WinPrivStaleRunReconciliation',
    'New-WinPrivSandbox',
    'Repair-WinPrivSandboxJournal',
    'Remove-WinPrivSandbox',
    'Test-WinPrivElevated'
)
