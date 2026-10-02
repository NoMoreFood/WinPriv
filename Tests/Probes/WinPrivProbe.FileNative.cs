using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace WinPrivProbe
{
    public static partial class Native
    {
        private const uint FILE_READ_DATA = 0x00000001;
        private const uint FILE_READ_ATTRIBUTES = 0x00000080;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint FILE_SHARE_READ_NATIVE = 0x00000001;
        private const uint FILE_SHARE_WRITE_NATIVE = 0x00000002;
        private const uint FILE_SHARE_DELETE_NATIVE = 0x00000004;
        private const uint FILE_OPEN = 0x00000001;
        private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
        private const uint FILE_NON_DIRECTORY_FILE = 0x00000040;
        private const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        private const uint FILE_SHARE_ALL = FILE_SHARE_READ_NATIVE | FILE_SHARE_WRITE_NATIVE | FILE_SHARE_DELETE_NATIVE;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint OPEN_EXISTING = 3;
        private const uint DUPLICATE_SAME_ACCESS = 2;
        private const uint DUPLICATE_CLOSE_SOURCE = 1;
        private const uint PROCESS_DUP_HANDLE = 0x00000040;
        private const uint DELETE_ACCESS = 0x00010000;

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_IO_STATUS_BLOCK
        {
            public IntPtr Status;
            public UIntPtr Information;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_RENAME_INFORMATION
        {
            public uint Flags;
            public IntPtr RootDirectory;
            public uint FileNameLength;
            public ushort FileName;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtOpenFile(out IntPtr fileHandle, uint desiredAccess,
            ref FILE_OBJECT_ATTRIBUTES objectAttributes, out FILE_IO_STATUS_BLOCK ioStatusBlock,
            uint shareAccess, uint openOptions);

        [DllImport("ntdll.dll")]
        private static extern int NtCreateFile(out IntPtr fileHandle, uint desiredAccess,
            ref FILE_OBJECT_ATTRIBUTES objectAttributes, out FILE_IO_STATUS_BLOCK ioStatusBlock,
            IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition,
            uint createOptions, IntPtr eaBuffer, uint eaLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(IntPtr handle, byte[] data, uint size, out uint read, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr targetProcess,
            out IntPtr target, uint access, bool inherit, uint options);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFileAttributesW(string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetFileAttributesExW(string path, int level, IntPtr information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectoryW(string path, IntPtr security);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool RemoveDirectoryW(string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool DeleteFileW(string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateHardLinkW(string path, string existingPath, IntPtr security);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryAttributesFile(ref FILE_OBJECT_ATTRIBUTES attributes, IntPtr information);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryFullAttributesFile(ref FILE_OBJECT_ATTRIBUTES attributes, IntPtr information);

        [DllImport("ntdll.dll")]
        private static extern int NtDeleteFile(ref FILE_OBJECT_ATTRIBUTES attributes);

        [DllImport("ntdll.dll")]
        private static extern int NtSetInformationFile(IntPtr handle, out FILE_IO_STATUS_BLOCK ioStatus,
            IntPtr information, uint length, int informationClass);

        public static Dictionary<string, object> RunNativeFile(string api, string path,
            string root = null, bool duplicateRoot = false, string renameRoot = null,
            string duplicateProcess = null, bool closeSource = false)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr nameStructure = IntPtr.Zero;
            IntPtr handle = IntPtr.Zero;
            IntPtr rootHandle = IntPtr.Zero;
            IntPtr processHandle = IntPtr.Zero;
            IntPtr information = IntPtr.Zero;
            try
            {
                // Resolve absolute and root-relative names for the native call.
                string fullPath = Path.GetFullPath(path);
                string nativePath = fullPath.StartsWith("\\\\?\\", StringComparison.Ordinal)
                    ? "\\??\\" + fullPath.Substring(4)
                    : fullPath.StartsWith("\\\\", StringComparison.Ordinal)
                        ? "\\??\\UNC\\" + fullPath.Substring(2) : "\\??\\" + fullPath;
                if (!String.IsNullOrEmpty(root))
                {
                    nativePath = path;
                    rootHandle = CreateFileW(root, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                        FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
                    if (rootHandle == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception();
                    if (duplicateRoot)
                    {
                        // Exercise source and target process handles with only duplication access.
                        IntPtr sourceProcess = GetCurrentProcess();
                        IntPtr targetProcess = sourceProcess;
                        if (!String.IsNullOrEmpty(duplicateProcess))
                        {
                            processHandle = OpenProcess(PROCESS_DUP_HANDLE, false, GetCurrentProcessId());
                            if (processHandle == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
                            if (duplicateProcess != "target") sourceProcess = processHandle;
                            if (duplicateProcess != "source") targetProcess = processHandle;
                        }
                        IntPtr duplicated;
                        bool success = DuplicateHandle(sourceProcess, rootHandle, targetProcess,
                            out duplicated, 0, false, DUPLICATE_SAME_ACCESS |
                            (closeSource ? DUPLICATE_CLOSE_SOURCE : 0));
                        if (closeSource) rootHandle = IntPtr.Zero;
                        if (!success) throw new System.ComponentModel.Win32Exception();
                        if (rootHandle != IntPtr.Zero) CloseHandle(rootHandle);
                        rootHandle = duplicated;
                    }
                }
                if (!String.IsNullOrEmpty(renameRoot) && !MoveFileExW(root, renameRoot, 0))
                    throw new System.ComponentModel.Win32Exception();

                // Marshal the counted name and object attributes for the requested native API.
                nameBuffer = Marshal.StringToHGlobalUni(nativePath);
                UNICODE_STRING name = new UNICODE_STRING();
                name.Buffer = nameBuffer;
                name.Length = checked((ushort)(nativePath.Length * 2));
                name.MaximumLength = checked((ushort)(name.Length + 2));
                nameStructure = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
                Marshal.StructureToPtr(name, nameStructure, false);

                FILE_OBJECT_ATTRIBUTES attributes = new FILE_OBJECT_ATTRIBUTES();
                attributes.Length = Marshal.SizeOf(typeof(FILE_OBJECT_ATTRIBUTES));
                attributes.ObjectName = nameStructure;
                attributes.RootDirectory = rootHandle;
                attributes.Attributes = OBJ_CASE_INSENSITIVE;
                FILE_IO_STATUS_BLOCK ioStatus = new FILE_IO_STATUS_BLOCK();
                uint access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
                uint share = FILE_SHARE_ALL;
                uint options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;

                // Exercise opens, attributes, and deletion through their native entry points.
                int status;
                if (String.Equals(api, "NtOpenFile", StringComparison.OrdinalIgnoreCase) ||
                    String.Equals(api, "open", StringComparison.OrdinalIgnoreCase))
                {
                    status = NtOpenFile(out handle, access, ref attributes, out ioStatus, share, options);
                    result["api"] = "NtOpenFile";
                }
                else if (String.Equals(api, "NtCreateFile", StringComparison.OrdinalIgnoreCase) ||
                    String.Equals(api, "create", StringComparison.OrdinalIgnoreCase))
                {
                    status = NtCreateFile(out handle, access, ref attributes, out ioStatus,
                        IntPtr.Zero, 0, share, FILE_OPEN, options, IntPtr.Zero, 0);
                    result["api"] = "NtCreateFile";
                }
                else
                {
                    information = Marshal.AllocHGlobal(64);
                    if (api == "NtQueryAttributesFile") status = NtQueryAttributesFile(ref attributes, information);
                    else if (api == "NtQueryFullAttributesFile")
                        status = NtQueryFullAttributesFile(ref attributes, information);
                    else if (api == "NtDeleteFile") status = NtDeleteFile(ref attributes);
                    else throw new ArgumentException("Unknown native file API", "api");
                    result["api"] = api;
                }

                // Capture native status and any readable file content.
                result["path"] = fullPath;
                result["nativePath"] = nativePath;
                result["status"] = status;
                result["statusHex"] = Hex32(status);
                result["ioStatus"] = unchecked((long)ioStatus.Status.ToInt64());
                result["opened"] = status >= 0 && handle != IntPtr.Zero;
                result["success"] = status >= 0;
                if (status >= 0 && handle != IntPtr.Zero)
                {
                    byte[] bytes = new byte[4096];
                    uint read;
                    if (ReadFile(handle, bytes, (uint)bytes.Length, out read, IntPtr.Zero))
                        result["content"] = System.Text.Encoding.UTF8.GetString(bytes, 0, (int)read);
                }
                if (!(bool)result["success"])
                    result["reason"] = "Native file open returned " + Hex32(status) + ".";
                return result;
            }
            catch (Exception error)
            {
                result["reason"] = error.GetType().FullName + ": " + error.Message;
                return result;
            }
            finally
            {
                if (handle != IntPtr.Zero) CloseHandle(handle);
                if (rootHandle != IntPtr.Zero && rootHandle != new IntPtr(-1)) CloseHandle(rootHandle);
                if (processHandle != IntPtr.Zero) CloseHandle(processHandle);
                if (information != IntPtr.Zero) Marshal.FreeHGlobal(information);
                if (nameStructure != IntPtr.Zero) Marshal.FreeHGlobal(nameStructure);
                if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
            }
        }

        public static Dictionary<string, object> RunFilePath(string action, string path,
            string target, string root, bool duplicateRoot, string duplicateProcess = null, bool closeSource = false)
        {
            if (action == "relative-rename") return RunNativeFile("NtOpenFile", path, root, renameRoot: target);
            if (action.StartsWith("Nt", StringComparison.Ordinal))
                return RunNativeFile(action, path, root, duplicateRoot,
                    duplicateProcess: duplicateProcess, closeSource: closeSource);
            Dictionary<string, object> result = MethodResult(true, false, null);
            try
            {
                // Exercise the public file APIs and capture observable results.
                bool success = true;
                switch (action)
                {
                    case "read": result["content"] = File.ReadAllText(path); break;
                    case "write": File.WriteAllText(path, target); break;
                    case "attributes":
                        uint attributes = GetFileAttributesW(path);
                        result["attributes"] = attributes;
                        success = attributes != UInt32.MaxValue;
                        break;
                    case "attributes-ex":
                        IntPtr data = Marshal.AllocHGlobal(64);
                        try { success = GetFileAttributesExW(path, 0, data); }
                        finally { Marshal.FreeHGlobal(data); }
                        break;
                    case "mkdir": success = CreateDirectoryW(path, IntPtr.Zero); break;
                    case "rmdir": success = RemoveDirectoryW(path); break;
                    case "delete": success = DeleteFileW(path); break;
                    case "move": success = MoveFileExW(path, target, 1); break;
                    case "link": success = CreateHardLinkW(target, path, IntPtr.Zero); break;
                    case "native-rename":
                    {
                        // Pass the counted destination unchanged to the native rename API.
                        IntPtr handle = CreateFileW(path, DELETE_ACCESS | SYNCHRONIZE, FILE_SHARE_ALL,
                            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
                        if (handle == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception();
                        IntPtr information = IntPtr.Zero;
                        try
                        {
                            byte[] name = System.Text.Encoding.Unicode.GetBytes(target);
                            int offset = Marshal.OffsetOf(typeof(FILE_RENAME_INFORMATION), "FileName").ToInt32();
                            int size = Math.Max(Marshal.SizeOf(typeof(FILE_RENAME_INFORMATION)), offset + name.Length);
                            information = Marshal.AllocHGlobal(size);
                            FILE_RENAME_INFORMATION rename = new FILE_RENAME_INFORMATION();
                            rename.Flags = 1;
                            rename.FileNameLength = (uint)name.Length;
                            Marshal.StructureToPtr(rename, information, false);
                            Marshal.Copy(name, 0, IntPtr.Add(information, offset), name.Length);
                            FILE_IO_STATUS_BLOCK ioStatus;
                            int status = NtSetInformationFile(handle, out ioStatus, information, (uint)size, 10);
                            result["statusHex"] = Hex32(status);
                            success = status >= 0;
                        }
                        finally
                        {
                            if (information != IntPtr.Zero) Marshal.FreeHGlobal(information);
                            CloseHandle(handle);
                        }
                        break;
                    }
                    case "list": result["entries"] = Directory.GetFileSystemEntries(path, "*"); break;
                    default: throw new ArgumentException("Unknown file path action", "action");
                }
                result["success"] = success;
                if (!success) result["lastError"] = Marshal.GetLastWin32Error();
            }
            catch (Exception error)
            {
                result["errorType"] = error.GetType().FullName;
                result["hresult"] = error.HResult;
                result["reason"] = error.Message;
            }
            return result;
        }

    }
}
