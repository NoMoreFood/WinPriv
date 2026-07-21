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

        [DllImport("ntdll.dll")]
        private static extern int NtOpenFile(out IntPtr fileHandle, uint desiredAccess,
            ref FILE_OBJECT_ATTRIBUTES objectAttributes, out FILE_IO_STATUS_BLOCK ioStatusBlock,
            uint shareAccess, uint openOptions);

        [DllImport("ntdll.dll")]
        private static extern int NtCreateFile(out IntPtr fileHandle, uint desiredAccess,
            ref FILE_OBJECT_ATTRIBUTES objectAttributes, out FILE_IO_STATUS_BLOCK ioStatusBlock,
            IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition,
            uint createOptions, IntPtr eaBuffer, uint eaLength);

        public static Dictionary<string, object> RunNativeFile(string api, string path)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr nameStructure = IntPtr.Zero;
            IntPtr handle = IntPtr.Zero;
            try
            {
                string fullPath = Path.GetFullPath(path);
                string nativePath = "\\??\\" + fullPath;
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
                attributes.Attributes = OBJ_CASE_INSENSITIVE;
                FILE_IO_STATUS_BLOCK ioStatus;
                uint access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
                uint share = FILE_SHARE_READ_NATIVE | FILE_SHARE_WRITE_NATIVE | FILE_SHARE_DELETE_NATIVE;
                uint options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;
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
                else throw new ArgumentException("api must be NtOpenFile or NtCreateFile", "api");

                result["path"] = fullPath;
                result["nativePath"] = nativePath;
                result["status"] = status;
                result["statusHex"] = Hex32(status);
                result["ioStatus"] = unchecked((long)ioStatus.Status.ToInt64());
                result["opened"] = status >= 0 && handle != IntPtr.Zero;
                result["success"] = status >= 0 && handle != IntPtr.Zero;
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
                if (nameStructure != IntPtr.Zero) Marshal.FreeHGlobal(nameStructure);
                if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
            }
        }
    }
}
