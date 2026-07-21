using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace WinPrivProbe
{
    public static partial class Native
    {
        private const uint KEY_QUERY_VALUE = 0x0001;
        private const uint KEY_ENUMERATE_SUB_KEYS = 0x0008;
        private const uint KEY_WOW64_64KEY = 0x0100;
        private const uint KEY_WOW64_32KEY = 0x0200;
        private const int ERROR_SUCCESS = 0;
        private const int ERROR_NO_MORE_ITEMS = 259;
        private const uint ERROR_BUFFER_OVERFLOW = 111;
        private const uint ERROR_NO_DATA = 232;
        private const int STATUS_SUCCESS = 0;
        private const int STATUS_BUFFER_OVERFLOW = unchecked((int)0x80000005);
        private const int STATUS_NO_MORE_ENTRIES = unchecked((int)0x8000001A);
        private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);
        private const int KeyValueBasicInformation = 0;
        private const int KeyValueFullInformation = 1;
        private const int KeyValuePartialInformation = 2;
        private const int KeyValueFullInformationAlign64 = 3;
        private const int KeyValuePartialInformationAlign64 = 4;
        private const int AF_UNSPEC = 0;
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;
        private const int SOCKET_ERROR = -1;
        private const int WSAEFAULT = 10014;
        private const int NS_DNS = 12;
        private const uint LUP_RETURN_NAME = 0x0010;
        private const uint LUP_RETURN_ADDR = 0x0100;
        private const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WKSTA_TRANSPORT_INFO_0
        {
            public uint wkti0_quality_of_service;
            public uint wkti0_number_of_vcs;
            public IntPtr wkti0_transport_name;
            public IntPtr wkti0_transport_address;
            public int wkti0_wan_ish;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SOCKET_ADDRESS
        {
            public IntPtr lpSockaddr;
            public int iSockaddrLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CSADDR_INFO
        {
            public SOCKET_ADDRESS LocalAddr;
            public SOCKET_ADDRESS RemoteAddr;
            public int iSocketType;
            public int iProtocol;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WSAQUERYSETW
        {
            public uint dwSize;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpszServiceInstanceName;
            public IntPtr lpServiceClassId;
            public IntPtr lpVersion;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpszComment;
            public uint dwNameSpace;
            public IntPtr lpNSProviderId;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpszContext;
            public uint dwNumberOfProtocols;
            public IntPtr lpafpProtocols;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpszQueryString;
            public uint dwNumberOfCsAddrs;
            public IntPtr lpcsaBuffer;
            public uint dwOutputFlags;
            public IntPtr lpBlob;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct WSAQUERYSETA
        {
            public uint dwSize;
            [MarshalAs(UnmanagedType.LPStr)] public string lpszServiceInstanceName;
            public IntPtr lpServiceClassId;
            public IntPtr lpVersion;
            [MarshalAs(UnmanagedType.LPStr)] public string lpszComment;
            public uint dwNameSpace;
            public IntPtr lpNSProviderId;
            [MarshalAs(UnmanagedType.LPStr)] public string lpszContext;
            public uint dwNumberOfProtocols;
            public IntPtr lpafpProtocols;
            [MarshalAs(UnmanagedType.LPStr)] public string lpszQueryString;
            public uint dwNumberOfCsAddrs;
            public IntPtr lpcsaBuffer;
            public uint dwOutputFlags;
            public IntPtr lpBlob;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegOpenKeyExW(IntPtr root, string subKey, uint options,
            uint desiredAccess, out IntPtr key);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegQueryValueExW(IntPtr key, string valueName, IntPtr reserved,
            out uint type, IntPtr data, ref uint dataLength);

        [DllImport("advapi32.dll")]
        private static extern int RegCloseKey(IntPtr key);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryValueKey(IntPtr key, ref UNICODE_STRING valueName,
            int informationClass, IntPtr information, uint length, out uint resultLength);

        [DllImport("ntdll.dll")]
        private static extern int NtEnumerateValueKey(IntPtr key, uint index,
            int informationClass, IntPtr information, uint length, out uint resultLength);

        [DllImport("iphlpapi.dll")]
        private static extern uint GetAdaptersInfo(IntPtr adapterInfo, ref uint sizePointer);

        [DllImport("iphlpapi.dll")]
        private static extern uint GetAdaptersAddresses(uint family, uint flags, IntPtr reserved,
            IntPtr adapterAddresses, ref uint sizePointer);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetWkstaTransportEnum(string serverName, uint level,
            out IntPtr buffer, uint preferredMaximumLength, out uint entriesRead,
            out uint totalEntries, ref uint resumeHandle);

        [DllImport("netapi32.dll")]
        private static extern uint NetApiBufferFree(IntPtr buffer);

        [DllImport("ws2_32.dll")]
        private static extern int WSAStartup(ushort versionRequested, IntPtr wsaData);

        [DllImport("ws2_32.dll")]
        private static extern int WSACleanup();

        [DllImport("ws2_32.dll")]
        private static extern int WSAGetLastError();

        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WSALookupServiceBeginW(ref WSAQUERYSETW restrictions,
            uint controlFlags, out IntPtr lookup);

        [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern int WSALookupServiceBeginA(ref WSAQUERYSETA restrictions,
            uint controlFlags, out IntPtr lookup);

        [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int WSALookupServiceNextW(IntPtr lookup, uint controlFlags,
            ref uint bufferLength, IntPtr results);

        [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern int WSALookupServiceNextA(IntPtr lookup, uint controlFlags,
            ref uint bufferLength, IntPtr results);

        [DllImport("ws2_32.dll")]
        private static extern int WSALookupServiceEnd(IntPtr lookup);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        private static extern int AmsiInitialize(string applicationName, out IntPtr context);

        [DllImport("amsi.dll")]
        private static extern void AmsiUninitialize(IntPtr context);

        [DllImport("amsi.dll")]
        private static extern int AmsiOpenSession(IntPtr context, out IntPtr session);

        [DllImport("amsi.dll")]
        private static extern void AmsiCloseSession(IntPtr context, IntPtr session);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        private static extern int AmsiScanString(IntPtr context, string value, string contentName,
            IntPtr session, out int result);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        private static extern int AmsiScanBuffer(IntPtr context, byte[] value, uint length,
            string contentName, IntPtr session, out int result);

        private static IntPtr RegistryRoot(string root)
        {
            if (String.Equals(root, "HKCR", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(root, "HKEY_CLASSES_ROOT", StringComparison.OrdinalIgnoreCase))
                return new IntPtr(unchecked((int)0x80000000));
            if (String.Equals(root, "HKCU", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(root, "HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
                return new IntPtr(unchecked((int)0x80000001));
            if (String.Equals(root, "HKLM", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(root, "HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
                return new IntPtr(unchecked((int)0x80000002));
            if (String.Equals(root, "HKU", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(root, "HKEY_USERS", StringComparison.OrdinalIgnoreCase))
                return new IntPtr(unchecked((int)0x80000003));
            if (String.Equals(root, "HKCC", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(root, "HKEY_CURRENT_CONFIG", StringComparison.OrdinalIgnoreCase))
                return new IntPtr(unchecked((int)0x80000005));
            throw new ArgumentException("Unsupported registry root: " + root);
        }

        private static uint RegistryViewAccess(string view)
        {
            if (String.Equals(view, "32", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(view, "x86", StringComparison.OrdinalIgnoreCase)) return KEY_WOW64_32KEY;
            if (String.Equals(view, "64", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(view, "x64", StringComparison.OrdinalIgnoreCase)) return KEY_WOW64_64KEY;
            return 0;
        }

        private static Dictionary<string, object> RegistryData(int status, uint type, byte[] data)
        {
            Dictionary<string, object> result = MethodResult(true, status == ERROR_SUCCESS,
                status == ERROR_SUCCESS ? null : Win32Message(status));
            result["status"] = status;
            result["statusHex"] = Hex32(status);
            result["type"] = type;
            result["dataLength"] = data == null ? 0 : data.Length;
            result["dataBase64"] = data == null ? null : Convert.ToBase64String(data);
            result["displayValue"] = DecodeRegistryValue(type, data);
            return result;
        }

        private static object DecodeRegistryValue(uint type, byte[] data)
        {
            if (data == null) return null;
            if (type == 1 || type == 2)
                return Encoding.Unicode.GetString(data).TrimEnd('\0');
            if (type == 4 && data.Length >= 4) return BitConverter.ToUInt32(data, 0);
            if (type == 11 && data.Length >= 8) return BitConverter.ToUInt64(data, 0);
            if (type == 7)
                return Encoding.Unicode.GetString(data).TrimEnd('\0').Split(new char[] { '\0' });
            return Convert.ToBase64String(data);
        }

        public static Dictionary<string, object> ReadRegistry(string root, string subKey,
            string valueName, string view)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr key = IntPtr.Zero;
            try
            {
                int open = RegOpenKeyExW(RegistryRoot(root), subKey, 0,
                    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | RegistryViewAccess(view), out key);
                result["root"] = root;
                result["key"] = subKey;
                result["valueName"] = valueName;
                result["view"] = view;
                result["openStatus"] = open;
                if (open != ERROR_SUCCESS)
                {
                    result["reason"] = Win32Message(open);
                    return result;
                }
                result["win32"] = ReadRegistryWin32(key, valueName);
                result["ntBasic"] = ReadRegistryNt(key, valueName, KeyValueBasicInformation);
                result["ntPartial"] = ReadRegistryNt(key, valueName, KeyValuePartialInformation);
                result["ntPartialAlign64"] = ReadRegistryNt(key, valueName, KeyValuePartialInformationAlign64);
                result["ntFull"] = ReadRegistryNt(key, valueName, KeyValueFullInformation);
                result["ntFullAlign64"] = ReadRegistryNt(key, valueName, KeyValueFullInformationAlign64);
                result["ntEnumerate"] = EnumerateRegistryNt(key);
                result["success"] = true;
                return result;
            }
            catch (EntryPointNotFoundException error)
            {
                result["supported"] = false;
                result["reason"] = error.Message;
                return result;
            }
            catch (Exception error)
            {
                result["reason"] = error.GetType().FullName + ": " + error.Message;
                return result;
            }
            finally
            {
                if (key != IntPtr.Zero) RegCloseKey(key);
            }
        }

        public static Dictionary<string, object> ReadRegistryMethod(string root, string subKey,
            string valueName, string view, string method)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr key = IntPtr.Zero;
            try
            {
                int open = RegOpenKeyExW(RegistryRoot(root), subKey, 0,
                    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | RegistryViewAccess(view), out key);
                if (open != ERROR_SUCCESS)
                {
                    result["openStatus"] = open;
                    result["reason"] = Win32Message(open);
                    return result;
                }
                if (String.Equals(method, "win32", StringComparison.OrdinalIgnoreCase))
                    return ReadRegistryWin32(key, valueName);
                if (String.Equals(method, "ntPartial", StringComparison.OrdinalIgnoreCase))
                {
                    Dictionary<string, object> partial = ReadRegistryNt(key, valueName, KeyValuePartialInformation);
                    partial["invalidHandleStatusHex"] = ReadRegistryNt(
                        new IntPtr(0x1234), valueName, KeyValuePartialInformation)["statusHex"];
                    return partial;
                }
                if (String.Equals(method, "ntBasic", StringComparison.OrdinalIgnoreCase))
                    return ReadRegistryNt(key, valueName, KeyValueBasicInformation);
                if (String.Equals(method, "ntPartialAlign64", StringComparison.OrdinalIgnoreCase))
                    return ReadRegistryNt(key, valueName, KeyValuePartialInformationAlign64);
                if (String.Equals(method, "ntFull", StringComparison.OrdinalIgnoreCase))
                    return ReadRegistryNt(key, valueName, KeyValueFullInformation);
                if (String.Equals(method, "ntFullAlign64", StringComparison.OrdinalIgnoreCase))
                    return ReadRegistryNt(key, valueName, KeyValueFullInformationAlign64);
                if (String.Equals(method, "ntEnumerate", StringComparison.OrdinalIgnoreCase))
                    return EnumerateRegistryNt(key);
                result["reason"] = "Unsupported registry method: " + method;
                return result;
            }
            catch (EntryPointNotFoundException error)
            {
                result["supported"] = false;
                result["reason"] = error.Message;
                return result;
            }
            catch (Exception error)
            {
                result["reason"] = error.GetType().FullName + ": " + error.Message;
                return result;
            }
            finally
            {
                if (key != IntPtr.Zero) RegCloseKey(key);
            }
        }

        private static Dictionary<string, object> ReadRegistryWin32(IntPtr key, string valueName)
        {
            uint type;
            uint required = 0;
            int sizeStatus = RegQueryValueExW(key, valueName, IntPtr.Zero, out type,
                IntPtr.Zero, ref required);
            if (sizeStatus != ERROR_SUCCESS)
            {
                Dictionary<string, object> failed = RegistryData(sizeStatus, type, null);
                failed["sizeStatus"] = sizeStatus;
                failed["requiredLength"] = required;
                return failed;
            }
            IntPtr buffer = required == 0 ? IntPtr.Zero : Marshal.AllocHGlobal((int)required);
            try
            {
                uint actual = required;
                int status = RegQueryValueExW(key, valueName, IntPtr.Zero, out type,
                    buffer, ref actual);
                byte[] data = null;
                if (status == ERROR_SUCCESS)
                {
                    data = new byte[actual];
                    if (actual != 0) Marshal.Copy(buffer, data, 0, (int)actual);
                }
                Dictionary<string, object> result = RegistryData(status, type, data);
                result["sizeStatus"] = sizeStatus;
                result["requiredLength"] = required;
                return result;
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }

        private static Dictionary<string, object> ReadRegistryNt(IntPtr key, string valueName,
            int informationClass)
        {
            IntPtr nameBuffer = Marshal.StringToHGlobalUni(valueName == null ? String.Empty : valueName);
            try
            {
                UNICODE_STRING name = new UNICODE_STRING();
                name.Length = (ushort)((valueName == null ? 0 : valueName.Length) * 2);
                name.MaximumLength = (ushort)(name.Length + 2);
                name.Buffer = nameBuffer;
                uint required;
                // A null/zero-length call is the normal NT size-query contract and
                // catches serializers that accidentally dereference their output.
                int sizeStatus = NtQueryValueKey(key, ref name, informationClass,
                    IntPtr.Zero, 0, out required);
                if (required == 0 || required > 16 * 1024 * 1024)
                {
                    Dictionary<string, object> failed = MethodResult(true, sizeStatus == STATUS_SUCCESS,
                        sizeStatus == STATUS_SUCCESS ? null : "NtQueryValueKey returned " + Hex32(sizeStatus));
                    failed["sizeStatus"] = sizeStatus;
                    failed["sizeStatusHex"] = Hex32(sizeStatus);
                    failed["status"] = sizeStatus;
                    failed["statusHex"] = Hex32(sizeStatus);
                    failed["requiredLength"] = required;
                    return failed;
                }
                int status = sizeStatus;
                IntPtr buffer = IntPtr.Zero;
                try
                {
                    uint capacity = required;
                    for (int attempt = 0; attempt < 3; attempt++)
                    {
                        if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                        capacity = checked(required + 64);
                        buffer = Marshal.AllocHGlobal((int)capacity);
                        ZeroMemory(buffer, (int)capacity);
                        uint returned;
                        status = NtQueryValueKey(key, ref name, informationClass,
                            buffer, capacity, out returned);
                        if ((status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) &&
                            returned > capacity && returned <= 16 * 1024 * 1024)
                        {
                            required = returned;
                            continue;
                        }
                        required = returned;
                        break;
                    }
                    Dictionary<string, object> parsed = ParseNtRegistry(informationClass,
                        status, buffer, required, capacity);
                    parsed["sizeStatus"] = sizeStatus;
                    parsed["sizeStatusHex"] = Hex32(sizeStatus);
                    parsed["requiredLength"] = required;
                    return parsed;
                }
                finally
                {
                    if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(nameBuffer);
            }
        }

        private static Dictionary<string, object> ParseNtRegistry(int informationClass,
            int status, IntPtr buffer, uint returnedLength, uint bufferCapacity)
        {
            Dictionary<string, object> result = MethodResult(true, status == STATUS_SUCCESS,
                status == STATUS_SUCCESS ? null : "NTSTATUS " + Hex32(status));
            result["status"] = status;
            result["statusHex"] = Hex32(status);
            result["informationClass"] = informationClass;
            result["returnedLength"] = returnedLength;
            if (buffer == IntPtr.Zero || returnedLength < 8) return result;
            uint type;
            uint dataLength;
            int dataOffset;
            if (informationClass == KeyValueBasicInformation)
            {
                if (returnedLength < 12) return result;
                type = unchecked((uint)Marshal.ReadInt32(buffer, 4));
                uint nameLength = unchecked((uint)Marshal.ReadInt32(buffer, 8));
                if (nameLength <= returnedLength - 12)
                    result["name"] = Marshal.PtrToStringUni(IntPtr.Add(buffer, 12), (int)(nameLength / 2));
                result["type"] = type;
                result["nameLength"] = nameLength;
                return result;
            }
            if (informationClass == KeyValueFullInformation ||
                informationClass == KeyValueFullInformationAlign64)
            {
                if (returnedLength < 20) return result;
                type = unchecked((uint)Marshal.ReadInt32(buffer, 4));
                dataOffset = Marshal.ReadInt32(buffer, 8);
                dataLength = unchecked((uint)Marshal.ReadInt32(buffer, 12));
                uint nameLength = unchecked((uint)Marshal.ReadInt32(buffer, 16));
                if (nameLength <= returnedLength - 20)
                    result["name"] = Marshal.PtrToStringUni(IntPtr.Add(buffer, 20), (int)(nameLength / 2));
            }
            else if (informationClass == KeyValuePartialInformationAlign64)
            {
                if (returnedLength < 8) return result;
                type = unchecked((uint)Marshal.ReadInt32(buffer, 0));
                dataLength = unchecked((uint)Marshal.ReadInt32(buffer, 4));
                dataOffset = 8;
                result["layout"] = "NativePartialInformationAlign64";
            }
            else
            {
                if (returnedLength < 12) return result;
                type = unchecked((uint)Marshal.ReadInt32(buffer, 4));
                dataLength = unchecked((uint)Marshal.ReadInt32(buffer, 8));
                dataOffset = 12;
            }
            result["type"] = type;
            result["dataLength"] = dataLength;
            if (status == STATUS_SUCCESS && dataOffset >= 0 && dataLength <= bufferCapacity &&
                (uint)dataOffset <= bufferCapacity - dataLength)
            {
                byte[] data = new byte[dataLength];
                if (dataLength != 0) Marshal.Copy(IntPtr.Add(buffer, dataOffset), data, 0, (int)dataLength);
                result["dataBase64"] = Convert.ToBase64String(data);
                result["displayValue"] = DecodeRegistryValue(type, data);
            }
            return result;
        }

        private static Dictionary<string, object> EnumerateRegistryNt(IntPtr key)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            List<Dictionary<string, object>> values = new List<Dictionary<string, object>>();
            int finalStatus = STATUS_NO_MORE_ENTRIES;
            for (uint index = 0; index < 1024; index++)
            {
                uint required;
                int sizeStatus = NtEnumerateValueKey(key, index, KeyValueFullInformation,
                    IntPtr.Zero, 0, out required);
                if (sizeStatus == STATUS_NO_MORE_ENTRIES)
                {
                    finalStatus = sizeStatus;
                    break;
                }
                if (required == 0 || required > 16 * 1024 * 1024)
                {
                    finalStatus = sizeStatus;
                    Dictionary<string, object> failed = MethodResult(true, false,
                        "Enumeration size query returned " + Hex32(sizeStatus));
                    failed["index"] = index;
                    failed["status"] = sizeStatus;
                    failed["statusHex"] = Hex32(sizeStatus);
                    values.Add(failed);
                    break;
                }
                IntPtr buffer = IntPtr.Zero;
                try
                {
                    int status = sizeStatus;
                    uint returned = required;
                    uint capacity = required;
                    for (int attempt = 0; attempt < 3; attempt++)
                    {
                        if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                        capacity = checked(required + 64);
                        buffer = Marshal.AllocHGlobal((int)capacity);
                        ZeroMemory(buffer, (int)capacity);
                        status = NtEnumerateValueKey(key, index, KeyValueFullInformation,
                            buffer, capacity, out returned);
                        if ((status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) &&
                            returned > capacity && returned <= 16 * 1024 * 1024)
                        {
                            required = returned;
                            continue;
                        }
                        break;
                    }
                    Dictionary<string, object> item = ParseNtRegistry(KeyValueFullInformation,
                        status, buffer, returned, capacity);
                    item["index"] = index;
                    item["sizeStatus"] = sizeStatus;
                    item["requiredLength"] = returned;
                    values.Add(item);
                    finalStatus = status;
                    if (status != STATUS_SUCCESS) break;
                }
                finally
                {
                    if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                }
            }
            result["values"] = values;
            result["count"] = values.Count;
            result["finalStatus"] = finalStatus;
            result["finalStatusHex"] = Hex32(finalStatus);
            bool success = finalStatus == STATUS_NO_MORE_ENTRIES;
            result["success"] = success;
            if (!success)
                result["reason"] = "NtEnumerateValueKey ended with " + Hex32(finalStatus);
            return result;
        }

        private static void ZeroMemory(IntPtr pointer, int length)
        {
            byte[] zeros = new byte[Math.Min(length, 8192)];
            int offset = 0;
            while (offset < length)
            {
                int count = Math.Min(zeros.Length, length - offset);
                Marshal.Copy(zeros, 0, IntPtr.Add(pointer, offset), count);
                offset += count;
            }
        }

        public static Dictionary<string, object> GetAdaptersState()
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            result["getAdaptersInfo"] = ReadAdaptersInfo();
            result["getAdaptersAddresses"] = ReadAdaptersAddresses();
            result["netWkstaTransportEnum"] = ReadWkstaTransports();
            return result;
        }

        private static Dictionary<string, object> ReadAdaptersInfo()
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            uint size = 0;
            uint first = GetAdaptersInfo(IntPtr.Zero, ref size);
            result["sizeStatus"] = first;
            result["requiredLength"] = size;
            if (first == ERROR_NO_DATA)
            {
                result["success"] = true;
                result["adapters"] = new List<Dictionary<string, object>>();
                return result;
            }
            if (size == 0 || size > 64 * 1024 * 1024)
            {
                result["reason"] = "GetAdaptersInfo did not return a usable buffer size.";
                return result;
            }
            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                uint status = GetAdaptersInfo(buffer, ref size);
                result["status"] = status;
                if (status != 0)
                {
                    result["reason"] = Win32Message(unchecked((int)status));
                    return result;
                }
                List<Dictionary<string, object>> adapters = new List<Dictionary<string, object>>();
                HashSet<long> visited = new HashSet<long>();
                IntPtr current = buffer;
                while (current != IntPtr.Zero && adapters.Count < 256 && visited.Add(current.ToInt64()))
                {
                    int baseOffset = IntPtr.Size + 4;
                    string name = Marshal.PtrToStringAnsi(IntPtr.Add(current, baseOffset), 260).TrimEnd('\0');
                    string description = Marshal.PtrToStringAnsi(IntPtr.Add(current, baseOffset + 260), 132).TrimEnd('\0');
                    int lengthOffset = baseOffset + 260 + 132;
                    uint addressLength = unchecked((uint)Marshal.ReadInt32(current, lengthOffset));
                    int safeLength = (int)Math.Min(addressLength, 8);
                    byte[] address = new byte[safeLength];
                    if (safeLength != 0) Marshal.Copy(IntPtr.Add(current, lengthOffset + 4), address, 0, safeLength);
                    Dictionary<string, object> item = new Dictionary<string, object>();
                    item["name"] = name;
                    item["description"] = description;
                    item["addressLength"] = addressLength;
                    item["addressBase64"] = Convert.ToBase64String(address);
                    item["addressHex"] = HexBytes(address);
                    adapters.Add(item);
                    current = Marshal.ReadIntPtr(current, 0);
                }
                result["adapters"] = adapters;
                result["success"] = true;
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static Dictionary<string, object> ReadAdaptersAddresses()
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            uint size = 0;
            uint first = GetAdaptersAddresses(AF_UNSPEC, 0, IntPtr.Zero, IntPtr.Zero, ref size);
            result["sizeStatus"] = first;
            result["requiredLength"] = size;
            if (size == 0 || size > 64 * 1024 * 1024)
            {
                result["reason"] = "GetAdaptersAddresses did not return a usable buffer size.";
                return result;
            }
            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                uint status = GetAdaptersAddresses(AF_UNSPEC, 0, IntPtr.Zero, buffer, ref size);
                result["status"] = status;
                if (status != 0)
                {
                    result["reason"] = Win32Message(unchecked((int)status));
                    return result;
                }
                List<Dictionary<string, object>> adapters = new List<Dictionary<string, object>>();
                HashSet<long> visited = new HashSet<long>();
                IntPtr current = buffer;
                while (current != IntPtr.Zero && adapters.Count < 256 && visited.Add(current.ToInt64()))
                {
                    IntPtr namePointer = Marshal.ReadIntPtr(current, 8 + IntPtr.Size);
                    int physicalOffset = 8 + (9 * IntPtr.Size);
                    uint addressLength = unchecked((uint)Marshal.ReadInt32(current, physicalOffset + 8));
                    int safeLength = (int)Math.Min(addressLength, 8);
                    byte[] address = new byte[safeLength];
                    if (safeLength != 0) Marshal.Copy(IntPtr.Add(current, physicalOffset), address, 0, safeLength);
                    int dnsSuffixPointerOffset = 8 + (6 * IntPtr.Size);
                    int descriptionPointerOffset = 8 + (7 * IntPtr.Size);
                    int friendlyPointerOffset = 8 + (8 * IntPtr.Size);
                    Dictionary<string, object> item = new Dictionary<string, object>();
                    item["name"] = namePointer == IntPtr.Zero ? null : Marshal.PtrToStringAnsi(namePointer);
                    IntPtr dns = Marshal.ReadIntPtr(current, dnsSuffixPointerOffset);
                    IntPtr description = Marshal.ReadIntPtr(current, descriptionPointerOffset);
                    IntPtr friendly = Marshal.ReadIntPtr(current, friendlyPointerOffset);
                    item["dnsSuffix"] = dns == IntPtr.Zero ? null : Marshal.PtrToStringUni(dns);
                    item["description"] = description == IntPtr.Zero ? null : Marshal.PtrToStringUni(description);
                    item["friendlyName"] = friendly == IntPtr.Zero ? null : Marshal.PtrToStringUni(friendly);
                    item["addressLength"] = addressLength;
                    item["addressBase64"] = Convert.ToBase64String(address);
                    item["addressHex"] = HexBytes(address);
                    adapters.Add(item);
                    current = Marshal.ReadIntPtr(current, 8);
                }
                result["adapters"] = adapters;
                result["success"] = true;
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static Dictionary<string, object> ReadWkstaTransports()
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr buffer;
            uint read;
            uint total;
            uint resume = 0;
            uint status = NetWkstaTransportEnum(null, 0, out buffer, MAX_PREFERRED_LENGTH,
                out read, out total, ref resume);
            result["status"] = status;
            result["entriesRead"] = read;
            result["totalEntries"] = total;
            try
            {
                if (status != 0 && status != 234)
                {
                    result["reason"] = Win32Message(unchecked((int)status));
                    return result;
                }
                List<Dictionary<string, object>> transports = new List<Dictionary<string, object>>();
                int elementSize = Marshal.SizeOf(typeof(WKSTA_TRANSPORT_INFO_0));
                for (uint index = 0; index < read; index++)
                {
                    WKSTA_TRANSPORT_INFO_0 item = (WKSTA_TRANSPORT_INFO_0)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, checked((int)(index * elementSize))), typeof(WKSTA_TRANSPORT_INFO_0));
                    Dictionary<string, object> value = new Dictionary<string, object>();
                    value["qualityOfService"] = item.wkti0_quality_of_service;
                    value["numberOfVirtualCircuits"] = item.wkti0_number_of_vcs;
                    value["transportName"] = item.wkti0_transport_name == IntPtr.Zero ? null : Marshal.PtrToStringUni(item.wkti0_transport_name);
                    value["transportAddress"] = item.wkti0_transport_address == IntPtr.Zero ? null : Marshal.PtrToStringUni(item.wkti0_transport_address);
                    value["wan"] = item.wkti0_wan_ish != 0;
                    transports.Add(value);
                }
                result["transports"] = transports;
                result["success"] = true;
                return result;
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
        }

        private static string HexBytes(byte[] value)
        {
            StringBuilder result = new StringBuilder(value.Length * 2);
            for (int i = 0; i < value.Length; i++)
                result.Append(value[i].ToString("X2", CultureInfo.InvariantCulture));
            return result.ToString();
        }

        public static Dictionary<string, object> LookupWsa(string name)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr data = Marshal.AllocHGlobal(1024);
            try
            {
                int startup = WSAStartup(0x0202, data);
                result["startupStatus"] = startup;
                if (startup != 0)
                {
                    result["reason"] = "WSAStartup returned " + startup.ToString(CultureInfo.InvariantCulture);
                    return result;
                }
                result["unicode"] = LookupWsaOne(name, true);
                result["ansi"] = LookupWsaOne(name, false);
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
                try { WSACleanup(); } catch { }
                Marshal.FreeHGlobal(data);
            }
        }

        private static Dictionary<string, object> LookupWsaOne(string name, bool unicode)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            uint lookupFlags = LUP_RETURN_NAME | LUP_RETURN_ADDR;
            Guid serviceClass = new Guid("0002A800-0000-0000-C000-000000000046");
            IntPtr guidPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
            IntPtr lookup = IntPtr.Zero;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                Marshal.StructureToPtr(serviceClass, guidPointer, false);
                int begin;
                if (unicode)
                {
                    WSAQUERYSETW query = new WSAQUERYSETW();
                    query.dwSize = (uint)Marshal.SizeOf(typeof(WSAQUERYSETW));
                    query.lpszServiceInstanceName = name;
                    query.lpServiceClassId = guidPointer;
                    query.dwNameSpace = NS_DNS;
                    begin = WSALookupServiceBeginW(ref query, lookupFlags, out lookup);
                }
                else
                {
                    WSAQUERYSETA query = new WSAQUERYSETA();
                    query.dwSize = (uint)Marshal.SizeOf(typeof(WSAQUERYSETA));
                    query.lpszServiceInstanceName = name;
                    query.lpServiceClassId = guidPointer;
                    query.dwNameSpace = NS_DNS;
                    begin = WSALookupServiceBeginA(ref query, lookupFlags, out lookup);
                }
                int beginError = begin == SOCKET_ERROR ? WSAGetLastError() : 0;
                result["beginStatus"] = begin;
                result["beginError"] = beginError;
                if (begin == SOCKET_ERROR)
                {
                    result["reason"] = "WSALookupServiceBegin returned " + beginError.ToString(CultureInfo.InvariantCulture);
                    return result;
                }

                uint required = 0;
                int first = unicode
                    ? WSALookupServiceNextW(lookup, lookupFlags, ref required, IntPtr.Zero)
                    : WSALookupServiceNextA(lookup, lookupFlags, ref required, IntPtr.Zero);
                int firstError = first == SOCKET_ERROR ? WSAGetLastError() : 0;
                result["sizeStatus"] = first;
                result["sizeError"] = firstError;
                result["requiredLength"] = required;
                if (required == 0 || required > 16 * 1024 * 1024)
                {
                    result["reason"] = "WSALookupServiceNext did not return a usable buffer size.";
                    return result;
                }
                buffer = Marshal.AllocHGlobal((int)required);
                ZeroMemory(buffer, (int)required);
                int next = unicode
                    ? WSALookupServiceNextW(lookup, lookupFlags, ref required, buffer)
                    : WSALookupServiceNextA(lookup, lookupFlags, ref required, buffer);
                int nextError = next == SOCKET_ERROR ? WSAGetLastError() : 0;
                result["nextStatus"] = next;
                result["nextError"] = nextError;
                if (next == SOCKET_ERROR)
                {
                    result["reason"] = "WSALookupServiceNext returned " + nextError.ToString(CultureInfo.InvariantCulture);
                    return result;
                }
                string returnedName;
                uint count;
                IntPtr addresses;
                if (unicode)
                {
                    WSAQUERYSETW query = (WSAQUERYSETW)Marshal.PtrToStructure(buffer, typeof(WSAQUERYSETW));
                    returnedName = query.lpszServiceInstanceName;
                    count = query.dwNumberOfCsAddrs;
                    addresses = query.lpcsaBuffer;
                }
                else
                {
                    WSAQUERYSETA query = (WSAQUERYSETA)Marshal.PtrToStructure(buffer, typeof(WSAQUERYSETA));
                    returnedName = query.lpszServiceInstanceName;
                    count = query.dwNumberOfCsAddrs;
                    addresses = query.lpcsaBuffer;
                }
                result["name"] = returnedName;
                result["addressCount"] = count;
                List<Dictionary<string, object>> parsed = new List<Dictionary<string, object>>();
                int elementSize = Marshal.SizeOf(typeof(CSADDR_INFO));
                for (uint index = 0; index < count && index < 256; index++)
                {
                    CSADDR_INFO info = (CSADDR_INFO)Marshal.PtrToStructure(
                        IntPtr.Add(addresses, checked((int)(index * elementSize))), typeof(CSADDR_INFO));
                    Dictionary<string, object> address = ParseSocketAddress(info.RemoteAddr);
                    address["socketType"] = info.iSocketType;
                    address["protocol"] = info.iProtocol;
                    parsed.Add(address);
                }
                result["addresses"] = parsed;
                if (parsed.Count != 0)
                {
                    result["address"] = parsed[0].ContainsKey("address") ? parsed[0]["address"] : null;
                    result["family"] = parsed[0].ContainsKey("family") ? parsed[0]["family"] : null;
                }
                result["success"] = true;
                return result;
            }
            finally
            {
                if (lookup != IntPtr.Zero) WSALookupServiceEnd(lookup);
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                Marshal.FreeHGlobal(guidPointer);
            }
        }

        private static Dictionary<string, object> ParseSocketAddress(SOCKET_ADDRESS socketAddress)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            if (socketAddress.lpSockaddr == IntPtr.Zero || socketAddress.iSockaddrLength < 2)
            {
                result["family"] = 0;
                result["address"] = null;
                return result;
            }
            int family = Marshal.ReadInt16(socketAddress.lpSockaddr, 0);
            result["family"] = family;
            if (family == AF_INET && socketAddress.iSockaddrLength >= 8)
            {
                byte[] bytes = new byte[4];
                Marshal.Copy(IntPtr.Add(socketAddress.lpSockaddr, 4), bytes, 0, 4);
                result["address"] = new IPAddress(bytes).ToString();
            }
            else if (family == AF_INET6 && socketAddress.iSockaddrLength >= 24)
            {
                byte[] bytes = new byte[16];
                Marshal.Copy(IntPtr.Add(socketAddress.lpSockaddr, 8), bytes, 0, 16);
                result["address"] = new IPAddress(bytes).ToString();
            }
            else result["address"] = null;
            return result;
        }

        public static Dictionary<string, object> ScanAmsi(string content, string contentName)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr context = IntPtr.Zero;
            IntPtr session = IntPtr.Zero;
            try
            {
                int initialize = AmsiInitialize("WinPrivProbe", out context);
                result["initializeHresult"] = initialize;
                result["initializeHresultHex"] = Hex32(initialize);
                if (initialize < 0)
                {
                    result["reason"] = "AmsiInitialize returned " + Hex32(initialize);
                }
                int open = context == IntPtr.Zero ? unchecked((int)0x80070057) : AmsiOpenSession(context, out session);
                result["openSessionHresult"] = open;
                result["openSessionHresultHex"] = Hex32(open);
                byte[] bytes = Encoding.Unicode.GetBytes(content == null ? String.Empty : content);
                result["stringValid"] = AmsiStringCall(context, content, contentName, session);
                result["bufferValid"] = AmsiBufferCall(context, bytes, contentName, session);
                result["stringInvalid"] = AmsiStringCall(IntPtr.Zero, content, contentName, IntPtr.Zero);
                result["bufferInvalid"] = AmsiBufferCall(IntPtr.Zero, bytes, contentName, IntPtr.Zero);
                result["success"] = true;
                return result;
            }
            catch (DllNotFoundException error)
            {
                result["supported"] = false;
                result["reason"] = error.Message;
                return result;
            }
            catch (EntryPointNotFoundException error)
            {
                result["supported"] = false;
                result["reason"] = error.Message;
                return result;
            }
            catch (Exception error)
            {
                result["reason"] = error.GetType().FullName + ": " + error.Message;
                return result;
            }
            finally
            {
                if (context != IntPtr.Zero && session != IntPtr.Zero) AmsiCloseSession(context, session);
                if (context != IntPtr.Zero) AmsiUninitialize(context);
            }
        }

        private static Dictionary<string, object> AmsiStringCall(IntPtr context, string content,
            string contentName, IntPtr session)
        {
            int scanResult;
            int hresult = AmsiScanString(context, content == null ? String.Empty : content,
                contentName, session, out scanResult);
            Dictionary<string, object> result = MethodResult(true, hresult >= 0,
                hresult >= 0 ? null : "AMSI HRESULT " + Hex32(hresult));
            result["hresult"] = hresult;
            result["hresultHex"] = Hex32(hresult);
            result["result"] = scanResult;
            return result;
        }

        private static Dictionary<string, object> AmsiBufferCall(IntPtr context, byte[] content,
            string contentName, IntPtr session)
        {
            int scanResult;
            int hresult = AmsiScanBuffer(context, content, (uint)content.Length,
                contentName, session, out scanResult);
            Dictionary<string, object> result = MethodResult(true, hresult >= 0,
                hresult >= 0 ? null : "AMSI HRESULT " + Hex32(hresult));
            result["hresult"] = hresult;
            result["hresultHex"] = Hex32(hresult);
            result["result"] = scanResult;
            return result;
        }
    }
}
