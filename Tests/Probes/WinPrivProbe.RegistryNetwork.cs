using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace WinPrivProbe
{
    public static partial class Native
    {
        private const uint KEY_QUERY_VALUE = 0x0001;
        private const uint KEY_ENUMERATE_SUB_KEYS = 0x0008;
        private const uint KEY_WOW64_64KEY = 0x0100;
        private const uint KEY_WOW64_32KEY = 0x0200;
        private const int ERROR_SUCCESS = 0;
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
        private const int NS_DNS = 12;
        private const uint LUP_RETURN_NAME = 0x0010;
        private const uint LUP_RETURN_ADDR = 0x0100;
        private const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING { public ushort Length, MaximumLength; public IntPtr Buffer; }

        [StructLayout(LayoutKind.Sequential)]
        private struct WKSTA_TRANSPORT_INFO_0
        {
            public uint wkti0_quality_of_service, wkti0_number_of_vcs;
            public IntPtr wkti0_transport_name, wkti0_transport_address;
            public int wkti0_wan_ish;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SOCKET_ADDRESS { public IntPtr lpSockaddr; public int iSockaddrLength; }

        [StructLayout(LayoutKind.Sequential)]
        private struct CSADDR_INFO { public SOCKET_ADDRESS LocalAddr, RemoteAddr; public int iSocketType, iProtocol; }

        [StructLayout(LayoutKind.Sequential)]
        private struct WSAQUERYSET
        {
            public uint dwSize;
            public IntPtr lpszServiceInstanceName, lpServiceClassId, lpVersion, lpszComment;
            public uint dwNameSpace;
            public IntPtr lpNSProviderId, lpszContext;
            public uint dwNumberOfProtocols;
            public IntPtr lpafpProtocols, lpszQueryString;
            public uint dwNumberOfCsAddrs;
            public IntPtr lpcsaBuffer;
            public uint dwOutputFlags;
            public IntPtr lpBlob;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct HostAddrInfo
        {
            public int Flags, Family, SocketType, Protocol;
            public UIntPtr AddressLength;
            public IntPtr CanonicalName, Address, Next;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct HostAddrInfoEx
        {
            public int Flags, Family, SocketType, Protocol;
            public UIntPtr AddressLength;
            public IntPtr CanonicalName, Address, Blob;
            public UIntPtr BlobLength;
            public IntPtr Provider, Next;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct HostDnsRecord
        {
            public IntPtr Next, Name;
            public ushort Type, DataLength;
            public uint Flags, Ttl, Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct HostDnsRequest
        {
            public uint Version;
            public IntPtr Name;
            public ushort Type;
            public ulong Options;
            public IntPtr Servers;
            public uint Interface;
            public IntPtr Callback, Context;
            public int NetworkRequired;
            public uint NetworkIndex, CustomServerCount;
            public IntPtr CustomServers;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct HostDnsResult { public uint Version, Status; public ulong Options; public IntPtr Records, Reserved; }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void HostDnsCallback(IntPtr context, IntPtr result);

        [DllImport("kernel32.dll")]
        private static extern void RtlZeroMemory(IntPtr destination, UIntPtr length);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegOpenKeyExW(IntPtr root, string subKey, uint options, uint desiredAccess, out IntPtr key);

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
        private static extern uint NetWkstaTransportEnum(string serverName, uint level, out IntPtr buffer,
            uint preferredMaximumLength, out uint entriesRead, out uint totalEntries, ref uint resumeHandle);

        [DllImport("netapi32.dll")]
        private static extern uint NetApiBufferFree(IntPtr buffer);

        [DllImport("ws2_32.dll")]
        private static extern int WSAStartup(ushort versionRequested, IntPtr wsaData);

        [DllImport("ws2_32.dll")]
        private static extern int WSACleanup();

        [DllImport("ws2_32.dll")]
        private static extern int WSAGetLastError();

        [DllImport("ws2_32.dll", SetLastError = true)]
        private static extern int WSALookupServiceBeginW(ref WSAQUERYSET restrictions, uint controlFlags, out IntPtr lookup);

        [DllImport("ws2_32.dll", SetLastError = true)]
        private static extern int WSALookupServiceBeginA(ref WSAQUERYSET restrictions, uint controlFlags, out IntPtr lookup);

        [DllImport("ws2_32.dll", SetLastError = true)]
        private static extern int WSALookupServiceNextW(IntPtr lookup, uint controlFlags, ref uint bufferLength, IntPtr results);

        [DllImport("ws2_32.dll", SetLastError = true)]
        private static extern int WSALookupServiceNextA(IntPtr lookup, uint controlFlags, ref uint bufferLength, IntPtr results);

        [DllImport("ws2_32.dll")]
        private static extern int WSALookupServiceEnd(IntPtr lookup);

        [DllImport("ws2_32.dll", EntryPoint = "GetAddrInfoW", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int HostGetAddrInfoW(string name, IntPtr service, ref HostAddrInfo hints, out IntPtr result);

        [DllImport("ws2_32.dll", EntryPoint = "getaddrinfo", ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern int HostGetAddrInfoA(string name, IntPtr service, ref HostAddrInfo hints, out IntPtr result);

        [DllImport("ws2_32.dll", EntryPoint = "GetAddrInfoExW", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int HostGetAddrInfoEx(string name, IntPtr service, uint nameSpace, IntPtr provider,
            ref HostAddrInfoEx hints, IntPtr result, IntPtr timeout, IntPtr overlapped, IntPtr callback, IntPtr cancel);

        [DllImport("ws2_32.dll", EntryPoint = "GetAddrInfoExA", ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern int HostGetAddrInfoExA(string name, IntPtr service, uint nameSpace, IntPtr provider,
            ref HostAddrInfoEx hints, IntPtr result, IntPtr timeout, IntPtr overlapped, IntPtr callback, IntPtr cancel);

        [DllImport("ws2_32.dll", EntryPoint = "GetAddrInfoExOverlappedResult")]
        private static extern int HostGetAddrInfoExResult(IntPtr overlapped);

        [DllImport("ws2_32.dll", EntryPoint = "GetAddrInfoExCancel")]
        private static extern int HostCancelAddrInfoEx(ref IntPtr cancel);

        [DllImport("ws2_32.dll", EntryPoint = "FreeAddrInfoW")]
        private static extern void HostFreeAddrInfoW(IntPtr result);

        [DllImport("ws2_32.dll", EntryPoint = "freeaddrinfo")]
        private static extern void HostFreeAddrInfoA(IntPtr result);

        [DllImport("ws2_32.dll", EntryPoint = "FreeAddrInfoExW")]
        private static extern void HostFreeAddrInfoEx(IntPtr result);

        [DllImport("ws2_32.dll", EntryPoint = "FreeAddrInfoEx", ExactSpelling = true)]
        private static extern void HostFreeAddrInfoExA(IntPtr result);

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern uint HostDnsQueryW(string name, ushort type, uint options, IntPtr extra, out IntPtr result, IntPtr reserved);

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_A", ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern uint HostDnsQueryA(string name, ushort type, uint options, IntPtr extra, out IntPtr result, IntPtr reserved);

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_UTF8", ExactSpelling = true)]
        private static extern uint HostDnsQueryUtf8(byte[] name, ushort type, uint options, IntPtr extra, out IntPtr result, IntPtr reserved);

        [DllImport("dnsapi.dll", EntryPoint = "DnsQueryEx")]
        private static extern uint HostDnsQueryEx(ref HostDnsRequest request, IntPtr result, IntPtr cancel);

        [DllImport("dnsapi.dll", EntryPoint = "DnsCancelQuery")]
        private static extern uint HostCancelDnsQuery(IntPtr cancel);

        [DllImport("dnsapi.dll", EntryPoint = "DnsRecordListFree")]
        private static extern void HostFreeDnsRecords(IntPtr result, int freeType);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        private static extern int AmsiInitialize(string applicationName, out IntPtr context);

        [DllImport("amsi.dll")]
        private static extern void AmsiUninitialize(IntPtr context);

        [DllImport("amsi.dll")]
        private static extern int AmsiOpenSession(IntPtr context, out IntPtr session);

        [DllImport("amsi.dll")]
        private static extern void AmsiCloseSession(IntPtr context, IntPtr session);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        private static extern int AmsiScanString(IntPtr context, string value, string contentName, IntPtr session, out int result);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        private static extern int AmsiScanBuffer(IntPtr context, byte[] value, uint length, string contentName, IntPtr session, out int result);

        private static IntPtr RegistryRoot(string root)
        {
            switch (root == null ? "" : root.ToUpperInvariant())
            {
                case "HKCR": case "HKEY_CLASSES_ROOT": return new IntPtr(unchecked((int)0x80000000));
                case "HKCU": case "HKEY_CURRENT_USER": return new IntPtr(unchecked((int)0x80000001));
                case "HKLM": case "HKEY_LOCAL_MACHINE": return new IntPtr(unchecked((int)0x80000002));
                case "HKU": case "HKEY_USERS": return new IntPtr(unchecked((int)0x80000003));
                case "HKCC": case "HKEY_CURRENT_CONFIG": return new IntPtr(unchecked((int)0x80000005));
                default: throw new ArgumentException("Unsupported registry root: " + root);
            }
        }

        private static uint RegistryViewAccess(string view)
        {
            if (String.Equals(view, "32", StringComparison.OrdinalIgnoreCase) || String.Equals(view, "x86", StringComparison.OrdinalIgnoreCase)) return KEY_WOW64_32KEY;
            if (String.Equals(view, "64", StringComparison.OrdinalIgnoreCase) || String.Equals(view, "x64", StringComparison.OrdinalIgnoreCase)) return KEY_WOW64_64KEY;
            return 0;
        }

        private static object DecodeRegistryValue(uint type, byte[] data)
        {
            if (data == null) return null;
            if (type == 1 || type == 2) return Encoding.Unicode.GetString(data).TrimEnd('\0');
            if (type == 4 && data.Length >= 4) return BitConverter.ToUInt32(data, 0);
            if (type == 11 && data.Length >= 8) return BitConverter.ToUInt64(data, 0);
            if (type == 7) return Encoding.Unicode.GetString(data).TrimEnd('\0').Split(new char[] { '\0' });
            return Convert.ToBase64String(data);
        }

        private static Dictionary<string, object> RegistryData(int status, uint type, byte[] data)
        {
            Dictionary<string, object> result = MethodResult(true, status == ERROR_SUCCESS, status == ERROR_SUCCESS ? null : Win32Message(status));
            result["status"] = status;
            result["statusHex"] = Hex32(status);
            result["type"] = type;
            result["dataLength"] = data == null ? 0 : data.Length;
            result["dataBase64"] = data == null ? null : Convert.ToBase64String(data);
            result["displayValue"] = DecodeRegistryValue(type, data);
            return result;
        }

        public static Dictionary<string, object> ReadRegistryMethod(string root, string subKey,
            string valueName, string view, string method)
        {
            IntPtr key = IntPtr.Zero;
            try
            {
                int open = RegOpenKeyExW(RegistryRoot(root), subKey, 0,
                    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | RegistryViewAccess(view), out key);
                if (open != ERROR_SUCCESS)
                {
                    Dictionary<string, object> failed = MethodResult(true, false, Win32Message(open));
                    failed["openStatus"] = open;
                    return failed;
                }
                switch ((method ?? "").ToLowerInvariant())
                {
                    case "win32": return ReadRegistryWin32(key, valueName);
                    case "ntpartial":
                        Dictionary<string, object> partial = ReadRegistryNt(key, valueName, KeyValuePartialInformation);
                        partial["invalidHandleStatusHex"] = ReadRegistryNt(new IntPtr(0x1234), valueName, KeyValuePartialInformation)["statusHex"];
                        return partial;
                    case "ntpartialalign64": return ReadRegistryNt(key, valueName, KeyValuePartialInformationAlign64);
                    case "ntfull": return ReadRegistryNt(key, valueName, KeyValueFullInformation);
                    case "ntfullalign64": return ReadRegistryNt(key, valueName, KeyValueFullInformationAlign64);
                    case "ntenumerate": return EnumerateRegistryNt(key, KeyValueFullInformation);
                    case "ntenumeratebasic": return EnumerateRegistryNt(key, KeyValueBasicInformation);
                    case "ntenumeratepartial": return EnumerateRegistryNt(key, KeyValuePartialInformation);
                    case "ntenumeratepartialalign64": return EnumerateRegistryNt(key, KeyValuePartialInformationAlign64);
                    case "ntenumeratefullalign64": return EnumerateRegistryNt(key, KeyValueFullInformationAlign64);
                    default: return MethodResult(true, false, "Unsupported registry method: " + method);
                }
            }
            catch (EntryPointNotFoundException error) { return MethodResult(false, false, error.Message); }
            catch (Exception error) { return MethodResult(true, false, error.GetType().FullName + ": " + error.Message); }
            finally { if (key != IntPtr.Zero) RegCloseKey(key); }
        }

        private static Dictionary<string, object> ReadRegistryWin32(IntPtr key, string valueName)
        {
            uint type, required = 0;
            int sizeStatus = RegQueryValueExW(key, valueName, IntPtr.Zero, out type, IntPtr.Zero, ref required);
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
                int status = RegQueryValueExW(key, valueName, IntPtr.Zero, out type, buffer, ref actual);
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
            finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
        }

        private delegate int NtBufferQuery(IntPtr buffer, uint capacity, out uint returned);

        private static int QueryNtBuffer(uint initialRequired, NtBufferQuery query,
            out IntPtr buffer, out uint returned, out uint capacity)
        {
            buffer = IntPtr.Zero;
            returned = initialRequired;
            capacity = initialRequired;
            uint required = initialRequired;
            int status = STATUS_BUFFER_TOO_SMALL;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (buffer != IntPtr.Zero) { Marshal.FreeHGlobal(buffer); buffer = IntPtr.Zero; }
                capacity = checked(required + 64);
                buffer = Marshal.AllocHGlobal((int)capacity);
                RtlZeroMemory(buffer, new UIntPtr(capacity));
                status = query(buffer, capacity, out returned);
                if ((status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) &&
                    returned > capacity && returned <= 16 * 1024 * 1024)
                {
                    required = returned;
                    continue;
                }
                break;
            }
            return status;
        }

        private static Dictionary<string, object> ReadRegistryNt(IntPtr key, string valueName, int informationClass)
        {
            IntPtr nameBuffer = Marshal.StringToHGlobalUni(valueName ?? String.Empty);
            try
            {
                UNICODE_STRING name = new UNICODE_STRING
                {
                    Length = (ushort)((valueName == null ? 0 : valueName.Length) * 2),
                    Buffer = nameBuffer
                };
                name.MaximumLength = (ushort)(name.Length + 2);
                uint required;
                int sizeStatus = NtQueryValueKey(key, ref name, informationClass, IntPtr.Zero, 0, out required);
                if (required == 0 || required > 16 * 1024 * 1024)
                {
                    Dictionary<string, object> failed = MethodResult(true, sizeStatus == STATUS_SUCCESS,
                        sizeStatus == STATUS_SUCCESS ? null : "NtQueryValueKey returned " + Hex32(sizeStatus));
                    failed["sizeStatus"] = sizeStatus; failed["sizeStatusHex"] = Hex32(sizeStatus);
                    failed["status"] = sizeStatus; failed["statusHex"] = Hex32(sizeStatus);
                    failed["requiredLength"] = required;
                    return failed;
                }
                IntPtr buffer = IntPtr.Zero;
                try
                {
                    uint returned, capacity;
                    int status = QueryNtBuffer(required,
                        delegate(IntPtr b, uint c, out uint r) { return NtQueryValueKey(key, ref name, informationClass, b, c, out r); },
                        out buffer, out returned, out capacity);
                    Dictionary<string, object> parsed = ParseNtRegistry(informationClass, status, buffer, returned, capacity);
                    parsed["sizeStatus"] = sizeStatus;
                    parsed["sizeStatusHex"] = Hex32(sizeStatus);
                    parsed["requiredLength"] = returned;
                    return parsed;
                }
                finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
            }
            finally { Marshal.FreeHGlobal(nameBuffer); }
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
            uint type, dataLength;
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
            if (informationClass == KeyValueFullInformation || informationClass == KeyValueFullInformationAlign64)
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

        private static Dictionary<string, object> EnumerateRegistryNt(IntPtr key, int informationClass)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            List<Dictionary<string, object>> values = new List<Dictionary<string, object>>();
            int finalStatus = STATUS_NO_MORE_ENTRIES;
            for (uint index = 0; index < 1024; index++)
            {
                uint required;
                int sizeStatus = NtEnumerateValueKey(key, index, informationClass, IntPtr.Zero, 0, out required);
                if (sizeStatus == STATUS_NO_MORE_ENTRIES) { finalStatus = sizeStatus; break; }
                if (required == 0 || required > 16 * 1024 * 1024)
                {
                    finalStatus = sizeStatus;
                    Dictionary<string, object> failed = MethodResult(true, false, "Enumeration size query returned " + Hex32(sizeStatus));
                    failed["index"] = index; failed["status"] = sizeStatus; failed["statusHex"] = Hex32(sizeStatus);
                    values.Add(failed);
                    break;
                }
                IntPtr buffer = IntPtr.Zero;
                try
                {
                    uint returned, capacity;
                    uint currentIndex = index;
                    int status = QueryNtBuffer(required,
                        delegate(IntPtr b, uint c, out uint r) { return NtEnumerateValueKey(key, currentIndex, informationClass, b, c, out r); },
                        out buffer, out returned, out capacity);
                    Dictionary<string, object> item = ParseNtRegistry(informationClass, status, buffer, returned, capacity);
                    item["index"] = index;
                    item["sizeStatus"] = sizeStatus;
                    item["sizeRequiredLength"] = required;
                    item["requiredLength"] = returned;
                    uint shortCapacity = informationClass == KeyValueFullInformation || informationClass == KeyValueFullInformationAlign64 ? 22u
                        : informationClass == KeyValuePartialInformationAlign64 ? 10u : 14u;
                    uint shortRequired;
                    item["shortStatusHex"] = Hex32(NtEnumerateValueKey(key, index, informationClass, buffer, Math.Min(shortCapacity, capacity), out shortRequired));
                    item["shortRequiredLength"] = shortRequired;
                    item["shortType"] = unchecked((uint)Marshal.ReadInt32(buffer, informationClass == KeyValuePartialInformationAlign64 ? 0 : 4));
                    values.Add(item);
                    finalStatus = status;
                    if (status != STATUS_SUCCESS) break;
                }
                finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
            }
            result["values"] = values;
            result["count"] = values.Count;
            result["finalStatus"] = finalStatus;
            result["finalStatusHex"] = Hex32(finalStatus);
            result["success"] = finalStatus == STATUS_NO_MORE_ENTRIES;
            if (!(bool)result["success"]) result["reason"] = "NtEnumerateValueKey ended with " + Hex32(finalStatus);
            return result;
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
            if (first == ERROR_NO_DATA) { result["success"] = true; result["adapters"] = new List<Dictionary<string, object>>(); return result; }
            if (size == 0 || size > 64 * 1024 * 1024) { result["reason"] = "GetAdaptersInfo did not return a usable buffer size."; return result; }
            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                uint status = GetAdaptersInfo(buffer, ref size);
                result["status"] = status;
                if (status != 0) { result["reason"] = Win32Message(unchecked((int)status)); return result; }
                List<Dictionary<string, object>> adapters = new List<Dictionary<string, object>>();
                HashSet<long> visited = new HashSet<long>();
                for (IntPtr current = buffer; current != IntPtr.Zero && adapters.Count < 256 && visited.Add(current.ToInt64());
                    current = Marshal.ReadIntPtr(current, 0))
                {
                    int baseOffset = IntPtr.Size + 4;
                    int lengthOffset = baseOffset + 260 + 132;
                    uint addressLength = unchecked((uint)Marshal.ReadInt32(current, lengthOffset));
                    byte[] address = new byte[(int)Math.Min(addressLength, 8)];
                    if (address.Length != 0) Marshal.Copy(IntPtr.Add(current, lengthOffset + 4), address, 0, address.Length);
                    Dictionary<string, object> item = new Dictionary<string, object>();
                    item["name"] = Marshal.PtrToStringAnsi(IntPtr.Add(current, baseOffset), 260).TrimEnd('\0');
                    item["description"] = Marshal.PtrToStringAnsi(IntPtr.Add(current, baseOffset + 260), 132).TrimEnd('\0');
                    item["addressLength"] = addressLength;
                    item["addressBase64"] = Convert.ToBase64String(address);
                    item["addressHex"] = BitConverter.ToString(address).Replace("-", "");
                    adapters.Add(item);
                }
                result["adapters"] = adapters;
                result["success"] = true;
                return result;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static Dictionary<string, object> ReadAdaptersAddresses()
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            uint size = 0;
            uint first = GetAdaptersAddresses(AF_UNSPEC, 0, IntPtr.Zero, IntPtr.Zero, ref size);
            result["sizeStatus"] = first;
            result["requiredLength"] = size;
            if (size == 0 || size > 64 * 1024 * 1024) { result["reason"] = "GetAdaptersAddresses did not return a usable buffer size."; return result; }
            IntPtr buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                uint status = GetAdaptersAddresses(AF_UNSPEC, 0, IntPtr.Zero, buffer, ref size);
                result["status"] = status;
                if (status != 0) { result["reason"] = Win32Message(unchecked((int)status)); return result; }
                List<Dictionary<string, object>> adapters = new List<Dictionary<string, object>>();
                HashSet<long> visited = new HashSet<long>();
                for (IntPtr current = buffer; current != IntPtr.Zero && adapters.Count < 256 && visited.Add(current.ToInt64());
                    current = Marshal.ReadIntPtr(current, 8))
                {
                    IntPtr namePointer = Marshal.ReadIntPtr(current, 8 + IntPtr.Size);
                    int physicalOffset = 8 + (9 * IntPtr.Size);
                    uint addressLength = unchecked((uint)Marshal.ReadInt32(current, physicalOffset + 8));
                    byte[] address = new byte[(int)Math.Min(addressLength, 8)];
                    if (address.Length != 0) Marshal.Copy(IntPtr.Add(current, physicalOffset), address, 0, address.Length);
                    IntPtr dns = Marshal.ReadIntPtr(current, 8 + (6 * IntPtr.Size));
                    IntPtr description = Marshal.ReadIntPtr(current, 8 + (7 * IntPtr.Size));
                    IntPtr friendly = Marshal.ReadIntPtr(current, 8 + (8 * IntPtr.Size));
                    Dictionary<string, object> item = new Dictionary<string, object>();
                    item["name"] = namePointer == IntPtr.Zero ? null : Marshal.PtrToStringAnsi(namePointer);
                    item["dnsSuffix"] = dns == IntPtr.Zero ? null : Marshal.PtrToStringUni(dns);
                    item["description"] = description == IntPtr.Zero ? null : Marshal.PtrToStringUni(description);
                    item["friendlyName"] = friendly == IntPtr.Zero ? null : Marshal.PtrToStringUni(friendly);
                    item["addressLength"] = addressLength;
                    item["addressBase64"] = Convert.ToBase64String(address);
                    item["addressHex"] = BitConverter.ToString(address).Replace("-", "");
                    adapters.Add(item);
                }
                result["adapters"] = adapters;
                result["success"] = true;
                return result;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static Dictionary<string, object> ReadWkstaTransports()
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr buffer;
            uint read, total, resume = 0;
            uint status = NetWkstaTransportEnum(null, 0, out buffer, MAX_PREFERRED_LENGTH, out read, out total, ref resume);
            result["status"] = status;
            result["entriesRead"] = read;
            result["totalEntries"] = total;
            try
            {
                if (status != 0 && status != 234) { result["reason"] = Win32Message(unchecked((int)status)); return result; }
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
            finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
        }

        private static Dictionary<string, object> WithWsa(Action<Dictionary<string, object>> action)
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                IntPtr data = Marshal.AllocHGlobal(1024);
                bool started = false;
                try
                {
                    int startup = WSAStartup(0x0202, data);
                    result["startupStatus"] = startup;
                    if (startup != 0) { result["reason"] = "WSAStartup returned " + startup.ToString(CultureInfo.InvariantCulture); return; }
                    started = true;
                    action(result);
                    result["success"] = true;
                }
                finally
                {
                    if (started) try { WSACleanup(); } catch { }
                    Marshal.FreeHGlobal(data);
                }
            });
        }

        public static Dictionary<string, object> LookupWsa(string name)
        {
            return WithWsa(delegate(Dictionary<string, object> result)
            {
                result["unicode"] = LookupWsaOne(name, true);
                result["ansi"] = LookupWsaOne(name, false);
            });
        }

        private static Dictionary<string, object> LookupWsaOne(string name, bool unicode)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            uint lookupFlags = LUP_RETURN_NAME | LUP_RETURN_ADDR;
            IntPtr guidPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Guid)));
            IntPtr namePointer = unicode ? Marshal.StringToHGlobalUni(name) : Marshal.StringToHGlobalAnsi(name);
            IntPtr lookup = IntPtr.Zero;
            IntPtr buffer = IntPtr.Zero;
            try
            {
                Marshal.StructureToPtr(new Guid("0002A800-0000-0000-C000-000000000046"), guidPointer, false);
                WSAQUERYSET query = new WSAQUERYSET
                {
                    dwSize = (uint)Marshal.SizeOf(typeof(WSAQUERYSET)),
                    lpszServiceInstanceName = namePointer,
                    lpServiceClassId = guidPointer,
                    dwNameSpace = NS_DNS
                };
                int begin = unicode ? WSALookupServiceBeginW(ref query, lookupFlags, out lookup)
                    : WSALookupServiceBeginA(ref query, lookupFlags, out lookup);
                int beginError = begin == SOCKET_ERROR ? WSAGetLastError() : 0;
                result["beginStatus"] = begin; result["beginError"] = beginError;
                if (begin == SOCKET_ERROR) { result["reason"] = "WSALookupServiceBegin returned " + beginError.ToString(CultureInfo.InvariantCulture); return result; }

                uint required = 0;
                int first = unicode ? WSALookupServiceNextW(lookup, lookupFlags, ref required, IntPtr.Zero)
                    : WSALookupServiceNextA(lookup, lookupFlags, ref required, IntPtr.Zero);
                result["sizeStatus"] = first;
                result["sizeError"] = first == SOCKET_ERROR ? WSAGetLastError() : 0;
                result["requiredLength"] = required;
                if (required == 0 || required > 16 * 1024 * 1024) { result["reason"] = "WSALookupServiceNext did not return a usable buffer size."; return result; }

                buffer = Marshal.AllocHGlobal((int)required);
                RtlZeroMemory(buffer, new UIntPtr(required));
                int next = unicode ? WSALookupServiceNextW(lookup, lookupFlags, ref required, buffer)
                    : WSALookupServiceNextA(lookup, lookupFlags, ref required, buffer);
                int nextError = next == SOCKET_ERROR ? WSAGetLastError() : 0;
                result["nextStatus"] = next; result["nextError"] = nextError;
                if (next == SOCKET_ERROR) { result["reason"] = "WSALookupServiceNext returned " + nextError.ToString(CultureInfo.InvariantCulture); return result; }

                WSAQUERYSET output = (WSAQUERYSET)Marshal.PtrToStructure(buffer, typeof(WSAQUERYSET));
                result["name"] = output.lpszServiceInstanceName == IntPtr.Zero ? null
                    : (unicode ? Marshal.PtrToStringUni(output.lpszServiceInstanceName) : Marshal.PtrToStringAnsi(output.lpszServiceInstanceName));
                result["addressCount"] = output.dwNumberOfCsAddrs;
                List<Dictionary<string, object>> parsed = new List<Dictionary<string, object>>();
                int elementSize = Marshal.SizeOf(typeof(CSADDR_INFO));
                for (uint index = 0; index < output.dwNumberOfCsAddrs && index < 256; index++)
                {
                    CSADDR_INFO info = (CSADDR_INFO)Marshal.PtrToStructure(
                        IntPtr.Add(output.lpcsaBuffer, checked((int)(index * elementSize))), typeof(CSADDR_INFO));
                    Dictionary<string, object> address = ParseSocketAddress(info.RemoteAddr);
                    address["socketType"] = info.iSocketType;
                    address["protocol"] = info.iProtocol;
                    parsed.Add(address);
                }
                result["addresses"] = parsed;
                if (parsed.Count != 0) { result["address"] = parsed[0]["address"]; result["family"] = parsed[0]["family"]; }
                result["success"] = true;
                return result;
            }
            finally
            {
                if (lookup != IntPtr.Zero) WSALookupServiceEnd(lookup);
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                Marshal.FreeHGlobal(namePointer);
                Marshal.FreeHGlobal(guidPointer);
            }
        }

        private static Dictionary<string, object> ParseSocketAddress(SOCKET_ADDRESS socketAddress)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            if (socketAddress.lpSockaddr == IntPtr.Zero || socketAddress.iSockaddrLength < 2)
            {
                result["family"] = 0; result["address"] = null; return result;
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

        public static Dictionary<string, object> LookupHostResolvers(string name, int family, ushort type)
        {
            return WithWsa(delegate(Dictionary<string, object> result)
            {
                foreach (string api in new string[] { "addrWide", "addrAnsi", "addrEx", "addrExAnsi", "addrExAsync" })
                    result[api] = LookupHostAddress(name, family, api);
                foreach (string api in new string[] { "dnsWide", "dnsAnsi", "dnsUtf8", "dnsEx", "dnsExAsync", "dnsEx3" })
                    result[api] = LookupHostDns(name, type, api);
            });
        }

        private static Dictionary<string, object> LookupHostAddress(string name, int family, string api)
        {
            bool extended = api.StartsWith("addrEx", StringComparison.Ordinal);
            bool asynchronous = api == "addrExAsync";
            bool ansi = api == "addrAnsi" || api == "addrExAnsi";
            IntPtr addresses = IntPtr.Zero, overlapped = IntPtr.Zero, resultPointer = IntPtr.Zero, cancelPointer = IntPtr.Zero;
            using (ManualResetEvent completed = new ManualResetEvent(false))
            {
                try
                {
                    int status;
                    if (extended)
                    {
                        HostAddrInfoEx hints = new HostAddrInfoEx { Family = family, Flags = 2 };
                        if (asynchronous)
                        {
                            NativeOverlapped nativeOverlapped = new NativeOverlapped { EventHandle = completed.SafeWaitHandle.DangerousGetHandle() };
                            overlapped = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeOverlapped)));
                            Marshal.StructureToPtr(nativeOverlapped, overlapped, false);
                            cancelPointer = Marshal.AllocHGlobal(IntPtr.Size);
                            Marshal.WriteIntPtr(cancelPointer, IntPtr.Zero);
                        }
                        resultPointer = Marshal.AllocHGlobal(IntPtr.Size);
                        Marshal.WriteIntPtr(resultPointer, IntPtr.Zero);
                        status = ansi
                            ? HostGetAddrInfoExA(name, IntPtr.Zero, NS_DNS, IntPtr.Zero, ref hints, resultPointer, IntPtr.Zero, overlapped, IntPtr.Zero, cancelPointer)
                            : HostGetAddrInfoEx(name, IntPtr.Zero, NS_DNS, IntPtr.Zero, ref hints, resultPointer, IntPtr.Zero, overlapped, IntPtr.Zero, cancelPointer);
                        if (status == 997)
                        {
                            if (!completed.WaitOne(5000)) { IntPtr cancel = Marshal.ReadIntPtr(cancelPointer); HostCancelAddrInfoEx(ref cancel); }
                            completed.WaitOne();
                            status = HostGetAddrInfoExResult(overlapped);
                        }
                        addresses = Marshal.ReadIntPtr(resultPointer);
                    }
                    else
                    {
                        HostAddrInfo hints = new HostAddrInfo { Family = family, Flags = 2 };
                        status = api == "addrWide" ? HostGetAddrInfoW(name, IntPtr.Zero, ref hints, out addresses)
                            : HostGetAddrInfoA(name, IntPtr.Zero, ref hints, out addresses);
                    }

                    Dictionary<string, object> result = MethodResult(true, status == 0, null);
                    result["status"] = status;
                    List<Dictionary<string, object>> parsed = new List<Dictionary<string, object>>();
                    for (IntPtr current = addresses; current != IntPtr.Zero && parsed.Count < 256; )
                    {
                        IntPtr canonical, address, next;
                        int length;
                        if (extended)
                        {
                            HostAddrInfoEx info = (HostAddrInfoEx)Marshal.PtrToStructure(current, typeof(HostAddrInfoEx));
                            canonical = info.CanonicalName; address = info.Address; next = info.Next;
                            length = checked((int)info.AddressLength.ToUInt64());
                        }
                        else
                        {
                            HostAddrInfo info = (HostAddrInfo)Marshal.PtrToStructure(current, typeof(HostAddrInfo));
                            canonical = info.CanonicalName; address = info.Address; next = info.Next;
                            length = checked((int)info.AddressLength.ToUInt64());
                        }
                        if (canonical != IntPtr.Zero)
                            result["canonicalName"] = ansi ? Marshal.PtrToStringAnsi(canonical) : Marshal.PtrToStringUni(canonical);
                        parsed.Add(ParseSocketAddress(new SOCKET_ADDRESS { lpSockaddr = address, iSockaddrLength = length }));
                        current = next;
                    }
                    result["addresses"] = parsed;
                    return result;
                }
                finally
                {
                    if (addresses != IntPtr.Zero)
                    {
                        if (extended && ansi) HostFreeAddrInfoExA(addresses);
                        else if (extended) HostFreeAddrInfoEx(addresses);
                        else if (api == "addrWide") HostFreeAddrInfoW(addresses);
                        else HostFreeAddrInfoA(addresses);
                    }
                    if (overlapped != IntPtr.Zero) Marshal.FreeHGlobal(overlapped);
                    if (resultPointer != IntPtr.Zero) Marshal.FreeHGlobal(resultPointer);
                    if (cancelPointer != IntPtr.Zero) Marshal.FreeHGlobal(cancelPointer);
                }
            }
        }

        private static Dictionary<string, object> LookupHostDns(string name, ushort type, string api)
        {
            bool extended = api.StartsWith("dnsEx", StringComparison.Ordinal);
            bool asynchronous = api == "dnsExAsync";
            bool wide = extended || api == "dnsWide";
            IntPtr records = IntPtr.Zero, nativeResult = IntPtr.Zero, cancel = IntPtr.Zero, nativeName = IntPtr.Zero;
            bool callbackSeen = false, contextPreserved = true, pending = false;
            HostDnsCallback callback = null;
            using (ManualResetEvent completed = new ManualResetEvent(false))
            {
                try
                {
                    uint status;
                    if (extended)
                    {
                        nativeName = Marshal.StringToHGlobalUni(name);
                        HostDnsRequest request = new HostDnsRequest
                        {
                            Version = api == "dnsEx3" ? 3u : 1u, Name = nativeName, Type = type, Options = 0x10, Context = new IntPtr(1234)
                        };
                        if (asynchronous)
                        {
                            callback = delegate(IntPtr context, IntPtr queryResult)
                            {
                                contextPreserved = context == new IntPtr(1234);
                                callbackSeen = true;
                                completed.Set();
                            };
                            request.Callback = Marshal.GetFunctionPointerForDelegate(callback);
                        }
                        HostDnsResult response = new HostDnsResult { Version = 1 };
                        nativeResult = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(HostDnsResult)));
                        Marshal.StructureToPtr(response, nativeResult, false);
                        cancel = Marshal.AllocHGlobal(32);
                        RtlZeroMemory(cancel, new UIntPtr(32));
                        status = HostDnsQueryEx(ref request, nativeResult, cancel);
                        pending = status == 9506;
                        if (pending)
                        {
                            if (!completed.WaitOne(5000)) HostCancelDnsQuery(cancel);
                            completed.WaitOne();
                        }
                        response = (HostDnsResult)Marshal.PtrToStructure(nativeResult, typeof(HostDnsResult));
                        records = response.Records;
                        if (pending) status = response.Status;
                        if (request.Name != nativeName || request.Context != new IntPtr(1234))
                            throw new InvalidOperationException("The caller's DNS query was modified.");
                    }
                    else if (api == "dnsWide") status = HostDnsQueryW(name, type, 0x10, IntPtr.Zero, out records, IntPtr.Zero);
                    else if (api == "dnsAnsi") status = HostDnsQueryA(name, type, 0x10, IntPtr.Zero, out records, IntPtr.Zero);
                    else status = HostDnsQueryUtf8(Encoding.UTF8.GetBytes(name + "\0"), type, 0x10, IntPtr.Zero, out records, IntPtr.Zero);

                    Dictionary<string, object> result = MethodResult(true, status == 0, null);
                    result["status"] = status; result["pending"] = pending;
                    result["callbackSeen"] = callbackSeen; result["contextPreserved"] = contextPreserved;
                    List<Dictionary<string, object>> parsed = new List<Dictionary<string, object>>();
                    int headerSize = Marshal.SizeOf(typeof(HostDnsRecord));
                    for (IntPtr current = records; current != IntPtr.Zero && parsed.Count < 256; )
                    {
                        HostDnsRecord record = (HostDnsRecord)Marshal.PtrToStructure(current, typeof(HostDnsRecord));
                        Dictionary<string, object> item = new Dictionary<string, object>();
                        item["type"] = record.Type; item["ttl"] = record.Ttl;
                        item["name"] = wide ? Marshal.PtrToStringUni(record.Name) : Marshal.PtrToStringAnsi(record.Name);
                        if (record.Type == 1 || record.Type == 28)
                        {
                            byte[] bytes = new byte[record.Type == 1 ? 4 : 16];
                            Marshal.Copy(IntPtr.Add(current, headerSize), bytes, 0, bytes.Length);
                            item["address"] = new IPAddress(bytes).ToString();
                        }
                        parsed.Add(item);
                        current = record.Next;
                    }
                    result["records"] = parsed;
                    return result;
                }
                finally
                {
                    if (records != IntPtr.Zero) HostFreeDnsRecords(records, 1);
                    if (nativeResult != IntPtr.Zero) Marshal.FreeHGlobal(nativeResult);
                    if (cancel != IntPtr.Zero) Marshal.FreeHGlobal(cancel);
                    if (nativeName != IntPtr.Zero) Marshal.FreeHGlobal(nativeName);
                    GC.KeepAlive(callback);
                }
            }
        }

        private static Dictionary<string, object> AmsiCallResult(int hresult, int scanResult)
        {
            Dictionary<string, object> result = MethodResult(true, hresult >= 0, hresult >= 0 ? null : "AMSI HRESULT " + Hex32(hresult));
            result["hresult"] = hresult;
            result["hresultHex"] = Hex32(hresult);
            result["result"] = scanResult;
            return result;
        }

        public static Dictionary<string, object> ScanAmsi(string content, string contentName)
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                IntPtr context = IntPtr.Zero, session = IntPtr.Zero;
                try
                {
                    int initialize = AmsiInitialize("WinPrivProbe", out context);
                    result["initializeHresult"] = initialize;
                    result["initializeHresultHex"] = Hex32(initialize);
                    if (initialize < 0) result["reason"] = "AmsiInitialize returned " + Hex32(initialize);
                    int open = context == IntPtr.Zero ? unchecked((int)0x80070057) : AmsiOpenSession(context, out session);
                    result["openSessionHresult"] = open;
                    result["openSessionHresultHex"] = Hex32(open);
                    string text = content ?? String.Empty;
                    byte[] bytes = Encoding.Unicode.GetBytes(text);
                    int scan;
                    result["stringValid"] = AmsiCallResult(AmsiScanString(context, text, contentName, session, out scan), scan);
                    result["bufferValid"] = AmsiCallResult(AmsiScanBuffer(context, bytes, (uint)bytes.Length, contentName, session, out scan), scan);
                    result["stringInvalid"] = AmsiCallResult(AmsiScanString(IntPtr.Zero, text, contentName, IntPtr.Zero, out scan), scan);
                    result["bufferInvalid"] = AmsiCallResult(AmsiScanBuffer(IntPtr.Zero, bytes, (uint)bytes.Length, contentName, IntPtr.Zero, out scan), scan);
                    result["success"] = true;
                }
                finally
                {
                    if (context != IntPtr.Zero && session != IntPtr.Zero) AmsiCloseSession(context, session);
                    if (context != IntPtr.Zero) AmsiUninitialize(context);
                }
            });
        }
    }
}
