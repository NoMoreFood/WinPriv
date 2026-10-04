using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace WinPrivProbe
{
    public static partial class Native
    {
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
        private struct HostOverlapped
        {
            public IntPtr Internal, InternalHigh;
            public uint Offset, OffsetHigh;
            public IntPtr Event;
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
        private struct HostDnsResult
        {
            public uint Version, Status;
            public ulong Options;
            public IntPtr Records, Reserved;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void HostDnsCallback(IntPtr context, IntPtr result);

        [DllImport("ws2_32.dll", EntryPoint = "GetAddrInfoW", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int HostGetAddrInfoW(string name, IntPtr service,
            ref HostAddrInfo hints, out IntPtr result);

        [DllImport("ws2_32.dll", EntryPoint = "getaddrinfo", ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern int HostGetAddrInfoA(string name, IntPtr service,
            ref HostAddrInfo hints, out IntPtr result);

        [DllImport("ws2_32.dll", EntryPoint = "GetAddrInfoExW", ExactSpelling = true, CharSet = CharSet.Unicode)]
        private static extern int HostGetAddrInfoEx(string name, IntPtr service, uint nameSpace,
            IntPtr provider, ref HostAddrInfoEx hints, IntPtr result,
            IntPtr timeout, IntPtr overlapped, IntPtr callback, IntPtr cancel);

        [DllImport("ws2_32.dll", EntryPoint = "GetAddrInfoExA", ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern int HostGetAddrInfoExA(string name, IntPtr service, uint nameSpace,
            IntPtr provider, ref HostAddrInfoEx hints, IntPtr result,
            IntPtr timeout, IntPtr overlapped, IntPtr callback, IntPtr cancel);

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
        private static extern uint HostDnsQueryW(string name, ushort type, uint options,
            IntPtr extra, out IntPtr result, IntPtr reserved);

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_A", ExactSpelling = true, CharSet = CharSet.Ansi)]
        private static extern uint HostDnsQueryA(string name, ushort type, uint options,
            IntPtr extra, out IntPtr result, IntPtr reserved);

        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_UTF8", ExactSpelling = true)]
        private static extern uint HostDnsQueryUtf8(byte[] name, ushort type, uint options,
            IntPtr extra, out IntPtr result, IntPtr reserved);

        [DllImport("dnsapi.dll", EntryPoint = "DnsQueryEx")]
        private static extern uint HostDnsQueryEx(ref HostDnsRequest request, IntPtr result, IntPtr cancel);

        [DllImport("dnsapi.dll", EntryPoint = "DnsCancelQuery")]
        private static extern uint HostCancelDnsQuery(IntPtr cancel);

        [DllImport("dnsapi.dll", EntryPoint = "DnsRecordListFree")]
        private static extern void HostFreeDnsRecords(IntPtr result, int freeType);

        public static Dictionary<string, object> LookupHostResolvers(string name, int family, ushort type)
        {
            // Exercise application entry points with their native result ownership and asynchronous completion.
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr startupData = Marshal.AllocHGlobal(1024);
            try
            {
                int startup = WSAStartup(0x0202, startupData);
                if (startup != 0) throw new InvalidOperationException("WSAStartup returned " + startup);
                foreach (string api in new string[] { "addrWide", "addrAnsi", "addrEx", "addrExAnsi", "addrExAsync" })
                    result[api] = LookupHostAddress(name, family, api);
                foreach (string api in new string[] {
                    "dnsWide", "dnsAnsi", "dnsUtf8", "dnsEx", "dnsExAsync", "dnsEx3" })
                    result[api] = LookupHostDns(name, type, api);
                result["success"] = true;
                return result;
            }
            finally
            {
                WSACleanup();
                Marshal.FreeHGlobal(startupData);
            }
        }

        private static Dictionary<string, object> LookupHostAddress(string name, int family, string api)
        {
            bool extended = api.StartsWith("addrEx", StringComparison.Ordinal);
            bool asynchronous = api == "addrExAsync";
            bool ansi = api == "addrAnsi" || api == "addrExAnsi";
            IntPtr addresses = IntPtr.Zero;
            IntPtr overlapped = IntPtr.Zero, resultPointer = IntPtr.Zero, cancelPointer = IntPtr.Zero;
            using (ManualResetEvent completed = new ManualResetEvent(false))
            {
                try
                {
                    int status;
                    if (extended)
                    {
                        HostAddrInfoEx hints = new HostAddrInfoEx();
                        hints.Family = family;
                        hints.Flags = 2;
                        if (asynchronous)
                        {
                            HostOverlapped nativeOverlapped = new HostOverlapped();
                            nativeOverlapped.Event = completed.SafeWaitHandle.DangerousGetHandle();
                            overlapped = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(HostOverlapped)));
                            Marshal.StructureToPtr(nativeOverlapped, overlapped, false);
                            cancelPointer = Marshal.AllocHGlobal(IntPtr.Size);
                            Marshal.WriteIntPtr(cancelPointer, IntPtr.Zero);
                        }
                        resultPointer = Marshal.AllocHGlobal(IntPtr.Size);
                        Marshal.WriteIntPtr(resultPointer, IntPtr.Zero);
                        status = ansi
                            ? HostGetAddrInfoExA(name, IntPtr.Zero, NS_DNS, IntPtr.Zero, ref hints,
                                resultPointer, IntPtr.Zero, overlapped, IntPtr.Zero, cancelPointer)
                            : HostGetAddrInfoEx(name, IntPtr.Zero, NS_DNS, IntPtr.Zero, ref hints,
                                resultPointer, IntPtr.Zero, overlapped, IntPtr.Zero, cancelPointer);
                        if (status == 997)
                        {
                            if (!completed.WaitOne(5000))
                            {
                                IntPtr cancel = Marshal.ReadIntPtr(cancelPointer);
                                HostCancelAddrInfoEx(ref cancel);
                            }
                            completed.WaitOne();
                            status = HostGetAddrInfoExResult(overlapped);
                        }
                        addresses = Marshal.ReadIntPtr(resultPointer);
                    }
                    else
                    {
                        HostAddrInfo hints = new HostAddrInfo();
                        hints.Family = family;
                        hints.Flags = 2;
                        status = api == "addrWide"
                            ? HostGetAddrInfoW(name, IntPtr.Zero, ref hints, out addresses)
                            : HostGetAddrInfoA(name, IntPtr.Zero, ref hints, out addresses);
                    }

                    // Preserve every address and the canonical name reported by the native resolver.
                    Dictionary<string, object> result = MethodResult(true, status == 0, null);
                    result["status"] = status;
                    List<Dictionary<string, object>> parsed = new List<Dictionary<string, object>>();
                    for (IntPtr current = addresses; current != IntPtr.Zero && parsed.Count < 256; )
                    {
                        IntPtr canonical, address, next;
                        int length;
                        if (extended)
                        {
                            HostAddrInfoEx info = (HostAddrInfoEx)Marshal.PtrToStructure(
                                current, typeof(HostAddrInfoEx));
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
                            result["canonicalName"] = ansi
                                ? Marshal.PtrToStringAnsi(canonical) : Marshal.PtrToStringUni(canonical);
                        parsed.Add(ParseSocketAddress(new SOCKET_ADDRESS {
                            lpSockaddr = address, iSockaddrLength = length }));
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
                        HostDnsRequest request = new HostDnsRequest();
                        request.Version = api == "dnsEx3" ? 3u : 1u;
                        request.Name = nativeName;
                        request.Type = type;
                        request.Options = 0x10;
                        request.Context = new IntPtr(1234);
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
                        HostDnsResult response = new HostDnsResult();
                        response.Version = 1;
                        nativeResult = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(HostDnsResult)));
                        Marshal.StructureToPtr(response, nativeResult, false);
                        cancel = Marshal.AllocHGlobal(32);
                        ZeroMemory(cancel, 32);
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
                    else if (api == "dnsWide")
                        status = HostDnsQueryW(name, type, 0x10, IntPtr.Zero, out records, IntPtr.Zero);
                    else if (api == "dnsAnsi")
                        status = HostDnsQueryA(name, type, 0x10, IntPtr.Zero, out records, IntPtr.Zero);
                    else
                        status = HostDnsQueryUtf8(Encoding.UTF8.GetBytes(name + "\0"), type, 0x10,
                            IntPtr.Zero, out records, IntPtr.Zero);

                    // Read DNS records without rewriting names, address sets, or TTLs in the probe.
                    Dictionary<string, object> result = MethodResult(true, status == 0, null);
                    result["status"] = status;
                    result["pending"] = pending;
                    result["callbackSeen"] = callbackSeen;
                    result["contextPreserved"] = contextPreserved;
                    List<Dictionary<string, object>> parsed = new List<Dictionary<string, object>>();
                    int headerSize = Marshal.SizeOf(typeof(HostDnsRecord));
                    for (IntPtr current = records; current != IntPtr.Zero && parsed.Count < 256; )
                    {
                        HostDnsRecord record = (HostDnsRecord)Marshal.PtrToStructure(current, typeof(HostDnsRecord));
                        Dictionary<string, object> item = new Dictionary<string, object>();
                        item["type"] = record.Type;
                        item["ttl"] = record.Ttl;
                        item["name"] = wide
                            ? Marshal.PtrToStringUni(record.Name) : Marshal.PtrToStringAnsi(record.Name);
                        if (record.Type == 1 || record.Type == 28)
                        {
                            byte[] bytes = new byte[record.Type == 1 ? 4 : 16];
                            Marshal.Copy(IntPtr.Add(current, headerSize), bytes, 0, bytes.Length);
                            item["address"] = new System.Net.IPAddress(bytes).ToString();
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
    }
}
