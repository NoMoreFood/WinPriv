using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace WinPrivTests
{
    public static class LsaPolicy
    {
        private const uint POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
        private const uint POLICY_CREATE_ACCOUNT = 0x00000010;
        private const uint POLICY_LOOKUP_NAMES = 0x00000800;
        private const int STATUS_SUCCESS = 0;
        private const int STATUS_NO_MORE_ENTRIES = unchecked((int)0x8000001A);
        private const int STATUS_OBJECT_NAME_NOT_FOUND = unchecked((int)0xC0000034);

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_ENUMERATION_INFORMATION
        {
            public IntPtr Sid;
        }

        [DllImport("advapi32.dll")]
        private static extern int LsaOpenPolicy(IntPtr systemName,
            ref LSA_OBJECT_ATTRIBUTES objectAttributes, uint desiredAccess, out IntPtr policyHandle);

        [DllImport("advapi32.dll")]
        private static extern int LsaClose(IntPtr objectHandle);

        [DllImport("advapi32.dll")]
        private static extern int LsaFreeMemory(IntPtr buffer);

        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(int status);

        [DllImport("advapi32.dll")]
        private static extern int LsaEnumerateAccountRights(IntPtr policyHandle, byte[] accountSid,
            out IntPtr userRights, out uint countOfRights);

        [DllImport("advapi32.dll")]
        private static extern int LsaAddAccountRights(IntPtr policyHandle, byte[] accountSid,
            [In] LSA_UNICODE_STRING[] userRights, uint countOfRights);

        [DllImport("advapi32.dll")]
        private static extern int LsaRemoveAccountRights(IntPtr policyHandle, byte[] accountSid,
            [MarshalAs(UnmanagedType.Bool)] bool allRights,
            [In] LSA_UNICODE_STRING[] userRights, uint countOfRights);

        [DllImport("advapi32.dll")]
        private static extern int LsaEnumerateAccountsWithUserRight(IntPtr policyHandle,
            ref LSA_UNICODE_STRING userRight, out IntPtr buffer, out uint countReturned);

        public static string ResolveSid(string accountOrSid)
        {
            return GetSid(accountOrSid).Value;
        }

        public static string[] GetRights(string accountOrSid)
        {
            SecurityIdentifier sid = GetSid(accountOrSid);
            byte[] sidBytes = SidBytes(sid);
            IntPtr policy = OpenPolicy(POLICY_LOOKUP_NAMES);
            IntPtr buffer = IntPtr.Zero;
            try
            {
                uint count;
                int status = LsaEnumerateAccountRights(policy, sidBytes, out buffer, out count);
                if (status == STATUS_OBJECT_NAME_NOT_FOUND || LsaNtStatusToWinError(status) == 2)
                    return new string[0];
                ThrowStatus(status, "LsaEnumerateAccountRights");
                List<string> rights = new List<string>();
                int size = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
                for (uint index = 0; index < count; index++)
                {
                    LSA_UNICODE_STRING value = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, checked((int)(index * size))), typeof(LSA_UNICODE_STRING));
                    rights.Add(ReadString(value));
                }
                return rights.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();
            }
            finally
            {
                if (buffer != IntPtr.Zero) LsaFreeMemory(buffer);
                LsaClose(policy);
            }
        }

        public static void SetRights(string accountOrSid, string[] desiredRights)
        {
            SecurityIdentifier sid = GetSid(accountOrSid);
            string[] desired = (desiredRights ?? new string[0])
                .Where(value => !String.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            string[] current = GetRights(sid.Value);
            string[] remove = current.Except(desired, StringComparer.OrdinalIgnoreCase).ToArray();
            string[] add = desired.Except(current, StringComparer.OrdinalIgnoreCase).ToArray();
            IntPtr policy = OpenPolicy(POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT);
            try
            {
                if (remove.Length != 0)
                {
                    WithStrings(remove, values => ThrowStatus(
                        LsaRemoveAccountRights(policy, SidBytes(sid), false, values, (uint)values.Length),
                        "LsaRemoveAccountRights"));
                }
                if (add.Length != 0)
                {
                    WithStrings(add, values => ThrowStatus(
                        LsaAddAccountRights(policy, SidBytes(sid), values, (uint)values.Length),
                        "LsaAddAccountRights"));
                }
            }
            finally { LsaClose(policy); }
        }

        public static string[] GetAccountSidsWithRight(string right)
        {
            if (String.IsNullOrWhiteSpace(right)) throw new ArgumentException("right is required", "right");
            IntPtr policy = OpenPolicy(POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION);
            IntPtr buffer = IntPtr.Zero;
            IntPtr rightBuffer = Marshal.StringToHGlobalUni(right);
            try
            {
                LSA_UNICODE_STRING value = MakeString(right, rightBuffer);
                uint count;
                int status = LsaEnumerateAccountsWithUserRight(policy, ref value, out buffer, out count);
                if (status == STATUS_NO_MORE_ENTRIES || status == STATUS_OBJECT_NAME_NOT_FOUND ||
                    LsaNtStatusToWinError(status) == 2) return new string[0];
                ThrowStatus(status, "LsaEnumerateAccountsWithUserRight");
                List<string> sids = new List<string>();
                int size = Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION));
                for (uint index = 0; index < count; index++)
                {
                    LSA_ENUMERATION_INFORMATION item = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, checked((int)(index * size))), typeof(LSA_ENUMERATION_INFORMATION));
                    sids.Add(new SecurityIdentifier(item.Sid).Value);
                }
                return sids.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToArray();
            }
            finally
            {
                if (buffer != IntPtr.Zero) LsaFreeMemory(buffer);
                Marshal.FreeHGlobal(rightBuffer);
                LsaClose(policy);
            }
        }

        public static void SetAccountsWithRight(string right, string[] desiredAccountsOrSids)
        {
            string[] desired = (desiredAccountsOrSids ?? new string[0])
                .Where(value => !String.IsNullOrWhiteSpace(value)).Select(ResolveSid)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            string[] current = GetAccountSidsWithRight(right);
            foreach (string sid in current.Except(desired, StringComparer.OrdinalIgnoreCase))
            {
                string[] rights = GetRights(sid).Where(value =>
                    !String.Equals(value, right, StringComparison.OrdinalIgnoreCase)).ToArray();
                SetRights(sid, rights);
            }
            foreach (string sid in desired.Except(current, StringComparer.OrdinalIgnoreCase))
            {
                string[] rights = GetRights(sid).Concat(new string[] { right }).ToArray();
                SetRights(sid, rights);
            }
        }

        private static SecurityIdentifier GetSid(string accountOrSid)
        {
            if (String.IsNullOrWhiteSpace(accountOrSid)) throw new ArgumentException("account or SID is required");
            if (accountOrSid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
                return new SecurityIdentifier(accountOrSid);
            return (SecurityIdentifier)new NTAccount(accountOrSid).Translate(typeof(SecurityIdentifier));
        }

        private static byte[] SidBytes(SecurityIdentifier sid)
        {
            byte[] value = new byte[sid.BinaryLength];
            sid.GetBinaryForm(value, 0);
            return value;
        }

        private static IntPtr OpenPolicy(uint access)
        {
            LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
            attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            IntPtr policy;
            int status = LsaOpenPolicy(IntPtr.Zero, ref attributes, access, out policy);
            ThrowStatus(status, "LsaOpenPolicy");
            return policy;
        }

        private static string ReadString(LSA_UNICODE_STRING value)
        {
            return value.Buffer == IntPtr.Zero || value.Length == 0
                ? String.Empty : Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
        }

        private static LSA_UNICODE_STRING MakeString(string value, IntPtr buffer)
        {
            LSA_UNICODE_STRING result = new LSA_UNICODE_STRING();
            result.Buffer = buffer;
            result.Length = checked((ushort)(value.Length * 2));
            result.MaximumLength = checked((ushort)(result.Length + 2));
            return result;
        }

        private static void WithStrings(string[] strings, Action<LSA_UNICODE_STRING[]> action)
        {
            IntPtr[] buffers = new IntPtr[strings.Length];
            LSA_UNICODE_STRING[] values = new LSA_UNICODE_STRING[strings.Length];
            try
            {
                for (int index = 0; index < strings.Length; index++)
                {
                    buffers[index] = Marshal.StringToHGlobalUni(strings[index]);
                    values[index] = MakeString(strings[index], buffers[index]);
                }
                action(values);
            }
            finally
            {
                foreach (IntPtr buffer in buffers)
                    if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            }
        }

        private static void ThrowStatus(int status, string operation)
        {
            if (status == STATUS_SUCCESS) return;
            uint error = LsaNtStatusToWinError(status);
            throw new Win32Exception(unchecked((int)error), operation + " failed (NTSTATUS 0x" +
                unchecked((uint)status).ToString("X8") + ")");
        }
    }
}
