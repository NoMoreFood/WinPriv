using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace WinPrivProbe
{
    public static partial class Native
    {
        [DllImport("winsta.dll", SetLastError = true)]
        private static extern byte WinStationGetCurrentSessionCapabilities(uint capability, out uint value);

        [DllImport("winscard.dll")]
        private static extern int SCardEstablishContext(uint scope, IntPtr reserved1, IntPtr reserved2,
            out UIntPtr context);

        [DllImport("winscard.dll", CharSet = CharSet.Unicode)]
        private static extern int SCardListReadersW(UIntPtr context, string groups, out IntPtr readers,
            ref uint characters);

        [DllImport("winscard.dll")]
        private static extern int SCardIsValidContext(UIntPtr context);

        [DllImport("winscard.dll")]
        private static extern int SCardFreeMemory(UIntPtr context, IntPtr memory);

        [DllImport("winscard.dll")]
        private static extern int SCardReleaseContext(UIntPtr context);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptSignHash(IntPtr key, IntPtr paddingInfo, byte[] hash, int hashSize,
            byte[] signature, int signatureSize, out int resultSize, uint flags);

        public static Dictionary<string, object> GetSoftwareSigning()
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            byte[] hash = new byte[32];
            int size;
            result["invalidHandleStatus"] = unchecked((uint)NCryptSignHash(IntPtr.Zero, IntPtr.Zero,
                hash, hash.Length, null, 0, out size, 0));

            // Exercise silent and interactive signing without persisting a key.
            List<Dictionary<string, object>> signatures = new List<Dictionary<string, object>>();
            using (ECDsaCng key = new ECDsaCng(256))
            using (var handle = key.Key.Handle)
            {
                foreach (uint flags in new uint[] { 0, 0x40 })
                {
                    Dictionary<string, object> signing = new Dictionary<string, object>();
                    signing["flags"] = flags;
                    int status = NCryptSignHash(handle.DangerousGetHandle(), IntPtr.Zero,
                        hash, hash.Length, null, 0, out size, flags);
                    signing["sizeStatus"] = unchecked((uint)status);
                    if (status == 0)
                    {
                        byte[] signature = new byte[size];
                        status = NCryptSignHash(handle.DangerousGetHandle(), IntPtr.Zero,
                            hash, hash.Length, signature, signature.Length, out size, flags);
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
            // Observe session queries outside WinSCard and reserved-argument validation.
            Dictionary<string, object> result = new Dictionary<string, object>();
            uint capabilities;
            result["capabilitySuccess"] = WinStationGetCurrentSessionCapabilities(1, out capabilities) != 0;
            result["capabilities"] = capabilities;
            result["sessionId"] = Process.GetCurrentProcess().SessionId;
            UIntPtr context;
            result["invalidReservedStatus"] = unchecked((uint)SCardEstablishContext(2,
                new IntPtr(1), IntPtr.Zero, out context));

            // Enumerate user and system contexts without authenticating to the card.
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
                        finally
                        {
                            if (readers != IntPtr.Zero) SCardFreeMemory(context, readers);
                        }
                    }
                    finally
                    {
                        reading["releaseStatus"] = unchecked((uint)SCardReleaseContext(context));
                    }
                }
                contexts.Add(reading);
            }
            result["contexts"] = contexts;
            return result;
        }
    }
}
