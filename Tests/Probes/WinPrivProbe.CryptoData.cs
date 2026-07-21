using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace WinPrivProbe
{
    public static partial class Native
    {
        private const uint BCRYPT_SUCCESS = 0;
        private const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
        private const uint PROV_RSA_AES = 24;
        private const byte PLAINTEXTKEYBLOB = 8;
        private const byte CUR_BLOB_VERSION = 2;
        private const uint CALG_AES_128 = 0x0000660e;
        private const uint KP_IV = 1;
        private const uint KP_MODE = 4;
        private const uint CRYPT_MODE_CBC = 1;
        private const short SQL_HANDLE_ENV = 1;
        private const short SQL_HANDLE_DBC = 2;
        private const int SQL_ATTR_ODBC_VERSION = 200;
        private const int SQL_OV_ODBC3 = 3;
        private const short SQL_NTS = -3;
        private const ushort SQL_DRIVER_NOPROMPT = 0;
        private const short SQL_SUCCESS = 0;
        private const short SQL_SUCCESS_WITH_INFO = 1;
        private const short SQL_NO_DATA = 100;
        private const uint POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
        private const uint POLICY_LOOKUP_NAMES = 0x00000800;
        private const int STATUS_MORE_ENTRIES = 0x00000105;

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

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_POLICY_PRIVILEGE_DEFINITION
        {
            public LSA_UNICODE_STRING Name;
            public LUID LocalValue;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr algorithm,
            string algorithmId, string implementation, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr algorithm, uint flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptGetProperty(IntPtr handle, string property, byte[] output,
            int outputLength, out int resultLength, uint flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptSetProperty(IntPtr handle, string property, byte[] input,
            int inputLength, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(IntPtr algorithm, out IntPtr key,
            IntPtr keyObject, int keyObjectLength, byte[] secret, int secretLength, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr key);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptEncrypt(IntPtr key, IntPtr input, int inputLength,
            IntPtr paddingInfo, IntPtr iv, int ivLength, IntPtr output, int outputLength,
            out int resultLength, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDecrypt(IntPtr key, IntPtr input, int inputLength,
            IntPtr paddingInfo, IntPtr iv, int ivLength, IntPtr output, int outputLength,
            out int resultLength, uint flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptAcquireContextW(out IntPtr provider, string container,
            string providerName, uint providerType, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptReleaseContext(IntPtr provider, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptImportKey(IntPtr provider, byte[] data, uint dataLength,
            IntPtr publicKey, uint flags, out IntPtr key);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptDestroyKey(IntPtr key);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptSetKeyParam(IntPtr key, uint parameter, byte[] data, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptEncrypt(IntPtr key, IntPtr hash, bool final, uint flags,
            byte[] data, ref uint dataLength, uint bufferLength);

        [DllImport("advapi32.dll", EntryPoint = "CryptEncrypt", SetLastError = true)]
        private static extern bool CryptEncryptSize(IntPtr key, IntPtr hash, bool final, uint flags,
            IntPtr data, ref uint dataLength, uint bufferLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptDecrypt(IntPtr key, IntPtr hash, bool final, uint flags,
            byte[] data, ref uint dataLength);

        [DllImport("advapi32.dll", EntryPoint = "SystemFunction040")]
        private static extern int RtlEncryptMemory(byte[] memory, uint memorySize, uint optionFlags);

        [DllImport("advapi32.dll", EntryPoint = "SystemFunction041")]
        private static extern int RtlDecryptMemory(byte[] memory, uint memorySize, uint optionFlags);

        [DllImport("odbc32.dll")]
        private static extern short SQLAllocHandle(short handleType, IntPtr inputHandle, out IntPtr outputHandle);

        [DllImport("odbc32.dll")]
        private static extern short SQLFreeHandle(short handleType, IntPtr handle);

        [DllImport("odbc32.dll")]
        private static extern short SQLSetEnvAttr(IntPtr environment, int attribute,
            IntPtr value, int stringLength);

        [DllImport("odbc32.dll", CharSet = CharSet.Unicode)]
        private static extern short SQLDriverConnectW(IntPtr connection, IntPtr window,
            string connectionStringIn, short connectionStringInLength,
            StringBuilder connectionStringOut, short connectionStringOutMaximum,
            out short connectionStringOutLength, ushort driverCompletion);

        [DllImport("odbc32.dll", CharSet = CharSet.Ansi)]
        private static extern short SQLDriverConnectA(IntPtr connection, IntPtr window,
            string connectionStringIn, short connectionStringInLength,
            StringBuilder connectionStringOut, short connectionStringOutMaximum,
            out short connectionStringOutLength, ushort driverCompletion);

        [DllImport("odbc32.dll", CharSet = CharSet.Unicode)]
        private static extern short SQLGetDiagRecW(short handleType, IntPtr handle,
            short recordNumber, StringBuilder state, out int nativeError,
            StringBuilder message, short messageMaximum, out short messageLength);

        [DllImport("odbc32.dll", CharSet = CharSet.Ansi)]
        private static extern short SQLGetDiagRecA(short handleType, IntPtr handle,
            short recordNumber, StringBuilder state, out int nativeError,
            StringBuilder message, short messageMaximum, out short messageLength);

        [DllImport("ole32.dll")]
        private static extern int CoInitialize(IntPtr reserved);

        [DllImport("ole32.dll")]
        private static extern int CoInitializeEx(IntPtr reserved, uint coInitialize);

        [DllImport("ole32.dll")]
        private static extern void CoUninitialize();

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

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
        private static extern int LsaEnumerateAccountsWithUserRight(IntPtr policyHandle,
            ref LSA_UNICODE_STRING userRight, out IntPtr buffer, out uint countReturned);

        [DllImport("advapi32.dll")]
        private static extern int LsaEnumeratePrivileges(IntPtr policyHandle,
            ref uint enumerationContext, out IntPtr buffer, uint preferredMaximumLength,
            out uint countReturned);

        public static Dictionary<string, object> RunCrypto(byte[] plaintext)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            if (plaintext == null || plaintext.Length == 0 || plaintext.Length % 16 != 0)
            {
                result["reason"] = "plaintext must be non-empty and a multiple of 16 bytes";
                return result;
            }
            result["plaintextBase64"] = Convert.ToBase64String(plaintext);
            result["processId"] = GetCurrentProcessId();
            result["threadId"] = GetCurrentThreadId();
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = (byte)i;
                iv[i] = (byte)(0xA0 + i);
            }
            result["keyBase64"] = Convert.ToBase64String(key);
            result["ivBase64"] = Convert.ToBase64String(iv);
            try
            {
                Dictionary<string, object>[] bcrypt = RunBcrypt(plaintext, key, iv);
                result["bcryptSeparate"] = bcrypt[0];
                result["bcryptInPlace"] = bcrypt[1];
            }
            catch (DllNotFoundException error)
            {
                result["bcryptSeparate"] = MethodResult(false, false, error.Message);
                result["bcryptInPlace"] = MethodResult(false, false, error.Message);
            }
            catch (EntryPointNotFoundException error)
            {
                result["bcryptSeparate"] = MethodResult(false, false, error.Message);
                result["bcryptInPlace"] = MethodResult(false, false, error.Message);
            }
            catch (Exception error)
            {
                result["bcryptSeparate"] = MethodResult(true, false, error.GetType().FullName + ": " + error.Message);
                result["bcryptInPlace"] = MethodResult(true, false, error.GetType().FullName + ": " + error.Message);
            }
            result["cryptoApi"] = RunCryptoApi(plaintext, key, iv);
            result["rtl"] = RunRtlCrypto(plaintext);
            result["success"] = true;
            return result;
        }

        private static Dictionary<string, object>[] RunBcrypt(byte[] plaintext, byte[] secret, byte[] iv)
        {
            Dictionary<string, object> separate = MethodResult(true, false, null);
            Dictionary<string, object> inPlace = MethodResult(true, false, null);
            IntPtr algorithm = IntPtr.Zero;
            IntPtr key = IntPtr.Zero;
            IntPtr keyObject = IntPtr.Zero;
            try
            {
                int status = BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0);
                separate["openStatus"] = status;
                inPlace["openStatus"] = status;
                if (status != 0) throw new InvalidOperationException("BCryptOpenAlgorithmProvider returned " + Hex32(status));
                byte[] chaining = Encoding.Unicode.GetBytes("ChainingModeCBC\0");
                status = BCryptSetProperty(algorithm, "ChainingMode", chaining, chaining.Length, 0);
                if (status != 0) throw new InvalidOperationException("BCryptSetProperty returned " + Hex32(status));
                byte[] objectLengthBytes = new byte[4];
                int returned;
                status = BCryptGetProperty(algorithm, "ObjectLength", objectLengthBytes,
                    objectLengthBytes.Length, out returned, 0);
                if (status != 0) throw new InvalidOperationException("BCryptGetProperty returned " + Hex32(status));
                int objectLength = BitConverter.ToInt32(objectLengthBytes, 0);
                keyObject = Marshal.AllocHGlobal(objectLength);
                status = BCryptGenerateSymmetricKey(algorithm, out key, keyObject, objectLength,
                    secret, secret.Length, 0);
                if (status != 0) throw new InvalidOperationException("BCryptGenerateSymmetricKey returned " + Hex32(status));

                byte[] separateCipher;
                int encryptStatus = BcryptTransform(key, plaintext, iv, true, false, out separateCipher);
                byte[] separatePlain = new byte[0];
                int decryptStatus = encryptStatus == 0
                    ? BcryptTransform(key, separateCipher, iv, false, false, out separatePlain)
                    : -1;
                separate["encryptStatus"] = encryptStatus;
                separate["encryptStatusHex"] = Hex32(encryptStatus);
                separate["decryptStatus"] = decryptStatus;
                separate["decryptStatusHex"] = Hex32(decryptStatus);
                separate["ciphertextBase64"] = Convert.ToBase64String(separateCipher);
                separate["decryptedBase64"] = Convert.ToBase64String(separatePlain);
                separate["encryptRecordExpectedBase64"] = Convert.ToBase64String(plaintext);
				separate["decryptRecordExpectedBase64"] = Convert.ToBase64String(separatePlain);
                separate["success"] = encryptStatus == 0 && decryptStatus == 0 && BytesEqual(plaintext, separatePlain);
                if (!(bool)separate["success"])
                    separate["reason"] = "BCrypt separate-buffer round trip failed.";

                byte[] inPlaceCipher;
                encryptStatus = BcryptTransform(key, plaintext, iv, true, true, out inPlaceCipher);
                byte[] inPlacePlain = new byte[0];
                decryptStatus = encryptStatus == 0
                    ? BcryptTransform(key, inPlaceCipher, iv, false, true, out inPlacePlain)
                    : -1;
                inPlace["encryptStatus"] = encryptStatus;
                inPlace["encryptStatusHex"] = Hex32(encryptStatus);
                inPlace["decryptStatus"] = decryptStatus;
                inPlace["decryptStatusHex"] = Hex32(decryptStatus);
                inPlace["ciphertextBase64"] = Convert.ToBase64String(inPlaceCipher);
                inPlace["decryptedBase64"] = Convert.ToBase64String(inPlacePlain);
                inPlace["encryptRecordExpectedBase64"] = Convert.ToBase64String(plaintext);
                inPlace["decryptRecordExpectedBase64"] = Convert.ToBase64String(inPlacePlain);
                inPlace["success"] = encryptStatus == 0 && decryptStatus == 0 && BytesEqual(plaintext, inPlacePlain);
                if (!(bool)inPlace["success"])
                    inPlace["reason"] = "BCrypt in-place round trip failed.";
                return new Dictionary<string, object>[] { separate, inPlace };
            }
            finally
            {
                if (key != IntPtr.Zero) BCryptDestroyKey(key);
                if (keyObject != IntPtr.Zero) Marshal.FreeHGlobal(keyObject);
                if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
            }
        }

        private static int BcryptTransform(IntPtr key, byte[] input, byte[] iv, bool encrypt,
            bool inPlace, out byte[] output)
        {
            IntPtr inputPointer = Marshal.AllocHGlobal(input.Length);
            IntPtr outputPointer = inPlace ? inputPointer : Marshal.AllocHGlobal(input.Length);
            IntPtr ivPointer = Marshal.AllocHGlobal(iv.Length);
            try
            {
                Marshal.Copy(input, 0, inputPointer, input.Length);
                Marshal.Copy(iv, 0, ivPointer, iv.Length);
                int returned;
                int status = encrypt
                    ? BCryptEncrypt(key, inputPointer, input.Length, IntPtr.Zero, ivPointer, iv.Length,
                        outputPointer, input.Length, out returned, 0)
                    : BCryptDecrypt(key, inputPointer, input.Length, IntPtr.Zero, ivPointer, iv.Length,
                        outputPointer, input.Length, out returned, 0);
                if (status == 0 && returned >= 0 && returned <= input.Length)
                {
                    output = new byte[returned];
                    if (returned != 0) Marshal.Copy(outputPointer, output, 0, returned);
                }
                else output = new byte[0];
                return status;
            }
            finally
            {
                Marshal.FreeHGlobal(ivPointer);
                if (!inPlace) Marshal.FreeHGlobal(outputPointer);
                Marshal.FreeHGlobal(inputPointer);
            }
        }

        private static Dictionary<string, object> RunCryptoApi(byte[] plaintext, byte[] secret, byte[] iv)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr provider = IntPtr.Zero;
            IntPtr encryptKey = IntPtr.Zero;
            IntPtr decryptKey = IntPtr.Zero;
            try
            {
                if (!CryptAcquireContextW(out provider, null, null, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                byte[] blob = PlaintextKeyBlob(secret);
                if (!CryptImportKey(provider, blob, (uint)blob.Length, IntPtr.Zero, 0, out encryptKey))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                if (!CryptImportKey(provider, blob, (uint)blob.Length, IntPtr.Zero, 0, out decryptKey))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                byte[] mode = BitConverter.GetBytes(CRYPT_MODE_CBC);
                if (!CryptSetKeyParam(encryptKey, KP_MODE, mode, 0) ||
                    !CryptSetKeyParam(decryptKey, KP_MODE, mode, 0) ||
                    !CryptSetKeyParam(encryptKey, KP_IV, iv, 0) ||
                    !CryptSetKeyParam(decryptKey, KP_IV, iv, 0))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
				uint queriedLength = (uint)plaintext.Length;
				bool sizeQuery = CryptEncryptSize(encryptKey, IntPtr.Zero, true, 0,
					IntPtr.Zero, ref queriedLength, 0);
				int sizeQueryError = sizeQuery ? 0 : Marshal.GetLastWin32Error();
                byte[] buffer = new byte[plaintext.Length + 16];
                Buffer.BlockCopy(plaintext, 0, buffer, 0, plaintext.Length);
                uint length = (uint)plaintext.Length;
                bool encrypted = CryptEncrypt(encryptKey, IntPtr.Zero, true, 0,
                    buffer, ref length, (uint)buffer.Length);
                int encryptError = encrypted ? 0 : Marshal.GetLastWin32Error();
                byte[] cipher = new byte[length];
                if (length != 0) Buffer.BlockCopy(buffer, 0, cipher, 0, (int)length);
                uint decryptedLength = length;
                bool decrypted = encrypted && CryptDecrypt(decryptKey, IntPtr.Zero, true, 0,
                    buffer, ref decryptedLength);
                int decryptError = decrypted ? 0 : Marshal.GetLastWin32Error();
                byte[] clear = new byte[decrypted ? decryptedLength : 0];
                if (decryptedLength != 0 && decrypted)
                    Buffer.BlockCopy(buffer, 0, clear, 0, (int)decryptedLength);
                result["encryptSuccess"] = encrypted;
                result["encryptLastError"] = encryptError;
				result["sizeQuerySuccess"] = sizeQuery;
				result["sizeQueryLastError"] = sizeQueryError;
				result["sizeQueryLength"] = queriedLength;
                result["decryptSuccess"] = decrypted;
                result["decryptLastError"] = decryptError;
                result["ciphertextBase64"] = Convert.ToBase64String(cipher);
                result["decryptedBase64"] = Convert.ToBase64String(clear);
                result["encryptRecordExpectedBase64"] = Convert.ToBase64String(plaintext);
                result["decryptRecordExpectedBase64"] = Convert.ToBase64String(clear);
				result["success"] = sizeQuery && encrypted && decrypted && BytesEqual(plaintext, clear);
                if (!(bool)result["success"]) result["reason"] = "CryptoAPI round trip failed.";
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
                if (encryptKey != IntPtr.Zero) CryptDestroyKey(encryptKey);
                if (decryptKey != IntPtr.Zero) CryptDestroyKey(decryptKey);
                if (provider != IntPtr.Zero) CryptReleaseContext(provider, 0);
            }
        }

        private static byte[] PlaintextKeyBlob(byte[] secret)
        {
            byte[] blob = new byte[12 + secret.Length];
            blob[0] = PLAINTEXTKEYBLOB;
            blob[1] = CUR_BLOB_VERSION;
            Buffer.BlockCopy(BitConverter.GetBytes(CALG_AES_128), 0, blob, 4, 4);
            Buffer.BlockCopy(BitConverter.GetBytes((uint)secret.Length), 0, blob, 8, 4);
            Buffer.BlockCopy(secret, 0, blob, 12, secret.Length);
            return blob;
        }

        private static Dictionary<string, object> RunRtlCrypto(byte[] plaintext)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            try
            {
                byte[] buffer = (byte[])plaintext.Clone();
                int encryptStatus = RtlEncryptMemory(buffer, (uint)buffer.Length, 0);
                byte[] cipher = (byte[])buffer.Clone();
                int decryptStatus = encryptStatus == 0
                    ? RtlDecryptMemory(buffer, (uint)buffer.Length, 0) : -1;
                result["encryptStatus"] = encryptStatus;
                result["encryptStatusHex"] = Hex32(encryptStatus);
                result["decryptStatus"] = decryptStatus;
                result["decryptStatusHex"] = Hex32(decryptStatus);
                result["ciphertextBase64"] = Convert.ToBase64String(cipher);
                result["decryptedBase64"] = Convert.ToBase64String(buffer);
                result["encryptRecordExpectedBase64"] = Convert.ToBase64String(plaintext);
                result["decryptRecordExpectedBase64"] = Convert.ToBase64String(buffer);
                result["success"] = encryptStatus == 0 && decryptStatus == 0 && BytesEqual(plaintext, buffer);
                if (!(bool)result["success"]) result["reason"] = "Rtl memory crypto round trip failed.";
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
        }

        private static bool BytesEqual(byte[] first, byte[] second)
        {
            if (first == null || second == null || first.Length != second.Length) return false;
            for (int i = 0; i < first.Length; i++) if (first[i] != second[i]) return false;
            return true;
        }

        public static Dictionary<string, object> RunOdbc(string connectionString)
        {
            Dictionary<string, object> result = MethodResult(true, true, null);
            try
            {
                result["unicode"] = RunOdbcOne(connectionString, true);
                result["ansi"] = RunOdbcOne(connectionString, false);
                return result;
            }
            catch (DllNotFoundException error)
            {
                result["supported"] = false;
                result["success"] = false;
                result["reason"] = error.Message;
                return result;
            }
            catch (EntryPointNotFoundException error)
            {
                result["supported"] = false;
                result["success"] = false;
                result["reason"] = error.Message;
                return result;
            }
        }

        private static Dictionary<string, object> RunOdbcOne(string connectionString, bool unicode)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr environment = IntPtr.Zero;
            IntPtr connection = IntPtr.Zero;
            try
            {
                short status = SQLAllocHandle(SQL_HANDLE_ENV, IntPtr.Zero, out environment);
                result["allocateEnvironmentStatus"] = status;
                if (status != SQL_SUCCESS && status != SQL_SUCCESS_WITH_INFO)
                {
                    result["reason"] = "SQLAllocHandle(SQL_HANDLE_ENV) returned " + status.ToString(CultureInfo.InvariantCulture);
                    return result;
                }
                status = SQLSetEnvAttr(environment, SQL_ATTR_ODBC_VERSION,
                    new IntPtr(SQL_OV_ODBC3), 0);
                result["setEnvironmentStatus"] = status;
                if (status != SQL_SUCCESS && status != SQL_SUCCESS_WITH_INFO)
                {
                    result["reason"] = "SQLSetEnvAttr returned " + status.ToString(CultureInfo.InvariantCulture);
                    return result;
                }
                status = SQLAllocHandle(SQL_HANDLE_DBC, environment, out connection);
                result["allocateConnectionStatus"] = status;
                if (status != SQL_SUCCESS && status != SQL_SUCCESS_WITH_INFO)
                {
                    result["reason"] = "SQLAllocHandle(SQL_HANDLE_DBC) returned " + status.ToString(CultureInfo.InvariantCulture);
                    return result;
                }
                StringBuilder output = new StringBuilder(1024);
                short outputLength;
                short connect = unicode
                    ? SQLDriverConnectW(connection, IntPtr.Zero, connectionString, SQL_NTS,
                        output, (short)output.Capacity, out outputLength, SQL_DRIVER_NOPROMPT)
                    : SQLDriverConnectA(connection, IntPtr.Zero, connectionString, SQL_NTS,
                        output, (short)output.Capacity, out outputLength, SQL_DRIVER_NOPROMPT);
                result["api"] = unicode ? "SQLDriverConnectW" : "SQLDriverConnectA";
                result["connectionString"] = connectionString;
                result["returnCode"] = connect;
                result["outputConnectionString"] = output.ToString();
                result["outputLength"] = outputLength;
                result["diagnostics"] = ReadOdbcDiagnostics(connection, unicode);
                result["success"] = true;
                result["callSucceeded"] = connect == SQL_SUCCESS || connect == SQL_SUCCESS_WITH_INFO;
                return result;
            }
            catch (Exception error)
            {
                result["reason"] = error.GetType().FullName + ": " + error.Message;
                return result;
            }
            finally
            {
                if (connection != IntPtr.Zero) SQLFreeHandle(SQL_HANDLE_DBC, connection);
                if (environment != IntPtr.Zero) SQLFreeHandle(SQL_HANDLE_ENV, environment);
            }
        }

        private static List<Dictionary<string, object>> ReadOdbcDiagnostics(IntPtr connection, bool unicode)
        {
            List<Dictionary<string, object>> result = new List<Dictionary<string, object>>();
            for (short record = 1; record <= 64; record++)
            {
                StringBuilder state = new StringBuilder(6);
                StringBuilder message = new StringBuilder(2048);
                int nativeError;
                short messageLength;
                short status = unicode
                    ? SQLGetDiagRecW(SQL_HANDLE_DBC, connection, record, state, out nativeError,
                        message, (short)message.Capacity, out messageLength)
                    : SQLGetDiagRecA(SQL_HANDLE_DBC, connection, record, state, out nativeError,
                        message, (short)message.Capacity, out messageLength);
                if (status == SQL_NO_DATA) break;
                Dictionary<string, object> item = new Dictionary<string, object>();
                item["returnCode"] = status;
                item["state"] = state.ToString();
                item["nativeError"] = nativeError;
                item["message"] = message.ToString();
                result.Add(item);
                if (status != SQL_SUCCESS && status != SQL_SUCCESS_WITH_INFO) break;
            }
            return result;
        }

        public static Dictionary<string, object> RunAdo(string connectionString, string initializer)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            object connection = null;
            bool coInitialized = false;
            try
            {
                bool useLegacy = String.Equals(initializer, "legacy", StringComparison.OrdinalIgnoreCase);
                bool useExtended = String.Equals(initializer, "ex", StringComparison.OrdinalIgnoreCase);
                if (!useLegacy && !useExtended)
                {
                    result["reason"] = "initializer must be legacy or ex";
                    return result;
                }

                int coResult;
                if (useLegacy)
                {
                    coResult = CoInitialize(IntPtr.Zero);
                    result["initializer"] = "CoInitialize";
                    result["coInitializeLegacyHresult"] = coResult;
                    result["coInitializeLegacyHresultHex"] = Hex32(coResult);
                }
                else
                {
                    uint apartmentFlag = Thread.CurrentThread.GetApartmentState() == ApartmentState.STA ? 2u : 0u;
                    coResult = CoInitializeEx(IntPtr.Zero, apartmentFlag);
                    result["initializer"] = "CoInitializeEx";
                    result["coInitializeHresult"] = coResult;
                    result["coInitializeHresultHex"] = Hex32(coResult);
                    result["coInitializeExApartmentFlag"] = apartmentFlag;
                }
                result["initializerHresult"] = coResult;
                result["initializerHresultHex"] = Hex32(coResult);
                coInitialized = coResult == 0 || coResult == 1;
                if (!coInitialized)
                {
                    result["reason"] = "COM initialization failed with " + Hex32(coResult) + ".";
                    return result;
                }
                Type type = Type.GetTypeFromProgID("ADODB.Connection", false);
                if (type == null)
                {
                    result["supported"] = false;
                    result["reason"] = "ADODB.Connection is not registered.";
                    return result;
                }
                connection = Activator.CreateInstance(type);
                result["connectionString"] = connectionString;
                try
                {
                    type.InvokeMember("Open", BindingFlags.InvokeMethod, null, connection,
                        new object[] { connectionString, String.Empty, String.Empty, -1 });
                    result["openSucceeded"] = true;
                }
                catch (TargetInvocationException error)
                {
                    Exception actual = error.InnerException == null ? error : error.InnerException;
                    result["openSucceeded"] = false;
                    result["openErrorType"] = actual.GetType().FullName;
                    result["openError"] = actual.Message;
                    result["openHresult"] = Marshal.GetHRForException(actual);
                    result["openHresultHex"] = Hex32(Marshal.GetHRForException(actual));
                }
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
                if (connection != null && Marshal.IsComObject(connection))
                    Marshal.FinalReleaseComObject(connection);
                if (coInitialized) CoUninitialize();
            }
        }

        public static Dictionary<string, object> RunFile(string action, string path, byte[] data)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            result["action"] = action;
            result["path"] = path;
            try
            {
                if (String.Equals(action, "write", StringComparison.OrdinalIgnoreCase))
                {
                    File.WriteAllBytes(path, data == null ? new byte[0] : data);
                }
                else if (String.Equals(action, "append", StringComparison.OrdinalIgnoreCase))
                {
                    using (FileStream stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read))
                    {
                        byte[] value = data == null ? new byte[0] : data;
                        stream.Write(value, 0, value.Length);
                        stream.Flush(true);
                    }
                }
                else if (!String.Equals(action, "read", StringComparison.OrdinalIgnoreCase) &&
                    !String.Equals(action, "metadata", StringComparison.OrdinalIgnoreCase))
                {
                    result["reason"] = "Unsupported file action: " + action;
                    return result;
                }

                FileInfo info = new FileInfo(path);
                result["exists"] = info.Exists;
                if (!info.Exists)
                {
                    result["reason"] = "File does not exist.";
                    return result;
                }
                result["length"] = info.Length;
                result["attributes"] = info.Attributes.ToString();
                result["lastWriteTimeUtc"] = info.LastWriteTimeUtc.ToString("o", CultureInfo.InvariantCulture);
                if (!String.Equals(action, "metadata", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] bytes = File.ReadAllBytes(path);
                    result["bytesBase64"] = Convert.ToBase64String(bytes);
                    using (SHA256 sha = SHA256.Create())
                        result["sha256"] = HexBytes(sha.ComputeHash(bytes));
                }
                result["success"] = true;
                return result;
            }
            catch (Exception error)
            {
                result["errorType"] = error.GetType().FullName;
                result["reason"] = error.Message;
                result["hresult"] = Marshal.GetHRForException(error);
                result["hresultHex"] = Hex32(Marshal.GetHRForException(error));
                return result;
            }
        }

        public static Dictionary<string, object> ReadLsa(string account, string sidValue, string right)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr policy = IntPtr.Zero;
            try
            {
                SecurityIdentifier sid;
                if (!String.IsNullOrEmpty(sidValue)) sid = new SecurityIdentifier(sidValue);
                else if (!String.IsNullOrEmpty(account))
                    sid = (SecurityIdentifier)new NTAccount(account).Translate(typeof(SecurityIdentifier));
                else sid = WindowsIdentity.GetCurrent().User;
                byte[] sidBytes = new byte[sid.BinaryLength];
                sid.GetBinaryForm(sidBytes, 0);
                result["sid"] = sid.Value;
                result["account"] = TranslateSid(sid);

                LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
                attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
                int status = LsaOpenPolicy(IntPtr.Zero, ref attributes,
                    POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES, out policy);
                result["openStatus"] = status;
                result["openStatusHex"] = Hex32(status);
                if (status != 0)
                {
                    uint error = LsaNtStatusToWinError(status);
                    result["win32Error"] = error;
                    result["reason"] = new System.ComponentModel.Win32Exception(unchecked((int)error)).Message;
                    return result;
                }
                result["accountRights"] = EnumerateAccountRights(policy, sidBytes);
                result["accountsWithRight"] = EnumerateAccountsWithRight(policy, right);
                result["availableRights"] = EnumeratePolicyPrivileges(policy);
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
                if (policy != IntPtr.Zero) LsaClose(policy);
            }
        }

        private static Dictionary<string, object> EnumerateAccountRights(IntPtr policy, byte[] sid)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            IntPtr buffer;
            uint count;
            int status = LsaEnumerateAccountRights(policy, sid, out buffer, out count);
            result["status"] = status;
            result["statusHex"] = Hex32(status);
            try
            {
                List<string> rights = new List<string>();
                if (status == 0)
                {
                    int size = Marshal.SizeOf(typeof(LSA_UNICODE_STRING));
                    for (uint index = 0; index < count; index++)
                    {
                        LSA_UNICODE_STRING value = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                            IntPtr.Add(buffer, checked((int)(index * size))), typeof(LSA_UNICODE_STRING));
                        rights.Add(LsaString(value));
                    }
                    result["success"] = true;
                }
                else
                {
                    uint error = LsaNtStatusToWinError(status);
                    result["win32Error"] = error;
                    result["reason"] = new System.ComponentModel.Win32Exception(unchecked((int)error)).Message;
                }
                result["rights"] = rights;
                result["count"] = rights.Count;
                return result;
            }
            finally
            {
                if (buffer != IntPtr.Zero) LsaFreeMemory(buffer);
            }
        }

        private static Dictionary<string, object> EnumerateAccountsWithRight(IntPtr policy, string right)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            if (String.IsNullOrEmpty(right))
            {
                result["supported"] = false;
                result["reason"] = "No right was supplied; querying all accounts is intentionally not performed.";
                result["accounts"] = new List<Dictionary<string, object>>();
                return result;
            }
            IntPtr rightBuffer = Marshal.StringToHGlobalUni(right);
            IntPtr buffer = IntPtr.Zero;
            try
            {
                LSA_UNICODE_STRING value = new LSA_UNICODE_STRING();
                value.Buffer = rightBuffer;
                value.Length = (ushort)(right.Length * 2);
                value.MaximumLength = (ushort)(value.Length + 2);
                uint count;
                int status = LsaEnumerateAccountsWithUserRight(policy, ref value, out buffer, out count);
                result["status"] = status;
                result["statusHex"] = Hex32(status);
                List<Dictionary<string, object>> accounts = new List<Dictionary<string, object>>();
                if (status == 0)
                {
                    int size = Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION));
                    for (uint index = 0; index < count; index++)
                    {
                        LSA_ENUMERATION_INFORMATION info = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                            IntPtr.Add(buffer, checked((int)(index * size))), typeof(LSA_ENUMERATION_INFORMATION));
                        SecurityIdentifier sid = new SecurityIdentifier(info.Sid);
                        Dictionary<string, object> account = new Dictionary<string, object>();
                        account["sid"] = sid.Value;
                        account["account"] = TranslateSid(sid);
                        accounts.Add(account);
                    }
                    result["success"] = true;
                }
                else if (status == STATUS_NO_MORE_ENTRIES)
                {
                    result["success"] = true;
                }
                else
                {
                    uint error = LsaNtStatusToWinError(status);
                    result["win32Error"] = error;
                    result["reason"] = new System.ComponentModel.Win32Exception(unchecked((int)error)).Message;
                }
                result["right"] = right;
                result["accounts"] = accounts;
                result["count"] = accounts.Count;
                return result;
            }
            finally
            {
                if (buffer != IntPtr.Zero) LsaFreeMemory(buffer);
                Marshal.FreeHGlobal(rightBuffer);
            }
        }

        private static Dictionary<string, object> EnumeratePolicyPrivileges(IntPtr policy)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            List<Dictionary<string, object>> rights = new List<Dictionary<string, object>>();
            uint context = 0;
            int finalStatus = 0;
            for (int page = 0; page < 128; page++)
            {
                IntPtr buffer;
                uint count;
                int status = LsaEnumeratePrivileges(policy, ref context, out buffer, 64 * 1024, out count);
                finalStatus = status;
                try
                {
                    if (status != 0 && status != STATUS_MORE_ENTRIES && status != STATUS_NO_MORE_ENTRIES)
                    {
                        uint error = LsaNtStatusToWinError(status);
                        result["win32Error"] = error;
                        result["reason"] = new System.ComponentModel.Win32Exception(unchecked((int)error)).Message;
                        break;
                    }
                    int size = Marshal.SizeOf(typeof(LSA_POLICY_PRIVILEGE_DEFINITION));
                    for (uint index = 0; index < count; index++)
                    {
                        LSA_POLICY_PRIVILEGE_DEFINITION definition =
                            (LSA_POLICY_PRIVILEGE_DEFINITION)Marshal.PtrToStructure(
                            IntPtr.Add(buffer, checked((int)(index * size))),
                            typeof(LSA_POLICY_PRIVILEGE_DEFINITION));
                        Dictionary<string, object> item = new Dictionary<string, object>();
                        item["name"] = LsaString(definition.Name);
                        item["luid"] = definition.LocalValue.HighPart.ToString(CultureInfo.InvariantCulture) + ":" +
                            definition.LocalValue.LowPart.ToString(CultureInfo.InvariantCulture);
                        rights.Add(item);
                    }
                    if (status == STATUS_NO_MORE_ENTRIES || status == 0) break;
                }
                finally
                {
                    if (buffer != IntPtr.Zero) LsaFreeMemory(buffer);
                }
            }
            result["rights"] = rights;
            result["count"] = rights.Count;
            result["finalStatus"] = finalStatus;
            result["finalStatusHex"] = Hex32(finalStatus);
            result["success"] = finalStatus == 0 || finalStatus == STATUS_NO_MORE_ENTRIES;
            return result;
        }

        private static string LsaString(LSA_UNICODE_STRING value)
        {
            if (value.Buffer == IntPtr.Zero || value.Length == 0) return String.Empty;
            return Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
        }

        private static string TranslateSid(SecurityIdentifier sid)
        {
            try { return sid.Translate(typeof(NTAccount)).Value; }
            catch { return null; }
        }
    }
}
