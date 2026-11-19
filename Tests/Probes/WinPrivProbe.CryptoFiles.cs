using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace WinPrivProbe
{
    public static partial class Native
    {
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
        private const uint FILE_READ_DATA = 0x00000001;
        private const uint FILE_READ_ATTRIBUTES = 0x00000080;
        private const uint SYNCHRONIZE = 0x00100000;
        private const uint FILE_SHARE_ALL = 0x00000007;
        private const uint FILE_OPEN = 0x00000001;
        private const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
        private const uint FILE_NON_DIRECTORY_FILE = 0x00000040;
        private const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint OPEN_EXISTING = 3;
        private const uint DUPLICATE_CLOSE_SOURCE = 1;
        private const uint DUPLICATE_SAME_ACCESS = 2;
        private const uint PROCESS_DUP_HANDLE = 0x00000040;
        private const uint DELETE_ACCESS = 0x00010000;

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory, ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor, SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_IO_STATUS_BLOCK { public IntPtr Status; public UIntPtr Information; }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_RENAME_INFORMATION { public uint Flags; public IntPtr RootDirectory; public uint FileNameLength; public ushort FileName; }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr algorithm, string algorithmId, string implementation, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr algorithm, uint flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptGetProperty(IntPtr handle, string property, byte[] output, int outputLength, out int resultLength, uint flags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptSetProperty(IntPtr handle, string property, byte[] input, int inputLength, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(IntPtr algorithm, out IntPtr key, IntPtr keyObject,
            int keyObjectLength, byte[] secret, int secretLength, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr key);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptEncrypt(IntPtr key, IntPtr input, int inputLength, IntPtr paddingInfo,
            IntPtr iv, int ivLength, IntPtr output, int outputLength, out int resultLength, uint flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDecrypt(IntPtr key, IntPtr input, int inputLength, IntPtr paddingInfo,
            IntPtr iv, int ivLength, IntPtr output, int outputLength, out int resultLength, uint flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CryptAcquireContextW(out IntPtr provider, string container, string providerName, uint providerType, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptReleaseContext(IntPtr provider, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptImportKey(IntPtr provider, byte[] data, uint dataLength, IntPtr publicKey, uint flags, out IntPtr key);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptDestroyKey(IntPtr key);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptSetKeyParam(IntPtr key, uint parameter, byte[] data, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptEncrypt(IntPtr key, IntPtr hash, bool final, uint flags, byte[] data, ref uint dataLength, uint bufferLength);

        [DllImport("advapi32.dll", EntryPoint = "CryptEncrypt", SetLastError = true)]
        private static extern bool CryptEncryptSize(IntPtr key, IntPtr hash, bool final, uint flags, IntPtr data, ref uint dataLength, uint bufferLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptDecrypt(IntPtr key, IntPtr hash, bool final, uint flags, byte[] data, ref uint dataLength);

        [DllImport("advapi32.dll", EntryPoint = "SystemFunction040")]
        private static extern int RtlEncryptMemory(byte[] memory, uint memorySize, uint optionFlags);

        [DllImport("advapi32.dll", EntryPoint = "SystemFunction041")]
        private static extern int RtlDecryptMemory(byte[] memory, uint memorySize, uint optionFlags);

        [DllImport("odbc32.dll")]
        private static extern short SQLAllocHandle(short handleType, IntPtr inputHandle, out IntPtr outputHandle);

        [DllImport("odbc32.dll")]
        private static extern short SQLFreeHandle(short handleType, IntPtr handle);

        [DllImport("odbc32.dll")]
        private static extern short SQLSetEnvAttr(IntPtr environment, int attribute, IntPtr value, int stringLength);

        [DllImport("odbc32.dll", CharSet = CharSet.Unicode)]
        private static extern short SQLDriverConnectW(IntPtr connection, IntPtr window, string connectionStringIn,
            short connectionStringInLength, StringBuilder connectionStringOut, short connectionStringOutMaximum,
            out short connectionStringOutLength, ushort driverCompletion);

        [DllImport("odbc32.dll", CharSet = CharSet.Ansi)]
        private static extern short SQLDriverConnectA(IntPtr connection, IntPtr window, string connectionStringIn,
            short connectionStringInLength, StringBuilder connectionStringOut, short connectionStringOutMaximum,
            out short connectionStringOutLength, ushort driverCompletion);

        [DllImport("ole32.dll")]
        private static extern int CoInitialize(IntPtr reserved);

        [DllImport("ole32.dll")]
        private static extern int CoInitializeEx(IntPtr reserved, uint coInitialize);

        [DllImport("ole32.dll")]
        private static extern void CoUninitialize();

        [DllImport("ntdll.dll")]
        private static extern int NtOpenFile(out IntPtr fileHandle, uint desiredAccess,
            ref FILE_OBJECT_ATTRIBUTES objectAttributes, out FILE_IO_STATUS_BLOCK ioStatusBlock, uint shareAccess, uint openOptions);

        [DllImport("ntdll.dll")]
        private static extern int NtCreateFile(out IntPtr fileHandle, uint desiredAccess,
            ref FILE_OBJECT_ATTRIBUTES objectAttributes, out FILE_IO_STATUS_BLOCK ioStatusBlock, IntPtr allocationSize,
            uint fileAttributes, uint shareAccess, uint createDisposition, uint createOptions, IntPtr eaBuffer, uint eaLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

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

        public static Dictionary<string, object> RunCrypto(byte[] plaintext, string collisionDirectory)
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

            string collisionPath = null;
            byte[] retainedCapture = Encoding.ASCII.GetBytes("Existing capture");
            if (!String.IsNullOrEmpty(collisionDirectory))
            {
                collisionPath = Path.Combine(collisionDirectory, String.Format(CultureInfo.InvariantCulture,
                    "00000-PID{0:D5}-TID{1:D5}-BCryptEncrypt.bin", GetCurrentProcessId(), GetCurrentThreadId()));
                File.WriteAllBytes(collisionPath, retainedCapture);
                result["collisionPath"] = collisionPath;
            }
            byte[] key = new byte[16], iv = new byte[16];
            for (int i = 0; i < 16; i++) { key[i] = (byte)i; iv[i] = (byte)(0xA0 + i); }
            result["keyBase64"] = Convert.ToBase64String(key);
            result["ivBase64"] = Convert.ToBase64String(iv);

            Dictionary<string, object> bcryptOutcome = RunSafe(delegate(Dictionary<string, object> r)
            {
                Dictionary<string, object>[] bcrypt = RunBcrypt(plaintext, key, iv);
                result["bcryptSeparate"] = bcrypt[0];
                result["bcryptInPlace"] = bcrypt[1];
                r["success"] = true;
            });
            if (!(bool)bcryptOutcome["success"])
            {
                result["bcryptSeparate"] = bcryptOutcome;
                result["bcryptInPlace"] = bcryptOutcome;
            }
            result["cryptoApi"] = RunCryptoApi(plaintext, key, iv);
            result["rtl"] = RunRtlCrypto(plaintext);
            result["collisionPreserved"] = collisionPath == null || Enumerable.SequenceEqual(File.ReadAllBytes(collisionPath), retainedCapture);
            result["success"] = true;
            return result;
        }

        private static Dictionary<string, object>[] RunBcrypt(byte[] plaintext, byte[] secret, byte[] iv)
        {
            IntPtr algorithm = IntPtr.Zero, key = IntPtr.Zero, keyObject = IntPtr.Zero;
            try
            {
                int status = BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0);
                if (status != 0) throw new InvalidOperationException("BCryptOpenAlgorithmProvider returned " + Hex32(status));
                byte[] chaining = Encoding.Unicode.GetBytes("ChainingModeCBC\0");
                status = BCryptSetProperty(algorithm, "ChainingMode", chaining, chaining.Length, 0);
                if (status != 0) throw new InvalidOperationException("BCryptSetProperty returned " + Hex32(status));
                byte[] objectLengthBytes = new byte[4];
                int returned;
                status = BCryptGetProperty(algorithm, "ObjectLength", objectLengthBytes, 4, out returned, 0);
                if (status != 0) throw new InvalidOperationException("BCryptGetProperty returned " + Hex32(status));
                int objectLength = BitConverter.ToInt32(objectLengthBytes, 0);
                keyObject = Marshal.AllocHGlobal(objectLength);
                status = BCryptGenerateSymmetricKey(algorithm, out key, keyObject, objectLength, secret, secret.Length, 0);
                if (status != 0) throw new InvalidOperationException("BCryptGenerateSymmetricKey returned " + Hex32(status));

                List<Dictionary<string, object>> results = new List<Dictionary<string, object>>();
                foreach (bool inPlace in new bool[] { false, true })
                {
                    byte[] cipher, clear = new byte[0];
                    int encryptStatus = BcryptTransform(key, plaintext, iv, true, inPlace, out cipher);
                    int decryptStatus = encryptStatus == 0 ? BcryptTransform(key, cipher, iv, false, inPlace, out clear) : -1;
                    Dictionary<string, object> item = MethodResult(true,
                        encryptStatus == 0 && decryptStatus == 0 && Enumerable.SequenceEqual(plaintext, clear), null);
                    item["openStatus"] = 0;
                    item["encryptStatus"] = encryptStatus; item["encryptStatusHex"] = Hex32(encryptStatus);
                    item["decryptStatus"] = decryptStatus; item["decryptStatusHex"] = Hex32(decryptStatus);
                    item["ciphertextBase64"] = Convert.ToBase64String(cipher);
                    item["decryptedBase64"] = Convert.ToBase64String(clear);
                    item["encryptRecordExpectedBase64"] = Convert.ToBase64String(plaintext);
                    item["decryptRecordExpectedBase64"] = Convert.ToBase64String(clear);
                    if (!(bool)item["success"]) item["reason"] = "BCrypt " + (inPlace ? "in-place" : "separate-buffer") + " round trip failed.";
                    results.Add(item);
                }
                return results.ToArray();
            }
            finally
            {
                if (key != IntPtr.Zero) BCryptDestroyKey(key);
                if (keyObject != IntPtr.Zero) Marshal.FreeHGlobal(keyObject);
                if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
            }
        }

        private static int BcryptTransform(IntPtr key, byte[] input, byte[] iv, bool encrypt, bool inPlace, out byte[] output)
        {
            IntPtr inputPtr = Marshal.AllocHGlobal(input.Length);
            IntPtr outputPtr = inPlace ? inputPtr : Marshal.AllocHGlobal(input.Length);
            IntPtr ivPtr = Marshal.AllocHGlobal(iv.Length);
            try
            {
                Marshal.Copy(input, 0, inputPtr, input.Length);
                Marshal.Copy(iv, 0, ivPtr, iv.Length);
                int returned;
                if (encrypt)
                {
                    string directory = Environment.GetEnvironmentVariable("_WINPRIV_EV_RECORD_CRYPTO_");
                    string pattern = String.Format(CultureInfo.InvariantCulture,
                        "*-PID{0:D5}-TID{1:D5}-BCryptEncrypt.bin", GetCurrentProcessId(), GetCurrentThreadId());
                    int before = Directory.Exists(directory) ? Directory.GetFiles(directory, pattern).Length : 0;
                    int queryStatus = BCryptEncrypt(key, inputPtr, input.Length, IntPtr.Zero, ivPtr, iv.Length, IntPtr.Zero, 0, out returned, 0);
                    if (queryStatus != 0 || returned != input.Length)
                        throw new InvalidOperationException("BCryptEncrypt size query failed: " + Hex32(queryStatus));
                    if (Directory.Exists(directory) && Directory.GetFiles(directory, pattern).Length != before)
                        throw new InvalidOperationException("BCryptEncrypt recorded a size query.");
                    Marshal.Copy(iv, 0, ivPtr, iv.Length);
                }
                int status = encrypt
                    ? BCryptEncrypt(key, inputPtr, input.Length, IntPtr.Zero, ivPtr, iv.Length, outputPtr, input.Length, out returned, 0)
                    : BCryptDecrypt(key, inputPtr, input.Length, IntPtr.Zero, ivPtr, iv.Length, outputPtr, input.Length, out returned, 0);
                if (status == 0 && returned >= 0 && returned <= input.Length)
                {
                    output = new byte[returned];
                    if (returned != 0) Marshal.Copy(outputPtr, output, 0, returned);
                }
                else output = new byte[0];
                return status;
            }
            finally
            {
                Marshal.FreeHGlobal(ivPtr);
                if (!inPlace) Marshal.FreeHGlobal(outputPtr);
                Marshal.FreeHGlobal(inputPtr);
            }
        }

        private static Dictionary<string, object> RunCryptoApi(byte[] plaintext, byte[] secret, byte[] iv)
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                IntPtr provider = IntPtr.Zero, encryptKey = IntPtr.Zero, decryptKey = IntPtr.Zero;
                try
                {
                    if (!CryptAcquireContextW(out provider, null, null, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    byte[] blob = new byte[12 + secret.Length];
                    blob[0] = PLAINTEXTKEYBLOB; blob[1] = CUR_BLOB_VERSION;
                    Buffer.BlockCopy(BitConverter.GetBytes(CALG_AES_128), 0, blob, 4, 4);
                    Buffer.BlockCopy(BitConverter.GetBytes((uint)secret.Length), 0, blob, 8, 4);
                    Buffer.BlockCopy(secret, 0, blob, 12, secret.Length);
                    if (!CryptImportKey(provider, blob, (uint)blob.Length, IntPtr.Zero, 0, out encryptKey) ||
                        !CryptImportKey(provider, blob, (uint)blob.Length, IntPtr.Zero, 0, out decryptKey))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    byte[] mode = BitConverter.GetBytes(CRYPT_MODE_CBC);
                    if (!CryptSetKeyParam(encryptKey, KP_MODE, mode, 0) || !CryptSetKeyParam(decryptKey, KP_MODE, mode, 0) ||
                        !CryptSetKeyParam(encryptKey, KP_IV, iv, 0) || !CryptSetKeyParam(decryptKey, KP_IV, iv, 0))
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    uint queriedLength = (uint)plaintext.Length;
                    bool sizeQuery = CryptEncryptSize(encryptKey, IntPtr.Zero, true, 0, IntPtr.Zero, ref queriedLength, 0);
                    int sizeQueryError = sizeQuery ? 0 : Marshal.GetLastWin32Error();
                    byte[] buffer = new byte[plaintext.Length + 16];
                    Buffer.BlockCopy(plaintext, 0, buffer, 0, plaintext.Length);
                    uint length = (uint)plaintext.Length;
                    bool encrypted = CryptEncrypt(encryptKey, IntPtr.Zero, true, 0, buffer, ref length, (uint)buffer.Length);
                    int encryptError = encrypted ? 0 : Marshal.GetLastWin32Error();
                    byte[] cipher = new byte[length];
                    if (length != 0) Buffer.BlockCopy(buffer, 0, cipher, 0, (int)length);
                    uint decryptedLength = length;
                    bool decrypted = encrypted && CryptDecrypt(decryptKey, IntPtr.Zero, true, 0, buffer, ref decryptedLength);
                    int decryptError = decrypted ? 0 : Marshal.GetLastWin32Error();
                    byte[] clear = new byte[decrypted ? decryptedLength : 0];
                    if (decryptedLength != 0 && decrypted) Buffer.BlockCopy(buffer, 0, clear, 0, (int)decryptedLength);

                    result["encryptSuccess"] = encrypted; result["encryptLastError"] = encryptError;
                    result["sizeQuerySuccess"] = sizeQuery; result["sizeQueryLastError"] = sizeQueryError;
                    result["sizeQueryLength"] = queriedLength;
                    result["decryptSuccess"] = decrypted; result["decryptLastError"] = decryptError;
                    result["ciphertextBase64"] = Convert.ToBase64String(cipher);
                    result["decryptedBase64"] = Convert.ToBase64String(clear);
                    result["encryptRecordExpectedBase64"] = Convert.ToBase64String(plaintext);
                    result["decryptRecordExpectedBase64"] = Convert.ToBase64String(clear);
                    result["success"] = sizeQuery && encrypted && decrypted && Enumerable.SequenceEqual(plaintext, clear);
                    if (!(bool)result["success"]) result["reason"] = "CryptoAPI round trip failed.";
                }
                finally
                {
                    if (encryptKey != IntPtr.Zero) CryptDestroyKey(encryptKey);
                    if (decryptKey != IntPtr.Zero) CryptDestroyKey(decryptKey);
                    if (provider != IntPtr.Zero) CryptReleaseContext(provider, 0);
                }
            });
        }

        private static Dictionary<string, object> RunRtlCrypto(byte[] plaintext)
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                byte[] buffer = (byte[])plaintext.Clone();
                int encryptStatus = RtlEncryptMemory(buffer, (uint)buffer.Length, 0);
                byte[] cipher = (byte[])buffer.Clone();
                int decryptStatus = encryptStatus == 0 ? RtlDecryptMemory(buffer, (uint)buffer.Length, 0) : -1;
                result["encryptStatus"] = encryptStatus; result["encryptStatusHex"] = Hex32(encryptStatus);
                result["decryptStatus"] = decryptStatus; result["decryptStatusHex"] = Hex32(decryptStatus);
                result["ciphertextBase64"] = Convert.ToBase64String(cipher);
                result["decryptedBase64"] = Convert.ToBase64String(buffer);
                result["encryptRecordExpectedBase64"] = Convert.ToBase64String(plaintext);
                result["decryptRecordExpectedBase64"] = Convert.ToBase64String(buffer);
                result["success"] = encryptStatus == 0 && decryptStatus == 0 && Enumerable.SequenceEqual(plaintext, buffer);
                if (!(bool)result["success"]) result["reason"] = "Rtl memory crypto round trip failed.";
            });
        }

        public static Dictionary<string, object> RunOdbc(string connectionString)
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                result["unicode"] = RunOdbcOne(connectionString, true);
                result["ansi"] = RunOdbcOne(connectionString, false);
                result["success"] = true;
            });
        }

        private static Dictionary<string, object> RunOdbcOne(string connectionString, bool unicode)
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                IntPtr environment = IntPtr.Zero, connection = IntPtr.Zero;
                try
                {
                    short status = SQLAllocHandle(SQL_HANDLE_ENV, IntPtr.Zero, out environment);
                    result["allocateEnvironmentStatus"] = status;
                    if (status != SQL_SUCCESS && status != SQL_SUCCESS_WITH_INFO) { result["reason"] = "SQLAllocHandle(ENV) returned " + status; return; }
                    status = SQLSetEnvAttr(environment, SQL_ATTR_ODBC_VERSION, new IntPtr(SQL_OV_ODBC3), 0);
                    result["setEnvironmentStatus"] = status;
                    if (status != SQL_SUCCESS && status != SQL_SUCCESS_WITH_INFO) { result["reason"] = "SQLSetEnvAttr returned " + status; return; }
                    status = SQLAllocHandle(SQL_HANDLE_DBC, environment, out connection);
                    result["allocateConnectionStatus"] = status;
                    if (status != SQL_SUCCESS && status != SQL_SUCCESS_WITH_INFO) { result["reason"] = "SQLAllocHandle(DBC) returned " + status; return; }

                    StringBuilder output = new StringBuilder(1024);
                    short outputLength;
                    short connect = unicode
                        ? SQLDriverConnectW(connection, IntPtr.Zero, connectionString, SQL_NTS, output, (short)output.Capacity, out outputLength, SQL_DRIVER_NOPROMPT)
                        : SQLDriverConnectA(connection, IntPtr.Zero, connectionString, SQL_NTS, output, (short)output.Capacity, out outputLength, SQL_DRIVER_NOPROMPT);
                    result["api"] = unicode ? "SQLDriverConnectW" : "SQLDriverConnectA";
                    result["connectionString"] = connectionString;
                    result["returnCode"] = connect;
                    result["outputConnectionString"] = output.ToString();
                    result["outputLength"] = outputLength;
                    result["callSucceeded"] = connect == SQL_SUCCESS || connect == SQL_SUCCESS_WITH_INFO;
                    result["success"] = true;
                }
                finally
                {
                    if (connection != IntPtr.Zero) SQLFreeHandle(SQL_HANDLE_DBC, connection);
                    if (environment != IntPtr.Zero) SQLFreeHandle(SQL_HANDLE_ENV, environment);
                }
            });
        }

        public static Dictionary<string, object> RunAdo(string connectionString, string initializer, bool storedString)
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                object connection = null;
                bool coInitialized = false;
                try
                {
                    bool useLegacy = String.Equals(initializer, "legacy", StringComparison.OrdinalIgnoreCase);
                    if (!useLegacy && !String.Equals(initializer, "ex", StringComparison.OrdinalIgnoreCase))
                    {
                        result["reason"] = "initializer must be legacy or ex";
                        return;
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
                    if (!coInitialized) { result["reason"] = "COM initialization failed with " + Hex32(coResult) + "."; return; }

                    Type type = Type.GetTypeFromProgID("ADODB.Connection", false);
                    if (type == null) { result["supported"] = false; result["reason"] = "ADODB.Connection is not registered."; return; }
                    connection = Activator.CreateInstance(type);
                    result["connectionString"] = connectionString;
                    if (storedString)
                        type.InvokeMember("ConnectionString", BindingFlags.SetProperty, null, connection, new object[] { connectionString });
                    try
                    {
                        type.InvokeMember("Open", BindingFlags.InvokeMethod, null, connection,
                            storedString ? new object[0] : new object[] { connectionString, String.Empty, String.Empty, -1 });
                        result["openSucceeded"] = true;
                    }
                    catch (TargetInvocationException error)
                    {
                        Exception actual = error.InnerException ?? error;
                        result["openSucceeded"] = false;
                        result["openErrorType"] = actual.GetType().FullName;
                        result["openError"] = actual.Message;
                        result["openHresult"] = Marshal.GetHRForException(actual);
                        result["openHresultHex"] = Hex32(Marshal.GetHRForException(actual));
                        if (!(actual is COMException)) { result["reason"] = "Unexpected ADO Open failure: " + actual.GetType().FullName + ": " + actual.Message; return; }
                    }
                    result["effectiveConnectionString"] = type.InvokeMember("ConnectionString", BindingFlags.GetProperty, null, connection, null);
                    result["success"] = true;
                }
                finally
                {
                    if (connection != null && Marshal.IsComObject(connection)) Marshal.FinalReleaseComObject(connection);
                    if (coInitialized) CoUninitialize();
                }
            });
        }

        public static Dictionary<string, object> RunFile(string action, string path, byte[] data)
        {
            Dictionary<string, object> result = MethodResult(true, false, null);
            result["action"] = action; result["path"] = path;
            try
            {
                if (String.Equals(action, "write", StringComparison.OrdinalIgnoreCase))
                    File.WriteAllBytes(path, data ?? new byte[0]);
                else if (!String.Equals(action, "read", StringComparison.OrdinalIgnoreCase))
                {
                    result["reason"] = "Unsupported file action: " + action;
                    return result;
                }
                byte[] bytes = File.ReadAllBytes(path);
                result["exists"] = true;
                result["length"] = (long)bytes.Length;
                result["bytesBase64"] = Convert.ToBase64String(bytes);
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

        public static Dictionary<string, object> RunNativeFile(string api, string path,
            string root = null, bool duplicateRoot = false, string renameRoot = null,
            string duplicateProcess = null, bool closeSource = false)
        {
            return RunSafe(delegate(Dictionary<string, object> result)
            {
                IntPtr nameBuffer = IntPtr.Zero, nameStructure = IntPtr.Zero, handle = IntPtr.Zero;
                IntPtr rootHandle = IntPtr.Zero, processHandle = IntPtr.Zero, information = IntPtr.Zero;
                try
                {
                    string fullPath = Path.GetFullPath(path);
                    string nativePath = @"\??\" + ExtendedPath(fullPath).Substring(4);
                    if (!String.IsNullOrEmpty(root))
                    {
                        nativePath = path;
                        rootHandle = CreateFileW(root, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                            FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
                        if (rootHandle == new IntPtr(-1)) throw new Win32Exception();
                        if (duplicateRoot)
                        {
                            IntPtr sourceProcess = GetCurrentProcess(), targetProcess = sourceProcess;
                            if (!String.IsNullOrEmpty(duplicateProcess))
                            {
                                processHandle = OpenProcess(PROCESS_DUP_HANDLE, false, GetCurrentProcessId());
                                if (processHandle == IntPtr.Zero) throw new Win32Exception();
                                if (duplicateProcess != "target") sourceProcess = processHandle;
                                if (duplicateProcess != "source") targetProcess = processHandle;
                            }
                            IntPtr duplicated;
                            bool ok = DuplicateHandle(sourceProcess, rootHandle, targetProcess, out duplicated, 0, false,
                                DUPLICATE_SAME_ACCESS | (closeSource ? DUPLICATE_CLOSE_SOURCE : 0));
                            if (closeSource) rootHandle = IntPtr.Zero;
                            if (!ok) throw new Win32Exception();
                            if (rootHandle != IntPtr.Zero) CloseHandle(rootHandle);
                            rootHandle = duplicated;
                        }
                    }
                    if (!String.IsNullOrEmpty(renameRoot) && !MoveFileExW(root, renameRoot, 0))
                        throw new Win32Exception();

                    nameBuffer = Marshal.StringToHGlobalUni(nativePath);
                    UNICODE_STRING name = new UNICODE_STRING { Buffer = nameBuffer, Length = checked((ushort)(nativePath.Length * 2)) };
                    name.MaximumLength = checked((ushort)(name.Length + 2));
                    nameStructure = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
                    Marshal.StructureToPtr(name, nameStructure, false);

                    FILE_OBJECT_ATTRIBUTES attributes = new FILE_OBJECT_ATTRIBUTES
                    {
                        Length = Marshal.SizeOf(typeof(FILE_OBJECT_ATTRIBUTES)),
                        ObjectName = nameStructure, RootDirectory = rootHandle, Attributes = OBJ_CASE_INSENSITIVE
                    };
                    FILE_IO_STATUS_BLOCK ioStatus = new FILE_IO_STATUS_BLOCK();
                    uint access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
                    uint options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;

                    int status;
                    if (String.Equals(api, "NtOpenFile", StringComparison.OrdinalIgnoreCase))
                        status = NtOpenFile(out handle, access, ref attributes, out ioStatus, FILE_SHARE_ALL, options);
                    else if (String.Equals(api, "NtCreateFile", StringComparison.OrdinalIgnoreCase))
                        status = NtCreateFile(out handle, access, ref attributes, out ioStatus, IntPtr.Zero, 0, FILE_SHARE_ALL, FILE_OPEN, options, IntPtr.Zero, 0);
                    else
                    {
                        information = Marshal.AllocHGlobal(64);
                        if (api == "NtQueryAttributesFile") status = NtQueryAttributesFile(ref attributes, information);
                        else if (api == "NtQueryFullAttributesFile") status = NtQueryFullAttributesFile(ref attributes, information);
                        else if (api == "NtDeleteFile") status = NtDeleteFile(ref attributes);
                        else throw new ArgumentException("Unknown native file API", "api");
                    }

                    result["api"] = api;
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
                            result["content"] = Encoding.UTF8.GetString(bytes, 0, (int)read);
                    }
                    if (!(bool)result["success"]) result["reason"] = "Native file open returned " + Hex32(status) + ".";
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
            });
        }

        public static Dictionary<string, object> RunFilePath(string action, string path,
            string target, string root, bool duplicateRoot, string duplicateProcess = null, bool closeSource = false)
        {
            if (action == "relative-rename") return RunNativeFile("NtOpenFile", path, root, renameRoot: target);
            if (action.StartsWith("Nt", StringComparison.Ordinal))
                return RunNativeFile(action, path, root, duplicateRoot, duplicateProcess: duplicateProcess, closeSource: closeSource);
            Dictionary<string, object> result = MethodResult(true, false, null);
            try
            {
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
                        try { success = GetFileAttributesExW(path, 0, data); } finally { Marshal.FreeHGlobal(data); }
                        break;
                    case "mkdir": success = CreateDirectoryW(path, IntPtr.Zero); break;
                    case "rmdir": success = RemoveDirectoryW(path); break;
                    case "delete": success = DeleteFileW(path); break;
                    case "move": success = MoveFileExW(path, target, 1); break;
                    case "link": success = CreateHardLinkW(target, path, IntPtr.Zero); break;
                    case "native-rename":
                    {
                        IntPtr handle = CreateFileW(path, DELETE_ACCESS | SYNCHRONIZE, FILE_SHARE_ALL,
                            IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
                        if (handle == new IntPtr(-1)) throw new Win32Exception();
                        IntPtr information = IntPtr.Zero;
                        try
                        {
                            byte[] name = Encoding.Unicode.GetBytes(target);
                            int offset = Marshal.OffsetOf(typeof(FILE_RENAME_INFORMATION), "FileName").ToInt32();
                            int size = Math.Max(Marshal.SizeOf(typeof(FILE_RENAME_INFORMATION)), offset + name.Length);
                            information = Marshal.AllocHGlobal(size);
                            Marshal.StructureToPtr(new FILE_RENAME_INFORMATION { Flags = 1, FileNameLength = (uint)name.Length }, information, false);
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
