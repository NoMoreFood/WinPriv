# WinPriv

WinPriv is a Windows system administration utility that alters the runtime behavior of a target process and its child processes using API hooking via [Microsoft Detours](https://github.com/microsoft/detours). It intercepts and redirects common low-level system calls — registry access, file system operations, network lookups, cryptography, and more — without requiring system-wide policy changes or reboots.

Typical uses include testing security configurations on a per-process basis, working around application compatibility issues, auditing privileged areas of the file system, and diagnosing how applications interact with the registry and network.

## Features

- **Privilege management** — enable individual or all Windows privileges on a process token
- **Registry interception** — override specific registry values or block entire key subtrees
- **Network spoofing** — substitute MAC addresses and redirect DNS hostname lookups
- **File system bypass** — use backup/restore privileges to access ACL-protected files
- **OS and identity spoofing** — report server edition, fake admin membership, adjust integrity level
- **FIPS and policy control** — spoof FIPS enforcement state; suppress group policy registry reads
- **Cryptography recording** — capture plaintext input/output of Windows crypto functions
- **SQL connection monitoring** — display or rewrite ODBC connection strings before they are used
- **LSA rights management** — grant, revoke, and clear logon rights and privileges directly
- **Run-as support** — launch programs as the console user or a specific logged-on user
- **Process lifecycle utilities** — kill a named process before launch, measure execution time

## Downloads

Pre-built binaries for x86, x64, and ARM64 are in the [`Build/`](Build/) directory. Two executables are provided:

| Executable | Use when… |
|---|---|
| `WinPrivCmd.exe` | The target is a console application and you need its output |
| `WinPriv.exe` | The target is a GUI application and you do not want a console window |

The behavior of the subprocess is identical regardless of which launcher is used.

## Requirements

- Windows 10 or later
- Administrator rights are required for most operations
- No installation needed — the injection libraries are embedded as resources and extracted to the user's temp directory at runtime

## Usage

```
WinPrivCmd.exe [switches] <command to execute>
WinPriv.exe    [switches] <command to execute>
```

Switches may appear in any order before the target command. Multiple switches of the same type (e.g. multiple `/RegOverride` or `/RegBlock`) are fully supported and processed in order.

## Switches

### Privilege Management

**`/WithPrivs <privilege>[,<privilege>,...]`**  
Enable one or more named Windows privileges on the process token (e.g. `SeDebugPrivilege,SeBackupPrivilege`).

**`/WithAllPrivs`**  
Enable every privilege available on the current token.

**`/ListPrivileges`**  
Print all available privilege names and their descriptions, then exit.

---

### Registry Interception

**`/RegOverride <KeyPath> <ValueName> <Type> <Data>`**  
Return a fabricated value whenever the target process reads the specified registry entry. Supported types: `REG_DWORD`, `REG_SZ`, `REG_BINARY`, `REG_QWORD`.

```
/RegOverride HKCU\Software\Demo Enabled REG_DWORD 1
/RegOverride HKLM\Software\Demo UserName REG_SZ "James Bond"
```

**`/RegBlock <KeyPath>`**  
Report all values under the specified key (and its subkeys) as not found, regardless of their actual contents.

```
/RegBlock HKCU\Software\Policies\Demo
```

**`/FipsOn`** / **`/FipsOff`**  
Convenience wrappers around `/RegOverride` that spoof the FIPS enforcement registry setting to enabled or disabled.

**`/PolicyBlock`**  
Convenience wrapper around `/RegBlock` that suppresses all reads from `HKCU\Software\Policies` and `HKLM\Software\Policies`.

---

### Network Interception

**`/MacOverride <MAC>`**  
Return a spoofed MAC address for all calls to `GetAdaptersAddresses`, `GetAdaptersInfo`, and `NetWkstaTransportEnum`. The address may be delimited by dashes, colons, or nothing.

```
/MacOverride 00-11-22-33-44-66
```

**`/HostOverride <TargetHost> <ReplacementHost>`**  
Redirect DNS lookups for `<TargetHost>` to `<ReplacementHost>` (a hostname or IP address) by intercepting `WSALookupServiceNext`. Note: does not apply to Internet Explorer or applications that use IE libraries.

```
/HostOverride db.internal 127.0.0.1
/HostOverride prod-server staging-server
```

---

### File System

**`/BypassFileSecurity`**  
Enable backup and restore privileges and set the appropriate access flags so that the target process can read and write files regardless of their ACLs. Useful with tools like `icacls.exe`, `robocopy`, `cmd.exe`, or `powershell.exe` for inspecting or modifying secured areas.

```
WinPrivCmd.exe /BypassFileSecurity icacls.exe "C:\System Volume Information" /T
```

**`/BreakRemoteLocks`**  
Force-close remote file locks that are preventing access. Has no effect on locks held by processes on the same machine.

---

### OS and Identity Spoofing

**`/AdminImpersonate`**  
Make `IsUserAnAdmin()` and `CheckTokenMembership()` unconditionally return success, regardless of the user's actual group membership.

**`/ServerEdition`**  
Cause OS version query functions to report a Server edition of Windows instead of the actual edition.

**`/MediumPlus`**  
Launch the target process at the "Plus" variant of the current token's mandatory integrity level (e.g. Medium → Medium Plus) without a full elevation to High.

**`/DisableAmsi`**  
Disable AMSI (Antimalware Scan Interface) scanning for the target process.

---

### Cryptography and SQL

**`/RecordCrypto <Directory|SHOW>`**  
Intercept common Windows encryption and decryption functions and record their plaintext input and output. Each operation is written to a separate file in `<Directory>`. Specify `SHOW` to print results to the console or a message box instead.

**`/SqlConnectShow`**  
Display ODBC connection parameters immediately before each connection attempt.

**`/SqlConnectSearchReplace <SearchRegex> <Replacement>`**  
Rewrite ODBC connection strings before they are used. The search pattern is a regular expression.

```
WinPrivCmd.exe /SqlConnectSearchReplace "Provider=SQLOLEDB" "Provider=SQLNCLI11" App.exe
```

---

### Process Execution Control

**`/RunAsConsoleUser <command>`**  
Execute `<command>` as the user currently logged into the physical console (or the first active remote session if no console session exists). Waits for the process to exit. Useful when WinPriv itself is running as SYSTEM (e.g. in a scheduled task or management agent).

**`/RunAsConsoleUserNoWait <command>`**  
Same as above but returns immediately after starting the process.

**`/RunAsUser <UserName> <command>`**  
Execute `<command>` as `<UserName>`, who must be logged into the system. Waits for the process to exit.

**`/RunAsUserNoWait <UserName> <command>`**  
Same as above but returns immediately after starting the process.

**`/KillProcess <ProcessName>`**  
Terminate any running process with the given name before launching the target. Useful for applications that prevent multiple instances.

**`/WindowStyle <Style>`**  
Launch the target with the specified window state: `NoActive`, `Hidden`, `Maximized`, `Minimized`, `MinimizedNoActive`.

**`/UseShellExecute`**  
Launch the target with `ShellExecute()` instead of `CreateProcess()`. Use when the target is a registered application that is not on the system path.

**`/MeasureTime`**  
Print the total execution time of the target process after it exits.

---

### LSA Account Rights Management

These operations modify the local security policy directly and require administrator rights. Changes take effect for new logon sessions immediately.

**`/GrantRight <Right> <UserName>`**  
Grant a privilege constant (e.g. `SeDebugPrivilege`) or logon-right constant (e.g. `SeInteractiveLogonRight`) to a user or group.

```
/GrantRight SeDebugPrivilege DOMAIN\JDoe
/GrantRight SeBatchLogonRight LocalSvcAccount
/GrantRight SeServiceLogonRight "NT SERVICE\MyService"
```

**`/RevokeRight <Right> <UserName>`**  
Remove a privilege or logon right from a user or group.

**`/ClearDenyRights [UserName]`**  
Remove all deny-logon rights from `<UserName>`. If no name is given, clears deny-logon rights from every account on the local machine. The rights cleared are:

| Constant | Description |
|---|---|
| `SeDenyNetworkLogonRight` | Deny access from the network |
| `SeDenyInteractiveLogonRight` | Deny local logon |
| `SeDenyBatchLogonRight` | Deny logon as a batch job |
| `SeDenyServiceLogonRight` | Deny logon as a service |
| `SeDenyRemoteInteractiveLogonRight` | Deny Remote Desktop logon |

**`/GrantAllRights <UserName>`**  
Grant every available privilege and all allow-logon rights to the specified account. Deny-logon rights are not included.

---

### Utility

**`/LoadCommands <Path>`**  
Load additional switches from a configuration file. The file is plain text (UTF-8), one argument per line, with environment variable expansion (`%VAR%`) supported. Arguments from the file are merged with any remaining command-line arguments.

**`/ShowMessage <Message>`**  
Display a message box with the given text before launching the target process.

**`/AskMessage <Message>`**  
Display a Yes/No prompt before launching. If the user clicks No, execution is cancelled.

**`/ExtractLibrary`**  
Extract the embedded x86, x64, and ARM64 WinPriv injection libraries to the directory containing WinPriv. On subsequent runs, WinPriv will use those files instead of extracting to the user's temp directory. Useful in environments where temp-directory writes are restricted.

**`/Help`** or **`/?`**  
Display the full help text.

---

## Configuration Files

Switches can be stored in a plain-text `.cfg` file (UTF-8), one switch or argument per line. Environment variables in `%VAR%` form are expanded. A configuration file is loaded automatically if it has the same base name as the executable and lives in the same directory. Additional files can be loaded explicitly with `/LoadCommands`.

Example `MyApp.cfg`:
```
/RegOverride
HKLM\Software\MyApp
LicenseKey
REG_SZ
DEMO-0000-0000
/BypassFileSecurity
```

---

## Examples

Open a PowerShell session with full file system access, bypassing all ACLs:
```
WinPrivCmd.exe /BypassFileSecurity powershell.exe
```

Run an application while spoofing a specific MAC address and suppressing group policy reads:
```
WinPriv.exe /MacOverride 00-1A-2B-3C-4D-5E /PolicyBlock MyApp.exe
```

Redirect a database connection to a local test server:
```
WinPrivCmd.exe /HostOverride prod-db.corp.local 127.0.0.1 MyApp.exe
```

Grant a service account the right to log on as a service:
```
WinPrivCmd.exe /GrantRight SeServiceLogonRight "CORP\MySvcAccount"
```

Run a deployment script as the console user from a SYSTEM-context task:
```
WinPrivCmd.exe /RunAsConsoleUser deploy.cmd
```

---

## Building from Source

Requirements: Visual Studio with the v145 C++ toolset, Desktop development with C++, ARM64 build tools, and a Windows SDK.

Open `WinPriv.sln` and build either the `Release` or `Debug` configuration for the desired platform (`Win32`, `x64`, or `ARM64`). Release binaries are written to `Build\x86\`, `Build\x64\`, and `Build\ARM64\`; Debug binaries and PDBs are written beneath `Build\Debug\`. Both configurations automatically produce all three injection-library architectures before compiling launcher resources, including for direct `.vcxproj` builds.

The solution contains four projects:

| Project | Output | Description |
|---|---|---|
| `WinPriv` | `WinPriv.exe` | Main GUI executable |
| `WinPrivCmd` | `WinPrivCmd.exe` | Main console executable |
| `WinPrivLibrary` | `WinPrivLibrary.dll` | Injected hooking library containing the consolidated Detours fork |
| `WinPrivShared` | static lib | Shared privilege and LSA utilities |

The x86, x64, and ARM64 `WinPrivLibrary.dll` builds are embedded as resources inside each launcher and extracted to the user's temp directory at runtime. The native ARM64 launcher injects native ARM64 targets; use the x64 launcher under Windows emulation for x64 targets.

Code signing is best-effort by default: certificate or timestamp failures emit a build warning and preserve the generated executable. Use `/p:SkipCodeSigning=true` to skip signing or `/p:RequireCodeSigning=true` to make signing failures fatal.

---

## License

MIT — see [LICENSE](LICENSE).
