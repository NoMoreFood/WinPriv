# <img src=".github/WinPriv.png" width="48" height="48" alt="WinPriv icon"> WinPriv

WinPriv is a Windows system administration utility that launches a process with selected privileges and API hooks.
Its bundled fork of [Microsoft Detours](https://github.com/microsoft/detours) intercepts registry, file system,
network, cryptography, and other Windows API calls in the target and supported child processes.

Most overrides change what hooked processes see. Acquiring missing privileges can temporarily change local account
rights, and the LSA rights-management commands make persistent changes to local security policy.

Typical uses include testing security configurations on a per-process basis, working around application compatibility issues, auditing privileged areas of the file system, and diagnosing how applications interact with the registry and network.

## Features

- **Privilege management** — enable individual or all Windows privileges on a process token
- **Registry interception** — override value reads or hide values under selected keys and subkeys
- **Network spoofing** — substitute reported MAC addresses and host lookup results
- **File system bypass** — request backup/restore access when opening files
- **OS and identity spoofing** — report server edition and fake administrator membership checks
- **FIPS and policy control** — spoof FIPS enforcement state; suppress group policy registry reads
- **Cryptography recording** — capture plaintext from selected Windows encryption and decryption APIs
- **SQL connection monitoring** — display or rewrite ODBC and ADO connection strings
- **LSA rights management** — grant, revoke, and clear logon rights and privileges directly
- **Run-as support** — launch programs in an existing user session from LocalSystem, optionally at Medium Plus integrity
- **Process lifecycle utilities** — kill a named process before launch, measure execution time

## Downloads

Pre-built binaries, ZIP archives, and binary hashes are available from the
[GitHub releases](https://github.com/NoMoreFood/WinPriv/releases). Two executables are provided:

| Executable | Use when… |
|---|---|
| `WinPrivCmd.exe` | The target is a console application and you need its output |
| `WinPriv.exe` | The target is a GUI application and you do not want a console window |

Both launchers provide the same hook options. `WinPrivCmd.exe` writes launcher messages to the console;
`WinPriv.exe` displays them in message boxes.

Release archives keep the launchers in architecture folders. Standalone executable assets include an architecture
suffix, such as `WinPrivCmd-x64.exe`; the examples below use the filenames from the archive. Hash-file paths also
refer to the filenames inside the archive.

## Requirements

- Windows 10 or later
- Run elevated for account-rights changes or acquiring missing privileges. Overrides that do not request additional
  privileges can run as an ordinary user.
- The `/RunAs...` switches require LocalSystem and an existing user session.
- No installation is needed. Each launcher embeds all three injection libraries and normally extracts them to the
  Windows temporary directory. See `/ExtractLibrary` for reusing copies beside the launcher.

Source builds enable Control Flow Guard (CFG) in the launchers and injection libraries, including for strict-CFG processes. Process protections must still permit DLL loading and API hooking. When dynamic-code policy (ACG) already permits thread opt-out, WinPriv uses that permission during hook transactions and restores the previous thread policy afterward. It leaves the process policy unchanged and reports error 1655 when strict ACG prevents hook installation.

## Building

Run `Build\build.cmd` to rebuild and package the complete Release configuration. This requires Visual Studio C++
build tools with the v145 x86, x64, and ARM64 toolchains, a Windows SDK, and 7-Zip. MSBuild is found on `PATH` or
through the Visual Studio Installer.

The script builds the shared libraries and all three injection DLLs, then attempts to sign the DLLs in one batch.
It next builds both launchers for every architecture and the native test fixtures, and attempts to sign the six
launchers in one batch before packaging. The launchers embed the DLLs after the DLL signing step. Signing is
best-effort unless `RequireCodeSigning=true`; the native test fixtures are built, but tests are not run.
The archive contains the six launchers and the license; `Build\WinPriv-hash.txt` covers the launchers and archive.

Use `Build\build.cmd /SkipCodeSigning` for an unsigned local build, or `/PackageOnly` to package existing Release
launchers without compiling. Failures return a nonzero exit code, and the script does not pause for input.

## Usage

```
WinPrivCmd.exe [switches] <command to execute>
WinPriv.exe    [switches] <command to execute>
```

Switch names are case-insensitive and are processed from left to right. The first argument that does not start
with `/` begins the target command; all following arguments belong to that command. Put WinPriv switches before
the target. Repeated `/WithPrivs`, `/RegOverride`, `/RegBlock`, `/HostOverride`, and `/KillProcess` options accumulate.

Normal launches wait for the immediate target process and return its exit code. Hooks propagate to descendants
created through the intercepted `CreateProcessA/W` calls; WinPriv does not wait for the entire process tree.
Use `cmd.exe /c` when the target requires command-interpreter built-ins, batch-file handling, or shell syntax.

`/ListPrivileges`, `/ExtractLibrary`, the LSA rights-management commands, and `/Help` perform their action and exit
without launching a target. The `/RunAs...` switches also select a separate launch path, described below.

## Switches

### Privilege Management

**`/WithPrivs <privilege>[,<privilege>,...]`**  
Request one or more named privileges for the target (e.g. `SeDebugPrivilege,SeBackupPrivilege`). Use the exact
privilege names reported by `/ListPrivileges`, separated by commas without spaces.

WinPriv first tries to enable them in its current token. If privileges are missing, it attempts to grant them to
the current account in local security policy, prompts for that same account's credentials, and relaunches through
a new logon and UAC elevation. When the relaunched process returns, it removes only the account assignments it
added. This fallback requires permission to change local policy and interactive credentials; a relaunched console
target pauses for a key at exit.

**`/WithAllPrivs`**  
Request every privilege enumerated from the system's local security policy, using the same acquisition and
relaunch behavior as `/WithPrivs`.

**`/ListPrivileges`** or **`/ListPrivs`**

Print the privilege names and descriptions defined by local security policy, then exit. This lists system
privileges, rather than the privileges currently enabled in the caller's token.

---

### Registry Interception

**`/RegOverride <KeyPath> <ValueName> <Type> <Data>`**  
Override queries for the specified registry value, including a value that does not exist under an existing key.
Enumeration substitutes data for existing values; it does not add missing value names. The key must exist and be
readable when the injection library initializes. Supported roots are `HKLM`, `HKCU`, `HKCR`, and `HKU`, including
their full `HKEY_...` names.

Supported types are `REG_DWORD`, `REG_SZ`, `REG_BINARY`, and `REG_QWORD`. Integers accept decimal, `0x` hexadecimal,
or leading-zero octal notation. Binary data is an even number of hexadecimal digits without separators.

```
/RegOverride HKCU\Software\Demo Enabled REG_DWORD 1
/RegOverride HKLM\Software\Demo UserName REG_SZ "James Bond"
```

**`/RegBlock <KeyPath>`**  
Make value queries and value enumeration under the specified key and its subkeys report not found. The key must
exist and be readable when hooks initialize. Key opening and registry writes are not blocked or redirected.

```
/RegBlock HKCU\Software\Policies\Demo
```

**`/FipsOn`** / **`/FipsOff`**  
Override the `Enabled` DWORD under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy` to `1` or `0`
for hooked registry reads. The machine's FIPS policy is unchanged.

**`/PolicyBlock`**  
Apply `/RegBlock` to both `Software\Policies` and `Software\Microsoft\Windows\CurrentVersion\Policies` under
`HKCU` and `HKLM`. This hides registry values at those locations from hooked queries; it does not disable all
forms of Group Policy enforcement.

---

### Network Interception

**`/MacOverride <MAC>`**  
Substitute the reported adapter addresses returned by `GetAdaptersAddresses`, `GetAdaptersInfo`, and level-0
`NetWkstaTransportEnum` queries. The address may be delimited by dashes, colons, or nothing.

```
/MacOverride 00-11-22-33-44-66
```

**`/HostOverride <TargetHost> <ReplacementHost>`**  
Override matching host lookups through the ANSI and Unicode `WSALookupServiceBegin/Next` APIs. The replacement
must resolve to an IPv4 address before launch; an IPv4 literal is also accepted. Host names are matched exactly,
ignoring case. Applications using other resolver paths or their own DNS implementation are outside these hooks.

```
/HostOverride db.internal 127.0.0.1
/HostOverride prod-server staging-server
```

---

### File System

**`/BypassFileSecurity`**  
Request `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, and `SeChangeNotifyPrivilege`, and
add backup-intent flags to intercepted file open/create calls. This allows operations that Windows permits with
those privileges; file sharing rules and other process or file protections still apply. Missing privileges use
the acquisition and relaunch behavior described under `/WithPrivs`.

```
WinPrivCmd.exe /BypassFileSecurity icacls.exe "C:\System Volume Information" /T
```

**`/BreakRemoteLocks`**  
When a hooked file open/create fails with sharing-violation or access-denied status, try to close matching SMB
server file handles and retry the operation. This requires permission to enumerate and close files on the server.
It can close remote clients' handles to locally shared files, but does not close ordinary local process handles.

---

### OS and Identity Spoofing

**`/AdminImpersonate`**  
Make `IsUserAnAdmin()` report true and make successful `CheckTokenMembership()` queries for the built-in
Administrators group report membership. Other group-membership queries retain their normal results. The target
also receives the `RunAsInvoker` compatibility setting. These changes spoof checks without granting actual
administrator access or changing the token's group membership.

**`/ServerEdition`**  
Make extended `GetVersionExA/W` queries report a server product type and adjust `VerifyVersionInfoW` product-type
checks accordingly. This changes the results of those APIs, not the installed Windows edition.

**`/MediumPlus`**  
Set the duplicated session-user token to Medium Plus integrity. Place this before a `/RunAsConsoleUser`,
`/RunAsUser`, or corresponding `NoWait` switch. It has no effect on the normal hooked launch path.

**`/AmsiOn`** / **`/AmsiOff`**  
Preserve or disable Antimalware Scan Interface (AMSI) scanning for the target process and its child processes. The last AMSI switch wins. Intercepted `AmsiScanBuffer` and `AmsiScanString` calls report clean content when disabled.

**`/ClmOn`** / **`/ClmOff`**  
Enable or disable PowerShell Constrained Language Mode (CLM) for the target process and its child processes by overriding PowerShell policy queries. The last CLM switch wins. The machine policy is unchanged.

---

### Cryptography and SQL

**`/RecordCrypto <Directory|SHOW>`**  
Capture plaintext from `BCryptEncrypt/Decrypt`, `CryptEncrypt/Decrypt`, and `RtlEncryptMemory/DecryptMemory`:
input to encryption and output from decryption. Captured nonempty buffers are written to separate `.bin` files
in `<Directory>`. Specify `SHOW` to display text using the target process's console or message boxes instead.

**`/SqlConnectShow`**  
Display connection strings intercepted through ODBC `SQLDriverConnect` and ADO `Connection.Open`, after any
successful `/SqlConnectSearchReplace` rewrite.

**`/SqlConnectSearchReplace <SearchRegex> <Replacement>`**  
Rewrite intercepted ODBC and ADO connection strings before opening the connection, including ADO's stored
`ConnectionString` when `Open` omits it. The search uses a case-sensitive regular expression; replacement capture
references use `$1`, `$2`, and so on. An invalid pattern leaves the original connection string in use.

```
WinPrivCmd.exe /SqlConnectSearchReplace "Provider=SQLOLEDB" "Provider=SQLNCLI11" App.exe
```

---

### Process Execution Control

The `/RunAs...` commands use an existing Windows session token and require LocalSystem. They launch with that
user's environment on the interactive desktop, with a new console for console applications. They do not apply
the normal WinPriv hook options or `/WithPrivs`, `/WindowStyle`, `/UseShellExecute`, and `/MeasureTime` settings.
To apply hooks in that session, make another WinPriv invocation the run-as command.

**`/RunAsConsoleUser <command>`**  
Use the active console user's session, falling back to the first active non-SYSTEM user session. Disconnected
sessions are not selected by this switch. Wait for the process to exit and return its exit code.

**`/RunAsConsoleUserNoWait <command>`**  
Use the same session selection, returning zero after successful process creation without waiting for it to exit.

**`/RunAsUser <UserName> <command>`**  
Resolve `<UserName>` to an account and select its active session, or a disconnected session if no active one is
available. Wait for the process to exit and return its exit code. This reuses an existing session without prompting
for a password or creating a new user logon.

**`/RunAsUserNoWait <UserName> <command>`**  
Use the same account/session selection, returning zero after successful process creation without waiting.

**`/KillProcess <ProcessName>`**  
Attempt to terminate every matching executable name, such as `notepad.exe`, in the caller's session before launch.
When placed before a `/RunAs...` command, it instead acts in the selected user's session. Matching ignores case;
termination failures are reported but do not by themselves stop the target launch.

**`/WindowStyle <Style>`**  
Request an initial window state for a normal or shell launch: `NoActive`, `Hidden`, `Maximized`, `Minimized`, or
`MinimizedNoActive`. Applications can choose how to handle the startup window-state request.

**`/UseShellExecute`**  
Launch through `ShellExecuteEx`, allowing shell application resolution and file associations. WinPriv requires a
returned process handle to wait for completion and reports an error if none is provided. Shell launches delegated
to another process may not pass through WinPriv's process-creation hooks.

**`/MeasureTime`**  
Print elapsed wall-clock time in seconds for a normal target launch and wait, including process creation. This
does not measure all descendants or apply to the `/RunAs...` commands.

---

### LSA Account Rights Management

These commands modify account-right assignments in local security policy and require permission to change that
policy, normally an elevated administrator token. They make persistent changes, then exit without running a target
or processing further switches. Existing process tokens are not updated; new logons pick up changed privileges.

**`/GrantRight <Right> <UserName>`**  
Grant a privilege constant (e.g. `SeDebugPrivilege`) or logon-right constant (e.g. `SeInteractiveLogonRight`) to a
user or group on this machine.

```
/GrantRight SeDebugPrivilege DOMAIN\JDoe
/GrantRight SeBatchLogonRight LocalSvcAccount
/GrantRight SeServiceLogonRight "NT SERVICE\MyService"
```

**`/RevokeRight <Right> <UserName>`**  
Remove a privilege or logon right from a user or group.

**`/ClearDenyRights [UserName]`**  
Remove the listed deny-logon rights assigned directly to `<UserName>`. If no name is given, clear them from every
account with rights assigned in the machine's local security policy. Clearing one user's assignments does not
clear assignments on its groups. The rights cleared are:

| Constant | Description |
|---|---|
| `SeDenyNetworkLogonRight` | Deny access from the network |
| `SeDenyInteractiveLogonRight` | Deny local logon |
| `SeDenyBatchLogonRight` | Deny logon as a batch job |
| `SeDenyServiceLogonRight` | Deny logon as a service |
| `SeDenyRemoteInteractiveLogonRight` | Deny Remote Desktop logon |

**`/GrantAllRights <UserName>`**  
Grant every enumerated system privilege and the five allow-logon rights (network, interactive, remote interactive,
batch, and service) to the account. Existing deny-logon assignments remain in place.

---

### Utility

**`/LoadCommands <Path>`**  
Insert arguments from a UTF-8 configuration file at this position in the command line, preserving earlier
arguments and appending the remaining arguments afterward. Newlines act as spaces, quoting follows Windows
command-line rules, and `%VAR%` environment variables are expanded. See [Configuration Files](#configuration-files).

**`/ShowMessage <Message>`**  
Display a message box with the given text before launching the target process.

**`/AskMessage <Message>`**  
Display a Yes/No prompt before launching. If the user clicks No, execution is cancelled.

**`/ExtractLibrary`**  
Write the embedded libraries beside the running launcher as `WinPrivLibrary-32.dll`, `WinPrivLibrary-64.dll`, and
`WinPrivLibrary-arm64.dll`, overwriting existing copies, then exit. Subsequent launches reuse them only when all
three are present; otherwise all three payloads are extracted to the temporary directory. Re-extract the libraries
after upgrading the launcher to keep the versions together.

**`/Help`** or **`/?`**  
Display help and exit. Use `WinPrivCmd.exe /Help` for the full switch reference; the GUI launcher shows brief usage.

---

## Configuration Files

Configuration files are UTF-8, with an optional BOM. Their contents are parsed as a Windows command line after
newlines are converted to spaces and `%VAR%` environment variables are expanded. One argument per line is optional;
arguments containing spaces still need double quotes. There is no comment syntax.

An automatic configuration uses the **launcher's** filename with `.exe` replaced by `.cfg` and sits beside it:
`WinPrivCmd.exe` loads `WinPrivCmd.cfg`, while `WinPrivCmd-x64.exe` loads `WinPrivCmd-x64.cfg`. Its contents replace
the supplied command line entirely, so it must include the target command for a normal launch. Automatic configs
are not reloaded during WinPriv's internal privilege relaunch.

Explicit `/LoadCommands` files are inserted at the switch's position and can contain just options, leaving the
target on the command line. Relative paths resolve from the current working directory. Missing files, recursive
cycles, or excessive command-file expansion produce an error.

Example `WinPrivCmd.cfg` beside `WinPrivCmd.exe`, assuming the `HKLM\Software\MyApp` key already exists:
```
/RegOverride
HKLM\Software\MyApp
LicenseKey
REG_SZ
DEMO-0000-0000
/BypassFileSecurity
"C:\Tools\MyApp.exe"
```

---

## Examples

Open a PowerShell session with backup-intent file access and the requested backup/restore privileges:
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

Open `WinPriv.sln` and select `Release` or `Debug` with solution platform `x86`, `x64`, or `ARM64` (`x86` maps to
`Win32` in the project files). Release binaries are written to `Build\x86\`, `Build\x64\`, and `Build\ARM64\`;
Debug binaries and PDBs are written beneath `Build\Debug\`. Both configurations automatically produce all three
injection-library architectures before compiling launcher resources, including for direct `.vcxproj` builds.
Install all three C++ toolchains even when building a launcher for only one architecture.

The solution contains four product projects (listed below) and three native test fixture projects.

| Project | Output | Description |
|---|---|---|
| `WinPriv` | `WinPriv.exe` | Main GUI executable |
| `WinPrivCmd` | `WinPrivCmd.exe` | Main console executable |
| `WinPrivLibrary` | `WinPrivLibrary.dll` | Injected hooking library containing the consolidated Detours fork |
| `WinPrivShared` | static lib | Shared privilege and LSA utilities |

Each launcher embeds the x86, x64, and ARM64 `WinPrivLibrary.dll` builds. Injection selects the library for the
target's architecture, using a matching helper process when needed for a different architecture. The operating
system must support running both the launcher and the target. Library extraction and reuse follow the
`/ExtractLibrary` rules above.

Code signing uses SignTool from `PATH` or an installed Windows SDK. It is best-effort by default: certificate or timestamp failures emit a build warning and preserve the generated files. Use `/p:SkipCodeSigning=true` to skip signing or `/p:RequireCodeSigning=true` to make signing failures fatal in MSBuild. For `Build\build.cmd`, use `/SkipCodeSigning` or set `RequireCodeSigning=true` in the environment. Files are signed and verified as temporary copies before replacing the outputs.

---

## License

MIT — see [LICENSE](LICENSE).
