# WinPriv test suite

The suite exercises the public command-line contract, injected Win32/NT API hooks,
process propagation, build artifacts, and local security-policy operations. The
runner and assertions use PowerShell; most native calls are made through C#
definitions compiled at runtime with `Add-Type`. Source builds also compile three
small native fixtures that call the same detoured registry API through a normal PE
import, an MSVC delay-load import, and `LoadLibraryW`/`GetProcAddress`. No test
executable is checked in.

## Requirements

- Windows and PowerShell 7.6 for the main runner.
- Visual Studio/MSBuild with the v145 C++ toolset and Windows SDK 10 when the
  runner builds from source. The x86, x64, and ARM64 C++ components are all
  required because every launcher embeds all three injection payloads. Use
  `-BinaryRoot` to test an existing complete build without installing build
  tools on the test workstation. A release-only binary tree without the native
  hook-loading fixtures can still be tested; those three explicitly gated
  loading-path capabilities are reported as unavailable.
- Network access on the first run so Pester 5.7.1 can be downloaded into
  `Tests/.tools`; later runs can use `-Offline`.
- The Admin profile must run from an elevated administrator token.
- Fresh-user Admin cases require the Secondary Logon service and a local policy
  that permits the builtin Users alias to log on locally.

The Admin profile uses only the workstation's local SAM and is supported on a
standalone/workgroup PC; it does not require a domain account or domain
controller. Domain controllers are outside this local-SAM test contract.

The x86 launcher is paired with 32-bit Windows PowerShell 5.1. The x64 and
ARM64 launchers are paired with matching PowerShell 7.6 hosts. Override host
discovery with `WINPRIV_TEST_POWERSHELL_X86`,
`WINPRIV_TEST_POWERSHELL_X64`, or `WINPRIV_TEST_POWERSHELL_ARM64`.
The cross-architecture propagation tests explicitly override that default
pairing to exercise x86 -> x64 -> x86 and x64 -> x86 -> x64 process trees.

## Probe contract

`Probes\Invoke-WinPrivProbe.ps1` is compatible with Windows PowerShell 5.1 and
PowerShell 7.6. It accepts `-Operation`, `-OutputPath`, and either
`-ArgumentsJson` or UTF-8 `-ArgumentsBase64`, then writes one atomic JSON
envelope containing `supported`, `success`, `reason`, `result`, and `error`.
Operations cover process/token state, arguments, environment/current directory,
registry Win32 and NT queries, networking, AMSI, identity/version, crypto,
ODBC/ADO, Win32 and native files, LSA rights, and CreateProcessA/W descendants.
The harness always invokes it through the architecture-matched host.

## Running

Build an isolated copy of the current working tree and run safe tests:

```powershell
pwsh -NoProfile -File .\Tests\Invoke-WinPrivTests.ps1 -Profile Safe
```

Use `-Configuration Debug` to build the isolated source copy with the Debug
configuration and run the same suite against `Build\Debug`:

```powershell
pwsh -NoProfile -File .\Tests\Invoke-WinPrivTests.ps1 `
  -Profile Safe -Configuration Debug
```

Run the elevated, machine-state-sensitive tests:

```powershell
pwsh -NoProfile -File .\Tests\Invoke-WinPrivTests.ps1 -Profile Admin
```

Run all local profiles and retain every per-test artifact:

```powershell
pwsh -NoProfile -File .\Tests\Invoke-WinPrivTests.ps1 `
  -Profile Full -Architecture Auto -KeepArtifacts
```

Test previously built binaries instead of compiling a staged source copy:

```powershell
pwsh -NoProfile -File .\Tests\Invoke-WinPrivTests.ps1 `
  -Profile Safe -BinaryRoot .\Build -Architecture Auto
```

`-ResultsPath` must name either a path that does not yet exist or an existing
empty directory. The runner refuses files and nonempty directories so reports
and JSONL event streams from separate runs cannot be mixed.

`-AllowGlobalPolicyMutation` enables the no-username form of
`/ClearDenyRights`. It is never implied by `Admin` or `Full`. Before invoking
it, the suite snapshots all deny-right assignments and records a recovery
journal; restoration is verified in `finally`. Use it only on a disposable VM.

## Profiles and safety

- **Safe** confines files, registry values, processes, and temporary DLLs to a
  GUID-named suite root. It does not intentionally change local security policy.
- **Admin** uses a GUID-named empty local group for account-right tests and a
  temporary local user only for fresh-logon token tests. Principal creation is
  journaled before the local SAM is changed, and the user is placed in the
  locale-independent builtin Users alias. Fresh-user probe files are copied
  into the ACL-scoped sandbox; no repository access or loaded user profile is
  required. Every SID/right/ACL is journaled and restored before the test root
  is removed.
- **Full** runs Safe followed by Admin. Interactive dialog tests run only when
  an input desktop is available.

Every launched process is bounded by a timeout and placed in a Windows Job
Object when the host permits it. Process cleanup is by recorded PID, image path,
and start time—not by a broad executable name. ACL fixtures live on NTFS under
the suite root and preserve their original owner, SDDL, and content hash.
The runner performs a second exact-marker journal reconciliation in `finally`,
so an aborted Pester teardown cannot discard the only recovery record.

The selected scope deliberately does not perform positive SYSTEM/WTS run-as
tests, the true two-host SMB lock-breaking path, or interactive credential/UAC
privilege relaunch. Those capabilities remain in `Capabilities.psd1` and appear
as explicitly unavailable rather than silently disappearing.

## Results

The results directory contains:

- `WinPriv.Tests.xml` — NUnit test results;
- `run-summary.json` — the main runner host path, PowerShell version/edition,
  process and OS architectures, elevation state, binary hashes, gates, and totals;
- `coverage.json` — one terminal result for every capability in the manifest;
- `cleanup-delta.json` — processes, files, ACLs, principals, and LSA deltas observed
  during teardown;
- `process-events.jsonl` — bounded Job Object launch evidence; any timeout,
  start failure, or uncontained process tree fails the run;
- `artifacts/` — retained failure evidence, or all evidence with
  `-KeepArtifacts`.

Known WinPriv defects are not allowlisted. A test failure, timeout, unexpected
skip, missing capability result, or residual-state delta makes the runner and CI
exit nonzero.
