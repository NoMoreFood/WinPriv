# WinPriv Test Suite

The test suite verifies the public CLI contract, injected Win32/NT hooks, process propagation, build artifacts, and local security-policy operations. PowerShell drives Pester specs and assertions, runtime C# probes exercise native APIs via `Add-Type`, and three native fixtures (`WinPrivHookImport.exe`, `WinPrivHookDelayLoad.exe`, `WinPrivHookDynamic.exe`) verify load-time import, MSVC delay-load, dynamic `LoadLibraryW`/`GetProcAddress`, CFG/ACG mitigations, and controlled native API failure paths without checking binaries into the repository.

## Requirements

- Windows with PowerShell 7.6 for `Invoke-WinPrivTests.ps1`.
- Visual Studio/MSBuild with the `v145` C++ toolset (x86, x64, and ARM64 components) and Windows 10 SDK when building from source. Pass `-BinaryRoot` to test existing binaries without local build tools; missing native fixtures are reported as explicitly gated `Unavailable` capabilities.
- Network access on the first run to download the pinned Pester package from `RequiredModules.psd1` into `Tests\.tools` (subsequent runs accept `-Offline`).
- Elevated administrator token on a workstation or member server for `Admin` and `Full` profiles (domain controllers are unsupported). Fresh-user cases require the Secondary Logon service and a local policy allowing builtin `Users` interactive logon.

The x86 launcher pairs with 32-bit Windows PowerShell 5.1; x64 and ARM64 launchers pair with matching PowerShell 7.6 hosts. Override discovery with `WINPRIV_TEST_POWERSHELL_X86`, `WINPRIV_TEST_POWERSHELL_X64`, or `WINPRIV_TEST_POWERSHELL_ARM64`.

## Running

```powershell
# Build an isolated source copy and run Safe tests
pwsh -NoProfile -NonInteractive -File .\Tests\Invoke-WinPrivTests.ps1 -Profile Safe

# Build and run Debug binaries
pwsh -NoProfile -NonInteractive -File .\Tests\Invoke-WinPrivTests.ps1 -Profile Safe -Configuration Debug

# Run elevated Admin tests
pwsh -NoProfile -NonInteractive -File .\Tests\Invoke-WinPrivTests.ps1 -Profile Admin

# Run Safe + Admin tests and keep all sandbox artifacts
pwsh -NoProfile -NonInteractive -File .\Tests\Invoke-WinPrivTests.ps1 -Profile Full -Architecture Auto -KeepArtifacts

# Test existing binaries without rebuilding
pwsh -NoProfile -NonInteractive -File .\Tests\Invoke-WinPrivTests.ps1 -Profile Safe -BinaryRoot .\Build -Architecture Auto
```

`-ResultsPath` must be a new path or an empty directory. `-AllowGlobalPolicyMutation` opts in to testing no-username `/ClearDenyRights` (snapshot-journaled and restored in `finally`); use it only on a disposable VM.

## Profiles and Containment

- **Safe** isolates files, GUID-named HKCU keys, processes, and extracted DLLs under a marked run root without mutating local security policy.
- **Admin** creates GUID-named local group/user fixtures (in builtin `Users`, without loading user profiles), copies probes into an ACL-scoped sandbox, and journals every principal, ACL, and LSA right for restoration before cleanup.
- **Full** runs both `Safe` and `Admin` suites. Interactive dialog tests run only when an input desktop is available.

Every launched process runs inside a mandatory kill-on-close Windows Job Object with a timeout. The runner reconciles current-run and stale-run journals by exact ownership markers, refusing reparse points. Out-of-scope paths (SYSTEM/WTS run-as, two-host SMB lock breaking, interactive credential relaunch) remain visible in `Capabilities.psd1` as `Unavailable`.

## Output

Each run writes `WinPriv.Tests.xml` (NUnit), `run-summary.json`, `coverage.json`, `cleanup-delta.json`, `process-events.jsonl`, and (on failure or `-KeepArtifacts`) `artifacts/`. Any test failure, timeout, unexpected skip, missing capability, uncontained process, or residual state causes a nonzero exit code.
