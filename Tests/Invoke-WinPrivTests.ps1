#requires -Version 7.6

[CmdletBinding()]
param(
    [ValidateSet('Safe', 'Admin', 'Full')]
    [string]$Profile = 'Safe',

    [ValidateSet('Auto', 'x86', 'x64', 'ARM64')]
    [string[]]$Architecture = @('Auto'),

    [Alias('Configuration')]
    [ValidateSet('Release', 'Debug')]
    [string]$BuildConfiguration = 'Release',

    [string]$BinaryRoot,

    [string]$ResultsPath,

    [switch]$KeepArtifacts,

    [switch]$Offline,

    [switch]$AllowGlobalPolicyMutation
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:TestsRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$script:RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$script:ProductFiles = @('WinPriv.exe', 'WinPrivCmd.exe', 'WinPrivLibrary.dll', 'WinPriv-x86.dll', 'WinPriv-x64.dll', 'WinPriv-ARM64.dll')
$script:FixtureFiles = @('WinPrivHookImport.exe', 'WinPrivHookDelayLoad.exe', 'WinPrivHookDynamic.exe')

function Write-WinPrivTestJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value,
        [int]$Depth = 40
    )
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Path))
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth $Depth), $script:Utf8NoBom)
}

function Write-WinPrivInfrastructureNUnit {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][DateTime]$StartedUtc,
        [Parameter(Mandatory = $true)][DateTime]$EndedUtc
    )
    $elapsed = [Math]::Round(($EndedUtc - $StartedUtc).TotalSeconds, 3).ToString([Globalization.CultureInfo]::InvariantCulture)
    $escaped = [Security.SecurityElement]::Escape($Message)
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<test-results name="WinPriv infrastructure" total="1" errors="1" failures="0" not-run="0" date="$($EndedUtc.ToString('yyyy-MM-dd'))" time="$($EndedUtc.ToString('HH:mm:ss'))">
  <test-suite name="WinPriv test runner" executed="True" result="Error" success="False" time="$elapsed">
    <results>
      <test-case name="Test runner infrastructure" executed="True" result="Error" success="False">
        <failure><message>$escaped</message></failure>
      </test-case>
    </results>
  </test-suite>
</test-results>
"@
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $Path))
    [IO.File]::WriteAllText($Path, $xml, $script:Utf8NoBom)
}

function Get-WinPrivPackageTreeHash {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $records = foreach ($file in Get-ChildItem -LiteralPath $rootPath -File -Recurse) {
        if ($file.Name -eq '.winpriv-package-integrity.json') { continue }
        $relative = $file.FullName.Substring($rootPath.Length).TrimStart('\', '/') -replace '\\', '/'
        '{0}|{1}|{2}' -f $relative, $file.Length, (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes((($records | Sort-Object) -join "`n"))
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
}

function Test-WinPrivPesterExtraction {
    param(
        [Parameter(Mandatory = $true)][string]$ModuleDirectory,
        [Parameter(Mandatory = $true)]$Requirement,
        [Parameter(Mandatory = $true)][string]$PackageHash
    )
    $manifestPath = Join-Path $ModuleDirectory 'Pester.psd1'
    $assemblyPath = Join-Path $ModuleDirectory 'bin\net8.0\Pester.dll'
    $integrityPath = Join-Path $ModuleDirectory '.winpriv-package-integrity.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $assemblyPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $integrityPath -PathType Leaf)) {
        return $false
    }
    try {
        $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
        if ([version]$manifest.ModuleVersion -ne [version]$Requirement.Version -or
            [guid]$manifest.GUID -ne [guid]$Requirement.Guid) {
            return $false
        }
        $integrity = Get-Content -LiteralPath $integrityPath -Raw | ConvertFrom-Json
        if ($integrity.PackageSha256 -ne $PackageHash) { return $false }
        return (Get-WinPrivPackageTreeHash -Root $ModuleDirectory) -eq $integrity.TreeSha256
    }
    catch { return $false }
}

function Import-WinPrivPinnedPester {
    param([switch]$OfflineMode)

    $requirement = (Import-PowerShellDataFile -LiteralPath (Join-Path $script:TestsRoot 'RequiredModules.psd1')).Pester
    $toolsRoot = Join-Path $script:TestsRoot '.tools'
    $packagesRoot = Join-Path $toolsRoot 'packages'
    $moduleDirectory = Join-Path $toolsRoot 'Modules' 'Pester' $requirement.Version
    $packagePath = Join-Path $packagesRoot ("Pester.{0}.nupkg" -f $requirement.Version)
    $manifestPath = Join-Path $moduleDirectory 'Pester.psd1'
    foreach ($directory in @($toolsRoot, $packagesRoot, (Split-Path -Parent $moduleDirectory))) {
        [void][IO.Directory]::CreateDirectory($directory)
    }

    $loadedPester = Get-Module -Name Pester
    $loadedPinnedPester = $null
    if ($loadedPester) {
        $expectedModuleBase = [IO.Path]::GetFullPath($moduleDirectory)
        $foreign = @($loadedPester | Where-Object {
            [version]$_.Version -ne [version]$requirement.Version -or
            [guid]$_.Guid -ne [guid]$requirement.Guid -or
            [IO.Path]::GetFullPath($_.ModuleBase) -ne $expectedModuleBase
        })
        if ($foreign.Count -gt 0) {
            throw 'A different Pester module is already loaded. Start the test runner with pwsh -NoProfile so the pinned Pester assembly can be loaded safely.'
        }
        $loadedPinnedPester = $loadedPester | Select-Object -First 1
    }

    $lockPath = Join-Path $toolsRoot '.bootstrap.lock'
    $lock = $null
    $deadline = [DateTime]::UtcNow.AddMinutes(2)
    do {
        try {
            $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        }
        catch [IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Timed out waiting for the Pester cache lock '$lockPath'." }
            Start-Sleep -Milliseconds 200
        }
    } until ($null -ne $lock)

    try {
        $packageHash = if (Test-Path -LiteralPath $packagePath -PathType Leaf) {
            (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
        }
        else { $null }
        if ($packageHash -ne $requirement.Sha256) {
            if ($OfflineMode) {
                throw "Offline mode requires the verified Pester $($requirement.Version) package at '$packagePath'."
            }
            $downloadPath = "$packagePath.$([Guid]::NewGuid().ToString('N')).download"
            try {
                Invoke-WebRequest -Uri $requirement.PackageUri -OutFile $downloadPath -MaximumRetryCount 2 -ConnectionTimeoutSeconds 30
                $packageHash = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash
                if ($packageHash -ne $requirement.Sha256) {
                    throw "Pester package checksum mismatch. Expected $($requirement.Sha256), received $packageHash."
                }
                if (Test-Path -LiteralPath $packagePath) { Remove-Item -LiteralPath $packagePath -Force }
                Move-Item -LiteralPath $downloadPath -Destination $packagePath
            }
            finally {
                if (Test-Path -LiteralPath $downloadPath) { Remove-Item -LiteralPath $downloadPath -Force }
            }
        }

        if (-not (Test-WinPrivPesterExtraction -ModuleDirectory $moduleDirectory -Requirement $requirement -PackageHash $packageHash)) {
            if ($null -ne $loadedPinnedPester) {
                throw 'The pinned Pester module cache failed integrity validation after it was loaded. Start a fresh pwsh -NoProfile process so the cache can be repaired safely.'
            }
            $temporaryDirectory = "$moduleDirectory.$([Guid]::NewGuid().ToString('N')).extracting"
            try {
                [IO.Compression.ZipFile]::ExtractToDirectory($packagePath, $temporaryDirectory)
                $temporaryManifest = Import-PowerShellDataFile -LiteralPath (Join-Path $temporaryDirectory 'Pester.psd1')
                if ([version]$temporaryManifest.ModuleVersion -ne [version]$requirement.Version -or
                    [guid]$temporaryManifest.GUID -ne [guid]$requirement.Guid -or
                    -not (Test-Path -LiteralPath (Join-Path $temporaryDirectory 'bin\net8.0\Pester.dll') -PathType Leaf)) {
                    throw 'The verified Pester package did not contain the expected module payload.'
                }
                Write-WinPrivTestJson -Path (Join-Path $temporaryDirectory '.winpriv-package-integrity.json') -Value ([ordered]@{
                    SchemaVersion = 1
                    PackageSha256 = $packageHash
                    TreeSha256    = Get-WinPrivPackageTreeHash -Root $temporaryDirectory
                    Version       = $requirement.Version
                    Guid          = $requirement.Guid
                })
                if (Test-Path -LiteralPath $moduleDirectory) { Remove-Item -LiteralPath $moduleDirectory -Recurse -Force }
                [IO.Directory]::Move($temporaryDirectory, $moduleDirectory)
            }
            finally {
                if (Test-Path -LiteralPath $temporaryDirectory) { Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force }
            }
        }
    }
    finally {
        $lock.Dispose()
    }

    if ($null -ne $loadedPinnedPester) { return $loadedPinnedPester }
    $module = Import-Module -Name $manifestPath -Force -PassThru -ErrorAction Stop
    if ([version]$module.Version -ne [version]$requirement.Version -or
        [guid]$module.Guid -ne [guid]$requirement.Guid -or
        [IO.Path]::GetFullPath($module.ModuleBase) -ne [IO.Path]::GetFullPath($moduleDirectory)) {
        throw 'The imported Pester module does not match the pinned version, GUID, and cache path.'
    }
    return $module
}

function Copy-WinPrivSourceStage {
    param(
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$LogPath
    )
    if (Test-Path -LiteralPath $Destination) {
        throw "Source staging destination already exists: '$Destination'."
    }
    [void][IO.Directory]::CreateDirectory($Destination)
    $robocopy = Join-Path $env:WINDIR 'System32\robocopy.exe'
    $excludeDirectories = @(
        (Join-Path $script:RepositoryRoot '.git'),
        (Join-Path $script:RepositoryRoot '.vs'),
        (Join-Path $script:RepositoryRoot 'Build'),
        (Join-Path $script:TestsRoot '.tools'),
        (Join-Path $script:TestsRoot '.work'),
        (Join-Path $script:TestsRoot 'Native\Build'),
        (Join-Path $script:TestsRoot 'Results'),
        (Join-Path $script:TestsRoot 'TestResults')
    )
    if (-not [string]::IsNullOrWhiteSpace($ResultsPath)) {
        $resultRoot = [IO.Path]::GetFullPath($ResultsPath)
        $repositoryPrefix = $script:RepositoryRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if ($resultRoot.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            $excludeDirectories += $resultRoot
        }
    }
    $arguments = @(
        $script:RepositoryRoot, $Destination,
        '/E', '/COPY:DAT', '/DCOPY:DAT', '/R:2', '/W:1', '/XJ',
        '/NP', '/NFL', '/NDL', '/NJH', '/NJS', '/XD'
    ) + $excludeDirectories
    & $robocopy @arguments *> $LogPath
    if ($LASTEXITCODE -gt 7) {
        throw "robocopy failed while staging the source tree (exit code $LASTEXITCODE). See '$LogPath'."
    }
    # Retain only Build\build.cmd so the isolated packaging test can exercise it without stale binaries.
    $destinationBuild = Join-Path $Destination 'Build'
    [void][IO.Directory]::CreateDirectory($destinationBuild)
    Copy-Item -LiteralPath (Join-Path $script:RepositoryRoot 'Build\build.cmd') -Destination $destinationBuild -Force
}

function Find-WinPrivMSBuild {
    $override = $env:WINPRIV_TEST_MSBUILD
    if (-not [string]::IsNullOrWhiteSpace($override)) {
        if (-not (Test-Path -LiteralPath $override -PathType Leaf)) { throw "WINPRIV_TEST_MSBUILD does not exist: '$override'." }
        return [IO.Path]::GetFullPath($override)
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        $command = Get-Command vswhere.exe -ErrorAction SilentlyContinue
        if ($command) { $vswhere = $command.Source }
    }
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'vswhere.exe was not found. Install Visual Studio 2026 with the Desktop development with C++ workload.'
    }
    $instances = @(& $vswhere -all -products '*' -format json | ConvertFrom-Json | Sort-Object { [version]$_.installationVersion } -Descending)
    foreach ($instance in $instances) {
        $toolset = Join-Path $instance.installationPath 'VC\Auxiliary\Build\v145'
        $msbuild = Join-Path $instance.installationPath 'MSBuild\Current\Bin\MSBuild.exe'
        if ((Test-Path -LiteralPath $toolset -PathType Container) -and (Test-Path -LiteralPath $msbuild -PathType Leaf)) {
            return $msbuild
        }
    }
    throw 'No Visual Studio installation with MSBuild and the v145 C++ toolset was found.'
}

function Build-WinPrivStage {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$LogRoot,
        [Parameter(Mandatory = $true)][ValidateSet('Release', 'Debug')][string]$Configuration
    )
    $solution = Join-Path $SourceRoot 'WinPriv.sln'
    if (-not (Test-Path -LiteralPath $solution -PathType Leaf)) { throw "Staged solution is missing: '$solution'." }
    $msbuild = Find-WinPrivMSBuild
    # Complete every payload before any launcher embeds it, including Debug images with unique PDB signatures.
    $projects = @(
        'WinPrivShared\WinPrivShared.vcxproj',
        'WinPrivLibrary\WinPrivLibrary.vcxproj',
        'WinPriv\WinPriv.vcxproj',
        'WinPrivCmd\WinPrivCmd.vcxproj',
        'Tests\Native\HookLoadingFixture\HookLoadingFixture.Import.vcxproj',
        'Tests\Native\HookLoadingFixture\HookLoadingFixture.DelayLoad.vcxproj',
        'Tests\Native\HookLoadingFixture\HookLoadingFixture.Dynamic.vcxproj'
    )
    foreach ($project in $projects) {
        foreach ($platform in @('Win32', 'x64', 'ARM64')) {
            $name = [IO.Path]::GetFileNameWithoutExtension($project)
            $logPath = Join-Path $LogRoot "build-$name-$platform.log"
            Write-Host "Building $name $Configuration|$platform with v145..."
            $arguments = @(
                (Join-Path $SourceRoot $project),
                '/nologo', '/m:1', '/t:Rebuild', '/v:minimal',
                "/p:Configuration=$Configuration",
                "/p:Platform=$platform",
                '/p:PlatformToolset=v145',
                '/p:SkipCodeSigning=true',
                '/p:BuildProjectReferences=false',
                '/p:WinPrivPayloadChildBuild=true'
            )
            & $msbuild @arguments 2>&1 | Tee-Object -FilePath $logPath | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "$name $Configuration|$platform build failed with exit code $LASTEXITCODE. See '$logPath'."
            }
        }
    }
    $binaryRoot = if ($Configuration -eq 'Debug') { Join-Path $SourceRoot 'Build' 'Debug' } else { Join-Path $SourceRoot 'Build' }
    foreach ($platform in @('x86', 'x64', 'ARM64')) {
        $output = Join-Path $binaryRoot $platform
        foreach ($name in $script:ProductFiles) {
            if (-not (Test-Path -LiteralPath (Join-Path $output $name) -PathType Leaf)) {
                throw "$Configuration|$platform did not produce '$name' in '$output'."
            }
        }
        $fixtureOutput = Join-Path $SourceRoot 'Tests\Native\Build' $Configuration $platform
        foreach ($name in $script:FixtureFiles) {
            if (-not (Test-Path -LiteralPath (Join-Path $fixtureOutput $name) -PathType Leaf)) {
                throw "$Configuration|$platform did not produce native test fixture '$name' in '$fixtureOutput'."
            }
        }
    }
    return $binaryRoot
}

function Read-WinPrivJsonLines {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    return @(Get-Content -LiteralPath $Path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}

function Copy-WinPrivFailureArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$ResultsRoot
    )
    $destination = Join-Path $ResultsRoot 'artifacts'
    [void][IO.Directory]::CreateDirectory($destination)
    foreach ($name in @('build-logs', 'sandboxes')) {
        $source = Join-Path $RunRoot $name
        if (Test-Path -LiteralPath $source -PathType Container) {
            Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force
        }
    }
    return $destination
}

if (-not $IsWindows) {
    throw 'The WinPriv test suite can run only on Windows.'
}
$runId = '{0:yyyyMMddTHHmmssZ}-{1}' -f [DateTime]::UtcNow, [Guid]::NewGuid().ToString('N').Substring(0, 8)
if ([string]::IsNullOrWhiteSpace($ResultsPath)) {
    $ResultsPath = Join-Path $script:TestsRoot 'TestResults' $runId
}
$ResultsPath = [IO.Path]::GetFullPath($ResultsPath)
if (Test-Path -LiteralPath $ResultsPath) {
    if (-not (Test-Path -LiteralPath $ResultsPath -PathType Container)) {
        throw "ResultsPath must not be an existing file: '$ResultsPath'."
    }
    if ($null -ne (Get-ChildItem -LiteralPath $ResultsPath -Force | Select-Object -First 1)) {
        throw "ResultsPath must not be an existing nonempty directory: '$ResultsPath'. Choose a new path or an empty directory."
    }
}
else {
    [void][IO.Directory]::CreateDirectory($ResultsPath)
}

$suiteRunRoot = Join-Path ([IO.Path]::GetTempPath()) 'WinPrivTests'
$runRoot = Join-Path $suiteRunRoot $runId
$buildLogs = Join-Path $runRoot 'build-logs'
[void][IO.Directory]::CreateDirectory($buildLogs)
$runMarkerId = [Guid]::NewGuid().ToString('D')
$ownerProcess = Get-Process -Id $PID
$runnerIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $runnerPrincipal = [Security.Principal.WindowsPrincipal]::new($runnerIdentity)
    $runnerHostInfo = [ordered]@{
        HostName                    = $Host.Name
        HostVersion                 = [string]$Host.Version
        ExecutablePath              = $ownerProcess.Path
        PowerShellVersion           = $PSVersionTable.PSVersion.ToString()
        PowerShellEdition           = [string]$PSVersionTable.PSEdition
        ProcessArchitecture         = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        OperatingSystemArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        ProcessId                   = $PID
        Identity                    = $runnerIdentity.Name
        Elevated                    = $runnerPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    Write-WinPrivTestJson -Path (Join-Path $runRoot '.winpriv-test-run.json') -Value ([ordered]@{
        SchemaVersion = 1
        MarkerId      = $runMarkerId
        RunId         = $runId
        Root          = $runRoot
        CreatedUtc    = [DateTime]::UtcNow.ToString('o')
        Owner         = [ordered]@{
            ProcessId    = $PID
            Path         = $ownerProcess.Path
            StartTimeUtc = $ownerProcess.StartTime.ToUniversalTime().ToString('o')
        }
    })
}
finally {
    $runnerIdentity.Dispose()
    $ownerProcess.Dispose()
}

$summaryPath = Join-Path $ResultsPath 'run-summary.json'
$nunitPath = Join-Path $ResultsPath 'WinPriv.Tests.xml'
$coveragePath = Join-Path $ResultsPath 'coverage.json'
$cleanupPath = Join-Path $ResultsPath 'cleanup-delta.json'
$capabilityEventsPath = Join-Path $ResultsPath 'capability-results.jsonl'
$cleanupEventsPath = Join-Path $ResultsPath 'cleanup-events.jsonl'
$processEventsPath = Join-Path $ResultsPath 'process-events.jsonl'
$expectedSkipEventsPath = Join-Path $ResultsPath 'expected-skip-events.jsonl'
$architectureGatePath = Join-Path $ResultsPath 'architecture-gates.json'
$staleReconciliationPath = Join-Path $ResultsPath 'stale-run-reconciliation.json'
$manifestPath = Join-Path $script:TestsRoot 'Capabilities.psd1'
$probePath = Join-Path $script:TestsRoot 'Probes\Invoke-WinPrivProbe.ps1'
$harnessManifest = Join-Path $script:TestsRoot 'Modules\WinPriv.TestHarness\WinPriv.TestHarness.psd1'

$startedUtc = [DateTime]::UtcNow
$exitCode = 1
$infrastructureError = $null
$pesterResult = $null
$coverageReport = $null
$selectedArchitectures = @()
$architectureDetails = @()
$effectiveBinaryRoot = $null
$nativeFixtureRoot = $null
$sourceWasBuilt = $false
$artifactsPath = $null
$staleReconciliation = $null
$currentRunReconciliation = $null
$binaryInventory = [Collections.Generic.List[object]]::new()
$processEvents = @()
$unexpectedProcessEvents = @()
$expectedSkipCount = 0
$savedEnvironment = @{}
$fixtureRootOverride = [Environment]::GetEnvironmentVariable('WINPRIV_TEST_NATIVE_FIXTURE_ROOT', 'Process')

try {
    Import-Module -Name $harnessManifest -Force -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Capability manifest is missing: '$manifestPath'."
    }
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
        throw "Probe script is missing: '$probePath'."
    }
    $staleReconciliation = Invoke-WinPrivStaleRunReconciliation -SuiteRoot $suiteRunRoot -CurrentRunRoot $runRoot -ReportPath $staleReconciliationPath
    if ($staleReconciliation.HasFailures) {
        throw "Stale WinPriv test state requires manual recovery. See '$staleReconciliationPath'."
    }
    if ($Architecture.Count -gt 1 -and $Architecture -contains 'Auto') {
        throw "Architecture 'Auto' cannot be combined with an explicit architecture."
    }
    if ($AllowGlobalPolicyMutation -and $Profile -eq 'Safe') {
        throw '-AllowGlobalPolicyMutation requires the Admin or Full profile.'
    }
    if ($Profile -in @('Admin', 'Full')) {
        if (-not $runnerHostInfo.Elevated) {
            throw "The $Profile profile requires an elevated administrator PowerShell process."
        }
        $productOptions = Get-ItemProperty -LiteralPath `
            'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions' `
            -Name ProductType -ErrorAction Stop
        if ([string]$productOptions.ProductType -eq 'LanmanNT') {
            throw "The $Profile profile requires a workstation or member server with a local SAM; domain controllers are not supported."
        }
    }

    [void](Import-WinPrivPinnedPester -OfflineMode:$Offline)

    if ([string]::IsNullOrWhiteSpace($BinaryRoot)) {
        $stageRoot = Join-Path $runRoot 'source'
        Copy-WinPrivSourceStage -Destination $stageRoot -LogPath (Join-Path $buildLogs 'source-stage.log')
        $effectiveBinaryRoot = Build-WinPrivStage -SourceRoot $stageRoot -LogRoot $buildLogs -Configuration $BuildConfiguration
        $sourceWasBuilt = $true
    }
    else {
        $effectiveBinaryRoot = [IO.Path]::GetFullPath($BinaryRoot)
        if (-not (Test-Path -LiteralPath $effectiveBinaryRoot -PathType Container)) {
            throw "BinaryRoot does not exist: '$effectiveBinaryRoot'."
        }
    }

    $nativeFixtureCandidate = if (-not [string]::IsNullOrWhiteSpace($fixtureRootOverride)) {
        [IO.Path]::GetFullPath($fixtureRootOverride)
    }
    elseif ($sourceWasBuilt) {
        Join-Path $stageRoot 'Tests\Native\Build' $BuildConfiguration
    }
    else {
        Join-Path $script:RepositoryRoot 'Tests\Native\Build' $BuildConfiguration
    }
    if (Test-Path -LiteralPath $nativeFixtureCandidate -PathType Container) {
        $nativeFixtureRoot = [IO.Path]::GetFullPath($nativeFixtureCandidate)
    }

    $architectureDetails = @(Get-WinPrivTestArchitectures -Requested $Architecture -BinaryRoot $effectiveBinaryRoot -Detailed)
    $selectedArchitectures = @($architectureDetails | Where-Object Compatible | ForEach-Object Architecture)
    Write-WinPrivTestJson -Path $architectureGatePath -Value ([ordered]@{
        SchemaVersion  = 1
        Requested      = @($Architecture)
        OsArchitecture = $architectureDetails[0].OsArchitecture
        Gates          = $architectureDetails
    })
    if ($Architecture -notcontains 'Auto') {
        $unavailable = @($architectureDetails | Where-Object { -not $_.Compatible })
        if ($unavailable.Count -gt 0) {
            throw "Requested architecture gates failed: $(($unavailable | ForEach-Object { "$($_.Architecture): $($_.Reason)" }) -join '; ')"
        }
    }
    if ($selectedArchitectures.Count -eq 0) {
        throw 'No requested architecture has a compatible PowerShell host and complete WinPriv binaries.'
    }

    foreach ($item in @('x86', 'x64', 'ARM64')) {
        $groups = @(@{ Directory = (Join-Path $effectiveBinaryRoot $item); Files = $script:ProductFiles })
        if (-not [string]::IsNullOrWhiteSpace($nativeFixtureRoot)) {
            $groups += @{ Directory = (Join-Path $nativeFixtureRoot $item); Files = $script:FixtureFiles }
        }
        foreach ($group in $groups) {
            foreach ($name in $group.Files) {
                $path = Join-Path $group.Directory $name
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    $file = Get-Item -LiteralPath $path
                    [void]$binaryInventory.Add([pscustomobject]@{
                        Architecture = $item
                        Name         = $name
                        Path         = $file.FullName
                        Length       = $file.Length
                        Sha256       = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                        FileVersion  = [Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName).FileVersion
                    })
                }
            }
        }
    }

    $environment = [ordered]@{
        WINPRIV_TEST_BINARY_ROOT                  = $effectiveBinaryRoot
        WINPRIV_TEST_RUN_ROOT                     = $runRoot
        WINPRIV_TEST_PROFILE                      = $Profile
        WINPRIV_TEST_ARCHITECTURES                = $selectedArchitectures -join ';'
        WINPRIV_TEST_ALLOW_GLOBAL_POLICY_MUTATION = if ($AllowGlobalPolicyMutation) { '1' } else { '0' }
        WINPRIV_TEST_KEEP_ARTIFACTS               = if ($KeepArtifacts) { '1' } else { '0' }
        WINPRIV_TEST_PROBE_PATH                   = $probePath
        WINPRIV_TEST_CAPABILITY_MANIFEST          = $manifestPath
        WINPRIV_TEST_CAPABILITY_RESULTS_PATH      = $capabilityEventsPath
        WINPRIV_TEST_COVERAGE_PATH                = $coveragePath
        WINPRIV_TEST_CLEANUP_EVENTS_PATH          = $cleanupEventsPath
        WINPRIV_TEST_PROCESS_EVENTS_PATH          = $processEventsPath
        WINPRIV_TEST_DEFER_SANDBOX_CLEANUP        = '1'
        WINPRIV_TEST_SOURCE_ROOT                  = if ($sourceWasBuilt) { $stageRoot } else { $script:RepositoryRoot }
        WINPRIV_TEST_NATIVE_FIXTURE_ROOT          = $nativeFixtureRoot
        WINPRIV_TEST_EXPECTED_SKIP_EVENTS_PATH    = $expectedSkipEventsPath
    }
    foreach ($item in $selectedArchitectures) {
        $environment['WINPRIV_TEST_HOST_' + $item.ToUpperInvariant()] = Get-WinPrivTestHost -Architecture $item
    }
    foreach ($entry in $environment.GetEnumerator()) {
        $savedEnvironment[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
    }
    Clear-WinPrivCapabilityResults

    $testFiles = @(Get-ChildItem -LiteralPath $script:TestsRoot -Filter '*.Tests.ps1' -File | Sort-Object FullName)
    if ($testFiles.Count -eq 0) {
        throw "No Pester test files were found beneath '$script:TestsRoot'."
    }
    # Load shared wrappers in the runner scope so helpers invoked inside It blocks resolve across Pester scopes.
    . (Join-Path $script:TestsRoot 'TestCommon.ps1')

    $configuration = New-PesterConfiguration
    $configuration.Run.Path = @($testFiles.FullName)
    $configuration.Run.PassThru = $true
    $configuration.Run.Exit = $false
    $configuration.Run.Throw = $false
    $configuration.Filter.Tag = switch ($Profile) {
        'Safe' { @('Safe') }
        'Admin' { @('Admin') }
        'Full' { @('Safe', 'Admin') }
    }
    $configuration.Output.Verbosity = 'Detailed'
    $configuration.TestResult.Enabled = $true
    $configuration.TestResult.OutputFormat = 'NUnitXml'
    $configuration.TestResult.OutputPath = $nunitPath
    $pesterResult = Invoke-Pester -Configuration $configuration

    $coverageReport = Complete-WinPrivCapabilityReport -ManifestPath $manifestPath -OutputPath $coveragePath -Architecture $selectedArchitectures -Profile $Profile
    $expectedSkipCount = @(Read-WinPrivJsonLines -Path $expectedSkipEventsPath).Count
    $unexpectedSkipCount = [Math]::Max(0, $pesterResult.SkippedCount - $expectedSkipCount)
    $pesterFailed = [string]$pesterResult.Result -ne 'Passed' -or
        $pesterResult.FailedCount -gt 0 -or
        $pesterResult.FailedBlocksCount -gt 0 -or
        $pesterResult.FailedContainersCount -gt 0 -or
        $unexpectedSkipCount -gt 0
    $exitCode = if ($pesterFailed -or [bool]$coverageReport.HasFailures) { 1 } else { 0 }
}
catch {
    $infrastructureError = $_ | Out-String
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    $exitCode = 2
}
finally {
    try { $currentRunReconciliation = Invoke-WinPrivCurrentRunReconciliation -RunRoot $runRoot }
    catch {
        $currentRunReconciliation = [pscustomobject][ordered]@{
            SchemaVersion = 1; RunRoot = $runRoot; Sandboxes = @(); UnexpectedDeltas = @()
            ManualRecovery = @([pscustomobject]@{
                Kind = 'CurrentRunReconciliation'; Identifier = $runRoot; Reason = $_.Exception.Message
            })
            HasFailures = $true; HasManualRecovery = $true
        }
    }
    if ($currentRunReconciliation.HasFailures -and $exitCode -eq 0) { $exitCode = 3 }

    $processEvents = @(Read-WinPrivJsonLines -Path $processEventsPath)
    $unexpectedProcessEvents = @($processEvents | Where-Object {
        [bool]$_.TimedOut -or -not [string]::IsNullOrWhiteSpace([string]$_.StartError) -or -not [bool]$_.JobAssigned
    })
    if ($unexpectedProcessEvents.Count -gt 0 -and $exitCode -eq 0) { $exitCode = 1 }

    $cleanupEvents = @(Read-WinPrivJsonLines -Path $cleanupEventsPath)
    $unexpectedCleanupEvents = @($cleanupEvents | Where-Object {
        $_.Status -in @('RecoveredUnexpectedDelta', 'RepairFailed', 'Residual')
    })
    $residualPaths = [Collections.Generic.List[string]]::new()
    $ephemeralRemovalError = $null
    $artifactPreservationError = $null
    $reparsePoints = @()
    if (Test-Path -LiteralPath $runRoot -PathType Container) {
        $reparsePoints = @(Get-ChildItem -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        })
        if ($reparsePoints.Count -gt 0) {
            $ephemeralRemovalError = "Refused artifact copying and recursive cleanup because the run contains reparse points: $(($reparsePoints.FullName) -join '; ')"
        }
    }
    if ([bool]$currentRunReconciliation.HasManualRecovery -and $null -eq $ephemeralRemovalError) {
        $ephemeralRemovalError = 'Current-run journal reconciliation requires manual recovery; the marked run root was retained.'
    }
    $shouldPreserve = $KeepArtifacts -or $exitCode -ne 0 -or $unexpectedCleanupEvents.Count -gt 0 -or
        [bool]$currentRunReconciliation.HasFailures -or $null -ne $ephemeralRemovalError
    if ($shouldPreserve -and $reparsePoints.Count -eq 0 -and (Test-Path -LiteralPath $runRoot -PathType Container)) {
        try { $artifactsPath = Copy-WinPrivFailureArtifacts -RunRoot $runRoot -ResultsRoot $ResultsPath }
        catch { $artifactPreservationError = $_.Exception.Message }
    }
    if ((Test-Path -LiteralPath $runRoot -PathType Container) -and $reparsePoints.Count -eq 0 -and
        $null -eq $ephemeralRemovalError -and $null -eq $artifactPreservationError) {
        try { Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction Stop }
        catch {
            $ephemeralRemovalError = $_.Exception.Message
            if ($null -eq $artifactsPath) {
                try { $artifactsPath = Copy-WinPrivFailureArtifacts -RunRoot $runRoot -ResultsRoot $ResultsPath }
                catch { $artifactPreservationError = $_.Exception.Message }
            }
        }
    }
    if (Test-Path -LiteralPath $runRoot) { [void]$residualPaths.Add($runRoot) }
    $cleanupFailed = $null -ne $ephemeralRemovalError -or $residualPaths.Count -gt 0 -or $unexpectedCleanupEvents.Count -gt 0
    if (($cleanupFailed -or $null -ne $artifactPreservationError) -and $exitCode -eq 0) { $exitCode = 3 }

    $cleanupReport = [ordered]@{
        SchemaVersion             = 1
        GeneratedUtc              = [DateTime]::UtcNow.ToString('o')
        Events                    = $cleanupEvents
        EphemeralRunRoot          = $runRoot
        EphemeralRootRemoved      = -not (Test-Path -LiteralPath $runRoot)
        RemovalError              = $ephemeralRemovalError
        ArtifactPreservationError = $artifactPreservationError
        ResidualPaths             = $residualPaths.ToArray()
        UnexpectedDeltas          = @($unexpectedCleanupEvents)
        CurrentRunReconciliation  = $currentRunReconciliation
        ArtifactsPreserved        = $null -ne $artifactsPath
        ArtifactsPath             = $artifactsPath
        HasUnexpectedDelta        = $unexpectedCleanupEvents.Count -gt 0
        HasResidualState          = $residualPaths.Count -gt 0 -or $null -ne $ephemeralRemovalError -or
            $null -ne $artifactPreservationError -or
            @($unexpectedCleanupEvents | Where-Object { $_.Status -in @('RepairFailed', 'Residual') }).Count -gt 0
    }
    try { Write-WinPrivTestJson -Path $cleanupPath -Value $cleanupReport }
    catch {
        if ($null -eq $infrastructureError) { $infrastructureError = $_ | Out-String }
        if ($exitCode -eq 0) { $exitCode = 2 }
    }

    $endedUtc = [DateTime]::UtcNow
    if ($null -eq $coverageReport) {
        $coverageReport = [pscustomobject][ordered]@{
            SchemaVersion         = 1
            GeneratedUtc          = $endedUtc.ToString('o')
            ManifestPath          = $manifestPath
            Profile               = $Profile
            Architectures         = @($selectedArchitectures)
            ResultCount           = 0
            Coverage              = @()
            Missing               = @()
            RequiredMissing       = @([pscustomobject]@{ Id = 'test-runner.infrastructure'; Architecture = 'All'; Required = $true; Test = 'Runner' })
            UnexpectedNonVerified = @([pscustomobject]@{ Id = 'test-runner.infrastructure'; Architecture = 'All'; Status = 'Failed'; Reason = $infrastructureError })
            UnmanifestedResults   = @()
            HasFailures           = $true
            InfrastructureError   = $infrastructureError
        }
        try { Write-WinPrivTestJson -Path $coveragePath -Value $coverageReport }
        catch {
            if ($null -eq $infrastructureError) { $infrastructureError = $_ | Out-String }
            if ($exitCode -eq 0) { $exitCode = 2 }
        }
    }
    $nunitValid = $false
    if (Test-Path -LiteralPath $nunitPath -PathType Leaf) {
        try {
            $nunitDocument = [Xml.XmlDocument]::new()
            $nunitDocument.Load($nunitPath)
            $nunitValid = $null -ne $nunitDocument.DocumentElement
        }
        catch { $nunitValid = $false }
    }
    if (-not $nunitValid) {
        if ([string]::IsNullOrWhiteSpace([string]$infrastructureError)) {
            $infrastructureError = "Pester did not produce a valid NUnit XML document at '$nunitPath'."
            if ($exitCode -eq 0) { $exitCode = 2 }
        }
        try { Write-WinPrivInfrastructureNUnit -Path $nunitPath -Message ([string]$infrastructureError) -StartedUtc $startedUtc -EndedUtc $endedUtc }
        catch {
            if ($null -eq $infrastructureError) { $infrastructureError = $_ | Out-String }
            if ($exitCode -eq 0) { $exitCode = 2 }
        }
    }
    $pesterSummary = if ($null -ne $pesterResult) {
        [ordered]@{
            Result                 = [string]$pesterResult.Result
            TotalCount             = $pesterResult.TotalCount
            PassedCount            = $pesterResult.PassedCount
            FailedCount            = $pesterResult.FailedCount
            FailedBlocksCount      = $pesterResult.FailedBlocksCount
            FailedContainersCount  = $pesterResult.FailedContainersCount
            SkippedCount           = $pesterResult.SkippedCount
            ExpectedSkippedCount   = $expectedSkipCount
            UnexpectedSkippedCount = [Math]::Max(0, $pesterResult.SkippedCount - $expectedSkipCount)
            NotRunCount            = $pesterResult.NotRunCount
            Duration               = [string]$pesterResult.Duration
            NUnitPath              = $nunitPath
        }
    } else { $null }
    $coverageSummary = if ($null -ne $coverageReport) {
        [ordered]@{
            ResultCount           = $coverageReport.ResultCount
            RequiredMissingCount  = @($coverageReport.RequiredMissing).Count
            UnexpectedStatusCount = @($coverageReport.UnexpectedNonVerified).Count
            UnmanifestedCount     = @($coverageReport.UnmanifestedResults).Count
            HasFailures           = [bool]$coverageReport.HasFailures
            Path                  = $coveragePath
        }
    } else { $null }
    $summary = [ordered]@{
        SchemaVersion             = 1
        RunId                     = $runId
        StartedUtc                = $startedUtc.ToString('o')
        EndedUtc                  = $endedUtc.ToString('o')
        DurationSeconds           = [Math]::Round(($endedUtc - $startedUtc).TotalSeconds, 3)
        Profile                   = $Profile
        Configuration             = $BuildConfiguration
        RequestedArchitectures    = @($Architecture)
        Architectures             = @($selectedArchitectures)
        BinaryRoot                = $effectiveBinaryRoot
        NativeFixtureRoot         = $nativeFixtureRoot
        BinaryInventory           = $binaryInventory.ToArray()
        ArchitectureGates         = @($architectureDetails)
        SourceWasBuilt            = $sourceWasBuilt
        Offline                   = [bool]$Offline
        KeepArtifacts             = [bool]$KeepArtifacts
        AllowGlobalPolicyMutation = [bool]$AllowGlobalPolicyMutation
        RunnerHost                = $runnerHostInfo
        ProcessContainment        = [ordered]@{
            EventCount   = @($processEvents).Count
            FailureCount = @($unexpectedProcessEvents).Count
            Failures     = @($unexpectedProcessEvents)
            EventsPath   = $processEventsPath
        }
        Pester                    = $pesterSummary
        Coverage                  = $coverageSummary
        Cleanup                   = $cleanupReport
        StaleRunReconciliation    = $staleReconciliation
        CurrentRunReconciliation  = $currentRunReconciliation
        InfrastructureError       = $infrastructureError
        ExitCode                  = $exitCode
    }
    try { Write-WinPrivTestJson -Path $summaryPath -Value $summary }
    catch {
        Write-Error "Unable to write run summary '$summaryPath': $($_.Exception.Message)" -ErrorAction Continue
        if ($exitCode -eq 0) { $exitCode = 2 }
    }

    foreach ($entry in $savedEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}

Write-Host "WinPriv test results: $ResultsPath"
Write-Host "WinPriv test exit code: $exitCode"
exit $exitCode
