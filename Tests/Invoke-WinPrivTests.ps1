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

function Write-WinPrivTestJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value,
        [int]$Depth = 40
    )
    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth $Depth), $script:Utf8NoBom)
}

function Write-WinPrivInfrastructureNUnit {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][DateTime]$StartedUtc,
        [Parameter(Mandatory = $true)][DateTime]$EndedUtc
    )
    $document = [Xml.XmlDocument]::new()
    $declaration = $document.CreateXmlDeclaration('1.0', 'utf-8', $null)
    [void]$document.AppendChild($declaration)
    $root = $document.CreateElement('test-results')
    foreach ($pair in ([ordered]@{ name = 'WinPriv infrastructure'; total = '1'; errors = '1'; failures = '0'; 'not-run' = '0'; date = $EndedUtc.ToString('yyyy-MM-dd'); time = $EndedUtc.ToString('HH:mm:ss') }).GetEnumerator()) {
        $root.SetAttribute($pair.Key, $pair.Value)
    }
    [void]$document.AppendChild($root)
    $suite = $document.CreateElement('test-suite')
    $suite.SetAttribute('name', 'WinPriv test runner')
    $suite.SetAttribute('executed', 'True')
    $suite.SetAttribute('result', 'Error')
    $suite.SetAttribute('success', 'False')
    $suite.SetAttribute('time', [Math]::Round(($EndedUtc - $StartedUtc).TotalSeconds, 3).ToString([Globalization.CultureInfo]::InvariantCulture))
    [void]$root.AppendChild($suite)
    $results = $document.CreateElement('results')
    [void]$suite.AppendChild($results)
    $testCase = $document.CreateElement('test-case')
    $testCase.SetAttribute('name', 'Test runner infrastructure')
    $testCase.SetAttribute('executed', 'True')
    $testCase.SetAttribute('result', 'Error')
    $testCase.SetAttribute('success', 'False')
    [void]$results.AppendChild($testCase)
    $failure = $document.CreateElement('failure')
    $messageElement = $document.CreateElement('message')
    $messageElement.InnerText = $Message
    [void]$failure.AppendChild($messageElement)
    [void]$testCase.AppendChild($failure)
    $settings = [Xml.XmlWriterSettings]::new()
    $settings.Encoding = $script:Utf8NoBom
    $settings.Indent = $true
    $writer = [Xml.XmlWriter]::Create($Path, $settings)
    try { $document.Save($writer) } finally { $writer.Dispose() }
}

function Get-WinPrivPackageTreeHash {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $records = foreach ($file in Get-ChildItem -LiteralPath $rootPath -File -Recurse) {
        if ($file.Name -eq '.winpriv-package-integrity.json') { continue }
        $relative = $file.FullName.Substring($rootPath.Length).TrimStart('\', '/') -replace '\\', '/'
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        '{0}|{1}|{2}' -f $relative, $file.Length, $hash
    }
    $payload = ($records | Sort-Object) -join "`n"
    $bytes = [Text.Encoding]::UTF8.GetBytes($payload)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
}

function Expand-WinPrivVerifiedPackage {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $destinationPath = [IO.Path]::GetFullPath($Destination)
    [void](New-Item -ItemType Directory -Path $destinationPath -Force)
    $prefix = $destinationPath.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $archive = [IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        foreach ($entry in $archive.Entries) {
            $entryPath = $entry.FullName -replace '/', [IO.Path]::DirectorySeparatorChar
            $target = [IO.Path]::GetFullPath((Join-Path $destinationPath $entryPath))
            if (-not $target.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Package entry '$($entry.FullName)' escapes its extraction root."
            }
            if ([string]::IsNullOrEmpty($entry.Name)) {
                [void](New-Item -ItemType Directory -Path $target -Force)
                continue
            }
            $targetDirectory = Split-Path -Parent $target
            if (-not (Test-Path -LiteralPath $targetDirectory -PathType Container)) {
                [void](New-Item -ItemType Directory -Path $targetDirectory -Force)
            }
            $inputStream = $entry.Open()
            $outputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try { $inputStream.CopyTo($outputStream) }
            finally {
                $outputStream.Dispose()
                $inputStream.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Test-WinPrivPesterExtraction {
    param(
        [Parameter(Mandatory = $true)][string]$ModuleDirectory,
        [Parameter(Mandatory = $true)]$Requirement,
        [Parameter(Mandatory = $true)][string]$PackageHash
    )
    $manifestPath = Join-Path $ModuleDirectory 'Pester.psd1'
    $assemblyPath = Join-Path $ModuleDirectory 'bin\netstandard2.0\Pester.dll'
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
    catch {
        return $false
    }
}

function Import-WinPrivPinnedPester {
    param([switch]$OfflineMode)

    $requirements = Import-PowerShellDataFile -LiteralPath (Join-Path $script:TestsRoot 'RequiredModules.psd1')
    $requirement = $requirements.Pester
    $toolsRoot = Join-Path $script:TestsRoot '.tools'
    $packagesRoot = Join-Path $toolsRoot 'packages'
    $modulesRoot = Join-Path $toolsRoot 'Modules'
    $packagePath = Join-Path $packagesRoot ("Pester.{0}.nupkg" -f $requirement.Version)
    $moduleDirectory = Join-Path (Join-Path $modulesRoot 'Pester') $requirement.Version
    $manifestPath = Join-Path $moduleDirectory 'Pester.psd1'
    foreach ($directory in @($toolsRoot, $packagesRoot, $modulesRoot, (Split-Path -Parent $moduleDirectory))) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            [void](New-Item -ItemType Directory -Path $directory -Force)
        }
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
        $packageValid = (Test-Path -LiteralPath $packagePath -PathType Leaf) -and
            ((Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash -eq $requirement.Sha256)
        if (-not $packageValid) {
            if ($OfflineMode) {
                throw "Offline mode requires the verified Pester $($requirement.Version) package at '$packagePath'."
            }
            $downloadPath = "$packagePath.$([Guid]::NewGuid().ToString('N')).download"
            try {
                Invoke-WebRequest -Uri $requirement.PackageUri -OutFile $downloadPath -MaximumRetryCount 2 -ConnectionTimeoutSeconds 30
                $actualHash = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash
                if ($actualHash -ne $requirement.Sha256) {
                    throw "Pester package checksum mismatch. Expected $($requirement.Sha256), received $actualHash."
                }
                if (Test-Path -LiteralPath $packagePath) { Remove-Item -LiteralPath $packagePath -Force }
                Move-Item -LiteralPath $downloadPath -Destination $packagePath
            }
            finally {
                if (Test-Path -LiteralPath $downloadPath) { Remove-Item -LiteralPath $downloadPath -Force }
            }
        }

        $packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
        if ($packageHash -ne $requirement.Sha256) {
            throw "Cached Pester package checksum mismatch at '$packagePath'."
        }
        if (-not (Test-WinPrivPesterExtraction -ModuleDirectory $moduleDirectory -Requirement $requirement -PackageHash $packageHash)) {
            if ($null -ne $loadedPinnedPester) {
                throw 'The pinned Pester module cache failed integrity validation after it was loaded. Start a fresh pwsh -NoProfile process so the cache can be repaired safely.'
            }
            $temporaryDirectory = "$moduleDirectory.$([Guid]::NewGuid().ToString('N')).extracting"
            try {
                Expand-WinPrivVerifiedPackage -PackagePath $packagePath -Destination $temporaryDirectory
                $temporaryManifest = Import-PowerShellDataFile -LiteralPath (Join-Path $temporaryDirectory 'Pester.psd1')
                if ([version]$temporaryManifest.ModuleVersion -ne [version]$requirement.Version -or
                    [guid]$temporaryManifest.GUID -ne [guid]$requirement.Guid -or
                    -not (Test-Path -LiteralPath (Join-Path $temporaryDirectory 'bin\netstandard2.0\Pester.dll') -PathType Leaf)) {
                    throw 'The verified Pester package did not contain the expected module payload.'
                }
                $treeHash = Get-WinPrivPackageTreeHash -Root $temporaryDirectory
                Write-WinPrivTestJson -Path (Join-Path $temporaryDirectory '.winpriv-package-integrity.json') -Value ([ordered]@{
                    SchemaVersion = 1
                    PackageSha256 = $packageHash
                    TreeSha256    = $treeHash
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
    [void](New-Item -ItemType Directory -Path $Destination -Force)
    $robocopy = Join-Path $env:WINDIR 'System32\robocopy.exe'
    $excludeDirectories = @(
        (Join-Path $script:RepositoryRoot '.git'),
        (Join-Path $script:RepositoryRoot '.vs'),
        (Join-Path $script:RepositoryRoot 'Build'),
        (Join-Path $script:TestsRoot '.tools'),
        (Join-Path $script:TestsRoot 'Native\Build'),
        (Join-Path $script:TestsRoot 'Results'),
        (Join-Path $script:TestsRoot 'results'),
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
    $code = $LASTEXITCODE
    if ($code -gt 7) {
        throw "robocopy failed while staging the source tree (exit code $code). See '$LogPath'."
    }
    # Build contains committed release artifacts as well as the packaging entry
    # point.  Keep stale artifacts out of the stage, but retain the script that
    # the isolated packaging contract test exercises after the fresh build.
    $destinationBuild = Join-Path $Destination 'Build'
    [void](New-Item -ItemType Directory -Path $destinationBuild -Force)
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
    foreach ($platform in @('x86', 'x64', 'ARM64')) {
        $logPath = Join-Path $LogRoot "build-$platform.log"
        Write-Host "Building WinPriv $Configuration|$platform with v145..."
        $arguments = @(
            $solution,
            '/nologo', '/m:1', '/t:Rebuild', '/v:minimal',
            "/p:Configuration=$Configuration",
            "/p:Platform=$platform",
            '/p:PlatformToolset=v145',
            '/p:SkipCodeSigning=true',
            '/p:BuildProjectReferences=true'
        )
        & $msbuild @arguments 2>&1 | Tee-Object -FilePath $logPath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "WinPriv $Configuration|$platform build failed with exit code $LASTEXITCODE. See '$logPath'."
        }
        $binaryRoot = if ($Configuration -eq 'Debug') {
            Join-Path (Join-Path $SourceRoot 'Build') 'Debug'
        } else {
            Join-Path $SourceRoot 'Build'
        }
        $output = Join-Path $binaryRoot $platform
        foreach ($name in @('WinPriv.exe', 'WinPrivCmd.exe', 'WinPrivLibrary.dll')) {
            if (-not (Test-Path -LiteralPath (Join-Path $output $name) -PathType Leaf)) {
                throw "$Configuration|$platform did not produce '$name' in '$output'."
            }
        }
        $fixtureOutput = Join-Path (Join-Path (Join-Path $SourceRoot 'Tests\Native\Build') $Configuration) $platform
        foreach ($name in @('WinPrivHookImport.exe', 'WinPrivHookDelayLoad.exe', 'WinPrivHookDynamic.exe')) {
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
    [void](New-Item -ItemType Directory -Path $destination -Force)
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
    $ResultsPath = Join-Path (Join-Path $script:TestsRoot 'TestResults') $runId
}
$ResultsPath = [IO.Path]::GetFullPath($ResultsPath)
if (Test-Path -LiteralPath $ResultsPath) {
    if (-not (Test-Path -LiteralPath $ResultsPath -PathType Container)) {
        throw "ResultsPath must not be an existing file: '$ResultsPath'."
    }
    $existingResult = Get-ChildItem -LiteralPath $ResultsPath -Force | Select-Object -First 1
    if ($null -ne $existingResult) {
        throw "ResultsPath must not be an existing nonempty directory: '$ResultsPath'. Choose a new path or an empty directory."
    }
}
else {
    [void](New-Item -ItemType Directory -Path $ResultsPath)
}
$suiteRunRoot = Join-Path ([IO.Path]::GetTempPath()) 'WinPrivTests'
$runRoot = Join-Path $suiteRunRoot $runId
$buildLogs = Join-Path $runRoot 'build-logs'
[void](New-Item -ItemType Directory -Path $buildLogs -Force)
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
$cleanupReport = $null
$selectedArchitectures = @()
$architectureDetails = @()
$effectiveBinaryRoot = $null
$nativeFixtureRoot = $null
$sourceWasBuilt = $false
$artifactsPath = $null
$staleReconciliation = $null
$currentRunReconciliation = $null
$binaryInventory = @()
$processEvents = @()
$unexpectedProcessEvents = @()
$savedEnvironment = @{}
$environmentNames = @(
    'WINPRIV_TEST_ROOT', 'WINPRIV_TEST_REPOSITORY_ROOT', 'WINPRIV_TEST_BINARY_ROOT',
    'WINPRIV_TEST_RESULTS_PATH', 'WINPRIV_TEST_RUN_ROOT', 'WINPRIV_TEST_PROFILE',
    'WINPRIV_TEST_ARCHITECTURES', 'WINPRIV_TEST_ALLOW_GLOBAL_POLICY_MUTATION',
    'WINPRIV_TEST_OFFLINE', 'WINPRIV_TEST_KEEP_ARTIFACTS', 'WINPRIV_TEST_PROBE_PATH',
    'WINPRIV_TEST_CAPABILITY_MANIFEST', 'WINPRIV_TEST_CAPABILITY_RESULTS_PATH',
    'WINPRIV_TEST_COVERAGE_PATH', 'WINPRIV_TEST_CLEANUP_PATH',
    'WINPRIV_TEST_CLEANUP_EVENTS_PATH', 'WINPRIV_TEST_SUMMARY_PATH',
    'WINPRIV_TEST_DEFER_SANDBOX_CLEANUP', 'WINPRIV_TEST_SOURCE_ROOT',
    'WINPRIV_TEST_NATIVE_FIXTURE_ROOT',
    'WINPRIV_TEST_EXPECTED_SKIP_EVENTS_PATH', 'WINPRIV_TEST_PROCESS_EVENTS_PATH'
)
foreach ($name in $environmentNames) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

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
        if (-not (Test-WinPrivElevated)) {
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
    Import-Module -Name $harnessManifest -Force -ErrorAction Stop

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

    $fixtureRootOverride = [string]$savedEnvironment['WINPRIV_TEST_NATIVE_FIXTURE_ROOT']
    $nativeFixtureCandidate = if (-not [string]::IsNullOrWhiteSpace($fixtureRootOverride)) {
        [IO.Path]::GetFullPath($fixtureRootOverride)
    }
    elseif ($sourceWasBuilt) {
        Join-Path (Join-Path $stageRoot 'Tests\Native\Build') $BuildConfiguration
    }
    else {
        Join-Path (Join-Path $script:RepositoryRoot 'Tests\Native\Build') $BuildConfiguration
    }
    if (Test-Path -LiteralPath $nativeFixtureCandidate -PathType Container) {
        $nativeFixtureRoot = [IO.Path]::GetFullPath($nativeFixtureCandidate)
    }

    $architectureDetails = @(Get-WinPrivTestArchitectures -Requested $Architecture -BinaryRoot $effectiveBinaryRoot -Detailed)
    $selectedArchitectures = @($architectureDetails | Where-Object Compatible | ForEach-Object Architecture)
    Write-WinPrivTestJson -Path $architectureGatePath -Value ([ordered]@{
        SchemaVersion = 1
        Requested     = @($Architecture)
        OsArchitecture = $architectureDetails[0].OsArchitecture
        Gates         = $architectureDetails
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
        $directory = Join-Path $effectiveBinaryRoot $item
        foreach ($name in @('WinPriv.exe', 'WinPrivCmd.exe', 'WinPrivLibrary.dll')) {
            $path = Join-Path $directory $name
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $file = Get-Item -LiteralPath $path
                $binaryInventory += [pscustomobject]@{
                    Architecture = $item
                    Name = $name
                    Path = $file.FullName
                    Length = $file.Length
                    Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                    FileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName).FileVersion
                }
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($nativeFixtureRoot)) {
            $fixtureDirectory = Join-Path $nativeFixtureRoot $item
            foreach ($name in @('WinPrivHookImport.exe', 'WinPrivHookDelayLoad.exe', 'WinPrivHookDynamic.exe')) {
                $path = Join-Path $fixtureDirectory $name
                if (Test-Path -LiteralPath $path -PathType Leaf) {
                    $file = Get-Item -LiteralPath $path
                    $binaryInventory += [pscustomobject]@{
                        Architecture = $item
                        Name = $name
                        Path = $file.FullName
                        Length = $file.Length
                        Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                        FileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName).FileVersion
                    }
                }
            }
        }
    }

    $environment = [ordered]@{
        WINPRIV_TEST_ROOT                         = $script:TestsRoot
        WINPRIV_TEST_REPOSITORY_ROOT              = $script:RepositoryRoot
        WINPRIV_TEST_BINARY_ROOT                  = $effectiveBinaryRoot
        WINPRIV_TEST_RESULTS_PATH                 = $ResultsPath
        WINPRIV_TEST_RUN_ROOT                     = $runRoot
        WINPRIV_TEST_PROFILE                      = $Profile
        WINPRIV_TEST_ARCHITECTURES                = $selectedArchitectures -join ';'
        WINPRIV_TEST_ALLOW_GLOBAL_POLICY_MUTATION = if ($AllowGlobalPolicyMutation) { '1' } else { '0' }
        WINPRIV_TEST_OFFLINE                      = if ($Offline) { '1' } else { '0' }
        WINPRIV_TEST_KEEP_ARTIFACTS               = if ($KeepArtifacts) { '1' } else { '0' }
        WINPRIV_TEST_PROBE_PATH                   = $probePath
        WINPRIV_TEST_CAPABILITY_MANIFEST          = $manifestPath
        WINPRIV_TEST_CAPABILITY_RESULTS_PATH      = $capabilityEventsPath
        WINPRIV_TEST_COVERAGE_PATH                = $coveragePath
        WINPRIV_TEST_CLEANUP_PATH                 = $cleanupPath
        WINPRIV_TEST_CLEANUP_EVENTS_PATH          = $cleanupEventsPath
        WINPRIV_TEST_PROCESS_EVENTS_PATH          = $processEventsPath
        WINPRIV_TEST_SUMMARY_PATH                 = $summaryPath
        WINPRIV_TEST_DEFER_SANDBOX_CLEANUP        = '1'
        WINPRIV_TEST_SOURCE_ROOT                  = if ($sourceWasBuilt) { Join-Path $runRoot 'source' } else { $script:RepositoryRoot }
        WINPRIV_TEST_NATIVE_FIXTURE_ROOT           = $nativeFixtureRoot
        WINPRIV_TEST_EXPECTED_SKIP_EVENTS_PATH    = $expectedSkipEventsPath
    }
    foreach ($entry in $environment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
    }
    foreach ($item in $selectedArchitectures) {
        $hostPath = Get-WinPrivTestHost -Architecture $item
        [Environment]::SetEnvironmentVariable(('WINPRIV_TEST_HOST_' + $item.ToUpperInvariant()), $hostPath, 'Process')
    }
    Clear-WinPrivCapabilityResults -Confirm:$false

    $testFiles = @(Get-ChildItem -LiteralPath $script:TestsRoot -Filter '*.Tests.ps1' -File -Recurse | Where-Object {
        $_.FullName -notlike "$(Join-Path $script:TestsRoot '.tools')*" -and
        $_.FullName -notlike "$(Join-Path $script:TestsRoot 'Results')*" -and
        $_.FullName -notlike "$(Join-Path $script:TestsRoot 'TestResults')*"
    } | Sort-Object FullName)
    if ($testFiles.Count -eq 0) {
        throw "No Pester test files were found beneath '$script:TestsRoot'."
    }
    # Pester performs discovery and execution in separate scopes.  Load the
    # shared wrappers in the runner scope as well so functions used inside It
    # blocks remain resolvable even though each spec also loads discovery-time
    # helpers for its -ForEach data.
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

    $processEvents = @(Read-WinPrivJsonLines -Path $processEventsPath)
    $unexpectedProcessEvents = @($processEvents | Where-Object {
        [bool]$_.TimedOut -or -not [string]::IsNullOrWhiteSpace([string]$_.StartError) -or -not [bool]$_.JobAssigned
    })
    $coverageReport = Complete-WinPrivCapabilityReport -ManifestPath $manifestPath -OutputPath $coveragePath -Architecture $selectedArchitectures -Profile $Profile
    $expectedSkipCount = @(Read-WinPrivJsonLines -Path $expectedSkipEventsPath).Count
    $unexpectedSkipCount = [Math]::Max(0, $pesterResult.SkippedCount - $expectedSkipCount)
    # Pester includes tests rejected by the profile tag filter in NotRunCount.
    # Those are expected (for example, Admin tests in the Safe lane).  Container
    # discovery failures can set Result to Failed without incrementing FailedCount.
    $pesterFailed = [string]$pesterResult.Result -ne 'Passed' -or
        $pesterResult.FailedCount -gt 0 -or
        $pesterResult.FailedBlocksCount -gt 0 -or
        $pesterResult.FailedContainersCount -gt 0 -or
        $unexpectedSkipCount -gt 0 -or
        $unexpectedProcessEvents.Count -gt 0
    $coverageFailed = [bool]$coverageReport.HasFailures
    $exitCode = if ($pesterFailed -or $coverageFailed) { 1 } else { 0 }
}
catch {
    $infrastructureError = $_ | Out-String
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    $exitCode = 2
}
finally {
    try {
        $currentRunReconciliation = Invoke-WinPrivCurrentRunReconciliation -RunRoot $runRoot
    }
    catch {
        $currentRunReconciliation = [pscustomobject][ordered]@{
            SchemaVersion      = 1
            RunRoot            = $runRoot
            Sandboxes          = @()
            UnexpectedDeltas   = @()
            ManualRecovery     = @([pscustomobject]@{
                Kind = 'CurrentRunReconciliation'; Identifier = $runRoot; Reason = $_.Exception.Message
            })
            HasFailures        = $true
            HasManualRecovery  = $true
        }
    }
    if ($currentRunReconciliation.HasFailures -and $exitCode -eq 0) {
        $exitCode = 3
    }
    $processEvents = @(Read-WinPrivJsonLines -Path $processEventsPath)
    $unexpectedProcessEvents = @($processEvents | Where-Object {
        [bool]$_.TimedOut -or -not [string]::IsNullOrWhiteSpace([string]$_.StartError) -or -not [bool]$_.JobAssigned
    })
    if ($unexpectedProcessEvents.Count -gt 0 -and $exitCode -eq 0) {
        $exitCode = 1
    }
    $cleanupEvents = @(Read-WinPrivJsonLines -Path $cleanupEventsPath)
    $unexpectedCleanupEvents = @($cleanupEvents | Where-Object {
        $_.Status -in @('RecoveredUnexpectedDelta', 'RepairFailed', 'Residual')
    })
    $residualPaths = New-Object 'System.Collections.Generic.List[string]'
    $ephemeralRemovalError = $null
    $artifactPreservationError = $null
    $artifactPreservationAttempted = $false
    $shouldPreserve = $KeepArtifacts -or $exitCode -ne 0 -or $unexpectedCleanupEvents.Count -gt 0 -or
        [bool]$currentRunReconciliation.HasFailures
    $reparsePoints = @()
    if (Test-Path -LiteralPath $runRoot -PathType Container) {
        $reparsePoints = @(Get-ChildItem -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        })
        if ($reparsePoints.Count -gt 0) {
            $ephemeralRemovalError = "Refused artifact copying and recursive cleanup because the run contains reparse points: $(($reparsePoints.FullName) -join '; ')"
        }
    }
    if ($shouldPreserve -and $reparsePoints.Count -eq 0 -and (Test-Path -LiteralPath $runRoot -PathType Container)) {
        $artifactPreservationAttempted = $true
        try { $artifactsPath = Copy-WinPrivFailureArtifacts -RunRoot $runRoot -ResultsRoot $ResultsPath }
        catch { $artifactPreservationError = $_.Exception.Message }
    }

    if ([bool]$currentRunReconciliation.HasManualRecovery -and $null -eq $ephemeralRemovalError) {
        $ephemeralRemovalError = 'Current-run journal reconciliation requires manual recovery; the marked run root was retained.'
    }

    if ((Test-Path -LiteralPath $runRoot -PathType Container) -and $reparsePoints.Count -eq 0) {
        if ($null -eq $ephemeralRemovalError -and $null -eq $artifactPreservationError) {
            try { Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction Stop }
            catch { $ephemeralRemovalError = $_.Exception.Message }
        }
    }
    if (Test-Path -LiteralPath $runRoot) { [void]$residualPaths.Add($runRoot) }
    $cleanupFailed = $null -ne $ephemeralRemovalError -or $residualPaths.Count -gt 0 -or $unexpectedCleanupEvents.Count -gt 0
    if ($cleanupFailed -and -not $artifactPreservationAttempted -and $reparsePoints.Count -eq 0 -and
        (Test-Path -LiteralPath $runRoot -PathType Container)) {
        $artifactPreservationAttempted = $true
        try { $artifactsPath = Copy-WinPrivFailureArtifacts -RunRoot $runRoot -ResultsRoot $ResultsPath }
        catch { $artifactPreservationError = $_.Exception.Message }
    }
    if ($cleanupFailed -or $null -ne $artifactPreservationError) {
        if ($exitCode -eq 0) { $exitCode = 3 }
    }

    $cleanupReport = [ordered]@{
        SchemaVersion             = 1
        GeneratedUtc              = [DateTime]::UtcNow.ToString('o')
        Events                    = $cleanupEvents
        EphemeralRunRoot          = $runRoot
        EphemeralRootRemoved      = -not (Test-Path -LiteralPath $runRoot)
        RemovalError              = $ephemeralRemovalError
        ArtifactPreservationError = $artifactPreservationError
        ResidualPaths             = @($residualPaths | ForEach-Object { $_ })
        UnexpectedDeltas          = @($unexpectedCleanupEvents)
        CurrentRunReconciliation  = $currentRunReconciliation
        ArtifactsPreserved        = $null -ne $artifactsPath
        ArtifactsPath             = $artifactsPath
        HasUnexpectedDelta        = $unexpectedCleanupEvents.Count -gt 0
        HasResidualState          = $residualPaths.Count -gt 0 -or $null -ne $ephemeralRemovalError -or $null -ne $artifactPreservationError -or
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
            Result       = [string]$pesterResult.Result
            TotalCount   = $pesterResult.TotalCount
            PassedCount  = $pesterResult.PassedCount
            FailedCount  = $pesterResult.FailedCount
            FailedBlocksCount = $pesterResult.FailedBlocksCount
            FailedContainersCount = $pesterResult.FailedContainersCount
            SkippedCount = $pesterResult.SkippedCount
            ExpectedSkippedCount = @(Read-WinPrivJsonLines -Path $expectedSkipEventsPath).Count
            UnexpectedSkippedCount = if ($null -ne $coverageReport) {
                [Math]::Max(0, $pesterResult.SkippedCount - @(Read-WinPrivJsonLines -Path $expectedSkipEventsPath).Count)
            } else { $pesterResult.SkippedCount }
            NotRunCount  = $pesterResult.NotRunCount
            Duration     = [string]$pesterResult.Duration
            NUnitPath    = $nunitPath
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
        BinaryInventory           = @($binaryInventory)
        ArchitectureGates         = @($architectureDetails)
        SourceWasBuilt            = $sourceWasBuilt
        Offline                   = [bool]$Offline
        KeepArtifacts             = [bool]$KeepArtifacts
        AllowGlobalPolicyMutation = [bool]$AllowGlobalPolicyMutation
        RunnerHost                = $runnerHostInfo
        ProcessContainment        = [ordered]@{
            EventCount      = @($processEvents).Count
            FailureCount    = @($unexpectedProcessEvents).Count
            Failures        = @($unexpectedProcessEvents)
            EventsPath      = $processEventsPath
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

    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}

Write-Host "WinPriv test results: $ResultsPath"
Write-Host "WinPriv test exit code: $exitCode"
exit $exitCode
