[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Position = 0)]
    [string] $Operation,

    [string] $OutputPath,

    [string] $ArgumentsJson,

    [string] $ArgumentsBase64,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $RemainingArguments
)

# Stays within the Windows PowerShell 5.1 language surface because WinPriv launches x86 probes under powershell.exe.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Utf8NoBom = New-Object Text.UTF8Encoding($false)

if ([string]::IsNullOrWhiteSpace($Operation)) {
    $Operation = [Environment]::GetEnvironmentVariable('WINPRIV_PROBE_OPERATION')
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = [Environment]::GetEnvironmentVariable('WINPRIV_PROBE_OUTPUT_PATH')
}
if ([string]::IsNullOrWhiteSpace($ArgumentsJson) -and -not [string]::IsNullOrWhiteSpace($ArgumentsBase64)) {
    $ArgumentsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgumentsBase64))
}
if ([string]::IsNullOrWhiteSpace($ArgumentsJson)) {
    $ArgumentsJson = [Environment]::GetEnvironmentVariable('WINPRIV_PROBE_ARGUMENTS_JSON')
}
if ([string]::IsNullOrWhiteSpace($ArgumentsJson)) { $ArgumentsJson = '{}' }
if ([string]::IsNullOrWhiteSpace($Operation)) { $Operation = 'state' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { throw 'OutputPath is required (or set WINPRIV_PROBE_OUTPUT_PATH).' }

function Write-AtomicBytes {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] [byte[]] $Bytes)

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith('\\?\', [StringComparison]::Ordinal)) {
        $fullPath = if ($fullPath.StartsWith('\\', [StringComparison]::Ordinal)) {
            '\\?\UNC\' + $fullPath.Substring(2)
        } else { '\\?\' + $fullPath }
    }
    $directory = [IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrEmpty($directory)) { [void][IO.Directory]::CreateDirectory($directory) }
    $temporaryPath = [IO.Path]::Combine($directory, ('.winpriv-probe.{0}.{1}.tmp' -f $PID, [Guid]::NewGuid().ToString('N')))
    $stream = $null
    try {
        $stream = New-Object IO.FileStream($temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        if ($null -ne ('WinPrivProbe.Native' -as [type])) {
            if (-not [WinPrivProbe.Native]::AtomicMove($temporaryPath, $fullPath)) {
                throw (New-Object ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
            }
        }
        else {
            if ([IO.File]::Exists($fullPath)) { [IO.File]::Delete($fullPath) }
            [IO.File]::Move($temporaryPath, $fullPath)
        }
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
}

function Get-ArgumentValue {
    param([Parameter(Mandatory = $true)] [string] $Name, $DefaultValue = $null)
    if ($null -eq $script:ProbeArguments) { return $DefaultValue }
    $property = $script:ProbeArguments.PSObject.Properties[$Name]
    if ($null -eq $property) { return $DefaultValue }
    return $property.Value
}

function ConvertTo-StringArray {
    param($Value)
    if ($null -eq $Value) { return [string[]]@() }
    return [string[]]@($Value | ForEach-Object { [Convert]::ToString($_, [Globalization.CultureInfo]::InvariantCulture) })
}

function Format-ProbeCommandLine {
    param([string] $HostPath, [string] $ChildOperation, [string] $ChildArgumentsJson, [string] $ChildOutputPath)
    $encodedArgs = [Convert]::ToBase64String($script:Utf8NoBom.GetBytes($ChildArgumentsJson))
    $tokens = @(
        $HostPath, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath, '-Operation', $ChildOperation, '-ArgumentsBase64', $encodedArgs,
        '-OutputPath', $ChildOutputPath
    )
    $quoted = foreach ($token in $tokens) {
        $value = [string]$token
        if ($value.Length -gt 0 -and $value -notmatch '[\s"]') { $value; continue }
        $builder = New-Object Text.StringBuilder
        [void]$builder.Append('"')
        $slashes = 0
        foreach ($ch in $value.ToCharArray()) {
            if ($ch -eq '\') { $slashes++; continue }
            if ($ch -eq '"') { [void]$builder.Append(('\' * ($slashes * 2 + 1)) + '"'); $slashes = 0; continue }
            if ($slashes -gt 0) { [void]$builder.Append('\' * $slashes); $slashes = 0 }
            [void]$builder.Append($ch)
        }
        if ($slashes -gt 0) { [void]$builder.Append('\' * ($slashes * 2)) }
        [void]$builder.Append('"')
        $builder.ToString()
    }
    return $quoted -join ' '
}

function ConvertTo-CustomEnvironmentEntries {
    param($CustomEnvironment, [string] $ChildOperation, [string] $ChildArgumentsJson, [string] $ChildOutputPath)
    $values = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('SystemRoot', 'WINDIR', 'ComSpec', 'TEMP', 'TMP', 'PATH')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($null -ne $value) { $values[$name] = $value }
    }
    if ($null -ne $CustomEnvironment) {
        foreach ($property in $CustomEnvironment.PSObject.Properties) {
            if ($null -eq $property.Value) { [void]$values.Remove($property.Name) }
            else { $values[$property.Name] = [Convert]::ToString($property.Value, [Globalization.CultureInfo]::InvariantCulture) }
        }
    }
    $values['WINPRIV_PROBE_OPERATION'] = $ChildOperation
    $values['WINPRIV_PROBE_ARGUMENTS_JSON'] = $ChildArgumentsJson
    $values['WINPRIV_PROBE_OUTPUT_PATH'] = $ChildOutputPath
    return [string[]]@($values.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value })
}

function Invoke-CreateProcessProbe {
    $api = [string](Get-ArgumentValue 'api' 'W')
    if ($api -notin @('A', 'W', 'a', 'w')) { throw 'create-process api must be A or W.' }
    $depth = [int](Get-ArgumentValue 'depth' 1)
    if ($depth -lt 1 -or $depth -gt 2) { throw 'create-process depth must be 1 or 2.' }
    $timeoutMilliseconds = [int](Get-ArgumentValue 'timeoutMilliseconds' 30000)
    if ($timeoutMilliseconds -lt 1 -or $timeoutMilliseconds -gt 300000) { throw 'create-process timeoutMilliseconds must be between 1 and 300000.' }
    $childOperation = [string](Get-ArgumentValue 'childOperation' 'state')
    $childArguments = Get-ArgumentValue 'childArguments' ([pscustomobject]@{})
    $childOutputPath = $OutputPath + '.child-' + $depth + '.json'
    $customEnvironmentSpecified = $null -ne $script:ProbeArguments.PSObject.Properties['customEnvironment']
    $customEnvironment = Get-ArgumentValue 'customEnvironment'

    if ($depth -gt 1) {
        $nested = [ordered]@{
            api = $api; depth = $depth - 1; timeoutMilliseconds = $timeoutMilliseconds
            childOperation = $childOperation; childArguments = $childArguments
        }
        if ($customEnvironmentSpecified) { $nested['customEnvironment'] = $customEnvironment }
        $actualChildOperation = 'create-process'
        $actualChildArguments = [pscustomobject]$nested
    } else {
        $actualChildOperation = $childOperation
        $actualChildArguments = $childArguments
    }
    $childArgumentsJson = $actualChildArguments | ConvertTo-Json -Depth 32 -Compress
    $powerShellPath = [string](Get-ArgumentValue 'powerShellPath' ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName))
    $commandLine = Format-ProbeCommandLine $powerShellPath $actualChildOperation $childArgumentsJson $childOutputPath
    $environmentEntries = if ($customEnvironmentSpecified) {
        ConvertTo-CustomEnvironmentEntries $customEnvironment $actualChildOperation $childArgumentsJson $childOutputPath
    } else { $null }

    $parentState = [WinPrivProbe.Native]::GetState([string[]]@(), [string[]]@())
    $parentState['mockTimeOffset'] = [Environment]::GetEnvironmentVariable('_WINPRIV_EV_MOCK_TIME_')
    $nativeResult = [WinPrivProbe.Native]::RunCreateProcess(
        $api, $powerShellPath, $commandLine, [Environment]::CurrentDirectory, $environmentEntries, $timeoutMilliseconds)
    $nativeResult['parentState'] = $parentState
    $nativeResult['childOutputPath'] = $childOutputPath
    $nativeResult['depth'] = $depth

    $childOutputFile = [WinPrivProbe.Native]::ExtendedPath($childOutputPath)
    if ([IO.File]::Exists($childOutputFile)) {
        try {
            $childResult = [IO.File]::ReadAllText($childOutputFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
            $nativeResult['childResult'] = $childResult
            $childSuccess = $childResult.PSObject.Properties['success']
            if ($null -eq $childSuccess -or -not [bool]$childSuccess.Value) {
                $reasonProp = $childResult.PSObject.Properties['reason']
                $childReason = if ($null -ne $reasonProp -and -not [string]::IsNullOrWhiteSpace([string]$reasonProp.Value)) {
                    [string]$reasonProp.Value
                } else { 'The child probe returned an unsuccessful result envelope.' }
                $nativeResult['childResultError'] = $childReason
                $nativeResult['reason'] = 'Child probe failed: ' + $childReason
                $nativeResult['success'] = $false
            }
        }
        catch {
            $nativeResult['childResultError'] = $_.Exception.Message
            $nativeResult['reason'] = 'The child result envelope could not be read: ' + $_.Exception.Message
            $nativeResult['success'] = $false
        }
    } else {
        $nativeResult['childResultError'] = 'The child result file was not created.'
        $nativeResult['reason'] = 'The child result file was not created.'
        $nativeResult['success'] = $false
    }
    return $nativeResult
}

function Invoke-RegistryWorker {
    param([hashtable] $WorkerArguments, [string] $WorkerOutputPath)
    $outputFile = [WinPrivProbe.Native]::ExtendedPath($WorkerOutputPath)
    $hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $commandLine = Format-ProbeCommandLine $hostPath 'registry-worker' ($WorkerArguments | ConvertTo-Json -Depth 16 -Compress) $WorkerOutputPath
    $attempts = New-Object Collections.ArrayList
    $process = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $process = [WinPrivProbe.Native]::RunCreateProcess('W', $hostPath, $commandLine, [Environment]::CurrentDirectory, $null, 10000)
        [void]$attempts.Add($process)
        if ([IO.File]::Exists($outputFile)) {
            try { return [IO.File]::ReadAllText($outputFile, [Text.Encoding]::UTF8) | ConvertFrom-Json }
            catch {
                return [pscustomobject][ordered]@{
                    supported = $true; success = $false; reason = 'Could not parse registry worker output: ' + $_.Exception.Message; process = $process
                }
            }
        }
    }
    return [pscustomobject][ordered]@{
        supported = $true; success = $false
        reason = if ($process.ContainsKey('reason')) { [string]$process['reason'] } else { 'Registry worker exited without a result file.' }
        process = $process; processAttempts = [object[]]$attempts.ToArray()
    }
}

$requestedExitCode = 0
$operationName = $Operation.ToLowerInvariant()
$envelope = [ordered]@{ operation = $operationName; pid = $PID; supported = $false; success = $false; reason = $null; result = $null; error = $null }

try {
    $script:ProbeArguments = $ArgumentsJson | ConvertFrom-Json
    if ($null -eq $script:ProbeArguments) { $script:ProbeArguments = [pscustomobject]@{} }

    if ($null -eq ('WinPrivProbe.Native' -as [type])) {
        $assemblyPath = Join-Path $PSScriptRoot 'WinPrivProbe.dll'
        if (Test-Path -LiteralPath $assemblyPath -PathType Leaf) {
            Add-Type -Path $assemblyPath -ErrorAction Stop
        } else {
            $sourceFiles = [string[]]@(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'WinPrivProbe.*.cs' | Sort-Object Name | ForEach-Object FullName)
            Add-Type -Path $sourceFiles -ErrorAction Stop
        }
    }

    switch ($operationName) {
        'state' {
            $result = [WinPrivProbe.Native]::GetState((ConvertTo-StringArray $RemainingArguments), (ConvertTo-StringArray (Get-ArgumentValue 'environmentNames')))
            $result['argumentsJson'] = $script:ProbeArguments
        }
        'args' {
            $state = [WinPrivProbe.Native]::GetState(
                (ConvertTo-StringArray $RemainingArguments),
                (ConvertTo-StringArray (Get-ArgumentValue 'environmentNames')))
            $result = [ordered]@{
                commandLine = $state['commandLine']
                argv = $state['argv']
                remainingArguments = $state['remainingArguments']
                argumentsJson = $script:ProbeArguments
                argumentsJsonRaw = $ArgumentsJson
            }
        }
        'exit' {
            $requestedExitCode = [int](Get-ArgumentValue 'exitCode' 0)
            if ($requestedExitCode -lt 0 -or $requestedExitCode -gt 255) { throw 'exitCode must be between 0 and 255.' }
            $result = [WinPrivProbe.Native]::GetState((ConvertTo-StringArray $RemainingArguments), (ConvertTo-StringArray (Get-ArgumentValue 'environmentNames')))
            $result['requestedExitCode'] = $requestedExitCode
        }
        'window'           { $result = [WinPrivProbe.Native]::GetWindowState() }
        'smart-cards'      { $result = [WinPrivProbe.Native]::GetSmartCardReaders() }
        'software-signing' { $result = [WinPrivProbe.Native]::GetSoftwareSigning() }
        'token'            { $result = [WinPrivProbe.Native]::GetTokenState() }
        'registry' {
            $key = [string](Get-ArgumentValue 'key')
            if ([string]::IsNullOrEmpty($key)) { throw 'registry operation requires ArgumentsJson.key.' }
            $root = [string](Get-ArgumentValue 'root' 'HKCU')
            $valueName = [string](Get-ArgumentValue 'valueName' '')
            $view = [string](Get-ArgumentValue 'view' 'default')
            $result = [ordered]@{ supported = $true; success = $true; root = $root; key = $key; valueName = $valueName; view = $view }
            foreach ($method in @('win32', 'ntPartial', 'ntPartialAlign64', 'ntFull', 'ntFullAlign64', 'ntEnumerate')) {
                $workerOutput = $OutputPath + '.registry.' + $method + '.' + [Guid]::NewGuid().ToString('N') + '.json'
                $worker = Invoke-RegistryWorker @{ root = $root; key = $key; valueName = $valueName; view = $view; method = $method } $workerOutput
                $result[$method] = if ($worker.PSObject.Properties['result'] -and $null -ne $worker.result) { $worker.result } else { $worker }
            }
        }
        'registry-worker' {
            $key = [string](Get-ArgumentValue 'key'); $method = [string](Get-ArgumentValue 'method')
            if ([string]::IsNullOrEmpty($key) -or [string]::IsNullOrEmpty($method)) { throw 'registry-worker requires key and method.' }
            $result = [WinPrivProbe.Native]::ReadRegistryMethod(
                [string](Get-ArgumentValue 'root' 'HKCU'), $key, [string](Get-ArgumentValue 'valueName' ''),
                [string](Get-ArgumentValue 'view' 'default'), $method)
        }
        'adapters' { $result = [WinPrivProbe.Native]::GetAdaptersState() }
        'wsa'      { $result = [WinPrivProbe.Native]::LookupWsa([string](Get-ArgumentValue 'name' 'localhost')) }
        'hosts' {
            $result = [WinPrivProbe.Native]::LookupHostResolvers(
                [string](Get-ArgumentValue 'name' 'localhost'), [int](Get-ArgumentValue 'family' 0), [uint16](Get-ArgumentValue 'type' 1))
        }
        'amsi' {
            $result = [WinPrivProbe.Native]::ScanAmsi(
                [string](Get-ArgumentValue 'content' 'WinPriv benign AMSI probe text'), [string](Get-ArgumentValue 'contentName' 'WinPrivProbe.txt'))
        }
        'admin' { $result = [WinPrivProbe.Native]::GetAdminState() }
        'version' {
            $result = [WinPrivProbe.Native]::GetVersionState()
            $environment = [ordered]@{}
            foreach ($name in (ConvertTo-StringArray (Get-ArgumentValue 'environmentNames'))) {
                $environment[$name] = [Environment]::GetEnvironmentVariable($name)
            }
            $result['environment'] = $environment
        }
        'clock' { $result = [WinPrivProbe.Native]::GetClockState() }
        'crypto' {
            $workingDirectory = Get-ArgumentValue 'workingDirectory'
            if ($null -ne $workingDirectory) { [Environment]::CurrentDirectory = [string]$workingDirectory }
            $base64 = Get-ArgumentValue 'plaintextBase64'
            $bytes = if ($null -eq $base64) { [Text.Encoding]::UTF8.GetBytes('WinPrivProbeData') } else { [Convert]::FromBase64String([string]$base64) }
            $result = [WinPrivProbe.Native]::RunCrypto($bytes, [string](Get-ArgumentValue 'collisionDirectory'))
        }
        'odbc' {
            $result = [WinPrivProbe.Native]::RunOdbc(
                [string](Get-ArgumentValue 'connectionString' 'Driver={WinPrivProbe-Missing-6F20D78B};ProbeMarker=WINPRIV_ODBC_LOCAL_ONLY;'))
        }
        'ado' {
            $initializer = [string](Get-ArgumentValue 'initializer' 'ex')
            if ($initializer -notin @('legacy', 'ex')) { throw 'ado initializer must be legacy or ex.' }
            $result = [WinPrivProbe.Native]::RunAdo(
                [string](Get-ArgumentValue 'connectionString' 'Provider=WinPrivProbe.Missing.Provider;Data Source=WINPRIV_ADO_LOCAL_ONLY;'),
                $initializer, [bool](Get-ArgumentValue 'storedString' $false))
        }
        'file' {
            $path = [string](Get-ArgumentValue 'path')
            if ([string]::IsNullOrEmpty($path)) { throw 'file operation requires ArgumentsJson.path.' }
            $dataBase64 = Get-ArgumentValue 'dataBase64'
            $data = if ($null -eq $dataBase64) { [byte[]]@() } else { [Convert]::FromBase64String([string]$dataBase64) }
            $result = [WinPrivProbe.Native]::RunFile([string](Get-ArgumentValue 'action' 'read'), $path, $data)
        }
        'file-paths' {
            $result = @(foreach ($entry in (Get-ArgumentValue 'requests' @())) {
                $r = @{}
                foreach ($property in $entry.PSObject.Properties) { $r[$property.Name] = $property.Value }
                [WinPrivProbe.Native]::RunFilePath([string]$r['action'], [string]$r['path'], [string]$r['target'],
                    [string]$r['root'], [bool]$r['duplicateRoot'], [string]$r['duplicateProcess'], [bool]$r['closeSource'])
            })
        }
        'native-file' {
            $result = [WinPrivProbe.Native]::RunNativeFile([string](Get-ArgumentValue 'api' 'NtCreateFile'), [string](Get-ArgumentValue 'path'))
        }
        'create-process' { $result = Invoke-CreateProcessProbe }
        'sleep' {
            $milliseconds = [int](Get-ArgumentValue 'milliseconds' 100)
            if ($milliseconds -lt 0 -or $milliseconds -gt 600000) { throw 'sleep milliseconds must be between 0 and 600000.' }
            if ($milliseconds -gt 0) { Start-Sleep -Milliseconds $milliseconds }
            $result = [ordered]@{ milliseconds = $milliseconds; completed = $true }
        }
        'marker' {
            $markerPath = [string](Get-ArgumentValue 'path')
            if ([string]::IsNullOrEmpty($markerPath)) { throw 'marker operation requires ArgumentsJson.path.' }
            $content = [string](Get-ArgumentValue 'content' ('WinPrivProbe-' + $PID))
            $bytes = $script:Utf8NoBom.GetBytes($content)
            Write-AtomicBytes -Path $markerPath -Bytes $bytes
            $result = [ordered]@{ path = [IO.Path]::GetFullPath($markerPath); content = $content; length = $bytes.Length }
        }
        default {
            $envelope.reason = 'Unsupported probe operation: ' + $Operation
            $result = $null
        }
    }

    $envelope.result = $result
    if ($null -ne $result) {
        $isDict = $result -is [Collections.IDictionary]
        $envelope.supported = if ($isDict -and ([Collections.IDictionary]$result).Contains('supported')) {
            [bool]$result['supported']
        } else { $true }
        $envelope.success = if ($isDict -and ([Collections.IDictionary]$result).Contains('success')) {
            [bool]$result['success']
        } else { $true }
        if ($isDict -and ([Collections.IDictionary]$result).Contains('reason')) {
            $envelope.reason = [string]$result['reason']
        }
    }
}
catch {
    $envelope.supported = $false
    $envelope.success = $false
    $envelope.reason = $_.Exception.Message
    $envelope.error = [ordered]@{
        type = $_.Exception.GetType().FullName; message = $_.Exception.Message
        hresult = $_.Exception.HResult; scriptStackTrace = $_.ScriptStackTrace
    }
}
finally {
    Write-AtomicBytes -Path $OutputPath -Bytes $script:Utf8NoBom.GetBytes(($envelope | ConvertTo-Json -Depth 64 -Compress))
}

if ($operationName -eq 'exit') { exit $requestedExitCode }
if (-not $envelope.success) { exit 1 }
exit 0
