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

# This file deliberately stays within the Windows PowerShell 5.1 language
# surface. WinPriv uses it as an architecture-matched native API target.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Operation)) {
    $Operation = [Environment]::GetEnvironmentVariable('WINPRIV_PROBE_OPERATION')
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = [Environment]::GetEnvironmentVariable('WINPRIV_PROBE_OUTPUT_PATH')
}
if ([string]::IsNullOrWhiteSpace($ArgumentsJson)) {
    $ArgumentsJson = [Environment]::GetEnvironmentVariable('WINPRIV_PROBE_ARGUMENTS_JSON')
}
if ([string]::IsNullOrWhiteSpace($ArgumentsJson) -and -not [string]::IsNullOrWhiteSpace($ArgumentsBase64)) {
    $ArgumentsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgumentsBase64))
}
if ([string]::IsNullOrWhiteSpace($ArgumentsJson)) {
    $ArgumentsJson = '{}'
}
if ([string]::IsNullOrWhiteSpace($Operation)) {
    $Operation = 'state'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    throw 'OutputPath is required (or set WINPRIV_PROBE_OUTPUT_PATH).'
}

function Write-AtomicBytes {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [byte[]] $Bytes
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $directory = [IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrEmpty($directory) -and -not [IO.Directory]::Exists($directory)) {
        [void][IO.Directory]::CreateDirectory($directory)
    }
    # Keep the temporary leaf independent of the destination leaf. Nested
    # propagation probes already have long, descriptive result names; repeating
    # that name here can push the raw MoveFileExW call beyond legacy MAX_PATH.
    $temporaryPath = [IO.Path]::Combine(
        $directory,
        ('.winpriv-probe.{0}.{1}.tmp' -f $PID, [Guid]::NewGuid().ToString('N')))
    $stream = $null
    try {
        $stream = New-Object IO.FileStream(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null

        $nativeType = 'WinPrivProbe.Native' -as [type]
        if ($null -ne $nativeType) {
            if (-not [WinPrivProbe.Native]::AtomicMove($temporaryPath, $fullPath)) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw (New-Object ComponentModel.Win32Exception($errorCode))
            }
        }
        else {
            # Compilation failures still receive a result file. Output paths are
            # unique in the harness, so File.Move remains atomic for readers.
            if ([IO.File]::Exists($fullPath)) {
                [IO.File]::Delete($fullPath)
            }
            [IO.File]::Move($temporaryPath, $fullPath)
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if ([IO.File]::Exists($temporaryPath)) {
            [IO.File]::Delete($temporaryPath)
        }
    }
}

function Write-AtomicJson {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )
    $json = $Value | ConvertTo-Json -Depth 64 -Compress
    $encoding = New-Object Text.UTF8Encoding($false)
    Write-AtomicBytes -Path $Path -Bytes $encoding.GetBytes($json)
}

function Get-ArgumentValue {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        $DefaultValue = $null
    )
    if ($null -eq $script:ProbeArguments) {
        return $DefaultValue
    }
    $property = $script:ProbeArguments.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $DefaultValue
    }
    return $property.Value
}

function Test-ArgumentValue {
    param([Parameter(Mandatory = $true)] [string] $Name)
    if ($null -eq $script:ProbeArguments) {
        return $false
    }
    return $null -ne $script:ProbeArguments.PSObject.Properties[$Name]
}

function Test-DictionaryKey {
    param(
        [Parameter(Mandatory = $true)] $Dictionary,
        [Parameter(Mandatory = $true)] [string] $Key
    )
    if ($null -eq $Dictionary -or -not ($Dictionary -is [Collections.IDictionary])) {
        return $false
    }
    if ($null -ne $Dictionary.PSObject.Methods['ContainsKey']) {
        return [bool]$Dictionary.ContainsKey($Key)
    }
    return [bool]$Dictionary.Contains($Key)
}

function ConvertTo-StringArray {
    param($Value)
    if ($null -eq $Value) {
        return [string[]]@()
    }
    return [string[]]@($Value | ForEach-Object { [Convert]::ToString($_, [Globalization.CultureInfo]::InvariantCulture) })
}

function ConvertTo-NativeCommandLineArgument {
    param([AllowEmptyString()] [string] $Value)

    if ($null -eq $Value) {
        return '""'
    }
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-EnvironmentEntries {
    param(
        $CustomEnvironment,
        [bool] $MergeEnvironment,
        [string] $ChildOperation,
        [string] $ChildArgumentsJson,
        [string] $ChildOutputPath
    )

    $values = New-Object 'Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($MergeEnvironment) {
        foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
            $values[[string]$entry.Key] = [string]$entry.Value
        }
    }
    else {
        foreach ($name in @('SystemRoot', 'WINDIR', 'ComSpec', 'TEMP', 'TMP', 'PATH')) {
            $value = [Environment]::GetEnvironmentVariable($name)
            if ($null -ne $value) {
                $values[$name] = $value
            }
        }
    }
    if ($null -ne $CustomEnvironment) {
        foreach ($property in $CustomEnvironment.PSObject.Properties) {
            if ($null -eq $property.Value) {
                [void]$values.Remove($property.Name)
            }
            else {
                $values[$property.Name] = [Convert]::ToString($property.Value, [Globalization.CultureInfo]::InvariantCulture)
            }
        }
    }
    $values['WINPRIV_PROBE_OPERATION'] = $ChildOperation
    $values['WINPRIV_PROBE_ARGUMENTS_JSON'] = $ChildArgumentsJson
    $values['WINPRIV_PROBE_OUTPUT_PATH'] = $ChildOutputPath
    return [string[]]@($values.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, $_.Value })
}

function Invoke-CreateProcessProbe {
    $api = [string](Get-ArgumentValue -Name 'api' -DefaultValue 'W')
    if ($api -notin @('A', 'W', 'a', 'w')) {
        throw 'create-process api must be A or W.'
    }
    $depth = [int](Get-ArgumentValue -Name 'depth' -DefaultValue 1)
    if ($depth -lt 1 -or $depth -gt 2) {
        throw 'create-process depth must be 1 or 2.'
    }
    $timeoutMilliseconds = [int](Get-ArgumentValue -Name 'timeoutMilliseconds' -DefaultValue 30000)
    if ($timeoutMilliseconds -lt 1 -or $timeoutMilliseconds -gt 300000) {
        throw 'create-process timeoutMilliseconds must be between 1 and 300000.'
    }
    $childOperation = [string](Get-ArgumentValue -Name 'childOperation' -DefaultValue 'state')
    $childArguments = Get-ArgumentValue -Name 'childArguments' -DefaultValue ([pscustomobject]@{})
    $childOutputPath = [string](Get-ArgumentValue -Name 'childOutputPath' -DefaultValue ($OutputPath + '.child-' + $depth + '.json'))
    $customEnvironmentSpecified = Test-ArgumentValue -Name 'customEnvironment'
    $customEnvironment = Get-ArgumentValue -Name 'customEnvironment'
    $mergeEnvironment = [bool](Get-ArgumentValue -Name 'mergeEnvironment' -DefaultValue $true)

    if ($depth -gt 1) {
        $nested = [ordered]@{
            api = $api
            depth = $depth - 1
            timeoutMilliseconds = $timeoutMilliseconds
            childOperation = $childOperation
            childArguments = $childArguments
        }
        if ($customEnvironmentSpecified) {
            $nested['customEnvironment'] = $customEnvironment
            $nested['mergeEnvironment'] = $mergeEnvironment
        }
        $actualChildOperation = 'create-process'
        $actualChildArguments = [pscustomobject]$nested
    }
    else {
        $actualChildOperation = $childOperation
        $actualChildArguments = $childArguments
    }
    $childArgumentsJson = $actualChildArguments | ConvertTo-Json -Depth 32 -Compress

    $powerShellPath = [string](Get-ArgumentValue -Name 'powerShellPath' -DefaultValue ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName))
    $scriptPath = [string](Get-ArgumentValue -Name 'scriptPath' -DefaultValue $PSCommandPath)
    $commandArguments = @(
        $powerShellPath,
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $scriptPath,
        '-Operation',
        $actualChildOperation,
        '-ArgumentsJson',
        $childArgumentsJson,
        '-OutputPath',
        $childOutputPath
    )
    $commandLine = ($commandArguments | ForEach-Object { ConvertTo-NativeCommandLineArgument -Value ([string]$_) }) -join ' '
    $environmentEntries = $null
    if ($customEnvironmentSpecified) {
        $environmentEntries = ConvertTo-EnvironmentEntries `
            -CustomEnvironment $customEnvironment `
            -MergeEnvironment $mergeEnvironment `
            -ChildOperation $actualChildOperation `
            -ChildArgumentsJson $childArgumentsJson `
            -ChildOutputPath $childOutputPath
    }
    $parentState = [WinPrivProbe.Native]::GetState([string[]]@(), [string[]]@())
    $nativeResult = [WinPrivProbe.Native]::RunCreateProcess(
        $api,
        $powerShellPath,
        $commandLine,
        [Environment]::CurrentDirectory,
        $environmentEntries,
        $timeoutMilliseconds)
    $nativeResult['parentState'] = $parentState
    $nativeResult['childOutputPath'] = $childOutputPath
    $nativeResult['depth'] = $depth
    if ([IO.File]::Exists($childOutputPath)) {
        try {
            $childResult = [IO.File]::ReadAllText($childOutputPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
            $nativeResult['childResult'] = $childResult
            $childSuccessProperty = $childResult.PSObject.Properties['success']
            if ($null -eq $childSuccessProperty -or -not [bool]$childSuccessProperty.Value) {
                $childReasonProperty = $childResult.PSObject.Properties['reason']
                $childReason = if ($null -ne $childReasonProperty -and
                    -not [string]::IsNullOrWhiteSpace([string]$childReasonProperty.Value)) {
                    [string]$childReasonProperty.Value
                }
                else {
                    'The child probe returned an unsuccessful result envelope.'
                }
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
    }
    else {
        $nativeResult['childResultError'] = 'The child result file was not created.'
        $nativeResult['reason'] = 'The child result file was not created.'
        $nativeResult['success'] = $false
    }
    return $nativeResult
}

function Invoke-InternalProbeChild {
    param(
        [Parameter(Mandatory = $true)] [string] $ChildOperation,
        [Parameter(Mandatory = $true)] $ChildArguments,
        [Parameter(Mandatory = $true)] [string] $ChildOutputPath,
        [int] $TimeoutMilliseconds = 10000
    )

    $childJson = $ChildArguments | ConvertTo-Json -Depth 32 -Compress
    $hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $commandArguments = @(
        $hostPath, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath, '-Operation', $ChildOperation,
        '-ArgumentsJson', $childJson, '-OutputPath', $ChildOutputPath)
    $commandLine = ($commandArguments | ForEach-Object {
        ConvertTo-NativeCommandLineArgument -Value ([string]$_)
    }) -join ' '
    $processAttempts = New-Object Collections.ArrayList
    $process = $null
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        $process = [WinPrivProbe.Native]::RunCreateProcess(
            'W', $hostPath, $commandLine, [Environment]::CurrentDirectory, $null, $TimeoutMilliseconds)
        [void]$processAttempts.Add($process)
        if ([IO.File]::Exists($ChildOutputPath)) {
            try {
                return [IO.File]::ReadAllText($ChildOutputPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
            }
            catch {
                return [pscustomobject][ordered]@{
                    supported = $true
                    success = $false
                    reason = 'Could not parse registry worker output: ' + $_.Exception.Message
                    process = $process
                }
            }
        }
    }
    return [pscustomobject][ordered]@{
        supported = $true
        success = $false
        reason = if ($process.ContainsKey('reason')) { [string]$process['reason'] } else { 'Registry worker exited without a result file.' }
        process = $process
        processAttempts = [object[]]$processAttempts.ToArray()
    }
}

$startedUtc = [DateTime]::UtcNow
$requestedExitCode = 0
$operationName = $Operation.ToLowerInvariant()
$envelope = [ordered]@{
    schemaVersion = '1.0'
    operation = $Operation.ToLowerInvariant()
    pid = $PID
    startedUtc = $startedUtc.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    finishedUtc = $null
    supported = $false
    success = $false
    reason = $null
    result = $null
    error = $null
}

try {
    try {
        $script:ProbeArguments = $ArgumentsJson | ConvertFrom-Json
    }
    catch {
        # WinPriv's current target-command reconstruction does not preserve
        # embedded JSON quotes. The harness mirrors the exact JSON in the
        # environment so injected launches remain testable while the quoting
        # defect is reported independently by the CLI contract tests.
        $fallbackArgumentsJson = [Environment]::GetEnvironmentVariable('WINPRIV_PROBE_ARGUMENTS_JSON')
        if ([string]::IsNullOrWhiteSpace($fallbackArgumentsJson) -or
            [string]::Equals($fallbackArgumentsJson, $ArgumentsJson, [StringComparison]::Ordinal)) {
            throw
        }
        $script:ProbeArguments = $fallbackArgumentsJson | ConvertFrom-Json
        $ArgumentsJson = $fallbackArgumentsJson
    }
    if ($null -eq $script:ProbeArguments) {
        $script:ProbeArguments = [pscustomobject]@{}
    }

    $sourceFiles = [string[]]@(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'WinPrivProbe.*.cs' |
        Sort-Object -Property Name |
        ForEach-Object { $_.FullName })
    if ($null -eq ('WinPrivProbe.Native' -as [type])) {
        Add-Type -Path $sourceFiles -ErrorAction Stop
    }

    $state = $null
    switch ($operationName) {
        'capabilities' {
            $result = [ordered]@{
                operations = [string[]]@(
                    'capabilities', 'state', 'args', 'cwd', 'env', 'exit', 'window', 'token',
                    'registry', 'adapters', 'wsa', 'amsi', 'admin', 'version', 'crypto',
                    'odbc', 'ado', 'file', 'native-file', 'lsa', 'create-process', 'sleep', 'marker')
                nativeSourceFiles = [string[]]@(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'WinPrivProbe.*.cs' |
                    Sort-Object -Property Name | ForEach-Object { $_.Name })
                powershellVersion = $PSVersionTable.PSVersion.ToString()
                powershellEdition = if ($PSVersionTable.PSObject.Properties['PSEdition']) { $PSVersionTable.PSEdition } else { 'Desktop' }
            }
        }
        'state' {
            $state = [WinPrivProbe.Native]::GetState(
                (ConvertTo-StringArray -Value $RemainingArguments),
                (ConvertTo-StringArray -Value (Get-ArgumentValue -Name 'environmentNames')))
            $state['argumentsJson'] = $script:ProbeArguments
            $state['argumentsJsonRaw'] = $ArgumentsJson
            $result = $state
        }
        'args' {
            $state = [WinPrivProbe.Native]::GetState(
                (ConvertTo-StringArray -Value $RemainingArguments),
                (ConvertTo-StringArray -Value (Get-ArgumentValue -Name 'environmentNames')))
            $result = [ordered]@{
                commandLine = $state['commandLine']
                argv = $state['argv']
                remainingArguments = $state['remainingArguments']
                argumentsJson = $script:ProbeArguments
                argumentsJsonRaw = $ArgumentsJson
            }
        }
        'cwd' {
            $result = [ordered]@{ cwd = [Environment]::CurrentDirectory }
        }
        'env' {
            $state = [WinPrivProbe.Native]::GetState(
                (ConvertTo-StringArray -Value $RemainingArguments),
                (ConvertTo-StringArray -Value (Get-ArgumentValue -Name 'environmentNames')))
            $result = [ordered]@{ env = $state['env']; environment = $state['environment'] }
        }
        'exit' {
            $requestedExitCode = [int](Get-ArgumentValue -Name 'exitCode' -DefaultValue 0)
            if ($requestedExitCode -lt 0 -or $requestedExitCode -gt 255) {
                throw 'exitCode must be between 0 and 255.'
            }
            $state = [WinPrivProbe.Native]::GetState(
                (ConvertTo-StringArray -Value $RemainingArguments),
                (ConvertTo-StringArray -Value (Get-ArgumentValue -Name 'environmentNames')))
            $state['argumentsJson'] = $script:ProbeArguments
            $state['requestedExitCode'] = $requestedExitCode
            $result = $state
        }
        'window' {
            $result = [WinPrivProbe.Native]::GetWindowState()
        }
        'token' {
            $result = [WinPrivProbe.Native]::GetTokenState()
        }
        'registry' {
            $key = [string](Get-ArgumentValue -Name 'key')
            if ([string]::IsNullOrEmpty($key)) {
                throw 'registry operation requires ArgumentsJson.key.'
            }
            $root = [string](Get-ArgumentValue -Name 'root' -DefaultValue 'HKCU')
            $valueName = [string](Get-ArgumentValue -Name 'valueName' -DefaultValue '')
            $view = [string](Get-ArgumentValue -Name 'view' -DefaultValue 'default')
            $result = [ordered]@{
                supported = $true
                success = $true
                root = $root
                key = $key
                valueName = $valueName
                view = $view
            }
            foreach ($method in @('win32', 'ntPartial', 'ntPartialAlign64', 'ntFull', 'ntFullAlign64', 'ntEnumerate')) {
                $workerOutput = $OutputPath + '.registry.' + $method + '.' + [Guid]::NewGuid().ToString('N') + '.json'
                $workerArguments = [ordered]@{
                    root = $root
                    key = $key
                    valueName = $valueName
                    view = $view
                    method = $method
                }
                $worker = Invoke-InternalProbeChild -ChildOperation 'registry-worker' `
                    -ChildArguments $workerArguments -ChildOutputPath $workerOutput -TimeoutMilliseconds 10000
                if ($worker.PSObject.Properties['result'] -and $null -ne $worker.result) {
                    $result[$method] = $worker.result
                }
                else {
                    $result[$method] = $worker
                }
            }
        }
        'registry-worker' {
            $key = [string](Get-ArgumentValue -Name 'key')
            $method = [string](Get-ArgumentValue -Name 'method')
            if ([string]::IsNullOrEmpty($key) -or [string]::IsNullOrEmpty($method)) {
                throw 'registry-worker requires key and method.'
            }
            $result = [WinPrivProbe.Native]::ReadRegistryMethod(
                [string](Get-ArgumentValue -Name 'root' -DefaultValue 'HKCU'),
                $key,
                [string](Get-ArgumentValue -Name 'valueName' -DefaultValue ''),
                [string](Get-ArgumentValue -Name 'view' -DefaultValue 'default'),
                $method)
        }
        'adapters' {
            $result = [WinPrivProbe.Native]::GetAdaptersState()
        }
        'wsa' {
            $result = [WinPrivProbe.Native]::LookupWsa(
                [string](Get-ArgumentValue -Name 'name' -DefaultValue 'localhost'))
        }
        'amsi' {
            $result = [WinPrivProbe.Native]::ScanAmsi(
                [string](Get-ArgumentValue -Name 'content' -DefaultValue 'WinPriv benign AMSI probe text'),
                [string](Get-ArgumentValue -Name 'contentName' -DefaultValue 'WinPrivProbe.txt'))
        }
        'admin' {
            $result = [WinPrivProbe.Native]::GetAdminState()
        }
        'version' {
            $result = [WinPrivProbe.Native]::GetVersionState()
            $environment = [ordered]@{}
            foreach ($name in (ConvertTo-StringArray -Value (Get-ArgumentValue -Name 'environmentNames'))) {
                $environment[$name] = [Environment]::GetEnvironmentVariable($name)
            }
            $result['environment'] = $environment
        }
        'crypto' {
            $base64 = Get-ArgumentValue -Name 'plaintextBase64'
            if ($null -eq $base64) {
                $bytes = [Text.Encoding]::UTF8.GetBytes('WinPrivProbeData')
            }
            else {
                $bytes = [Convert]::FromBase64String([string]$base64)
            }
            $result = [WinPrivProbe.Native]::RunCrypto($bytes)
        }
        'odbc' {
            $result = [WinPrivProbe.Native]::RunOdbc(
                [string](Get-ArgumentValue -Name 'connectionString' -DefaultValue 'Driver={WinPrivProbe-Missing-6F20D78B};ProbeMarker=WINPRIV_ODBC_LOCAL_ONLY;'))
        }
        'ado' {
            $initializer = [string](Get-ArgumentValue -Name 'initializer' -DefaultValue 'ex')
            if ($initializer -notin @('legacy', 'ex')) {
                throw 'ado initializer must be legacy or ex.'
            }
            $result = [WinPrivProbe.Native]::RunAdo(
                [string](Get-ArgumentValue -Name 'connectionString' -DefaultValue 'Provider=WinPrivProbe.Missing.Provider;Data Source=WINPRIV_ADO_LOCAL_ONLY;'),
                $initializer)
        }
        'file' {
            $path = [string](Get-ArgumentValue -Name 'path')
            if ([string]::IsNullOrEmpty($path)) {
                throw 'file operation requires ArgumentsJson.path.'
            }
            $dataBase64 = Get-ArgumentValue -Name 'dataBase64'
            $data = if ($null -eq $dataBase64) { [byte[]]@() } else { [Convert]::FromBase64String([string]$dataBase64) }
            $result = [WinPrivProbe.Native]::RunFile(
                [string](Get-ArgumentValue -Name 'action' -DefaultValue 'read'),
                $path,
                $data)
        }
        'native-file' {
            $result = [WinPrivProbe.Native]::RunNativeFile(
                [string](Get-ArgumentValue -Name 'api' -DefaultValue 'NtCreateFile'),
                [string](Get-ArgumentValue -Name 'path'))
        }
        'lsa' {
            $result = [WinPrivProbe.Native]::ReadLsa(
                [string](Get-ArgumentValue -Name 'account' -DefaultValue ''),
                [string](Get-ArgumentValue -Name 'sid' -DefaultValue ''),
                [string](Get-ArgumentValue -Name 'right' -DefaultValue 'SeServiceLogonRight'))
        }
        'create-process' {
            $result = Invoke-CreateProcessProbe
        }
        'sleep' {
            $milliseconds = [int](Get-ArgumentValue -Name 'milliseconds' -DefaultValue 100)
            if ($milliseconds -lt 0 -or $milliseconds -gt 600000) {
                throw 'sleep milliseconds must be between 0 and 600000.'
            }
            if ($milliseconds -gt 0) {
                Start-Sleep -Milliseconds $milliseconds
            }
            $result = [ordered]@{ milliseconds = $milliseconds; completed = $true }
        }
        'marker' {
            $markerPath = [string](Get-ArgumentValue -Name 'path')
            if ([string]::IsNullOrEmpty($markerPath)) {
                throw 'marker operation requires ArgumentsJson.path.'
            }
            $delay = [int](Get-ArgumentValue -Name 'delayMilliseconds' -DefaultValue 0)
            if ($delay -lt 0 -or $delay -gt 600000) {
                throw 'marker delayMilliseconds must be between 0 and 600000.'
            }
            if ($delay -gt 0) {
                Start-Sleep -Milliseconds $delay
            }
            $content = [string](Get-ArgumentValue -Name 'content' -DefaultValue ('WinPrivProbe-' + $PID))
            Write-AtomicBytes -Path $markerPath -Bytes ((New-Object Text.UTF8Encoding($false)).GetBytes($content))
            $result = [ordered]@{
                path = [IO.Path]::GetFullPath($markerPath)
                content = $content
                length = (New-Object Text.UTF8Encoding($false)).GetByteCount($content)
            }
        }
        default {
            $envelope.supported = $false
            $envelope.success = $false
            $envelope.reason = 'Unsupported probe operation: ' + $Operation
            $result = $null
        }
    }

    $envelope.result = $result
    if ($null -ne $result -and (Test-DictionaryKey -Dictionary $result -Key 'supported')) {
        $envelope.supported = [bool]$result['supported']
    }
    elseif ($null -ne $result) {
        $envelope.supported = $true
    }
    if ($null -ne $result -and (Test-DictionaryKey -Dictionary $result -Key 'success')) {
        $envelope.success = [bool]$result['success']
        if (Test-DictionaryKey -Dictionary $result -Key 'reason') {
            $envelope.reason = [string]$result['reason']
        }
    }
    elseif ($null -ne $result) {
        $envelope.success = $true
    }
}
catch {
    $envelope.supported = $false
    $envelope.success = $false
    $envelope.reason = $_.Exception.Message
    $envelope.error = [ordered]@{
        type = $_.Exception.GetType().FullName
        message = $_.Exception.Message
        hresult = $_.Exception.HResult
        scriptStackTrace = $_.ScriptStackTrace
    }
}
finally {
    $envelope.finishedUtc = [DateTime]::UtcNow.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    Write-AtomicJson -Path $OutputPath -Value $envelope
}

if ($operationName -eq 'exit') {
    exit $requestedExitCode
}
if (-not $envelope.success) {
    exit 1
}
exit 0
