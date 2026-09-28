#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BinaryRoot,
    [Parameter(Mandatory)][string]$ResultsPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$BinaryRoot = [IO.Path]::GetFullPath($BinaryRoot)
$ResultsPath = [IO.Path]::GetFullPath($ResultsPath)
if ((Test-Path -LiteralPath $ResultsPath) -and @(Get-ChildItem -LiteralPath $ResultsPath -Force).Count) {
    throw 'ResultsPath must be new or empty.'
}
[void][IO.Directory]::CreateDirectory($ResultsPath)
Import-Module AppLocker -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Modules\WinPriv.TestHarness\WinPriv.TestHarness.psd1') -Force

$originalPolicy = Get-AppLockerPolicy -Local -Xml
$effectivePolicy = Get-AppLockerPolicy -Effective -Xml
if (([xml]$originalPolicy).SelectNodes('//RuleCollection/*').Count -or
    ([xml]$effectivePolicy).SelectNodes('//RuleCollection/*').Count) {
    throw 'This standalone test requires an unconfigured local and effective AppLocker policy.'
}
if ((Get-Service AppIDSvc).Status -ne 'Running') {
    throw 'The Application Identity service must already be running.'
}
$backupPath = Join-Path $ResultsPath 'original-policy.xml'
[IO.File]::WriteAllText($backupPath, $originalPolicy)
[IO.File]::WriteAllText((Join-Path $ResultsPath 'original-effective-policy.xml'), $effectivePolicy)
$hosts = @(
    @{ Name = 'WindowsPowerShell-x64'; Architecture = 'x64'
       Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
    @{ Name = 'WindowsPowerShell-x86'; Architecture = 'x86'
       Path = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" }
    @{ Name = 'PowerShell-x64'; Architecture = 'x64'; Path = "$env:ProgramFiles\PowerShell\7\pwsh.exe" }
)
foreach ($hostInfo in $hosts) {
    foreach ($path in @($hostInfo.Path, (Join-Path $BinaryRoot "$($hostInfo.Architecture)\WinPrivCmd.exe"))) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required executable is missing: $path" }
    }
}

$probe = @'
$ErrorActionPreference = 'Stop'
$ExecutionContext.SessionState.LanguageMode
try { [void][IO.File]::Exists('WinPriv-AppLocker-probe'); 'MethodAllowed' } catch { 'MethodBlocked' }
'@
$encodedProbe = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
$blockedRoot = Join-Path $ResultsPath 'blocked'
[void][IO.Directory]::CreateDirectory($blockedRoot)
$blockedScript = Join-Path $blockedRoot 'probe.ps1'
$allowedScript = Join-Path $ResultsPath 'allowed.ps1'
[IO.File]::WriteAllText($blockedScript, $probe)
[IO.File]::WriteAllText($allowedScript, $probe)
$blockedTarget = @{ TargetArguments = @('-File', $blockedScript) }
$allowedTarget = @{ TargetArguments = @('-File', $allowedScript) }
$evidence = New-Object 'Collections.Generic.List[object]'

function Invoke-LanguageCase {
    param($HostInfo, [string]$Name, [string]$Expected, [string[]]$Switches = @(),
        [string[]]$TargetArguments = @('-EncodedCommand', $encodedProbe),
        [switch]$Direct, [switch]$ReadinessProbe)
    $arguments = @($HostInfo.Path, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass') + $TargetArguments
    $executable = Join-Path $BinaryRoot "$($HostInfo.Architecture)\WinPrivCmd.exe"
    if ($Direct) { $executable = $HostInfo.Path; $arguments = $arguments[1..($arguments.Count - 1)] }
    else { $arguments = $Switches + $arguments }
    $invoke = @{
        FilePath = $executable; ArgumentList = $arguments; WorkingDirectory = $ResultsPath
        TimeoutSeconds = 20; CreateHiddenConsole = -not $Direct; CreateNoWindow = [bool]$Direct
    }
    $result = Invoke-WinPrivContainedProcess @invoke
    $method = if ($Expected -eq 'FullLanguage') { 'MethodAllowed' } else { 'MethodBlocked' }
    $passed = $result.Succeeded -and $result.JobAssigned -and
        $result.StdOut.Contains($Expected) -and $result.StdOut.Contains($method)
    if ($ReadinessProbe) { return $passed }
    $evidence.Add([pscustomobject]@{
        Host = $HostInfo.Name; Case = $Name; Expected = $Expected; Passed = $passed
        ExitCode = $result.ExitCode; StdOut = $result.StdOut; StdErr = $result.StdErr
        TimedOut = $result.TimedOut; StartError = $result.StartError; JobAssigned = $result.JobAssigned
    })
    if (-not $passed) { throw "$($HostInfo.Name) / $Name failed: $($result.StdOut) $($result.StdErr)" }
}

$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$escapedBlockedPath = [Security.SecurityElement]::Escape("$blockedRoot\*")
$policy = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="$([guid]::NewGuid())" Name="WinPriv review allow scripts" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="$([guid]::NewGuid())" Name="WinPriv review language detection" Description="" UserOrGroupSid="$sid" Action="Deny">
      <Conditions><FilePathCondition Path="*\__PSScriptPolicyTest_*" /></Conditions>
    </FilePathRule>
    <FilePathRule Id="$([guid]::NewGuid())" Name="WinPriv review blocked fixture" Description="" UserOrGroupSid="$sid" Action="Deny">
      <Conditions><FilePathCondition Path="$escapedBlockedPath" /></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@
$policyPath = Join-Path $ResultsPath 'temporary-policy.xml'
[IO.File]::WriteAllText($policyPath, $policy)
$completePath = Join-Path $ResultsPath 'restoration-complete'
$readyPath = Join-Path $ResultsPath 'watchdog-ready'
$watchdogScript = Join-Path $ResultsPath 'restore-watchdog.ps1'
$watchdog = @'
param([string]$BackupPath, [string]$CompletePath, [string]$ReadyPath, [int]$OwnerId)
$ErrorActionPreference = 'Stop'
Import-Module AppLocker
$owner = Get-Process -Id $OwnerId -ErrorAction Stop
Set-Content -LiteralPath $ReadyPath -Value ready
$deadline = (Get-Date).AddMinutes(10)
while (-not $owner.HasExited -and (Get-Date) -lt $deadline) {
    if (Test-Path -LiteralPath $CompletePath) { exit 0 }
    Start-Sleep -Seconds 1
}
Set-AppLockerPolicy -XmlPolicy $BackupPath
$expected = ([xml](Get-Content -Raw -LiteralPath $BackupPath)).OuterXml
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    if (([xml](Get-AppLockerPolicy -Local -Xml)).OuterXml -eq $expected -and
        ([xml](Get-AppLockerPolicy -Effective -Xml)).OuterXml -eq $expected) {
        Set-Content -LiteralPath ($BackupPath + '.watchdog-restored') -Value (Get-Date)
        exit 0
    }
    Start-Sleep -Milliseconds 250
}
throw 'Watchdog could not verify policy restoration.'
'@
[IO.File]::WriteAllText($watchdogScript, $watchdog)
$watchdogArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" "{1}" "{2}" "{3}" {4}' -f
    $watchdogScript, $backupPath, $completePath, $readyPath, $PID
$watchdogStart = @{
    FilePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    PassThru = $true; WindowStyle = 'Hidden'; ArgumentList = $watchdogArguments
}
$watchdogProcess = Start-Process @watchdogStart
$changed = $false
$restored = $false
$failure = $null
try {
    for ($attempt = 0; $attempt -lt 40 -and -not (Test-Path -LiteralPath $readyPath); $attempt++) {
        if ($watchdogProcess.HasExited) { throw 'Policy restoration watchdog could not start.' }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $readyPath)) { throw 'Policy restoration watchdog did not become ready.' }
    foreach ($hostInfo in $hosts) {
        Invoke-LanguageCase $hostInfo 'before-policy' 'FullLanguage' -Direct
    }
    $changed = $true
    Set-AppLockerPolicy -XmlPolicy $policyPath
    $expectedRuleIds = @(([xml]$policy).SelectNodes('//FilePathRule') | ForEach-Object Id)
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $applied = [xml](Get-AppLockerPolicy -Effective -Xml)
        $collection = $applied.SelectSingleNode('//RuleCollection[@Type="Script"]')
        $actualRuleIds = @($applied.SelectNodes('//FilePathRule') | ForEach-Object Id)
        if ($null -ne $collection -and $collection.EnforcementMode -eq 'Enabled' -and
            $actualRuleIds.Count -eq $expectedRuleIds.Count -and
            -not (Compare-Object $expectedRuleIds $actualRuleIds)) { break }
        Start-Sleep -Milliseconds 250
    }
    if ($attempt -eq 40) { throw 'The temporary policy did not become effective.' }
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if (Invoke-LanguageCase $hosts[0] 'activation' 'ConstrainedLanguage' -Direct -ReadinessProbe) { break }
        Start-Sleep -Milliseconds 500
    }
    if ($attempt -eq 20) { throw 'The effective policy did not constrain a fresh PowerShell host.' }
    [IO.File]::WriteAllText((Join-Path $ResultsPath 'applied-policy.xml'), (Get-AppLockerPolicy -Effective -Xml))
    foreach ($hostInfo in $hosts) {
        Invoke-LanguageCase $hostInfo 'enforced-command-control' 'ConstrainedLanguage' -Direct
        Invoke-LanguageCase $hostInfo 'enforced-script-control' 'ConstrainedLanguage' -Direct @blockedTarget
        Invoke-LanguageCase $hostInfo 'allowed-script-control' 'FullLanguage' -Direct @allowedTarget
        Invoke-LanguageCase $hostInfo 'no-switch-control' 'ConstrainedLanguage'
        foreach ($case in @(
            @{ Switches = @('/ClmOn'); Mode = 'ConstrainedLanguage' }
            @{ Switches = @('/ClmOff'); Mode = 'FullLanguage' }
            @{ Switches = @('/ClmOn', '/ClmOff'); Mode = 'FullLanguage' }
            @{ Switches = @('/ClmOff', '/ClmOn'); Mode = 'ConstrainedLanguage' }
        )) {
            $label = $case.Switches -join ' '
            Invoke-LanguageCase $hostInfo "$label command" $case.Mode -Switches $case.Switches
            Invoke-LanguageCase $hostInfo "$label blocked script" $case.Mode -Switches $case.Switches @blockedTarget
            Invoke-LanguageCase $hostInfo "$label allowed script" $case.Mode -Switches $case.Switches @allowedTarget
        }
        foreach ($child in $hosts) {
            $command = "& '$($child.Path.Replace("'", "''"))' -NoProfile -NonInteractive -EncodedCommand $encodedProbe"
            $encodedChild = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
            $childTarget = @{ TargetArguments = @('-EncodedCommand', $encodedChild) }
            Invoke-LanguageCase $hostInfo "child $($child.Name) on" 'ConstrainedLanguage' -Switches /ClmOn @childTarget
            Invoke-LanguageCase $hostInfo "child $($child.Name) off" 'FullLanguage' -Switches /ClmOff @childTarget
        }
    }
}
catch { $failure = $_ | Out-String }
finally {
    try {
        if ($changed) { Set-AppLockerPolicy -XmlPolicy $backupPath }
        for ($attempt = 0; $attempt -lt 40; $attempt++) {
            $actualPolicy = Get-AppLockerPolicy -Local -Xml
            $actualEffective = Get-AppLockerPolicy -Effective -Xml
            $restored = ([xml]$actualPolicy).OuterXml -eq ([xml]$originalPolicy).OuterXml -and
                ([xml]$actualEffective).OuterXml -eq ([xml]$effectivePolicy).OuterXml
            if ($restored) { break }
            Start-Sleep -Milliseconds 250
        }
        [IO.File]::WriteAllText((Join-Path $ResultsPath 'restored-policy.xml'), $actualPolicy)
        [IO.File]::WriteAllText((Join-Path $ResultsPath 'restored-effective-policy.xml'), $actualEffective)
        if (-not $restored) { throw 'AppLocker restoration verification failed; the watchdog remains active.' }
        [IO.File]::WriteAllText($completePath, 'Verified')
        if (-not $watchdogProcess.WaitForExit(5000)) { throw 'Policy was restored, but the watchdog did not exit.' }
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            if (Invoke-LanguageCase $hosts[0] 'restoration' 'FullLanguage' -Direct -ReadinessProbe) { break }
            Start-Sleep -Milliseconds 500
        }
        foreach ($hostInfo in $hosts) { Invoke-LanguageCase $hostInfo 'after-restoration' 'FullLanguage' -Direct }
    }
    catch { $failure = "$failure $($_ | Out-String)" }
    $summary = [ordered]@{
        Passed = [string]::IsNullOrWhiteSpace($failure); PolicyRestored = $restored
        Cases = @($evidence.ToArray()); Failure = $failure
    }
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ResultsPath 'results.json') -Encoding UTF8
    $watchdogProcess.Dispose()
}
if ($failure) { throw $failure }
Write-Output "Passed $($evidence.Count) AppLocker cases; original policy restored."
