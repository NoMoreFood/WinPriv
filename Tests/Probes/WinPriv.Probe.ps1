[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Position = 0)] [string] $Operation,
    [string] $OutputPath,
    [string] $ArgumentsJson,
    [Parameter(ValueFromRemainingArguments = $true)] [string[]] $RemainingArguments
)

# Compatibility entry point retained for callers that used the plan's original
# name. The harness uses Invoke-WinPrivProbe.ps1 directly.
$entryPoint = Join-Path $PSScriptRoot 'Invoke-WinPrivProbe.ps1'
& $entryPoint `
    -Operation $Operation `
    -OutputPath $OutputPath `
    -ArgumentsJson $ArgumentsJson `
    @RemainingArguments
exit $LASTEXITCODE
