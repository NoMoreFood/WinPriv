@{
    RootModule        = 'WinPriv.TestHarness.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '9830063b-b940-4d1a-96b8-a240ab65f667'
    Author            = 'WinPriv contributors'
    CompanyName       = 'WinPriv'
    Copyright         = '(c) WinPriv contributors. MIT License.'
    Description       = 'Process isolation, architecture dispatch, and capability reporting for the WinPriv test suite.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Add-WinPrivCapabilityResult'
        'Add-WinPrivCleanupJournalEntry'
        'Clear-WinPrivCapabilityResults'
        'Complete-WinPrivCapabilityReport'
        'Get-WinPrivCapabilityResults'
        'Get-WinPrivCleanupJournal'
        'Get-WinPrivPeArchitecture'
        'Get-WinPrivTestArchitectures'
        'Get-WinPrivTestHost'
        'Invoke-WinPriv'
        'Invoke-WinPrivContainedProcess'
        'Invoke-WinPrivProbe'
        'Invoke-WinPrivCurrentRunReconciliation'
        'Invoke-WinPrivStaleRunReconciliation'
        'New-WinPrivSandbox'
        'Repair-WinPrivSandboxJournal'
        'Remove-WinPrivSandbox'
        'Test-WinPrivElevated'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Windows', 'Testing', 'Pester', 'WinPriv')
            ProjectUri = 'https://github.com/NoMoreFood/WinPriv'
            LicenseUri = 'https://opensource.org/license/mit'
        }
    }
}
