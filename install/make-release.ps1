# This script combines all the necessary PowerShell scripts into a single release file.

. ./orc_constants.ps1
. ./orc_logging.ps1
. ./orc_import_expander.ps1

$orchestratorFile = "orchestrator.ps1"
$releaseFile = "orchestrator-release.ps1"

# Read orchestrator.ps1 (already contains host installer after MARKER)
$orchestratorContent = Get-Content -Path $orchestratorFile -Raw

# Process imports by expanding them inline
$finalContent = ExpandImportsInline -ScriptContent $orchestratorContent

# Write to release file
$finalContent | Out-File -FilePath $releaseFile -Encoding UTF8

Write-Host "$releaseFile created successfully." -ForegroundColor Green
