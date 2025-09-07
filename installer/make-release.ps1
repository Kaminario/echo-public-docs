# This script combines all the necessary PowerShell scripts into a single release file.

param(
    [ValidateSet("major", "minor", "patch")]
    [string]$Part = "patch"
)

# Function to increment version
function Increment-Version {
    param(
        [string]$Version,
        [string]$Part
    )

    $versionParts = $Version.Split('.')
    if ($versionParts.Length -ne 3) {
        throw "Invalid version format. Expected format: x.y.z"
    }

    $major = [int]$versionParts[0]
    $minor = [int]$versionParts[1]
    $patch = [int]$versionParts[2]

    switch ($Part) {
        "major" {
            $major++
            $minor = 0
            $patch = 0
        }
        "minor" {
            $minor++
            $patch = 0
        }
        "patch" {
            $patch++
        }
    }

    return "$major.$minor.$patch"
}

# Read and increment version
$versionFile = "../installer-release/version"
$orchestratorFile = "orchestrator.ps1"
$releaseFile = "../installer-release/orchestrator.ps1"

$currentVersion = Get-Content -Path $versionFile -Raw
$currentVersion = $currentVersion.Trim()
$newVersion = Increment-Version -Version $currentVersion -Part $Part

Write-Host "Incrementing $Part version from $currentVersion to $newVersion" -ForegroundColor Yellow

# Update version file
$newVersion | Out-File -FilePath $versionFile -Encoding UTF8 -NoNewline
Write-Host "Version updated in $versionFile" -ForegroundColor Green

. ./orc_constants.ps1
. ./orc_logging.ps1
. ./orc_import_expander.ps1

# Read orchestrator.ps1 (already contains host installer after MARKER)
$orchestratorContent = Get-Content -Path $orchestratorFile -Raw

# Process imports by expanding them inline
$finalContent = ExpandImportsInline -ScriptContent $orchestratorContent

# Replace version placeholder in the final content
$finalContent = $finalContent -replace '\{\{VERSION_PLACEHOLDER\}\}', $newVersion

# Write to release file
$finalContent | Out-File -FilePath $releaseFile -Encoding UTF8

Write-Host "$releaseFile created successfully." -ForegroundColor Green
