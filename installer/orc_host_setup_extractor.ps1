#region GetHostInstallScript
function GetHostInstallScript {
    <#
    .SYNOPSIS
        Extracts the host installation script from the orchestrator.

    .DESCRIPTION
        This function reads the orchestrator script content and extracts the host installer
        portion after the HOSTSETUP_START_MARKER.

    .PARAMETER OrchestratorPath
        Path to the orchestrator script. If not specified, uses the script that called this function.

    .OUTPUTS
        String containing the host installation script content
    #>

    param (
        [Parameter(Mandatory=$true)]
        [string]$OrchestratorPath
    )

    try {
        DebugMessage "Extracting host installation script from orchestrator..."

        # Read the orchestrator script content
        $orchestratorContent = Get-Content -Path $OrchestratorPath -Raw

        # Extract content after the HOSTSETUP_START_MARKER
        $hostScriptContent = $orchestratorContent -split $HOSTSETUP_START_MARKER | Select-Object -Last 1
        $hostScriptContent = $hostScriptContent.Trim()

        if ([string]::IsNullOrWhiteSpace($hostScriptContent)) {
            ErrorMessage "Failed to extract host installer script content from orchestrator."
            return $null
        }

        DebugMessage "Host installation script extracted successfully."
        return $hostScriptContent
    }
    catch {
        ErrorMessage "Failed to extract host installation script: $_"
        return $null
    }
}
#endregion GetHostInstallScript
