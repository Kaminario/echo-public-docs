#region Common Utility Functions



#region EnsureOutputDirectory
function EnsureOutputDirectory {
    <#
    .SYNOPSIS
        Validates output directory existence and write permissions for logs and artifacts.

    .DESCRIPTION
        This function ensures that the output directory exists and validates that the current
        user has write permissions to create log files and store installation artifacts.
        This validation happens early in the script to prevent failures during execution.

    .PARAMETER OutputDir
        The directory path where logs and artifacts will be stored.

    .RETURNS
        Boolean - True if directory is valid and writable, False otherwise
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$OutputDir
    )

    try {
        # Create directory if it doesn't exist
        if (-not (Test-Path $OutputDir)) {
            InfoMessage "Creating output directory: $OutputDir"
            New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
            InfoMessage "Output directory created successfully."
        } else {
            InfoMessage "Output directory exists: $OutputDir"
        }

        # Test write permissions by creating a temporary test file
        $testFile = Join-Path $OutputDir "write_test_$(Get-Date -Format 'yyyyMMdd_HHmmss').tmp"
        InfoMessage "Testing write permissions in output directory..."

        try {
            # Try to create and write to a test file
            "Write permission test" | Out-File -FilePath $testFile -Encoding UTF8

            # Verify file was created
            if (Test-Path $testFile) {
                InfoMessage "Write permissions validated successfully."
                # Clean up test file
                Remove-Item $testFile -Force
                return $true
            } else {
                ErrorMessage "Failed to verify test file creation in output directory."
                return $false
            }
        } catch {
            ErrorMessage "Write permission test failed: $_"
            return $false
        }

    } catch {
        ErrorMessage "Failed to create or validate output directory: $_"
        return $false
    }
}
#endregion EnsureOutputDirectory


#region ConvertSecureStringToPlainText
function ConvertSecureStringToPlainText {
    param (
        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$SecureString
    )

    if (-not $SecureString) {
        return $null
    }

    try {
        # Create a temporary PSCredential to extract the plain text password
        $tempCred = New-Object System.Management.Automation.PSCredential("temp", $SecureString)
        return $tempCred.GetNetworkCredential().Password
    } catch {
        Write-Error "Failed to convert SecureString to plain text: $_"
        return $null
    }
}
#endregion ConvertSecureStringToPlainText

#endregion Common Utility Functions
