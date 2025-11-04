#region FileUploader

<#
.SYNOPSIS
    Handles uploading execution logs to Flex.

.DESCRIPTION
    This module provides functionality to upload orchestrator execution logs to Flex.
    It handles token management and graceful error handling for this optional feature.

.NOTES
    File Name      : orc_log_uploader.ps1
    Author         : Silk.us, Inc.
    Prerequisite   : PowerShell version 5 or higher
    Copyright      : (c) 2025 Silk.us, Inc.

.FUNCTIONALITY
    Log upload to Flex, Token management
#>

#region UploadFile
function UploadFile {
    <#
    .SYNOPSIS
        Uploads a file to Flex.

    .DESCRIPTION
        Uploads a specified file to Flex.
        Handles token management by calling RetrieveFlexAuthToken if token is missing.
        Failures are logged as warnings and do not throw exceptions.

    .PARAMETER FlexIP
        Flex host IP address or hostname.

    .PARAMETER FilePath
        Path to the file to upload.

    .PARAMETER FlexToken
        Optional Flex authentication token. If missing, will call RetrieveFlexAuthToken to obtain one.

    .PARAMETER Config
        Configuration object required for obtaining credentials if token is missing.

    .PARAMETER RefId
        Optional reference ID for the upload. Defaults to "upload_<timestamp>".

    .PARAMETER UploadType
        Optional upload type. Defaults to "manual_upload".

    .RETURNS
        Boolean - True if upload succeeded, False otherwise.

    .EXAMPLE
        $success = UploadFile -FlexIP "192.168.1.100" -FilePath "C:\logs\orchestrator.log" -Config $config
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$FlexIP,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$false)]
        [string]$FlexToken,

        [Parameter(Mandatory=$false)]
        [PSCustomObject]$Config,

        [Parameter(Mandatory=$false)]
        [string]$RefId,

        [Parameter(Mandatory=$false)]
        [string]$UploadType = "manual_upload"
    )

    try {
        # Validate file exists
        if (-not (Test-Path $FilePath)) {
            WarningMessage "Cannot upload log file: File not found at $FilePath"
            return $false
        }

        # If FlexToken is missing, call RetrieveFlexAuthToken if Config is provided
        if (-not $FlexToken) {
            if (-not $Config) {
                WarningMessage "Cannot upload log file: Flex token is missing and Config is not provided"
                return $false
            }

            try {
                $FlexToken = RetrieveFlexAuthToken -Config $Config
                if (-not $FlexToken) {
                    WarningMessage "Cannot upload log file: Failed to obtain Flex authentication token"
                    return $false
                }
            } catch {
                WarningMessage "Cannot upload log file: Error obtaining Flex authentication token: $_"
                return $false
            }
        }

        # Generate RefId if not provided
        if (-not $RefId) {
            $RefId = "upload_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        }

        # Prepare form fields
        $fileName = Split-Path -Leaf $FilePath
        $formFields = @{
            "ref_id" = $RefId
            "upload_type" = $UploadType
            "pkg_name" = $fileName
        }

        # Call the upload API
        try {
            $response = CallFlexApiMultipart -FlexIP $FlexIP -FlexToken $FlexToken -ApiEndpoint "/api/v2/flex/callhome_generic_pkg_upload" -FormFields $formFields -FilePath $FilePath -FileFieldName "pkg"

            if ($null -eq $response) {
                WarningMessage "Failed to upload log file to Flex: API call returned null"
                return $false
            }

            # Parse response to check if upload was successful
            try {
                $jsonResponse = $response.Content | ConvertFrom-Json
                if ($jsonResponse.is_successful) {
                    InfoMessage "Successfully uploaded log file to Flex: $fileName"
                    return $true
                } else {
                    $errorMsg = if ($jsonResponse.error_message) { $jsonResponse.error_message } else { "Unknown error" }
                    WarningMessage "Failed to upload log file to Flex: $errorMsg"
                    return $false
                }
            } catch {
                # Response might not be JSON or might be empty
                WarningMessage "Failed to upload log file to Flex: Unable to parse response. Status: $($response.StatusCode)"
                return $false
            }
        } catch {
            WarningMessage "Failed to upload log file to Flex: $($_.Exception.Message)"
            return $false
        }
    } catch {
        # Catch any unexpected errors
        WarningMessage "Unexpected error during log file upload: $_"
        return $false
    }
}
#endregion UploadFile

#endregion FileUploader
