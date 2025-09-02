#region Common Utility Functions


#region ensureCacheDir
function ensureCacheDir {
    param (
        [string]$CacheDir = $null
    )
    # Ensure the cache directory exists
    if (-not (Test-Path $CacheDir)) {
        New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null
        InfoMessage "Created installer cache directory: $CacheDir"
    }
}
#endregion ensureCacheDir


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
