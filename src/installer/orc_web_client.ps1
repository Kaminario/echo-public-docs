#region NETWORK

#region CallSelfCertEndpoint
function CallSelfCertEndpoint {
    param (
        [string]$URL,
        [string]$HttpMethod,
        [object]$RequestBody,
        [hashtable]$Headers
    )

    DebugMessage "Calling [$HttpMethod]$URL"
    # capitalize the first letter of HttpMethod
    $HttpMethod = $HttpMethod.Substring(0,1).ToUpper() + $HttpMethod.Substring(1).ToLower()
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($IsPowerShell7) {
        if ( $HttpMethod -in @("POST", "PUT") -and $RequestBody -ne $null ) {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -Body $RequestBody -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
        }
    } else {
        if ($HttpMethod -in @("POST", "PUT") -and $RequestBody -ne $null ) {
            # If no request body is provided
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -Body $RequestBody -UseBasicParsing -ErrorAction Stop
        } else {
            $response = Invoke-WebRequest -Uri $URL -Method $HttpMethod -Headers $Headers -UseBasicParsing -ErrorAction Stop
        }
    }
    return $response
}
#endregion CallSelfCertEndpoint

#region CallSDPApi
function CallSDPApi {
    param (
        [string]$SDPHost,
        [string]$SDPPort,
        [string]$ApiEndpoint,
        [System.Management.Automation.PSCredential]$Credential
    )

    $url = "https://${SDPHost}:${SDPPort}/api/v2/$ApiEndpoint"

    DebugMessage "Call SDPApi USERNAME: $($Credential.UserName)"
    $BasicAuthString = "$($Credential.UserName):$($Credential.GetNetworkCredential().Password)"

    $BasicAuth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($BasicAuthString))
    $_headers = @{
        "Authorization" = "Basic $BasicAuth"
    }

    try {
        $response = CallSelfCertEndpoint -URL $url -HttpMethod "GET" -RequestBody $null -Headers $_headers
        if ($response.StatusCode -ne 200) {
            ErrorMessage "Failed to call SDP API at $url. Status code: $($response.StatusCode)"
            return $null
        }
        DebugMessage "Response from SDP API: $($response.StatusCode) - $($response.StatusDescription)"
        return $response
    } catch {
        ErrorMessage "Error calling SDP API: $_"
        return $null
    }
}
#endregion CallSDPApi

#region CallFlexApi
function CallFlexApi {
        param (
        [string]$FlexIP,
        [string]$FlexToken,
        [string]$ApiEndpoint,
        [string]$HttpMethod,
        [string]$RequestBody
    )

    $flexApiUrl = "https://$FlexIP$ApiEndpoint"
    $headers = @{ "Authorization" = "Bearer $FlexToken" }

    DebugMessage "Calling Flex API at $flexApiUrl with method $HttpMethod"
    try {
        $response = CallSelfCertEndpoint -URL $flexApiUrl -HttpMethod $HttpMethod -RequestBody $RequestBody -Headers $headers
        DebugMessage "Response from Flex API: $($response.StatusCode) - $($response.StatusDescription)"
        return $response
    } catch {
        ErrorMessage "Error calling Flex API: $_"
        return $null
    }

}
#endregion CallFlexApi

#region CallFlexApiMultipart-PS5
function CallFlexApiMultipart-PS5 {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FlexApiUrl,

        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,

        [Parameter(Mandatory=$true)]
        [hashtable]$FormFields,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$FileFieldName
    )

    # PowerShell 5.1 - manually construct multipart/form-data
    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"

    # Build multipart form body
    $bodyLines = @()

    # Add form fields
    foreach ($key in $FormFields.Keys) {
        $value = $FormFields[$key]
        $bodyLines += "--$boundary"
        $bodyLines += "Content-Disposition: form-data; name=`"$key`""
        $bodyLines += ""
        $bodyLines += $value
    }

    # Add file field
    $fileName = Split-Path -Leaf $FilePath
    $fileContent = [System.IO.File]::ReadAllBytes($FilePath)

    $bodyLines += "--$boundary"
    $bodyLines += "Content-Disposition: form-data; name=`"$FileFieldName`"; filename=`"$fileName`""
    $bodyLines += "Content-Type: application/octet-stream"
    $bodyLines += ""

    # Convert body lines to bytes
    $bodyText = $bodyLines -join $LF
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyText)

    # Append file content
    $fileBytes = New-Object System.Collections.ArrayList
    $fileBytes.AddRange($bodyBytes)
    $fileBytes.AddRange($fileContent)

    # Add closing boundary
    $closingBoundary = [System.Text.Encoding]::UTF8.GetBytes("$LF--$boundary--$LF")
    $fileBytes.AddRange($closingBoundary)

    # Set Content-Type header with boundary
    $Headers["Content-Type"] = "multipart/form-data; boundary=$boundary"

    $response = Invoke-WebRequest -Uri $FlexApiUrl -Method POST -Headers $Headers -Body $fileBytes -UseBasicParsing -ErrorAction Stop
    return $response
}
#endregion CallFlexApiMultipart-PS5

#region CallFlexApiMultipart-PS7
function CallFlexApiMultipart-PS7 {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FlexApiUrl,

        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,

        [Parameter(Mandatory=$true)]
        [hashtable]$FormFields,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$FileFieldName
    )

    # PowerShell 7+ supports -Form parameter which handles multipart/form-data automatically
    $formData = @{}
    foreach ($key in $FormFields.Keys) {
        $formData[$key] = $FormFields[$key]
    }
    $formData[$FileFieldName] = Get-Item $FilePath

    $response = Invoke-WebRequest -Uri $FlexApiUrl -Method POST -Headers $Headers -Form $formData -UseBasicParsing -SkipCertificateCheck -ErrorAction Stop
    return $response
}
#endregion CallFlexApiMultipart-PS7

#region CallFlexApiMultipart
function CallFlexApiMultipart {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FlexIP,

        [Parameter(Mandatory=$true)]
        [string]$FlexToken,

        [Parameter(Mandatory=$true)]
        [string]$ApiEndpoint,

        [Parameter(Mandatory=$true)]
        [hashtable]$FormFields,

        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$FileFieldName
    )

    $flexApiUrl = "https://$FlexIP$ApiEndpoint"
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7

    DebugMessage "Calling Flex API multipart upload at $flexApiUrl"

    # Validate file exists
    if (-not (Test-Path $FilePath)) {
        ErrorMessage "File not found: $FilePath"
        return $null
    }

    try {
        # Set headers
        $headers = @{
            "Authorization" = "Bearer $FlexToken"
            "Accept" = "application/json"
        }

        # Call appropriate function based on PowerShell version
        if ($IsPowerShell7) {
            $response = CallFlexApiMultipart-PS7 -FlexApiUrl $flexApiUrl -Headers $headers -FormFields $FormFields -FilePath $FilePath -FileFieldName $FileFieldName
        } else {
            $response = CallFlexApiMultipart-PS5 -FlexApiUrl $flexApiUrl -Headers $headers -FormFields $FormFields -FilePath $FilePath -FileFieldName $FileFieldName
        }

        DebugMessage "Response from Flex API multipart upload: $($response.StatusCode) - $($response.StatusDescription)"
        return $response
    } catch {
        WarningMessage "Error calling Flex API multipart upload: $_"
        return $null
    }
}
#endregion CallFlexApiMultipart

#endregion NETWORK
