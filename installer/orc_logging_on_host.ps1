
#region Logging
Function LogTimeStamp {
    # returns formatted timestamp
	return Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
}

function Sanitize {
    param (
        [string]$Text
    )

    # Reduct password from text, sometimes text contains connection string with password
    $ReductedText = $Text -replace '(?i)(?<=Password=)[^;]+', '[reducted]'

    # Replace the value of the $FlexToken variable with '[reducted]' only if it exists and is not empty
    if ($Global:FlexToken -and $Global:FlexToken.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:FlexToken), '[reducted]'
    }

    # Replace the value of the $SDPPassword variable with '[reducted]' only if it exists and is not empty
    if ($Global:SDPPassword -and $Global:SDPPassword.Length -gt 0) {
        $ReductedText = $ReductedText -replace [regex]::Escape($Global:SDPPassword), '[reducted]'
    }

    return $ReductedText
}

Function ArgsToSanitizedString {
    $sanitizedArgs = @()
    foreach ($arg in $args) {
        if ($arg -is [System.Management.Automation.ErrorRecord]) {
            $sanitizedArgs += Sanitize -Text $arg.Exception.Message
        } else {
            $sanitizedArgs += Sanitize -Text $arg.ToString()
        }
    }
    return [string]::Join(' ', $sanitizedArgs)
}

Function ErrorMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [ERROR] - $msg"
    Write-Error "$(LogTimeStamp) - $($MessageCurrentObject) - [ERROR] - $msg"
}

Function InfoMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [INFO] - $msg"
}

Function DebugMessage {
    if ($DebugPreference -ne 'Continue') {
        return
    }
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [DEBUG] - $msg"
}

Function WarningMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - $($MessageCurrentObject) - [WARN] - $msg"
}
#endregion Logging
