
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
    # Updated regex to handle both plain connection strings and JSON-embedded strings
    # Match password value until semicolon OR quote OR end of line
    $ReductedText = $Text -replace '(?i)(?<=Password=)[^;"]+', '[reducted]'

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
    Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [ERROR] $msg" -ForegroundColor Red
    Write-Error "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [ERROR] - $msg" -ErrorAction Continue
}

Function ImportantMessage {
    $msg = ArgsToSanitizedString @args
    Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [INFO] $msg" -ForegroundColor Green
}

Function InfoMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [INFO] $msg"
}

Function DebugMessage {
    if ($DebugPreference -ne 'Continue') {
        return
    }
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [DEBUG] $msg"
}

Function WarningMessage {
    $msg = ArgsToSanitizedString @args
	Write-Host "$(LogTimeStamp) - Host[$env:COMPUTERNAME] - $MessageCurrentObject - [WARN] $msg" -ForegroundColor Yellow
}

#region HostsSummaryReport
function WriteHostsSummary {
    <#
    .SYNOPSIS
        Writes a summary of all hosts with their issues and results to a file.

    .DESCRIPTION
        This function writes hosts summary to a file in a structured format:
        1. First shows all hosts with issues
        2. Then shows all hosts with results
        Format for each host:
        hostname:
          issues:
          - issue1
          - issue2
          result: {json object}

    .PARAMETER Hosts
        Array of host objects to write

    .PARAMETER OutputPath
        Path to the output file where summary will be written. Use "STDOUT" to print to console instead of writing to file

    .EXAMPLE
        WriteHostsSummary -Hosts $config.hosts -OutputPath "hosts_summary.txt"

    .EXAMPLE
        WriteHostsSummary -Hosts $config.hosts -OutputPath "STDOUT"
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Array]$Hosts,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )

    if ($Hosts.Count -eq 0) {
        if ($OutputPath -eq "STDOUT") {
            Write-Host "No hosts to display"
        } else {
            "No hosts to display" | Out-File -FilePath $OutputPath -Encoding UTF8
            InfoMessage "Hosts summary written to: $OutputPath"
        }
        return
    }

    # Separate hosts with issues and hosts with results
    $hostsWithIssues = @($Hosts | Where-Object { $_.issues.Count -gt 0 })
    $hostsWithResults = @($Hosts | Where-Object { $_.result -ne $null -and $_.issues.Count -eq 0 })

    # Create output content array
    $outputLines = @()
    $outputLines += "=============== HOSTS SUMMARY ==============="
    $outputLines += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $outputLines += ""

    # Write hosts with issues first
    if ($hostsWithIssues.Count -gt 0) {
        $outputLines += "HOSTS WITH ISSUES ($($hostsWithIssues.Count)):"
        $outputLines += ""

        foreach ($hostInfo in $hostsWithIssues) {
            $outputLines += "$($hostInfo.host_addr):"
            if ($hostInfo.issues.Count -gt 0) {
                $outputLines += "  issues:"
                foreach ($issue in $hostInfo.issues) {
                    $outputLines += "  - $issue"
                }
            }

            if ($hostInfo.result) {
                $outputLines += "  result:"
                $outputLines += "    Host Address: $($hostInfo.result.HostAddress)"
                $outputLines += "    Job State: $($hostInfo.result.JobState)"

                if ($hostInfo.result.Info -and $hostInfo.result.Info.Count -gt 0) {
                    $outputLines += "    Info:"
                    foreach ($info in $hostInfo.result.Info) {
                        if ($info -and $info.PSObject.Properties.Count -gt 0) {
                            foreach ($prop in $info.PSObject.Properties) {
                                $outputLines += "      $($prop.Name): $($prop.Value)"
                            }
                        }
                    }
                }

                if ($hostInfo.result.Error -and $hostInfo.result.Error.Count -gt 0) {
                    $outputLines += "    Errors:"
                    foreach ($error in $hostInfo.result.Error) {
                        $outputLines += "      - $error"
                    }
                }
            } else {
                $outputLines += "  result: null"
            }
            $outputLines += ""
        }
    }

    # Write hosts with results
    if ($hostsWithResults.Count -gt 0) {
        $outputLines += "HOSTS WITH RESULTS ($($hostsWithResults.Count)):"
        $outputLines += ""

        foreach ($hostInfo in $hostsWithResults) {
            # Skip hosts that were already shown in issues section
            if ($hostInfo.issues.Count -gt 0) {
                continue
            }

            $outputLines += "$($hostInfo.host_addr):"
            $outputLines += "  issues: none"

            $outputLines += "  result:"
            $outputLines += "    Host Address: $($hostInfo.result.HostAddress)"
            $outputLines += "    Job State: $($hostInfo.result.JobState)"

            if ($hostInfo.result.Info -and $hostInfo.result.Info.Count -gt 0) {
                $outputLines += "    Info:"
                foreach ($info in $hostInfo.result.Info) {
                    if ($info -and $info.PSObject.Properties.Count -gt 0) {
                        foreach ($prop in $info.PSObject.Properties) {
                            $outputLines += "      $($prop.Name): $($prop.Value)"
                        }
                    }
                }
            }

            if ($hostInfo.result.Error -and $hostInfo.result.Error.Count -gt 0) {
                $outputLines += "    Errors:"
                foreach ($error in $hostInfo.result.Error) {
                    $outputLines += "      - $error"
                }
            }
            $outputLines += ""
        }
    }

    # Output to console or file
    if ($OutputPath -eq "STDOUT") {
        # Print to console
        foreach ($line in $outputLines) {
            Write-Host $line
        }
    } else {
        # Write to file
        $outputLines | Out-File -FilePath $OutputPath -Encoding UTF8
        InfoMessage "Hosts report written to: $OutputPath"
    }
}

function DisplayInstallationSummary {
    <#
    .SYNOPSIS
        Displays a short summary of installation results to console.

    .DESCRIPTION
        Shows only the counts - how many hosts succeeded, failed, etc.
        For detailed information, use WriteHostsSummary.

    .PARAMETER Hosts
        Array of host objects to summarize

    .EXAMPLE
        DisplayInstallationSummary -Hosts $config.hosts
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Array]$Hosts
    )

    if ($Hosts.Count -eq 0) {
        InfoMessage "No hosts processed"
        return
    }

    $totalHosts = $Hosts.Count
    $successfulHosts = @($Hosts | Where-Object { $_.result.JobState -eq 'Success' }).Count
    $failedHosts = @($Hosts | Where-Object { $_.result.JobState -eq 'Failed' }).Count
    $hostsWithIssues = @($Hosts | Where-Object { $_.issues.Count -gt 0 }).Count

    InfoMessage "=============== INSTALLATION SUMMARY ==============="
    InfoMessage "Total hosts: $totalHosts"
    InfoMessage "Successful: $successfulHosts"
    InfoMessage "Failed: $failedHosts"
    InfoMessage "With issues: $hostsWithIssues"
    InfoMessage "=================================================="
}
#endregion HostsSummaryReport

#endregion Logging
