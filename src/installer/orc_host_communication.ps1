#region addHostsToTrustedHosts
function addHostsToTrustedHosts {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries
    )

    $hostsToAdd = @()
    foreach ($hostInfo in $hostEntries){
        $hostsToAdd += $hostInfo.host_addr
    }

    if($hostsToAdd.Count -eq 0){
        DebugMessage "No hosts to add to TrustedHosts list."
        return
    }

    $currentTrustedHosts = Get-Item WSMan:\localhost\Client\TrustedHosts
    $newHosts = @($hostsToAdd | Where-Object { $_ -notin $currentTrustedHosts.Value.Split(',') })

    if ($newHosts.Count -eq 0) {
        InfoMessage "All hosts are already in TrustedHosts list"
        return
    } else {
        InfoMessage "Not all hosts are in TrustedHosts list."
        InfoMessage "The following hosts will be added to TrustedHosts:"
        foreach ($hostAddr in $newHosts) {
            InfoMessage "$hostAddr"
        }
    }

    # ask user if they want to add hosts to TrustedHosts or process without it
    $confirmation = Read-Host "Do you want to add these hosts to TrustedHosts? (Y/n)"
    if ($confirmation -eq 'N' -or $confirmation -eq 'n') {
        InfoMessage "User declined to add hosts to TrustedHosts. Unable to proceed with installation."
        Exit 1
    }

    $hostsToAddString = $newHosts -join ','
    InfoMessage "The following hosts need to be added to TrustedHosts:"
    InfoMessage $hostsToAddString

    if ($currentTrustedHosts.Value) {
        $newValue = "$($currentTrustedHosts.Value),$hostsToAddString"
    } else {
        $newValue = $hostsToAddString
    }
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newValue -Force
    InfoMessage "Successfully added hosts to TrustedHosts"
}
#endregion addHostsToTrustedHosts

#region ensureHostCredentials
function ensureHostCredentials {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries
    )

    # Check if any hosts with credentials auth are missing username or password
    $missingCredHosts = @($hostEntries | Where-Object {
        $_.host_auth -eq $ENUM_CREDENTIALS -and (-not $_.host_user -or -not $_.host_pass)
    })

    # return if no missing
    if ($missingCredHosts.Count -eq 0) {
        return
    }

    ImportantMessage "Missing credentials detected for some hosts with credentials authentication."
    ImportantMessage "The provided username and password will be used for all hosts with missing credentials:"

    foreach ($hostInfo in $missingCredHosts) {
        ImportantMessage "$($hostInfo.host_addr)"
    }

    $cred = Get-Credential -Message "Enter Host's username and password"
    if (-not $cred) {
        ErrorMessage "No credentials provided. Cannot proceed without valid credentials for all hosts."
        Exit 1
    }

    foreach ($hostInfo in $missingCredHosts) {
        if (-not $hostInfo.host_user) {
            Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "host_user" -Value $cred.UserName -Force
        }
        if (-not $hostInfo.host_pass) {
            Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "host_pass" -Value $cred.GetNetworkCredential().Password -Force
        }
    }

    # convert all hosts with auth credentials to secured credentials
    foreach ($hostInfo in $hostEntries) {
        if ($hostInfo.host_auth -eq $ENUM_CREDENTIALS) {
            # Only convert if it's not already a SecureString
            if ($hostInfo.host_pass -is [string]) {
                $hostInfo.host_pass = ConvertTo-SecureString $hostInfo.host_pass -AsPlainText -Force
            }
        }
    }
}
#endregion ensureHostCredentials

#region resolveIPToHostname
function resolveIPToHostname {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )

    try {
        $hostname = [System.Net.Dns]::GetHostEntry($IPAddress).HostName
        if ($hostname -and $hostname -ne $IPAddress) {
            InfoMessage "Resolved IP $IPAddress to hostname: $hostname"
            return $hostname
        }
    } catch {
        DebugMessage "Failed to resolve IP $IPAddress to hostname: $_"
    }

    return $null
}
#endregion resolveIPToHostname

#region isActiveDirectoryUser
function isActiveDirectoryUser {
    # Check if the current user is logged in to Active Directory
    try {
        # Try multiple methods for cross-version compatibility
        $isDomainUser = $false

        # Method 1: Check environment variables (works in both PS 5.1 and 7)
        $userDomain = $env:USERDOMAIN
        $computerName = $env:COMPUTERNAME
        if ($userDomain -and $userDomain -ne $computerName) {
            $isDomainUser = $true
        }

        # Method 2: Try .NET method
        if (-not $isDomainUser) {
            try {
                $adUser = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                if ($adUser) {
                    $isDomainUser = $true
                }
            } catch {
                # Ignore errors, continue with other methods
            }
        }

        # Method 3: Check using WMI/CIM
        if (-not $isDomainUser) {
            try {
                if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                } else {
                    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
                }
                if ($computerSystem -and $computerSystem.PartOfDomain) {
                    $isDomainUser = $true
                }
            } catch {
                # Ignore errors
            }
        }

        if ($isDomainUser) {
            InfoMessage "Current user is logged in to Active Directory domain: $userDomain"
            return $true
        } else {
            InfoMessage "Current user is not logged in to Active Directory."
            return $false
        }
    } catch {
        DebugMessage "Failed to check Active Directory login status: $_"
        return $false
    }
}
#endregion isActiveDirectoryUser

#region isHostConnectivityValid
function isHostConnectivityValid {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$HostInfo
    )
    # Execute simple command on the host using defined authentication
    try {
        $scriptBlock = {
            try {
                Get-Date
            } catch {
                "ERROR: $($_.Exception.Message)"
            }
        }

        if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
            # Use current credentials for Active Directory authentication
            InfoMessage "Testing connectivity to $($HostInfo.host_addr) using $ENUM_ACTIVE_DIRECTORY authentication..."
            $result = Invoke-Command -ComputerName $HostInfo.host_addr -ScriptBlock $scriptBlock -ErrorAction Stop
        } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
            # Create credential object for explicit authentication
            $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)

            # Use session options for better compatibility
            $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            InfoMessage "Testing connectivity to $($HostInfo.host_addr) using $ENUM_CREDENTIALS authentication..."
            $result = Invoke-Command -ComputerName $HostInfo.host_addr -Credential $credential -ScriptBlock $scriptBlock -SessionOption $sessionOption -ErrorAction Stop
        } else {
            return $false
        }
        InfoMessage "Successfully connected to $($HostInfo.host_addr) with result: $result"
        # Check if result indicates an error
        if ($result -and $result.ToString().StartsWith("ERROR:")) {
            return $false
        }

        return $true
    } catch {
        return $false
    }
}
#endregion isHostConnectivityValid

#region EnsureHostsConnectivity
function EnsureHostsConnectivity {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries
    )

    # Fulfill credentials for hosts
    ensureHostCredentials -hostEntries $hostEntries

    # Check that all hosts have proper host_auth values
    foreach ($hostInfo in $hostEntries) {
        if ($hostInfo.host_auth -ne $ENUM_ACTIVE_DIRECTORY -and $hostInfo.host_auth -ne $ENUM_CREDENTIALS) {
            $hostInfo.issues += "Invalid host_auth value. Must be '$ENUM_ACTIVE_DIRECTORY' or '$ENUM_CREDENTIALS'"
            continue
        }
    }

    # Handle active_directory authentication
    $adHosts = @($hostEntries | Where-Object { $_.host_auth -eq $ENUM_ACTIVE_DIRECTORY })
    if ($adHosts.Count -gt 0) {
        # Ensure current user is domain user
        if (-not (isActiveDirectoryUser)) {
            foreach ($hostInfo in $adHosts) {
                $hostInfo.issues += "Current user is not logged in to Active Directory"
            }
        } else {
            foreach ($hostInfo in $adHosts) {
                # Check if host is IP address and try to resolve to hostname
                if ($hostInfo.host_addr -as [IPAddress]) {
                    $resolvedHostname = resolveIPToHostname -IPAddress $hostInfo.host_addr
                    if ($resolvedHostname) {
                        # Update host_addr to use the resolved hostname
                        $hostInfo.host_addr = $resolvedHostname
                        InfoMessage "Using resolved hostname $resolvedHostname for Active Directory authentication"
                    } else {
                        $hostInfo.issues += "Could not resolve IP $($hostInfo.host_addr) to hostname for $ENUM_ACTIVE_DIRECTORY auth"
                        continue
                    }
                }
            }
        }
    }

    # Handle credentials authentication
    $credHosts = @($hostEntries | Where-Object { $_.host_auth -eq $ENUM_CREDENTIALS })
    if ($credHosts.Count -gt 0) {

        # validate all host entries has an IP addresses
        $isError = $false
        foreach ($hostInfo in $credHosts) {
            if (-not ($hostInfo.host_addr -as [IPAddress])) {
                $hostInfo.issues += "Invalid host address '$($hostInfo.host_addr)'. Must be an IP address for $ENUM_CREDENTIALS authentication."
                $isError = $true
            }
        }
        if ($isError) {
            return @($hostEntries | Where-Object { $_.issues.Count -gt 0 })
        }

        try{
            addHostsToTrustedHosts -hostEntries $credHosts
        } catch {
            # print exception mesage
            ErrorMessage "$_"
            ErrorMessage "Failed to add hosts to TrustedHosts. Cannot proceed with $ENUM_CREDENTIALS authentication."
            Exit 1
        }
    }

    # Perform parallel connectivity testing for all hosts that passed validation
    $hostsToTest = @($hostEntries | Where-Object { $_.issues.Count -eq 0 })
    if ($hostsToTest.Count -gt 0) {
        testHostsConnectivityInParallel -hostEntries $hostsToTest -MaxConcurrency $script:MaxConcurrency
    }

    $badHosts = @($hostEntries | Where-Object { $_.issues.Count -gt 0 })

    return $badHosts
}
#endregion EnsureHostsConnectivity

#region testHostsConnectivityInParallel
function testHostsConnectivityInParallel {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$hostEntries,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10
    )

    # Connectivity test job logic
    $connectivityJobScript = {
        param($HostInfo, $ENUM_ACTIVE_DIRECTORY, $ENUM_CREDENTIALS)

        function InfoMessageCJS { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - ConnJob - [INFO] $message"}

        # Connectivity test logic (same as isHostConnectivityValid but in job)
        try {
            $scriptBlock = {
                try {
                    Get-Date
                } catch {
                    "ERROR: $($_.Exception.Message)"
                }
            }

            if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                InfoMessageCJS "Testing connectivity to $($HostInfo.host_addr) using $ENUM_ACTIVE_DIRECTORY authentication..."
                $result = Invoke-Command -ComputerName $HostInfo.host_addr -ScriptBlock $scriptBlock -ErrorAction Stop
            } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
                $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
                $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                InfoMessageCJS "Testing connectivity to $($HostInfo.host_addr) using $ENUM_CREDENTIALS authentication..."
                $result = Invoke-Command -ComputerName $HostInfo.host_addr -Credential $credential -ScriptBlock $scriptBlock -SessionOption $sessionOption -ErrorAction Stop
            } else {
                return @{ Success = $false; Error = "Invalid authentication method" }
            }

            InfoMessageCJS "Successfully connected to $($HostInfo.host_addr) with result: $result"

            # Check if result indicates an error
            if ($result -and $result.ToString().StartsWith("ERROR:")) {
                return @{ Success = $false; Error = "Remote command execution failed: $result" }
            }

            return @{ Success = $true; Error = $null }
        } catch {
            return @{ Success = $false; Error = $_.Exception.Message }
        }
    }

    # Result processor
    $resultProcessor = {
        param($JobInfo)

        $job = $JobInfo.Job
        $hostInfo = $JobInfo.Item

        if ($job.State -eq 'Completed') {
            $testResult = Receive-Job -Job $job
            if ($testResult -and $testResult.Success) {
                InfoMessage "Successfully verified connectivity to $($hostInfo.host_addr)"
            } else {
                $errorMsg = if ($testResult.Error) { $testResult.Error } else { "Unknown connectivity error" }
                $hostInfo.issues += "Failed to connect to host using $($hostInfo.host_auth) authentication: $errorMsg"
                }
        } else {
            $stdErrOut = Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
            $errorMsg = "Connectivity test job failed for $($hostInfo.host_addr). State: $($job.State). $stdErrOut"
            $hostInfo.issues += $errorMsg
        }
        Remove-Job -Job $job -Force
    }

    # Enhanced job script that includes constants
    $jobScriptWithConstants = {
        param($hostInfo)
        & ([ScriptBlock]::Create($using:connectivityJobScript)) $hostInfo $using:ENUM_ACTIVE_DIRECTORY $using:ENUM_CREDENTIALS
    }

    # Use generic batch processor
    Start-BatchJobProcessor -Items $hostEntries -JobScriptBlock $jobScriptWithConstants -ResultProcessor $resultProcessor -MaxConcurrency $MaxConcurrency -JobDescription "ConnectivityTest"
}
#endregion testHostsConnectivityInParallel
