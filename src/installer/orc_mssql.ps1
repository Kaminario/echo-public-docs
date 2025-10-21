#region SQL

#region TestSQLConnectionRemote
function TestSQLConnectionRemote {
    <#
    .SYNOPSIS
        Tests SQL Server connection on a remote host via PowerShell remoting.

    .DESCRIPTION
        Executes SQL connection test on the remote host where SQL Server is running.
        Uses existing host authentication (Active Directory or Credentials).

    .PARAMETER HostInfo
        Host object containing connection information and credentials

    .PARAMETER ConnectionString
        SQL Server connection string to test

    .OUTPUTS
        Returns $true if connection succeeds, $false otherwise
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$HostInfo,

        [Parameter(Mandatory=$true)]
        [string]$ConnectionString
    )

    $scriptBlock = {
        param($ConnString)
        try {
            $sqlConnection = New-Object System.Data.SqlClient.SqlConnection($ConnString)
            $sqlConnection.Open()
            $sqlConnection.Close()
            return @{ Success = $true; Error = $null }
        } catch {
            return @{ Success = $false; Error = $_.Exception.Message }
        }
    }

    try {
        # Use the same authentication method already validated by EnsureHostsConnectivity
        if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
            # Use current domain credentials (Kerberos)
            $result = Invoke-Command -ComputerName $HostInfo.host_addr `
                                     -ScriptBlock $scriptBlock `
                                     -ArgumentList $ConnectionString `
                                     -ErrorAction Stop
        }
        elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
            # Use explicit credentials
            $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
            $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

            $result = Invoke-Command -ComputerName $HostInfo.host_addr `
                                     -Credential $credential `
                                     -SessionOption $sessionOption `
                                     -ScriptBlock $scriptBlock `
                                     -ArgumentList $ConnectionString `
                                     -ErrorAction Stop
        }
        else {
            ErrorMessage "Invalid host_auth value for $($HostInfo.host_addr): $($HostInfo.host_auth)"
            return $false
        }

        if ($result.Success) {
            InfoMessage "SQL credential validation successful for $($HostInfo.host_addr)"
            return $true
        } else {
            DebugMessage "SQL credential validation failed for $($HostInfo.host_addr): $($result.Error)"
            return $false
        }
    } catch {
        ErrorMessage "Failed to test SQL connection on $($HostInfo.host_addr): $_"
        return $false
    }
}
#endregion TestSQLConnectionRemote

#region TestSQLCredentialsInParallel
function TestSQLCredentialsInParallel {
    <#
    .SYNOPSIS
        Tests SQL credentials in parallel across multiple hosts.

    .DESCRIPTION
        Executes SQL connection tests concurrently using the batch job processor.
        Updates host issues array with connection failures.

    .PARAMETER HostEntries
        Array of host objects to test

    .PARAMETER MaxConcurrency
        Maximum number of concurrent tests (default: 10)
    #>
    param (
        [Parameter(Mandatory=$true)]
        [Array]$HostEntries,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10
    )

    # SQL connection test job logic
    $sqlTestJobScript = {
        param($HostInfo, $ENUM_ACTIVE_DIRECTORY, $ENUM_CREDENTIALS, $GetMSSQLHostPortsScript)

        function InfoMessageSQL { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - SQLJob - [INFO] $message"}
        function DebugMessageSQL { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - SQLJob - [DEBUG] $message"}
        function WarningMessageSQL { param($message) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - SQLJob - [WARN] $message"}

        # Remote script that will execute on target host
        $remoteTestScript = {
            param($ConnectionString, $GetMSSQLHostPortsScript)

            # Define logging functions (used by both this script and GetMSSQLHostPorts)
            function InfoMessage { param($m) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [INFO] $m" }
            function DebugMessage { param($m) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [DEBUG] $m" }
            function WarningMessage { param($m) Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff') - Host[$env:COMPUTERNAME] - [WARN] $m" }

            # Define GetMSSQLHostPorts in remote scope
            $GetMSSQLHostPortsFunc = [ScriptBlock]::Create($GetMSSQLHostPortsScript)
            function GetMSSQLHostPorts { & $GetMSSQLHostPortsFunc }

            # Parse connection string
            $baseParams = @{}
            $parts = $ConnectionString.Trim() -split ';'
            foreach ($part in $parts) {
                if ($part.Trim()) {
                    $key, $value = $part -split '=', 2
                    $baseParams[$key.Trim()] = $value.Trim()
                }
            }

            # Build list of servers to test
            $serversToTest = @()

            if ($baseParams.ContainsKey('Server') -and $baseParams['Server'] -ne '') {
                # Case 1: Server specified - list with only one item
                InfoMessage "Server specified: $($baseParams['Server'])"
                $serversToTest = @($baseParams['Server'])
            } else {
                # Case 2: Server missing - discover and return list
                InfoMessage "No server specified, performing auto-discovery..."
                try {
                    $serversToTest = GetMSSQLHostPorts
                } catch {
                    return @{ Success = $false; Error = "Auto-discovery failed: $($_.Exception.Message)"; ErrorType = 'connection_error' }
                }
            }

            if ($serversToTest.Count -eq 0) {
                return @{ Success = $false; Error = "No SQL Server endpoints found"; ErrorType = 'connection_error' }
            }

            InfoMessage "Testing $($serversToTest.Count) endpoint(s)..."

            # Test each server in the list
            $lastError = $null
            $lastErrorType = 'unknown'

            foreach ($serverEndpoint in $serversToTest) {
                $testParams = $baseParams.Clone()
                $testParams['Server'] = $serverEndpoint
                $testConnString = ($testParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ';'

                DebugMessage "Testing: $serverEndpoint"
                try {
                    $sqlConn = New-Object System.Data.SqlClient.SqlConnection($testConnString)
                    $sqlConn.Open()
                    $sqlConn.Close()
                    InfoMessage "Success at: $serverEndpoint"
                    return @{ Success = $true; Error = $null; ErrorType = $null; ConnectionString = $testConnString }
                } catch {
                    $errorMessage = $_.Exception.Message
                    DebugMessage "Failed: $errorMessage"

                    # Categorize error type
                    if ($errorMessage -match 'Login failed|password|authentication|user') {
                        $lastErrorType = 'credential_error'
                        DebugMessage "Error categorized as: credential_error"
                    } elseif ($errorMessage -match 'server|timeout|network|could not open a connection|connection|host|address|endpoint') {
                        $lastErrorType = 'connection_error'
                        DebugMessage "Error categorized as: connection_error"
                    } else {
                        $lastErrorType = 'unknown'
                        DebugMessage "Error categorized as: unknown"
                    }

                    $lastError = $errorMessage
                }
            }

            return @{ Success = $false; Error = "Failed to connect to any SQL Server endpoint. Last error: $lastError"; ErrorType = $lastErrorType }
        }

        try {
            InfoMessageSQL "Testing SQL credentials for host $($HostInfo.host_addr)..."

            # Execute remote test
            $result = $null
            if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                $result = Invoke-Command -ComputerName $HostInfo.host_addr `
                                         -ScriptBlock $remoteTestScript `
                                         -ArgumentList $HostInfo.sql_connection_string, $GetMSSQLHostPortsScript `
                                         -ErrorAction Stop
            }
            elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
                $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
                $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                $result = Invoke-Command -ComputerName $HostInfo.host_addr `
                                         -Credential $credential `
                                         -SessionOption $sessionOption `
                                         -ScriptBlock $remoteTestScript `
                                         -ArgumentList $HostInfo.sql_connection_string, $GetMSSQLHostPortsScript `
                                         -ErrorAction Stop
            }
            else {
                return @{ Success = $false; Error = "Invalid host_auth value"; ErrorType = 'connection_error' }
            }

            if ($result.Success) {
                InfoMessageSQL "SQL validation successful for $($HostInfo.host_addr)"
                return @{ Success = $true; Error = $null; ErrorType = $null; ConnectionString = $result.ConnectionString }
            } else {
                return @{ Success = $false; Error = $result.Error; ErrorType = $result.ErrorType }
            }
        } catch {
            return @{ Success = $false; Error = "Remote test failed: $($_.Exception.Message)"; ErrorType = 'connection_error' }
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
                $sanitizedConnString = Sanitize $testResult.ConnectionString
                DebugMessage "SQL validation succeeded for $($hostInfo.host_addr), returned connection string: $sanitizedConnString"
                InfoMessage "SQL credential validation successful for $($hostInfo.host_addr)"
            } else {
                $errorMsg = if ($testResult.Error) { $testResult.Error } else { "Unknown SQL connection error" }
                $errorType = if ($testResult.ErrorType) { $testResult.ErrorType } else { "unknown" }
                DebugMessage "SQL validation failed for $($hostInfo.host_addr) - ErrorType: $errorType, Error: $errorMsg"

                # ALWAYS add to issues with error type embedded in the message
                # Format: "SQL validation failed [error_type]: error message"
                $issueMsg = "SQL validation failed [$errorType]: $errorMsg"
                DebugMessage "Adding to issues: $issueMsg"
                $hostInfo.issues += $issueMsg

                # Log appropriate message based on error type
                if ($errorType -eq 'connection_error') {
                    WarningMessage "SQL connection failed for $($hostInfo.host_addr) due to server configuration issue: $errorMsg"
                } else {
                    WarningMessage "SQL credential validation failed for $($hostInfo.host_addr): $errorMsg"
                }
            }
        } else {
            $stdErrOut = Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
            $errorMsg = "SQL validation job failed for $($hostInfo.host_addr). State: $($job.State). $stdErrOut"
            DebugMessage "Job state is $($job.State), adding to issues"
            $hostInfo.issues += "SQL validation failed [unknown]: $errorMsg"
        }
        DebugMessage ">>>>>>>>>>>>Removing job $($job.Id)"
        Remove-Job -Job $job -Force
        DebugMessage "<<<<<<<<<<<<Job $($job.Id) removed"
    }

    # Get GetMSSQLHostPorts function definition as string to pass to remote job
    $getMSSQLHostPortsFunc = Get-Command GetMSSQLHostPorts
    $getMSSQLHostPortsScript = $getMSSQLHostPortsFunc.Definition

    # Enhanced job script that includes constants and discovery function
    $jobScriptWithConstants = {
        param($hostInfo)
        & ([ScriptBlock]::Create($using:sqlTestJobScript)) $hostInfo $using:ENUM_ACTIVE_DIRECTORY $using:ENUM_CREDENTIALS $using:getMSSQLHostPortsScript
    }

    # Use generic batch processor
    Start-BatchJobProcessor -Items $HostEntries -JobScriptBlock $jobScriptWithConstants -ResultProcessor $resultProcessor -MaxConcurrency $MaxConcurrency -JobDescription "SQLValidation"
}
#endregion TestSQLCredentialsInParallel

#region ValidateHostSQLCredentials
function ValidateHostSQLCredentials {
    <#
    .SYNOPSIS
        Validates SQL credentials for all hosts requiring Agent installation.

    .DESCRIPTION
        Tests SQL Server connection for each host using TestSQLConnectionRemote.
        Prompts for new credentials if validation fails and retries until successful.
        Only retests hosts that previously failed validation.
        User can press Ctrl+C to abort the process.

    .PARAMETER Config
        Configuration object containing all host information

    .OUTPUTS
        Returns $true if all SQL credentials are valid, $false if user cancels
    #>
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )

    $goodHost = @($Config.hosts | Where-Object { $_.issues.Count -eq 0 })

    # Check if any hosts need Agent installation
    $hostsNeedingAgent = @($goodHost | Where-Object { $_.install_agent -eq $true })

    if ($hostsNeedingAgent.Count -eq 0) {
        InfoMessage "No hosts require Agent installation - skipping SQL credential validation"
        return $true
    }

    InfoMessage "Validating SQL credentials for $($hostsNeedingAgent.Count) host(s)..."

    $attempt = 1

    while ($hostsNeedingAgent.Count -gt 0) {
        # Test SQL credentials in parallel for remaining hosts
        InfoMessage "Testing SQL credentials in parallel (Attempt $attempt)..."
        TestSQLCredentialsInParallel -HostEntries $hostsNeedingAgent -MaxConcurrency $script:MaxConcurrency

        # Collect hosts that failed validation (have issues)
        $failedHosts = @($hostsNeedingAgent | Where-Object { $_.issues.Count -gt 0 })
        $successfulHosts = @($hostsNeedingAgent | Where-Object { $_.issues.Count -eq 0 })
        
        # Show progress after each attempt
        InfoMessage "SQL validation attempt $attempt results: $($successfulHosts.Count) successful, $($failedHosts.Count) failed"

        # Only clear issues and retry for hosts with credential_error
        # All other errors (connection_error, unknown) are not retriable
        $hostsToRetry = @()
        foreach ($hostInfo in $failedHosts) {
            $hasCredentialError = $false
            foreach ($issue in $hostInfo.issues) {
                if ($issue -match '\[credential_error\]') {
                    $hasCredentialError = $true
                    break
                }
            }

            if ($hasCredentialError) {
                # Credential error - clear issues and retry
                DebugMessage "Host $($hostInfo.host_addr) has credential_error, clearing issues for retry"
                $hostInfo.issues = @()
                $hostsToRetry += $hostInfo
            } else {
                # Non-retriable error - keep issues, don't retry
                DebugMessage "Host $($hostInfo.host_addr) has non-retriable error, keeping issue - host will be skipped"
                WarningMessage "Host $($hostInfo.host_addr) has non-retriable SQL validation error and will be skipped"
            }
        }

        # Update to only retry hosts with credential errors
        $hostsNeedingAgent = @($hostsToRetry)

        # If all hosts passed, we're done
        if ($hostsNeedingAgent.Count -eq 0) {
            # Generate comprehensive validation summary
            $allHostsNeedingAgent = @($Config.hosts | Where-Object { $_.install_agent -eq $true })
            $successfulHosts = @($allHostsNeedingAgent | Where-Object { $_.issues.Count -eq 0 })
            $failedHosts = @($allHostsNeedingAgent | Where-Object { $_.issues.Count -gt 0 })
            
            if ($failedHosts.Count -eq 0) {
                ImportantMessage "SQL credential validation completed successfully for all hosts"
            } else {
                ImportantMessage "SQL credential validation completed with some failures"
            }
            InfoMessage "Validation Summary:"
            InfoMessage "  Successful hosts: $($successfulHosts.Count)"
            InfoMessage "  Failed hosts: $($failedHosts.Count)"
            InfoMessage "  Total hosts requiring Agent: $($allHostsNeedingAgent.Count)"
            
            if ($successfulHosts.Count -gt 0) {
                InfoMessage "Hosts with successful SQL validation:"
                foreach ($h in $successfulHosts) {
                    InfoMessage "  - $($h.host_addr)"
                }
            }
            
            if ($failedHosts.Count -gt 0) {
                WarningMessage "Hosts with SQL validation failures (will be skipped):"
                foreach ($h in $failedHosts) {
                    $issues = $h.issues -join '; '
                    WarningMessage "  - $($h.host_addr) - $issues"
                }
            }
            
            return $true
        }

        # Prompt for new credentials
        $failedAddresses = $hostsNeedingAgent | ForEach-Object { $_.host_addr }
        WarningMessage "SQL credential validation failed for hosts: $($failedAddresses -join ', ')"
        WarningMessage "Please provide new SQL credentials (press Ctrl+C to abort)"

        $newCred = Get-Credential -Message "Enter SQL Server credentials"
        if (-not $newCred) {
            ErrorMessage "User cancelled SQL credential prompt. Cannot proceed without valid SQL Server credentials."
            return $false
        }

        # Update only failed hosts with new credentials and rebuild connection strings
        $newUser = $newCred.UserName
        $newPass = $newCred.GetNetworkCredential().Password

        foreach ($hostInfo in $hostsNeedingAgent) {
            # Update credentials
            $hostInfo.sql_user = $newUser
            $hostInfo.sql_pass = $newPass

            # Update credentials in the stored connection params hashtable
            $hostInfo.sql_connection_params['User ID'] = $newUser
            $hostInfo.sql_connection_params['Password'] = $newPass

            # Rebuild connection string from updated params
            $connectionStringParts = $hostInfo.sql_connection_params.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
            $hostInfo.sql_connection_string = [string]::Join(';', $connectionStringParts)

            $LogSqlConnectionString = Sanitize $hostInfo.sql_connection_string
            DebugMessage "Updated SQL connection string for host $($hostInfo.host_addr): $LogSqlConnectionString"
        }

        $attempt++
    }

    # Should never reach here, but just in case
    return $true
}
#endregion ValidateHostSQLCredentials

#region UpdateHostSqlConnectionString
function UpdateHostSqlConnectionString {
    param (
        [PSCustomObject]$Config
    )

    # each host in $config.hosts can contain "sql_user", and "sql_pass"
    # if missing ask for credentials and use it for all hosts without credentials
    # create a connectrion string for each host and update $config.hosts with "sql_connection_string"
    DebugMessage "Checking SQL credentials for each host..."

    $defaultSqlUser = $null
    $defaultSqlPass = $null
    $shouldPromptForCredentials = $false

    $goodHost = @($config.hosts | Where-Object { $_.issues.Count -eq 0 })

    # Check if any hosts need Agent installation
    $hostsNeedingAgent = @($goodHost | Where-Object { $_.install_agent -eq $true })

    if ($hostsNeedingAgent.Count -eq 0) {
        InfoMessage "No hosts require Agent installation - skipping SQL credential collection"
        return $true
    }

    # Check if any hosts requiring Agent are missing SQL credentials
    foreach ($hostInfo in $hostsNeedingAgent) {
        DebugMessage "Checking host $($hostInfo.host_addr) - sql_user='$($hostInfo.sql_user)' sql_pass='$($hostInfo.sql_pass)'"
        if ([string]::IsNullOrEmpty($hostInfo.sql_user) -or [string]::IsNullOrEmpty($hostInfo.sql_pass)) {
            DebugMessage "Host $($hostInfo.host_addr) missing credentials, setting shouldPromptForCredentials=true"
            $shouldPromptForCredentials = $true
            break
        }
    }

    InfoMessage "Should prompt for SQL credentials: $shouldPromptForCredentials"
    # If any hosts are missing credentials, prompt user for credentials
    if ($shouldPromptForCredentials) {
        DebugMessage "Prompting user for SQL credentials"
        WarningMessage "Some hosts are missing SQL credentials. Please provide credentials to use for all hosts with missing credentials."
        $credSQL = Get-Credential -Message "Enter SQL Server credentials"

        if (-not $credSQL) {
            DebugMessage "User cancelled credential prompt"
            ErrorMessage "No credentials provided. Cannot proceed without valid SQL Server credentials."
            return $false
        }

        DebugMessage "Credentials received, extracting username and password"
        $defaultSqlUser = $credSQL.UserName
        $defaultSqlPass = $credSQL.GetNetworkCredential().Password
        DebugMessage "Applying credentials to hosts with missing sql_user or sql_pass"

        # Apply credentials to all hosts that are missing either username or password
        foreach ($hostInfo in $Config.hosts) {
            if ([string]::IsNullOrEmpty($hostInfo.sql_user) -or [string]::IsNullOrEmpty($hostInfo.sql_pass)) {
                DebugMessage "Updating both sql_user and sql_pass for host $($hostInfo.host_addr)"
                $hostInfo.sql_user = $defaultSqlUser
                $hostInfo.sql_pass = $defaultSqlPass
            }
        }
    }

    foreach ($hostInfo in $Config.hosts) {
        # Build connection string parameters
        $hostSqlPass = if ($hostInfo.sql_pass -is [System.Security.SecureString]) {
            DebugMessage "Retrieving SQL password for host $($hostInfo.host_addr)"
            ConvertSecureStringToPlainText -SecureString $hostInfo.sql_pass
        } else {
            $hostInfo.sql_pass
        }
        $connectionParams = @{
            'User ID' = $hostInfo.sql_user
            'Password' = $hostSqlPass
            'Application Name' = 'SilkAgent'
        }

        # Add SQL Server parameter if specified (bypasses endpoint discovery)
        if ($hostInfo.sql_server) {
            $connectionParams['Server'] = $hostInfo.sql_server
            InfoMessage "Using specified SQL Server for host $($hostInfo.host_addr): $($hostInfo.sql_server)"
        } else {
            InfoMessage "No SQL Server specified for host $($hostInfo.host_addr), endpoint discovery will be performed during installation"
        }

        # Store parsed connection parameters for later reuse
        $hostInfo.sql_connection_params = $connectionParams

        # Build the connection string
        $connectionStringParts = $connectionParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $connectionString = [string]::Join(';', $connectionStringParts)

        # Add connection string to host object
        $hostInfo.sql_connection_string = $connectionString

        # Log the connection string (with masked password)
        $LogSqlConnectionString = Sanitize $connectionString
        DebugMessage "Prepared SQL connection string for host $($hostInfo.host_addr): $LogSqlConnectionString"
    }

    ImportantMessage "Successfully prepared SQL connection strings for all hosts"
    return $true
}
#endregion UpdateHostSqlConnectionString

#endregion SQL
