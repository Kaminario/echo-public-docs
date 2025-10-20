#region SQL

#region getSqlCredentials
function getSqlCredentials {
    param (
        [string]$Username,
        [string]$Password
    )
    # Check if user id is set, and ask for credentials if not
    while (-not $Username -or -not $Password) {
        WarningMessage "Please provide SQL credentials for the connection string."
        $cred = Get-Credential -Message "Enter your SQL Server credentials"
        if ($cred) {
            return $cred
        } else {
            ErrorMessage "No credentials provided. Cannot proceed without valid SQL Server credentials."
        }
    }
}
#endregion getSqlCredentials

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
        $failedHosts = @()

        # Test SQL credentials for remaining hosts
        foreach ($hostInfo in $hostsNeedingAgent) {
            InfoMessage "Testing SQL credentials for host $($hostInfo.host_addr) (Attempt $attempt)..."

            $isValid = TestSQLConnectionRemote -HostInfo $hostInfo -ConnectionString $hostInfo.sql_connection_string

            if (-not $isValid) {
                $failedHosts += $hostInfo
            }
        }

        # Update to only test failed hosts in next iteration
        $hostsNeedingAgent = @($failedHosts)

        # If all hosts passed, we're done
        if ($hostsNeedingAgent.Count -eq 0) {
            ImportantMessage "SQL credential validation successful for all hosts"
            return $true
        }

        # Prompt for new credentials
        $failedAddresses = $hostsNeedingAgent | ForEach-Object { $_.host_addr }
        WarningMessage "SQL credential validation failed for hosts: $($failedAddresses -join ', ')"
        WarningMessage "Please provide new SQL credentials (press Ctrl+C to abort)"

        $newCred = Get-Credential -Message "Enter SQL Server credentials"
        if (-not $newCred) {
            ErrorMessage "No credentials provided. Cannot proceed without valid SQL Server credentials."
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
    $commonCredentialsNeeded = $false

    $goodHost = @($config.hosts | Where-Object { $_.issues.Count -eq 0 })

    # Check if any hosts need Agent installation
    $hostsNeedingAgent = @($goodHost | Where-Object { $_.install_agent -eq $true })

    if ($hostsNeedingAgent.Count -eq 0) {
        InfoMessage "No hosts require Agent installation - skipping SQL credential collection"
        return $true
    }

    # Check if any hosts requiring Agent are missing SQL credentials
    foreach ($hostInfo in $hostsNeedingAgent) {
        if (-not $hostInfo.sql_user -or -not $hostInfo.sql_pass) {
            $commonCredentialsNeeded = $true
            break
        }
    }

    InfoMessage "Common SQL credentials needed: $commonCredentialsNeeded"
    # If any hosts are missing credentials, ask for default credentials to use
    if ($commonCredentialsNeeded) {
        $commonSqlPass = if ($Config.common.sql_pass) {
            ConvertSecureStringToPlainText -SecureString $Config.common.sql_pass
        } else {
            $null
        }
        $credSQL = getSqlCredentials -Username $Config.common.sql_user -Password $commonSqlPass
        if ($credSQL) {
            $defaultSqlUser = $credSQL.UserName
            $defaultSqlPass = $credSQL.GetNetworkCredential().Password
        } else {
            ErrorMessage "Failed to get SQL credentials"
            return $false
        }
         # Create connection string for each host
        foreach ($hostInfo in $Config.hosts) {
            # Use host-specific credentials if available, otherwise use default
            # the sql_user/pass fields is always exist but may be null
            if (-not $hostInfo.sql_user) {
                $hostInfo.sql_user = $defaultSqlUser
            }
            if (-not $hostInfo.sql_pass) {
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
