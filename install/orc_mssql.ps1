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

#region PrepSQLStr
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

    # Check if any hosts are missing SQL credentials
    foreach ($hostInfo in $Config.hosts) {
        if (-not $hostInfo.sql_user -or -not $hostInfo.sql_pass) {
            $commonCredentialsNeeded = $true
            break
        }
    }

    DebugMessage "Common SQL credentials needed: $commonCredentialsNeeded"
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
            if (-not $hostInfo.sql_user) {
                Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "sql_user" -Value $defaultSqlUser -Force
            }
            if (-not $hostInfo.sql_pass) {
                Add-Member -InputObject $hostInfo -MemberType NoteProperty -Name "sql_pass" -Value $defaultSqlPass -Force
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

        # Build the connection string
        $connectionStringParts = $connectionParams.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
        $connectionString = [string]::Join(';', $connectionStringParts)

        # Add connection string to host object
        $hostInfo | Add-Member -MemberType NoteProperty -Name "sql_connection_string" -Value $connectionString -Force

        # Log the connection string (with masked password)
        $LogSqlConnectionString = Sanitize $connectionString
        DebugMessage "Prepared SQL connection string for host $($hostInfo.host_addr): $LogSqlConnectionString"
    }

    ImportantMessage "Successfully prepared SQL connection strings for all hosts"
    return $true
}
#endregion PrepSQLStr

#endregion SQL
