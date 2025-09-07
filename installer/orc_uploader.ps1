#region InstallerUploader

#region EnsureLocalInstallers
function EnsureLocalInstallers {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    # Ensure installers present in local directory

    $localPaths = @{}
    $requiredInstallers = @('agent', 'vss')

    # Process all required installers
    foreach ($installerType in $requiredInstallers) {
        $installerConfig = $Config.installers.$installerType
        if (-not $installerConfig) {
            ErrorMessage "Missing required $installerType installer configuration in config.installers"
            return $null
        }

        # If path is provided and file exists, use it directly
        if ($InstallerConfig.path) {
            if (Test-Path $InstallerConfig.path) {
                InfoMessage "Using existing $InstallerType installer at: $($InstallerConfig.path)"
                $installerPath = $InstallerConfig.path
            } else {
                # If path is provided but doesn't exist
                ErrorMessage "$InstallerType installer path specified but file not found: $($InstallerConfig.path)"
                return $null
            }
        } else {
            if (-not $InstallerConfig.url) {
                ErrorMessage "No URL specified for $InstallerType installer in configuration"
                return $null
            }
            $installerPath = downloadInstaller -InstallerURL $InstallerConfig.url -CacheDir $SilkEchoInstallerCacheDir -InstallerType $installerType
        }

        if ($installerPath) {
            $localPaths[$installerType] = $installerPath
        } else {
            ErrorMessage "Failed to ensure $installerType installer is available locally"
            return $null
        }
    }

    InfoMessage "All installers are available locally"
    return $localPaths
}
#endregion EnsureLocalInstallers

#region downloadInstaller
function downloadInstaller {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InstallerURL,
        [Parameter(Mandatory=$true)]
        [string]$CacheDir,
        [Parameter(Mandatory=$true)]
        [string]$InstallerType
    )


    if (-not $InstallerURL) {
        ErrorMessage "No URL specified for $InstallerType installer in configuration"
        return $null
    }

    # If URL is provided, download to cache

    $fileName = "$InstallerType-installer.exe"
    $localPath = Join-Path $CacheDir $fileName

    # Check if already cached
    if (Test-Path $localPath) {
        InfoMessage "$InstallerType installer already cached at: $localPath"
        return $localPath
    }

    InfoMessage "Downloading $InstallerType installer from: $($InstallerURL)"
    try {
        ensureCacheDir $CacheDir
        # Use Invoke-WebRequest to download the file
        Invoke-WebRequest -Uri $InstallerURL -OutFile $localPath -UseBasicParsing

        if (Test-Path $localPath) {
            $fileSize = (Get-Item $localPath).Length
            InfoMessage "Downloaded $InstallerType installer ($fileSize bytes) to: $localPath"
            return $localPath
        } else {
            ErrorMessage "Download completed but file not found at: $localPath"
        }
    } catch {
        ErrorMessage "Failed to download $InstallerType installer: $_"
    }
    return $null
}
#endregion downloadInstaller

#region UploadInstallersToHosts
function UploadInstallersToHosts {
    param (
        [Parameter(Mandatory=$true)]
        [Array]$HostInfos,
        [Parameter(Mandatory=$true)]
        [hashtable]$LocalPaths,
        [Parameter(Mandatory=$false)]
        [int]$MaxConcurrency = 10
    )

    InfoMessage "Starting parallel upload of installers to $($HostInfos.Count) host(s) with max concurrency: $MaxConcurrency..."

    # Start upload jobs for all hosts
    $jobs = @()
    $batchCount = 0

    foreach ($hostInfo in $HostInfos) {
        # Wait if we've reached max concurrency
        while ($jobs.Count -ge $MaxConcurrency) {
            $completedJob = $jobs | Where-Object { $_.Job.State -ne 'Running' } | Select-Object -First 1
            if ($completedJob) {
                $processJobResult = processUploadJobResult -JobInfo $completedJob
                $jobs = @($jobs | Where-Object { $_.Job.Id -ne $completedJob.Job.Id })
                if (-not $processJobResult) {
                    # Clean up remaining jobs and return failure
                    $jobs | ForEach-Object { Remove-Job $_.Job -Force }
                    return $false
                }
            } else {
                Start-Sleep -Milliseconds 100
            }
        }

        # Start new job
        InfoMessage "Starting upload job for host: $($HostInfo.host_addr)"
        $job = Start-Job -ScriptBlock {
            param($HostInfo, $LocalPaths, $ENUM_ACTIVE_DIRECTORY, $ENUM_CREDENTIALS)

            function DebugMessage { param($message) Write-Host "[DEBUG] $message" -ForegroundColor Gray }
            function InfoMessage { param($message) Write-Host "[INFO] $message" -ForegroundColor Green }
            function ErrorMessage { param($message) Write-Host "[ERROR] $message" -ForegroundColor Red }

            # Simplified inline version of copyInstallersToHost
            $remoteRelDir = "Temp\silk-echo-install-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            $remoteDir = "C:\$remoteRelDir"
            $remotePaths = @{}

            try {
                # Create remote directory
                $scriptBlock = {
                    param($RemoteDir)
                    if (-not (Test-Path $RemoteDir)) {
                        New-Item -ItemType Directory -Path $RemoteDir -Force | Out-Null
                        Write-Output "Created remote directory: $RemoteDir"
                    }
                    return $RemoteDir
                }

                if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                    $result = Invoke-Command -ComputerName $HostInfo.host_addr -ScriptBlock $scriptBlock -ArgumentList $remoteDir -ErrorAction Stop
                } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
                    $credential = New-Object System.Management.Automation.PSCredential($HostInfo.host_user, $HostInfo.host_pass)
                    $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                    $result = Invoke-Command -ComputerName $HostInfo.host_addr -Credential $credential -ScriptBlock $scriptBlock -SessionOption $sessionOption -ArgumentList $remoteDir -ErrorAction Stop
                }

                DebugMessage "Remote directory prepared on $($HostInfo.host_addr): $remoteDir"

                # Copy each installer file
                foreach ($installerType in $LocalPaths.Keys) {
                    $localPath = $LocalPaths[$installerType]
                    $fileName = Split-Path $localPath -Leaf



                    DebugMessage "Copying $installerType installer to $($HostInfo.host_addr)..."
                    $remotePath = "$remoteDir\$fileName"

                    if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                        $remotePathUnc = "\\$($HostInfo.host_addr)\C$\$remoteRelDir\$fileName"
                        Copy-Item -Path $localPath -Destination $remotePathUnc -Force -ErrorAction Stop
                    } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {

                        $session = New-PSSession -ComputerName $HostInfo.host_addr -Credential $credential -SessionOption $sessionOption -ErrorAction Stop
                        Copy-Item -Path $localPath -Destination $remotePath -ToSession $session -Force -ErrorAction Stop
                        Remove-PSSession $session -ErrorAction SilentlyContinue
                    }
                    $remotePaths[$installerType] = $remotePath
                    DebugMessage "Copied $installerType installer to: $remotePath"
                }

                InfoMessage "All installers uploaded to $($HostInfo.host_addr)"
                return $remotePaths

            } catch {
                ErrorMessage "Failed to upload installers to $($HostInfo.host_addr): $_"
                return $null
            }
        } -ArgumentList $hostInfo, $LocalPaths, $ENUM_ACTIVE_DIRECTORY, $ENUM_CREDENTIALS

        $jobs += @{
            Job = $job
            HostInfo = $hostInfo
        }

        $batchCount++
        if ($batchCount % $MaxConcurrency -eq 0) {
            InfoMessage "Started upload jobs for $batchCount hosts..."
        }
    }

    # Wait for remaining jobs to complete
    InfoMessage "Waiting for remaining upload jobs to complete..."
    while ($jobs.Count -gt 0) {
        $completedJob = $jobs | Where-Object { $_.Job.State -ne 'Running' } | Select-Object -First 1
        if ($completedJob) {
            $processJobResult = processUploadJobResult -JobInfo $completedJob
            $jobs = @($jobs | Where-Object { $_.Job.Id -ne $completedJob.Job.Id })
            if (-not $processJobResult) {
                # Clean up remaining jobs and return failure
                $jobs | ForEach-Object { Remove-Job $_.Job -Force }
                return $false
            }
        } else {
            Start-Sleep -Milliseconds 100
        }
    }

    InfoMessage "Completed uploading installers to all hosts successfully"
    return $true
}

function processUploadJobResult {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$JobInfo
    )

    $job = $JobInfo.Job
    $hostInfo = $JobInfo.HostInfo

    if ($job.State -eq 'Completed') {
        $remoteInstallerPaths = Receive-Job -Job $job
        if ($remoteInstallerPaths) {
            # Store remote paths in host object for use by InstallSingleHost
            $hostInfo | Add-Member -MemberType NoteProperty -Name "remote_installer_paths" -Value $remoteInstallerPaths -Force
            InfoMessage "Successfully uploaded installers to $($hostInfo.host_addr)"
            Remove-Job -Job $job -Force
            return $true
        } else {
            ErrorMessage "Failed to upload installers to $($hostInfo.host_addr)"
            Remove-Job -Job $job -Force
            return $false
        }
    } else {
        $errorMsg = if ($job.State -eq 'Failed') {
            Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
        } else {
            "Job timed out or failed"
        }
        ErrorMessage "Upload job failed for $($hostInfo.host_addr): $errorMsg"
        Remove-Job -Job $job -Force
        return $false
    }
}
#endregion UploadInstallersToHosts


#endregion InstallerUploader
