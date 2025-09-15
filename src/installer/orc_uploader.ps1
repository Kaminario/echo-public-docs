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

    # Upload job logic
    $uploadJobScript = {
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
#UNCOMMENT
                # if ($HostInfo.host_auth -eq $ENUM_ACTIVE_DIRECTORY) {
                #     $remotePathUnc = "\\$($HostInfo.host_addr)\C$\$remoteRelDir\$fileName"
                #     Copy-Item -Path $localPath -Destination $remotePathUnc -Force -ErrorAction Stop
                # } elseif ($HostInfo.host_auth -eq $ENUM_CREDENTIALS) {
                #     $session = New-PSSession -ComputerName $HostInfo.host_addr -Credential $credential -SessionOption $sessionOption -ErrorAction Stop
                #     Copy-Item -Path $localPath -Destination $remotePath -ToSession $session -Force -ErrorAction Stop
                #     Remove-PSSession $session -ErrorAction SilentlyContinue
                # }
                $remotePaths[$installerType] = $remotePath
                DebugMessage "Copied $installerType installer to: $remotePath"
            }
            InfoMessage "All installers uploaded to $($HostInfo.host_addr)"
            return $remotePaths

        } catch {
            ErrorMessage "Failed to upload installers to $($HostInfo.host_addr): $_"
            return $null
        }
    }

    # Result processor
    $resultProcessor = {
        param($JobInfo)

        $job = $JobInfo.Job
        $hostInfo = $JobInfo.Item

        if ($job.State -eq 'Completed') {
            $remoteInstallerPaths = Receive-Job -Job $job
            if ($remoteInstallerPaths) {
                # Store remote paths in host object for use by InstallSingleHost
                $hostInfo.remote_installer_paths = $remoteInstallerPaths
                InfoMessage "Successfully uploaded installers to $($hostInfo.host_addr)"
            } else {
                AddHostIssueWithProgress -HostInfo $hostInfo -Issue "Failed to upload installers" -AllHosts $HostInfos
                ErrorMessage "Failed to upload installers to $($hostInfo.host_addr)"
            }
        } else {
            $stdErrOut = Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-String
            if ($job.State -eq 'Failed') {
                AddHostIssueWithProgress -HostInfo $hostInfo -Issue ("Job failed" + $stdErrOut) -AllHosts $HostInfos
            } else {
                AddHostIssueWithProgress -HostInfo $hostInfo -Issue ("Job failed to complete. State: $($job.State)" + $stdErrOut) -AllHosts $HostInfos
            }
            ErrorMessage "Upload job failed for $($hostInfo.host_addr): State $($job.State)"
        }
        Remove-Job -Job $job -Force
    }

    # Enhanced job script that includes constants and LocalPaths
    $jobScriptWithParams = {
        param($hostInfo)
        $ENUM_ACTIVE_DIRECTORY = "active_directory"
        $ENUM_CREDENTIALS = "credentials"
        & ([ScriptBlock]::Create($using:uploadJobScript)) $hostInfo $using:LocalPaths $ENUM_ACTIVE_DIRECTORY $ENUM_CREDENTIALS
    }

    # Use generic batch processor
    Start-BatchJobProcessor -Items $HostInfos -JobScriptBlock $jobScriptWithParams -ResultProcessor $resultProcessor -MaxConcurrency $MaxConcurrency -JobDescription "upload"

    # Check upload results and provide summary
    $successfulUploads = @($HostInfos | Where-Object { $_.remote_installer_paths })
    $failedUploads = @($HostInfos | Where-Object { -not $_.remote_installer_paths })

    if ($failedUploads.Count -gt 0) {
        WarningMessage "Upload failed for $($failedUploads.Count) hosts:"
        foreach ($hostInfo in $failedUploads) {
            WarningMessage " - $($hostInfo.host_addr)"
        }
    }

    if ($successfulUploads.Count -gt 0) {
        InfoMessage "Successfully uploaded installers to $($successfulUploads.Count) hosts"
    } else {
        ErrorMessage "Failed to upload installers to any hosts"
    }
}
#endregion UploadInstallersToHosts
#endregion InstallerUploader
