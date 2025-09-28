# Silk Echo Installer - Function Map and Context

## Function Map by Module

### **orchestrator.ps1** - Main Orchestration
- `MainOrchestrator`: Core installation orchestrator
  - Manages overall installation workflow
  - Handles installer caching, connectivity, authentication
  - Processes hosts in batches using fixed batch sizes
  - Collects results and generates summary

### **orc_invoke_remote_install.ps1** - Remote Job Execution
- `fetchStream`: Extracts and cleans output lines from job streams
- `FetchJobResult`: Processes job completion, determines success/failure
- `InstallSingleHost`: Starts remote PowerShell job for installation
- `ProcessSingleJobResult`: Safely processes completed jobs with error handling

### **orc_host_communication.ps1** - Connectivity Management
- `addHostsToTrustedHosts`: Adds hosts to PowerShell TrustedHosts list
- `ensureHostCredentials`: Validates/prompts for missing credentials
- `resolveIPToHostname`: Converts IPs to hostnames for AD authentication
- `isActiveDirectoryUser`: Checks if current user has AD authentication
- `isHostConnectivityValid`: Tests basic connectivity using auth method
- `EnsureHostsConnectivity`: Main function for connectivity validation

### **orc_uploader.ps1** - File Management
- `EnsureLocalInstallers`: Downloads/locates installer files locally
- `downloadInstaller`: Downloads files with caching support
- `UploadInstallersToHosts`: Uploads installers in parallel batches
- `processUploadJobResult`: Processes upload results, updates host objects

### **orc_config.ps1** - Configuration Processing
- `GenerateConfigTemplate`: Interactive configuration template creation
- `constructHosts`: Merges common config with individual host entries
- `ReadConfigFile`: Validates and parses JSON configuration
- `ensureInstallerDefault`: Sets default installer URLs

### **orc_logging.ps1** - Centralized Logging
- `LogTimeStamp`: Formatted timestamp generation
- `Sanitize`: Redacts sensitive information from logs
- `ArgsToSanitizedString`: Processes multiple arguments for logging
- `ErrorMessage`, `ImportantMessage`, `InfoMessage`, `DebugMessage`, `WarningMessage`: Logging functions

### **orc_flex_login.ps1** - Authentication
- `UpdateFlexAuthToken`: Obtains Flex API authentication token

### **orc_sdp.ps1** - SDP Integration
- `UpdateSDPCredentials`: Validates SDP credentials
- `GetSDPInfo`: Retrieves SDP information

### **orc_mssql.ps1** - SQL Server Integration
- `UpdateHostSqlConnectionString`: Creates SQL connection strings

### **orc_web_client.ps1** - HTTP Client
- `CallSelfCertEndpoint`, `CallSDPApi`, `CallFlexApi`: REST API calls

### **orc_requirements.ps1** - System Validation
- `EnsureRequirements`: Validates PowerShell version and admin privileges

### **orc_tracking.ps1** - Installation State Tracking
- `LoadCompletedHosts`: Loads simple completed hosts list from processing.json
- `SaveCompletedHosts`: Saves completed hosts list to JSON file with timestamp
- `IsHostCompleted`: Checks if host exists in completed hosts list to avoid duplicates
- `MarkHostCompleted`: Marks host as completed with current timestamp

### **orc_batch_installer.ps1** - Batch Installation Orchestration
- `StartBatchInstallation`: Coordinates parallel installation across multiple hosts with dynamic job scheduling
- `SaveInstallationResults`: Saves final installation results and generates comprehensive reports

### **orc_generic_batch_processor.ps1** - Generic Batch Processing Framework
- `Start-BatchJobProcessor`: Reusable dynamic parallel job processing engine with configurable concurrency
- Supports custom job scripts, result processors, and real-time progress tracking
- Used across upload, connectivity, and installation operations for consistent parallel processing

### **orc_constants_installer.ps1** - Installation-Specific Constants
- `INTERNAL_INSTALL_TIMEOUT_SECONDS`: Internal installation process timeout (110 seconds)
- Installation-specific timeout and processing constants

## Installation Workflow

1. **Pre-flight Checks**
   - `EnsureRequirements`: PowerShell version, admin privileges
   - `ReadConfigFile`: Configuration validation
   - `SkipCertificateCheck`: SSL certificate bypass setup
   - `ensureOutputDirectory`: Output directory and write permissions validation

2. **State Tracking Setup**
   - `LoadCompletedHosts`: Load simple completed hosts list from processing.json
   - `IsHostCompleted`: Filter out already completed hosts to avoid duplicates
   - **Automatic Resume**: Skip successfully completed hosts from previous runs

3. **Installer Preparation**
   - `EnsureLocalInstallers`: Download/locate installer files
   - Caches files in `$SilkEchoInstallerCacheDir`

4. **Connectivity Validation**
   - `EnsureHostsConnectivity`: Tests all hosts sequentially
   - **✅ FAULT-TOLERANT**: Failed hosts logged, script continues with valid hosts
   - **ISSUE**: Should be parallel per todo requirements
   - **FAILURE POINT**: Hosts marked with `host_connectivity_issue`

5. **Authentication Setup**
   - `UpdateHostSqlConnectionString`: SQL connection strings
   - `UpdateFlexAuthToken`: Flex API authentication
   - `UpdateSDPCredentials`: SDP credential validation

6. **File Distribution**
   - `UploadInstallersToHosts`: Parallel upload in batches
   - **✅ FAULT-TOLERANT**: Failed uploads logged, script continues with successful hosts
   - **FAILURE POINT**: Hosts without `remote_installer_paths` property are excluded

7. **Installation Execution**
   - `StartBatchInstallation`: Dynamic parallel installation orchestration
   - `Start-BatchJobProcessor`: Generic batch engine with immediate job scheduling
   - `MarkHostCompleted`: Marks successful hosts in completed list immediately
   - Dynamic job scheduling with immediate slot filling
   - Multi-tier timeout protection (110s internal, 120s orchestrator)
   - Real-time progress indication with job status updates

8. **Result Collection**
   - Results collected immediately upon job completion
   - `SaveCompletedHosts`: Completed hosts persisted after each successful job
   - Immediate log collection through result processor functions

## System Capabilities

### **Timeout Protection**
- Multi-tier timeout system (110s internal, 120s orchestrator)
- Clear timeout reporting with enhanced error messages
- Graceful timeout handling prevents hanging jobs

### **Dynamic Batch Processing**
- Dynamic job scheduling with immediate slot filling
- Jobs start as soon as slots become available (no batch waiting)
- Optimal resource utilization with configurable concurrency

### **Enhanced Error Handling**
- Fault-tolerant processing continues with valid hosts
- Upload failures marked but don't prevent installations
- Comprehensive error tracking with unified issues system

### **Real-time Progress Monitoring**
- Live progress updates with "X of Y completed, Z running" format
- Real-time status during all operations (upload, connectivity, installation)
- Detailed host-by-host progress tracking

### **State Persistence**
- Comprehensive installation state tracking via processing.json
- Automatic resume capability after interruption
- Duplicate installation prevention with completed host tracking

## Faulty Host Marking System

### **Host Fault Detection Points**

#### **1. Configuration Validation (orc_config.ps1:ReadConfigFile)**
- **Location**: Configuration file parsing
- **Failure Mechanism**: Script exits entirely on invalid JSON or missing required fields
- **Current Behavior**: Complete termination (no continuation)
- **Marking**: N/A - script terminates

#### **2. Connectivity Validation (orc_host_communication.ps1:EnsureHostsConnectivity)**
- **Location**: Host connectivity pre-checks
- **Property**: `issues` array (✅ **UPDATED**)
- **Failure Scenarios**:
  - Invalid `host_auth` value: `"Invalid host_auth value. Must be 'active_directory' or 'credentials'"`
  - AD auth with non-domain user: `"Current user is not logged in to Active Directory"`
  - IP resolution failure for AD: `"Could not resolve IP X.X.X.X to hostname for active_directory auth"`
  - Connectivity test failure: `"Failed to connect to host using [auth_type] authentication"`
  - Invalid IP for credentials: `"Invalid host address 'X'. Must be an IP address for credentials authentication."`
- **Behavior**: Mark failed hosts but continue with valid ones
- **Implementation**: Uses unified `issues` array instead of separate field

#### **3. Upload Failures (orc_uploader.ps1:UploadInstallersToHosts)**
- **Location**: File upload to remote hosts
- **Property**: `issues` array + `remote_installer_paths` (✅ **UPDATED**)
- **Behavior**: Mark failed uploads but continue with successful ones
- **Implementation**: Upload failures added to unified `issues` array, missing `remote_installer_paths` indicates failure

#### **4. Installation Job Failures (orc_invoke_remote_install.ps1:FetchJobResult)**
- **Location**: Remote installation job execution
- **Property**: `JobState` = 'Failed' vs 'Success'
- **Failure Scenarios**:
  - PowerShell job state != 'Completed'
  - Job execution errors
  - Script execution failures
  - Timeout conditions (not currently implemented)
- **Behavior**: Individual job failures logged, counted in summary
- **Implementation**: Correct job failure tracking


### **Host State Properties**

Hosts carry state information through these properties:
- `issues`: Array of strings tracking all problems (connectivity, upload, etc.) - empty = valid
- `remote_installer_paths`: Present = upload successful, missing = upload failed
- Final result `JobState`: 'Success' or 'Failed' after installation




## Development Guidelines

### **General Code Rules**

#### **1. Code Reuse and Modularity**
- **Reuse Common Functions**: Always check existing `orc_*.ps1` modules for reusable functions before creating new ones
- **Module Scoping**: Each `orc_*.ps1` file should focus on a specific functional area (logging, config, networking, etc.)
- **File Size Management**: Keep module files reasonably sized - split large modules into focused sub-modules when necessary
- **Function Naming**: Use clear, descriptive names that indicate the module and purpose (e.g., `UpdateFlexAuthToken`, `EnsureHostsConnectivity`)

#### **2. Logging and Output Management**
- **Remote Logging**: All logs written on remote machines must be echoed to the local orchestrator
- **Transcript Usage**: Use PowerShell transcript functionality to capture all remote execution output locally
- **Centralized Logging**: Use functions from `orc_logging.ps1` for consistent log formatting and credential sanitization
- **Log Levels**: Implement appropriate log levels (DEBUG, INFO, WARN, ERROR) with timestamp formatting

#### **3. Timeout and Reliability**
- **Mandatory Timeouts**: All operations that can hang must be executed with explicit timeout protection
- **Timeout Hierarchy**: Use multi-tier timeout approach (internal job timeout < orchestrator timeout)
- **Graceful Timeout Handling**: Provide clear timeout messages and cleanup when timeouts occur
- **Examples**: Remote PowerShell jobs, network operations, installer executions

#### **4. User Experience**
- **Progress Indication**: Display progress bars or spinners for long-running operations
- **Minimal User Interaction**: Minimize prompts and user input requirements during execution
- **Batch Operations**: Prefer automated batch processing over interactive individual operations
- **Clear Status Updates**: Provide real-time status updates during parallel operations

#### **5. Fault Tolerance**
- **Continue on Partial Failure**: Application should only stop when nothing can be accomplished
- **Host Filtering**: If any valid hosts remain for installation, continue processing
- **Graceful Degradation**: Mark failed hosts but continue with successful ones
- **Error Isolation**: Individual host failures should not impact other hosts

#### **6. PowerShell Compatibility**
- **Version Compatibility**: Use PowerShell 5.1+ compatible syntax for broad compatibility
- **Avoid Advanced Features**: Don't use features exclusive to PowerShell Core/7+ unless necessary
- **Cross-Platform Considerations**: Write code that works on Windows PowerShell and PowerShell Core
- **Cmdlet Compatibility**: Use cmdlets and parameters available in PowerShell 5.1

#### **7. Code Complexity and Clarity**
- **Avoid Over-Engineering**: Don't overcomplicate solutions - prefer simple, clear implementations
- **Readable Code**: Write code that is immediately understandable by other developers
- **Single Responsibility**: Each function should have one clear, well-defined purpose
- **Minimal Nesting**: Avoid deeply nested conditional structures and loops

#### **8. Comments and Documentation**
- **Strategic Comments**: Use comments only when the code's purpose or reason isn't immediately clear
- **Explain Why, Not What**: Focus comments on explaining reasoning rather than describing obvious actions
- **Complex Logic**: Always comment complex algorithms, workarounds, or non-obvious implementations
- **Function Headers**: Use PowerShell comment-based help for public functions

#### **9. Object Definition and Management**
- **Pre-define Complex Objects**: Define complex objects and their properties before usage rather than creating them dynamically
- **Consistent Object Structure**: Use consistent property names and structures across similar objects
- **Type Safety**: Prefer explicit object definitions over dynamic property creation where possible
- **Property Validation**: Validate object properties exist before accessing them

### **Code Examples**

#### **✅ Good: Pre-defined Object Structure**
```powershell
# Define host object structure upfront
$hostObject = [PSCustomObject]@{
    host_addr = $null
    issues = @()
    remote_installer_paths = $null
    sql_connection_string = $null
    result = $null
}
```

#### **❌ Avoid: Dynamic Property Creation**
```powershell
# Avoid creating properties on-the-fly
$hostObject | Add-Member -MemberType NoteProperty -Name "new_property" -Value $someValue
```

#### **✅ Good: Timeout Protection**
```powershell
$job = Start-Job -ScriptBlock $scriptBlock
Wait-Job $job -Timeout $TIMEOUT_SECONDS
if ($job.State -eq 'Running') {
    Stop-Job $job
    throw "Operation timed out after $TIMEOUT_SECONDS seconds"
}
```

#### **✅ Good: Progress Indication**
```powershell
InfoMessage "Progress: $completedCount of $totalCount operations completed, $runningCount running"
```

## System Architecture

### **Core Features**
- **Dynamic Batch Processing**: Parallel job execution with configurable concurrency limits
- **Generic Processing Framework**: Reusable batch processing engine for upload, connectivity, and installation operations
- **Fault Tolerance**: Graceful handling of host failures with continued processing of valid hosts
- **State Persistence**: Installation tracking to prevent duplicates and enable resumption
- **Multi-tier Timeouts**: Robust timeout protection (110s internal, 120s orchestrator)
- **Real-time Progress**: Live status updates during all operations

## Complex Parameter Passing in Job Architecture

### **Current Parameter Passing Patterns**

#### **1. Batch Installation Jobs (orc_batch_installer.ps1)**
```powershell
# Current approach: Large ArgumentList array (12+ parameters)
$ArgumentList = @(
    $hostInfo.flex_host_ip,
    $hostInfo.flex_access_token,
    $hostInfo.sql_connection_string,
    $agentPath, $vssPath,
    $hostInfo.sdp_id,
    $hostInfo.sdp_credential.UserName,
    $hostInfo.sdp_credential.GetNetworkCredential().Password,
    $IsDebug, $IsDryRun,
    $hostInfo.mount_points_directory,
    $HostSetupScript
)
```

#### **2. Generic Batch Processor (orc_generic_batch_processor.ps1)**
```powershell
# Current approach: Simple item passing
$job = Start-Job -ScriptBlock $JobScriptBlock -ArgumentList $item
```

#### **3. Enhanced Job Script Pattern (orc_batch_installer.ps1)**
```powershell
# Current approach: Using variables with $using: scope
$jobScriptWithConstants = {
    param($hostInfo)
    & ([ScriptBlock]::Create($using:installationJobScript)) `
        $hostInfo `
        $using:Config `
        $using:HostSetupScript `
        $using:ENUM_ACTIVE_DIRECTORY `
        $using:DryRun.IsPresent `
        ($using:DebugPreference -eq 'Continue')
}
```

### **Parameter Passing Efficiency Analysis**

#### **✅ Current Strengths**
1. **Variable Scope Handling**: Effective use of `$using:` scope for complex objects
2. **Null Validation**: Comprehensive null checking with parameter name mapping
3. **Credential Security**: Secure handling of credentials with GetNetworkCredential()
4. **Flexible Architecture**: Supports different job types with varied parameter needs

#### **⚠️ Current Challenges**
1. **Large ArgumentList Arrays**: 12+ parameters in installation jobs create maintenance overhead
2. **Parameter Order Dependency**: Positional parameters prone to errors if order changes
3. **Repetitive Validation**: Duplicate null checking logic across different job types
4. **Complex Nested Structures**: Deep object property access ($hostInfo.sdp_credential.UserName)
5. **Limited Type Safety**: No compile-time parameter validation

#### **🔧 Efficiency Improvement Recommendations**

##### **1. Parameter Object Pattern**
```powershell
# IMPROVED: Single parameter object approach
$jobParameters = @{
    HostInfo = $hostInfo
    Config = $Config
    Credentials = @{
        Flex = @{ IP = $hostInfo.flex_host_ip; Token = $hostInfo.flex_access_token }
        SDP = @{ ID = $hostInfo.sdp_id; User = $hostInfo.sdp_credential.UserName; Pass = $hostInfo.sdp_credential.GetNetworkCredential().Password }
        SQL = $hostInfo.sql_connection_string
    }
    Paths = @{ Agent = $agentPath; VSS = $vssPath; MountPoints = $hostInfo.mount_points_directory }
    Options = @{ Debug = $IsDebug; DryRun = $IsDryRun }
    Script = $HostSetupScript
}

$job = Start-Job -ScriptBlock $JobScriptBlock -ArgumentList $jobParameters
```

##### **2. Typed Parameter Classes (PowerShell 5+)**
```powershell
# ADVANCED: PowerShell class for type safety
class InstallationParameters {
    [string]$FlexIP
    [string]$FlexToken
    [string]$SQLConnectionString
    [string]$AgentPath
    [string]$VSSPath
    [boolean]$IsDebug
    [boolean]$IsDryRun

    InstallationParameters([hashtable]$params) {
        $this.FlexIP = $params.FlexIP
        $this.FlexToken = $params.FlexToken
        # ... initialize other properties
    }
}
```

##### **3. Configuration-Based Parameter Passing**
```powershell
# OPTIMAL: JSON/PSCustomObject serialization for complex parameters
$jobConfig = [PSCustomObject]@{
    Host = $hostInfo | Select-Object host_addr, mount_points_directory
    Authentication = @{
        Flex = @{ IP = $hostInfo.flex_host_ip; Token = $hostInfo.flex_access_token }
        SDP = @{ ID = $hostInfo.sdp_id; Credentials = $hostInfo.sdp_credential }
        SQL = $hostInfo.sql_connection_string
    }
    Installers = @{ Agent = $agentPath; VSS = $vssPath }
    ExecutionOptions = @{ Debug = $IsDebug; DryRun = $IsDryRun }
    Script = $HostSetupScript
} | ConvertTo-Json -Depth 5

$job = Start-Job -ScriptBlock {
    param($configJson)
    $config = $configJson | ConvertFrom-Json
    # Use structured config object
} -ArgumentList $jobConfig
```

##### **4. Factory Pattern for Job Creation**
```powershell
# ARCHITECTURAL: Job factory with parameter validation
function New-InstallationJob {
    param(
        [PSCustomObject]$HostInfo,
        [PSCustomObject]$Config,
        [string]$HostSetupScript,
        [hashtable]$Options = @{}
    )

    # Validate and build parameters internally
    $validatedParams = Build-JobParameters -HostInfo $HostInfo -Config $Config -Options $Options

    return Start-Job -ScriptBlock $Global:InstallationJobScript -ArgumentList $validatedParams
}
```

### **Implementation Options**
1. **Parameter Object Pattern**: Single structured object instead of large arrays
2. **Centralized Validation**: Common parameter validation functions
3. **Typed Parameter Classes**: Enhanced safety with PowerShell classes
4. **Job Factory Pattern**: Consistent job creation with validation

### **Performance Considerations**
- **Serialization Overhead**: JSON conversion adds ~5-10ms per job but improves maintainability
- **Memory Efficiency**: Structured objects reduce parameter duplication
- **Error Reduction**: Type safety and validation prevent runtime parameter errors
- **Development Speed**: Cleaner parameter patterns reduce debugging time significantly
