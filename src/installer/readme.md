# Silk Echo Installation Scripts

This directory contains PowerShell scripts for installing Silk Echo components (Node Agent and VSS Provider) on Windows systems, supporting both single-host and multi-host deployments.

## Quick Start (Usage)

### Hosts Setup
```powershell
# Generate configuration template
.\orchestrator.ps1 -CreateConfigTemplate

# Edit the generated config.json with your environment details
# Run validation (dry run)
.\orchestrator.ps1 -ConfigPath config.json -DryRun

# Install on single host
.\orchestrator.ps1 -ConfigPath config.json

# Use custom configuration with different MaxConcurrency
.\orchestrator.ps1 -ConfigPath "config.json" -MaxConcurrency 5

# Validation mode (dry run)
.\orchestrator.ps1 -ConfigPath "config.json" -DryRun

```

### Production Script Generation
```powershell
# Generate production-ready script
.\make-release.ps1
```

## What This System Does

The Silk Echo installer automates the deployment of Silk's data acceleration components across Windows environments:

1. **Silk Node Agent**: Provides data acceleration and caching capabilities
2. **Silk VSS Provider**: Enables Volume Shadow Copy Service integration
3. **Host Registration**: Registers hosts with Silk Flex management server
4. **SQL Server Integration**: Configures database connectivity for the Node Agent
5. **SDP Integration**: Connects to Silk Data Platform for storage services

The system supports parallel installation across multiple hosts with comprehensive validation, logging, error handling, and automatic state tracking to prevent duplicate installations and enable safe resumption after interruption.

## Directory Structure

This installer is organized as a modular PowerShell system with the following components:

### Main Scripts
| File | Purpose | Key Features |
|------|---------|--------------|
| **orchestrator.ps1** | Multi-host installation orchestrator | Parallel execution, connectivity validation, batch processing |
| **orc_host_installer.ps1** | Single-host installation script | Node Agent + VSS Provider installation, host registration |
| **make-release.ps1** | Production build script | Creates self-contained deployment package |

### Core Modules (orc_*.ps1)
| Module | Function | Description |
|--------|----------|-------------|
| **orc_constants.ps1** | Global constants | Version info, authentication enums, default URLs |
| **orc_common.ps1** | Utility functions | SecureString conversion, AD user detection |
| **orc_logging.ps1** | Centralized logging | Multi-level logging with credential sanitization |
| **orc_config.ps1** | Configuration management | JSON parsing, template generation, host inheritance |
| **orc_requirements.ps1** | System validation | PowerShell version, admin privileges checks |

### Authentication & Security
| Module | Function | Description |
|--------|----------|-------------|
| **orc_flex_login.ps1** | Silk Flex authentication | API token management, login endpoints |
| **orc_no_verify_cert.ps1** | Certificate handling | Self-signed cert bypass for dev environments |

### Network & Integration
| Module | Function | Description |
|--------|----------|-------------|
| **orc_web_client.ps1** | HTTP/API client | REST calls to Flex/SDP APIs |
| **orc_host_communication.ps1** | Host connectivity | PowerShell remoting, WinRM validation |
| **orc_mssql.ps1** | SQL Server integration | Connection strings, credential validation |
| **orc_sdp.ps1** | SDP integration | Silk Data Platform API connectivity |

### Installation Management
| Module | Function | Description |
|--------|----------|-------------|
| **orc_uploader.ps1** | File management | Installer download/caching, remote distribution |
| **orc_invoke_remote_install.ps1** | Remote execution | Parallel job management, result collection |
| **orc_tracking.ps1** | State tracking | Processing state persistence, duplicate prevention, resume capability |
| **orc_host_setup_extractor.ps1** | Script extraction | Dynamic script generation for remote hosts |
| **orc_import_expander.ps1** | Import processing | Inline script expansion for production builds |

### Configuration Files
| File | Purpose | Description |
|------|---------|-------------|
| **config-example.json** | Configuration template | Example with placeholders for all settings |

## Development Guide

### Architecture Overview

The installer follows a modular architecture pattern:

1. **Orchestrator Pattern**: `orchestrator.ps1` coordinates the entire installation process
2. **Module System**: Core functionality split into `orc_*.ps1` modules for maintainability
3. **Configuration Inheritance**: Common settings inherited by host-specific overrides
4. **Parallel Execution**: Concurrent installation across multiple hosts with configurable concurrency
5. **Production Build**: `make-release.ps1` creates single-file deployment packages

### Key Development Processes

#### 1. Authentication Flow
```
Host Auth (AD/Credentials) → Flex Login (API Token) → SDP Validation → SQL Validation
```

#### 2. Installation Pipeline
```
Download → Upload → Register → Install Agent → Install VSS → Validate
```

#### 3. Error Handling Strategy
- Comprehensive error tracking with sanitized credentials
- Multi-level logging (DEBUG, INFO, WARN, ERROR)
- Graceful degradation with detailed error reporting
- Summary reports with success/failure analytics

### Configuration System

The configuration system uses JSON with inheritance patterns:

```json
{
  "common": {
    "shared_property": "value"
  },
  "hosts": [
    {
      "host_addr": "host1", 
      "override_property": "host_specific_value"
    },
    "host2"  // Inherits all common properties
  ]
}
```

### Authentication Modes

- **Active Directory**: Kerberos authentication (requires hostnames, not IPs)
- **Credentials**: Username/password authentication (supports both hostnames and IPs)

#### Configuration Examples

**Kerberos (AD) Authentication:**
```json
{
  "common": { "host_auth": "active_directory" },
  "hosts": ["server01", "server02"]  // Hostnames required
}
```

**Credential Authentication:**
```json
{
  "common": { 
    "host_auth": "credentials",
    "host_user": "admin",
    "host_pass": "password"
  },
  "hosts": ["10.1.1.100", "10.1.1.101"]  // IPs supported
}
```

**SQL Server Configuration:**
```json
{
  "common": {
    "sql_user": "sa",
    "sql_pass": "password",
    "sql_server": "localhost,1433"  // Optional - bypasses endpoint discovery
  },
  "hosts": [
    {
      "host_addr": "host1",
      "sql_server": "host1,1433"  // Host-specific SQL Server with port
    },
    "host2"  // Uses common sql_server or performs endpoint discovery
  ]
}
```

### Development Workflow

#### Setting Up Development Environment

```powershell
# 1. Generate configuration template
.\orchestrator.ps1 -CreateConfigTemplate

# 2. Edit the generated config.json with your environment details
notepad config.json

# 3. Validate configuration without making changes
.\orchestrator.ps1 -ConfigPath config.json -DryRun

# 4. Run installation (starts with limited hosts for testing)
.\orchestrator.ps1 -ConfigPath config.json -MaxConcurrency 2

# 5. Enable verbose output for debugging
.\orchestrator.ps1 -ConfigPath config.json -Verbose
```

#### Modifying Core Modules

When modifying `orc_*.ps1` modules:

1. **Test changes locally** with `orchestrator.ps1` in development mode
2. **Validate module imports** - each module should be self-contained
3. **Test production build** with `make-release.ps1` to ensure imports expand correctly
4. **Maintain logging standards** - use consistent logging levels and credential sanitization

#### Production Build Process

```powershell
# Generate production-ready single-file script
.\make-release.ps1

# This creates orchestrator-release.ps1 containing:
# - All orc_*.ps1 modules inlined
# - Expanded imports and dependencies
# - Self-contained deployment package
```

#### Debugging and Troubleshooting

**PowerShell Features:**
```powershell
# Get comprehensive help
Get-Help .\orchestrator.ps1 -Full

# Enable debug output
.\orchestrator.ps1 -ConfigPath "config.json" -Verbose

# Enable PowerShell debugging
.\orchestrator.ps1 -ConfigPath "config.json" -Debug
```

**Common Development Issues:**
- **Import Errors**: Check module paths and ensure all `orc_*.ps1` files are present
- **Authentication Failures**: Verify host_auth setting matches your environment (AD vs credentials)
- **Network Issues**: Test PowerShell remoting manually: `Test-WSMan <hostname>`
- **Certificate Issues**: Use `-Verbose` to see certificate validation bypasses

## System Requirements

### Development Environment
- Windows OS with PowerShell 5.1+ (Desktop or Core edition)
- Administrator privileges for development machine
- Network access to target hosts and management servers
- Git for version control

### Target Hosts (Installation Targets)
- Windows operating system
- PowerShell remoting enabled (WinRM service)
- SQL Server installed and accessible
- Administrator privileges for installation
- Network access to Flex and SDP management servers

### External Dependencies
- Valid SQL Server connection strings
- Silk Flex server access credentials
- SDP (Silk Data Platform) credentials  
- Download URLs for Silk Agent and VSS Provider installers

## API Reference

### orchestrator.ps1 Parameters

| Parameter | Type | Description | Required | Default |
|-----------|------|-------------|----------|---------|
| `ConfigPath` | String | Path to configuration JSON file | No | - |
| `CreateConfigTemplate` | Switch | Generate configuration template | No | false |
| `MaxConcurrency` | Int | Parallel installation limit | No | 10 |
| `DryRun` | Switch | Validation mode (no changes) | No | false |
| `Verbose` | Switch | Verbose logging output | No | false |
| `Debug` | Switch | Debug-level logging | No | false |

### Configuration Schema

**Root Configuration Object:**
```json
{
  "installers": {
    "agent": { "url": "string", "path": "string" },
    "vss": { "url": "string", "path": "string" }
  },
  "common": { /* inherited by all hosts */ },
  "hosts": [ /* array of host objects or strings */ ]
}
```

**Host Configuration Properties:**
| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `host_addr` | String | Hostname or IP address | Yes |
| `host_auth` | String | `"active_directory"` or `"credentials"` | Yes |
| `host_user` | String | Username (if credentials auth) | Conditional |
| `host_pass` | String | Password (if credentials auth) | Conditional |
| `sql_user` | String | SQL Server username | Yes |
| `sql_pass` | String | SQL Server password | Yes |
| `sql_server` | String | SQL Server instance (bypasses endpoint discovery) | No |
| `flex_host_ip` | String | Flex management server IP | Yes |
| `flex_user` | String | Flex username | Yes |
| `flex_pass` | String | Flex password | Yes |
| `sdp_id` | String | SDP system identifier | Yes |
| `sdp_user` | String | SDP username | Yes |
| `sdp_pass` | String | SDP password | Yes |
| `mount_points_directory` | String | Directory for mount points | Yes |

### Module Functions

**Core Logging (`orc_logging.ps1`):**
- `Log-Error`, `Log-Info`, `Log-Warn`, `Log-Debug`
- Automatic credential sanitization
- Timestamped output formatting

**Configuration Management (`orc_config.ps1`):**
- `Get-ConfigFromFile` - Load and validate JSON configuration
- `New-ConfigTemplate` - Interactive template generation
- Host inheritance resolution

**Authentication (`orc_flex_login.ps1`):**
- `Get-FlexAuthToken` - Obtain API authentication token
- Automatic token refresh and session management

**Installation State Tracking (`orc_tracking.ps1`):**
- `LoadCompletedHosts` - Load simple completed hosts list from processing.json
- `SaveCompletedHosts` - Save completed hosts list with timestamps  
- `IsHostCompleted` - Check if host exists in completed hosts list
- `MarkHostCompleted` - Mark host as completed with current timestamp
