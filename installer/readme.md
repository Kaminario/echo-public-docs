# Silk Echo Installation Scripts

This directory contains PowerShell scripts for installing Silk Echo components (Node Agent and VSS Provider) on Windows systems, supporting both single-host and multi-host deployments.

## What This Script Does

The Silk Echo installer automates the deployment of Silk's data acceleration components across Windows environments:

1. **Silk Node Agent**: Provides data acceleration and caching capabilities
2. **Silk VSS Provider**: Enables Volume Shadow Copy Service integration
3. **Host Registration**: Registers hosts with Silk Flex management server
4. **SQL Server Integration**: Configures database connectivity for the Node Agent
5. **SDP Integration**: Connects to Silk Data Platform for storage services

The system supports parallel installation across multiple hosts with comprehensive validation, logging, and error handling.

## Files Overview

| File | Purpose |
|------|---------|
| `orchestrator.ps1` | Multi-host installation orchestrator with parallel execution |
| `orc_host_installer.ps1` | Host installation script (used internally by orchestrator) |
| `config-example.json` | Configuration template for multi-host deployments |
| `make-release.ps1` | Production build script that creates standalone installer |

## Quick Start

### Single Host Setup
For single host installations, use the orchestrator with a single-host config file:

### Multi-Host Setup
```powershell
# Install across multiple hosts using config file
.\orchestrator.ps1 -ConfigPath "bulk-setup-config.json"

# Use custom configuration with different MaxConcurrency
.\orchestrator.ps1 -ConfigPath "custom-config.json" -MaxConcurrency 5

# Validation mode (dry run)
.\orchestrator.ps1 -ConfigPath "bulk-setup-config.json" -DryRun

# Combined options
.\orchestrator.ps1 -ConfigPath "config.json" -MaxConcurrency 3 -DryRun
```

## Generating Production Script and config.json

### Production Script Generation

To create a single, self-contained script for deployment:

```powershell
# Generate production-ready script
.\make-release.ps1
```

This creates `orchestrator-release.ps1` - a single file containing all dependencies that can be deployed independently.

### Configuration File Generation

Generate a `config.json` template for multi-host deployments:

```powershell
# Interactive template generation
.\orchestrator.ps1 -CreateConfigTemplate
```

This will:
1. Prompt for authentication method (Active Directory vs credentials)
2. Generate appropriate `config.json` template
3. Create placeholders for all required settings


### Configuration Notes

- **Kerberos Authentication**: When using Kerberos authentication, the `hosts` array MUST contain hostnames (not IP addresses). IP addresses will cause authentication failures.
- **Mixed Authentication**: You can use IP addresses in the `hosts` array only when using username/password authentication methods.
- **Example with IP addresses** (username/password auth only):
  ```json
  "hosts": ["10.209.137.4", "10.209.137.5", "10.209.137.6"]
  ```
- **Example with hostnames** (required for Kerberos):
  ```json
  "hosts": ["server01", "server02", "server03"]
  ```

## PowerShell Features

The `orchestrator.ps1` script supports standard PowerShell features:

- **Get-Help**: Use `Get-Help .\orchestrator.ps1` to view detailed parameter information and examples
- **Verbose and Debug**: Add `-Verbose` or `-Debug` parameters to enable debug level output for detailed execution information

Examples:
```powershell
# Get help for orchestrator script
Get-Help .\orchestrator.ps1 -Full

# Run with debug level output
.\orchestrator.ps1 -ConfigPath "config.json" -Verbose
```

## How to Run Locally

### Development Setup

1. **Clone the repository** and navigate to the install directory
2. **Ensure prerequisites** are met (see Requirements section below)
3. **Configure target environment** by editing `config-example.json` or generating new config

### Local Development Workflow

```powershell
# 1. Generate configuration template
.\orchestrator.ps1 -CreateConfigTemplate

# 2. Edit the generated config.json with your environment details
notepad config.json

# 3. Validate configuration without making changes
.\orchestrator.ps1 -ConfigPath config.json -DryRun

# 4. Run installation (starts with a few hosts for testing)
.\orchestrator.ps1 -ConfigPath config.json -MaxConcurrency 2

# 5. Enable verbose output for debugging
.\orchestrator.ps1 -ConfigPath config.json -Verbose
```

### Testing Single Host Installation

For testing or single-host scenarios, create a config file with a single host and use the orchestrator:

```powershell
# Create single-host config and test installation
.\orchestrator.ps1 -ConfigPath "single-host-config.json" -DryRun
```

### Production Deployment

```powershell
# 1. Generate production script
.\make-release.ps1

# 2. Deploy orchestrator-release.ps1 to target environment
# 3. Run with production configuration
```

## Requirements

- Windows OS with PowerShell 5.1+
- Administrator privileges
- Network connectivity to target hosts
- Valid SQL Server connection
- Flex server access credentials
- SDP (Silk Data Platform) credentials
- Download URLs for Silk Agent and VSS Provider installers
- PowerShell remoting enabled on target hosts (for multi-host setup)
- WinRM service running on target hosts (for multi-host setup)

## Parameters


### orchestrator.ps1 Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `ConfigPath` | Path to configuration JSON file | No | - |
| `CreateConfigTemplate` | Create a configuration template file | No |
| `MaxConcurrency` | Number of hosts to install in parallel | No | 10 |
| `DryRun` | Validation mode without actual installation | No | false |
| `Debug/Verbose` | Enable debug output | No | false |
