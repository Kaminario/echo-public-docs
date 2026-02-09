# Component versions - update these to lock specific releases
Set-Variable -Name SilkAgentVersion -Value "v1.1.8" -Option AllScope -Scope Script
Set-Variable -Name SvssVersion -Value "2.0.18" -Option AllScope -Scope Script

# Installer URLs
Set-Variable -Name SilkAgentURL -Value "https://storage.googleapis.com/silk-public-files/silk-agent-installer-$SilkAgentVersion.exe" -Option AllScope -Scope Script
Set-Variable -Name SilkVSSURL -Value "https://storage.googleapis.com/silk-public-files/svss-$SvssVersion.exe" -Option AllScope -Scope Script
