#region SetTLSVersion
function SetTLSVersion {
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($IsPowerShell7) {
        # if Powershell version is 7 or higher, set both TLS 1.2 and TLS 1.3
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
            Write-Host "Enabled TLS 1.2 and TLS 1.3."
        }
        catch {
            Write-Host "TLS 1.3 not supported, enabling only TLS 1.2."
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
            Write-Host "Enabled TLS 1.2."
        }
    } else {
        # for Windows PowerShell, set only TLS 1.2
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Write-Host "Enabled TLS 1.2."
    }
}
#endregion SetTLSVersion

#region SkipCertificateCheck
function SkipCertificateCheck {
    $IsPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
    if ($IsPowerShell7) {
        # if Powershell version is 7 or higher, set SkipCertificateCheck
        return
    }

    # set policy only once per powershell sessions
    $currentPolicy = [System.Net.ServicePointManager]::CertificatePolicy
    if ($currentPolicy -eq $null -or ($currentPolicy.GetType().FullName -ne "TrustAllCertsPolicy")) {
        add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    } else {
        Write-Host "Certificate policy already set to $([System.Net.ServicePointManager]::CertificatePolicy). skipping."
    }
}
#endregion SkipCertificateCheck
