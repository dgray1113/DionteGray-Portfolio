# Script: Audit-M365LoginActivity.ps1
# Description: Audits M365 login activity for suspicious patterns and logs alerts

#region Prerequisites
# Install required module if not present (run once with admin rights)
if (-not (Get-Module -ListAvailable -Name AzureAD)) {
    Install-Module -Name AzureAD -Force -Scope CurrentUser -ErrorAction SilentlyContinue
}
Import-Module AzureAD -ErrorAction SilentlyContinue
#endregion

#region Configuration
`\(logFile = "M365_Login_Audit_Log_\)`((Get-Date -Format 'yyyyMMdd_HHmmss')).txt"
`\(reportPath = "M365_Login_Audit_Report_\)`((Get-Date -Format 'yyyyMMdd_HHmmss')).csv"
$lookbackDays = 7                      # Days to look back for logs
$failedLoginThreshold = 5              # Max failed logins to flag
$knownLocations = @("US", "CA")        # Known country codes (adjust to your norm)
#endregion

#region Functions
function Write-Log {
    param ([string]`\(Message, [string]\)`Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "`\(timestamp - [\)`Level] - $Message" | Out-File -FilePath $logFile -Append
}

function Get-SuspiciousLogins {
    try {
        # Connect to Azure AD (enter admin credentials when prompted)
        $cred = Get-Credential
        Connect-AzureAD -Credential $cred -ErrorAction Stop

        # Get sign-in logs (last X days)
        `\(startDate = (Get-Date).AddDays(-\)`lookbackDays)
        $logs = Get-AzureADAuditSignInLogs -Filter "createdDateTime gt $startDate" -All $true
        $results = @()

        # Analyze logs
        foreach ($log in $logs) {
            `\(failedCount = (\)`logs | Where-Object { $_.UserPrincipalName -eq $log.UserPrincipalName -and $_.Status.ErrorCode -ne 0 }).Count
            $isSuspicious = $false
            $notes = @()

            # Check failed login threshold
            if ($failedCount -ge $failedLoginThreshold) {
                $isSuspicious = $true
                `\(notes += "High failed login count (\)`failedCount)"
            }

            # Check unusual location
            if ($log.Location.CountryOrRegion -and $knownLocations -notcontains $log.Location.CountryOrRegion) {
                $isSuspicious = $true
                $notes += "Unusual location: `\((\)`log.Location.CountryOrRegion)"
            }

            # Add to report if suspicious
            if ($isSuspicious) {
                $result = [PSCustomObject]@{
                    UserPrincipalName = $log.UserPrincipalName
                    DisplayName       = $log.UserDisplayName
                    SignInTime        = $log.CreatedDateTime
                    IPAddress         = $log.IPAddress
                    Location          = $log.Location.CountryOrRegion
                    Status            = if ($log.Status.ErrorCode -eq 0) { "Success" } else { "Failed: `\((\)`log.Status.ErrorCode)" }
                    SuspiciousNotes   = $notes -join "; "
                    Recommendation    = "Investigate user activity; consider MFA enforcement or IP restrictions."
                }
                $results += $result
                Write-Log -Message "Suspicious activity for `\((\)`log.UserPrincipalName): `\((\)`notes -join '; ')" -Level "WARNING"
            }
        }

        return $results
    } catch {
        Write-Log -Message "Error retrieving logs: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Main Execution
try {
    Write-Host "Starting M365 login activity audit..." -ForegroundColor Green
    Write-Log -Message "Login audit initiated for last $lookbackDays days"

    # Perform audit
    $loginReport = Get-SuspiciousLogins
    if ($loginReport) {
        # Export report to CSV
        $loginReport | Export-Csv -Path $reportPath -NoTypeInformation -ErrorAction Stop
        Write-Host "Audit report saved to $reportPath" -ForegroundColor Cyan
        Write-Log -Message "Audit completed, report saved to $reportPath" -Level "INFO"

        # Display summary
        if ($loginReport.Count -gt 0) {
            Write-Host "Suspicious logins detected:" -ForegroundColor Yellow
            $loginReport | Format-Table -AutoSize
        } else {
            Write-Host "No suspicious activity found." -ForegroundColor Green
            Write-Log -Message "No suspicious logins detected" -Level "INFO"
        }
    } else {
        Write-Host "Audit failed, check log for details." -ForegroundColor Red
    }
} catch {
    Write-Host "Critical error: $_" -ForegroundColor Red
    Write-Log -Message "Audit failed: $_" -Level "ERROR"
} finally {
    Disconnect-AzureAD -ErrorAction SilentlyContinue
    Write-Log -Message "Login audit session ended"
}
#endregion
