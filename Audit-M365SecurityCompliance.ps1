# Script: Audit-M365SecurityCompliance.ps1
# Description: Performs a comprehensive M365 security compliance audit with remediation recommendations

#region Prerequisites
# Install required modules if not present (run once with admin rights)
$modules = @("MSOnline", "AzureAD", "ExchangeOnlineManagement")
foreach ($module in $modules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Install-Module -Name $module -Force -Scope CurrentUser -ErrorAction SilentlyContinue
    }
    Import-Module $module -ErrorAction SilentlyContinue
}
#endregion

#region Configuration
$logFile = "M365_SecurityCompliance_Log.txt"
`\(reportPath = "M365_SecurityCompliance_Report_\)`((Get-Date -Format 'yyyyMMdd_HHmmss')).csv"
$adminEmail = "dgray1113@icloud.com"  # Replace with your email
$riskThreshold = 5                    # Number of risky sign-ins to flag
#endregion

#region Functions
function Write-Log {
    param ([string]`\(Message, [string]\)`Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "`\(timestamp - [\)`Level] - $Message" | Out-File -FilePath $logFile -Append
}

function Get-M365ComplianceStatus {
    try {
        $cred = Get-Credential
        Connect-MsolService -Credential $cred -ErrorAction Stop
        Connect-AzureAD -Credential $cred -ErrorAction Stop
        Connect-ExchangeOnline -Credential $cred -ShowProgress $false -ErrorAction Stop

        $report = @()

        # Check MFA status
        $users = Get-MsolUser -All
        `\(mfaDisabledCount = (\)`users | Where-Object { -not $_.StrongAuthenticationRequirements }).Count
        `\(mfaStatus = if (\)`mfaDisabledCount -gt 0) { "Non-compliant ($mfaDisabledCount users without MFA)" } else { "Compliant" }
        $report += [PSCustomObject]@{
            Check            = "MFA Enabled for All Users"
            Status           = $mfaStatus
            Recommendation   = if ($mfaDisabledCount -gt 0) { "Enable MFA for all users via Entra or PowerShell" } else { "None" }
            LastChecked      = Get-Date
        }
        Write-Log -Message "MFA check: $mfaStatus" -Level "INFO"

        # Check mailbox auditing
        $mailboxAudit = Get-OrganizationConfig | Select-Object -Property AuditDisabled
        `\(auditStatus = if (\)`mailboxAudit.AuditDisabled) { "Non-compliant" } else { "Compliant" }
        $report += [PSCustomObject]@{
            Check            = "Mailbox Auditing Enabled"
            Status           = $auditStatus
            Recommendation   = if (`\(mailboxAudit.AuditDisabled) { "Enable via Set-OrganizationConfig -AuditDisabled `\)`false" } else { "None" }
            LastChecked      = Get-Date
        }
        Write-Log -Message "Mailbox audit check: $auditStatus" -Level "INFO"

        # Check risky sign-ins (Azure AD)
        $riskySignIns = Get-AzureADAuditSignInLogs -Filter "RiskLevel eq 'high'" -Top $riskThreshold
        $riskCount = $riskySignIns.Count
        `\(riskStatus = if (\)`riskCount -gt 0) { "Non-compliant ($riskCount risky sign-ins detected)" } else { "Compliant" }
        $report += [PSCustomObject]@{
            Check            = "Risky Sign-Ins Detected"
            Status           = $riskStatus
            Recommendation   = if ($riskCount -gt 0) { "Review risky sign-ins in Azure AD and enforce conditional access" } else { "None" }
            LastChecked      = Get-Date
        }
        if ($riskCount -gt 0) { Write-Log -Message "Detected $riskCount risky sign-ins" -Level "WARNING" }

        return $report
    } catch {
        Write-Log -Message "Error in compliance check: $_" -Level "ERROR"
        return $null
    }
}
#endregion

#region Main Execution
try {
    Write-Host "Starting M365 Security Compliance Audit..." -ForegroundColor Green
    Write-Log -Message "Audit initiated"

    # Perform compliance audit
    $complianceReport = Get-M365ComplianceStatus
    if ($complianceReport) {
        # Export report to CSV with timestamp
        $complianceReport | Export-Csv -Path $reportPath -NoTypeInformation -ErrorAction Stop
        Write-Host "Compliance report saved to $reportPath" -ForegroundColor Cyan
        Write-Log -Message "Compliance report generated: $reportPath" -Level "INFO"

        # Display summary
        $nonCompliant = $complianceReport | Where-Object { $_.Status -notlike "Compliant*" }
        if ($nonCompliant) {
            Write-Host "Non-compliant findings detected:" -ForegroundColor Yellow
            $nonCompliant | Format-Table -AutoSize
        } else {
            Write-Host "All checks passed!" -ForegroundColor Green
        }
    } else {
        Write-Host "Audit failed, check log for details." -ForegroundColor Red
    }
} catch {
    Write-Host "Critical error: $_" -ForegroundColor Red
    Write-Log -Message "Critical failure: $_" -Level "ERROR"
} finally {
    # Disconnect services
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Disconnect-AzureAD -ErrorAction SilentlyContinue
    Disconnect-MsolService -ErrorAction SilentlyContinue
    Write-Log -Message "Audit session completed"
}
#endregion
