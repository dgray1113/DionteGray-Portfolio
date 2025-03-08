# Script: Monitor-M365ServiceHealth.ps1
# Description: Monitors Microsoft 365 service health, generates a report, and emails it

#region Prerequisites
# Install required modules if not present (run once with admin rights)
if (-not (Get-Module -ListAvailable -Name MSOnline)) {
    Install-Module -Name MSOnline -Force -Scope CurrentUser -ErrorAction SilentlyContinue
}
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser -ErrorAction SilentlyContinue
}

# Import modules
Import-Module MSOnline
Import-Module ExchangeOnlineManagement
#endregion

#region Configuration
$adminEmail = "dgray1113@icloud.com"  # Replace with your email for testing
$smtpServer = "smtp.office365.com"
$smtpPort = 587
$fromEmail = "admin@yourdomain.com"    # Replace with a valid M365 sender
$toEmail = $adminEmail
$subject = "M365 Service Health Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
$reportPath = "M365_Service_Health_Report.csv"
#endregion

#region Functions
function Get-ServiceHealthReport {
    param ([string]$ServiceName = "*")
    try {
        $healthIssues = Get-MsolServiceHealthIssues -Service $ServiceName -ErrorAction Stop
        if ($healthIssues) {
            $report = $healthIssues | Select-Object Service, Status, LastModifiedTime, IncidentType
            return $report
        } else {
            return [PSCustomObject]@{ Service = "All"; Status = "Healthy"; LastModifiedTime = Get-Date; IncidentType = "None" }
        }
    } catch {
        Write-Host "Error fetching service health: $_" -ForegroundColor Red
        return $null
    }
}
#endregion

#region Main Execution
try {
    # Connect to services (enter admin credentials when prompted)
    $msolCred = Get-Credential
    Connect-MsolService -Credential $msolCred -ErrorAction Stop
    Connect-ExchangeOnline -Credential $msolCred -ShowProgress $false -ErrorAction Stop

    # Get service health report
    $healthReport = Get-ServiceHealthReport
    if ($healthReport) {
        # Export to CSV
        $healthReport | Export-Csv -Path $reportPath -NoTypeInformation -ErrorAction Stop
        Write-Host "Service health report saved to $reportPath" -ForegroundColor Cyan

        # Prepare email body
        $body = "Microsoft 365 Service Health Report`n`n"
        $body += $healthReport | Format-Table -AutoSize | Out-String
        $body += "`nDetailed report attached: $reportPath"

        # Send email
        $mailParams = @{
            SmtpServer = $smtpServer
            Port       = $smtpPort
            UseSsl     = $true
            Credential = $msolCred
            From       = $fromEmail
            To         = $toEmail
            Subject    = $subject
            Body       = $body
            Attachments = $reportPath
        }
        Send-MailMessage @mailParams -ErrorAction Stop
        Write-Host "Email sent to $toEmail" -ForegroundColor Green
    } else {
        Write-Host "No report generated due to errors." -ForegroundColor Red
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
} finally {
    # Disconnect services
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Disconnect-MsolService -ErrorAction SilentlyContinue
}
#endregion
