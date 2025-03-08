# Script: Audit-M365SecurityGroups.ps1
# Description: Audits Microsoft 365 security groups, generates a report, and logs changes

#region Prerequisites
# Install required modules if not present (run once with admin rights)
if (-not (Get-Module -ListAvailable -Name MSOnline)) {
    Install-Module -Name MSOnline -Force -Scope CurrentUser -ErrorAction SilentlyContinue
}
if (-not (Get-Module -ListAvailable -Name AzureAD)) {
    Install-Module -Name AzureAD -Force -Scope CurrentUser -ErrorAction SilentlyContinue
}

# Import modules
Import-Module MSOnline
Import-Module AzureAD
#endregion

#region Configuration
$logFile = "M365_SecurityGroup_Audit_Log.txt"
$reportPath = "M365_SecurityGroup_Audit_Report.csv"
$adminEmail = "dgray1113@icloud.com"  # Replace with your email for notifications (optional)
$logThreshold = 10                    # Number of members to flag as high
#endregion

#region Functions
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logFile -Append
}

function Get-SecurityGroupAudit {
    try {
        # Connect to Azure AD (enter admin credentials when prompted)
        $cred = Get-Credential
        Connect-AzureAD -Credential $cred -ErrorAction Stop
        Connect-MsolService -Credential $cred -ErrorAction Stop

        # Get all security groups
        $groups = Get-AzureADGroup -All $true | Where-Object { $_.SecurityEnabled -eq $true }
        $auditReport = @()

        foreach ($group in $groups) {
            $members = Get-AzureADGroupMember -ObjectId $group.ObjectId -All $true
            $owners = Get-AzureADGroupOwner -ObjectId $group.ObjectId -All $true
            $memberCount = $members.Count
            $isHighMembership = $memberCount -gt $logThreshold

            $auditEntry = [PSCustomObject]@{
                GroupName        = $group.DisplayName
                GroupId          = $group.ObjectId
                MemberCount      = $memberCount
                Owners           = ($owners | ForEach-Object { $_.DisplayName }) -join ", "
                HighMembership   = $isHighMembership
                LastModified     = $group.LastDirSyncTime
            }
            $auditReport += $auditEntry

            # Log if high membership or no owners
            if ($isHighMembership -or ($owners.Count -eq 0)) {
                $logMessage = "Alert: Group '$($group.DisplayName)' has $memberCount members" +
                              "$(if ($owners.Count -eq 0) { ' and no owners' })"
                Write-Log -Message $logMessage
            }
        }

        return $auditReport
    } catch {
        Write-Log -Message "Error during audit: $_"
        return $null
    }
}
#endregion

#region Main Execution
try {
    Write-Host "Starting M365 Security Group Audit..." -ForegroundColor Green
    Write-Log -Message "Audit started"

    # Perform audit
    $report = Get-SecurityGroupAudit
    if ($report) {
        # Export to CSV
        $report | Export-Csv -Path $reportPath -NoTypeInformation -ErrorAction Stop
        Write-Host "Audit report saved to $reportPath" -ForegroundColor Cyan
        Write-Log -Message "Audit completed, report saved to $reportPath"

        # Optional: Send notification (uncomment and configure SMTP if needed)
        # $smtpParams = @{
        #     SmtpServer = "smtp.office365.com"
        #     Port       = 587
        #     UseSsl     = $true
        #     Credential = $cred
        #     From       = "admin@yourdomain.com"
        #     To         = $adminEmail
        #     Subject    = "M365 Security Group Audit Report - $(Get-Date -Format 'yyyy-MM-dd')"
        #     Body       = "Audit report attached. Check log for alerts."
        #     Attachments = $reportPath
        # }
        # Send-MailMessage @smtpParams -ErrorAction Stop
        # Write-Host "Notification sent to $adminEmail" -ForegroundColor Green
        # Write-Log -Message "Notification sent to $adminEmail"
    } else {
        Write-Host "Audit failed, check log for details." -ForegroundColor Red
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    Write-Log -Message "Critical error: $_"
} finally {
    # Disconnect services
    Disconnect-AzureAD -ErrorAction SilentlyContinue
    Disconnect-MsolService -ErrorAction SilentlyContinue
    Write-Log -Message "Audit session ended"
}
#endregion
