
# Script: Get-M365UserLicenses.ps1
# Description: Generates a report of Microsoft 365 user licenses

# Install MSOnline module if not present (run once with admin rights)
if (-not (Get-Module -ListAvailable -Name MSOnline)) {
    Install-Module -Name MSOnline -Force -Scope CurrentUser
}

# Import module
Import-Module MSOnline

# Connect to MSOnline (enter admin credentials when prompted)
Connect-MsolService

# Get all users and their license details
$users = Get-MsolUser -All | Select-Object UserPrincipalName, DisplayName, isLicensed, Licenses
$report = @()

foreach ($user in $users) {
    `\(licenseDetails = if (\)`user.isLicensed) { ($user.Licenses | ForEach-Object { $_.AccountSkuId }) -join ", " } else { "No License" }
    $report += [PSCustomObject]@{
        UserPrincipalName = $user.UserPrincipalName
        DisplayName       = $user.DisplayName
        Licensed          = $user.isLicensed
        LicenseDetails    = $licenseDetails
    }
}

# Display the report
Write-Host "Microsoft 365 User License Report:" -ForegroundColor Green
$report | Format-Table -AutoSize

# Export to a CSV file (optional, for later testing)
$report | Export-Csv -Path "M365_License_Report.csv" -NoTypeInformation
Write-Host "Report exported to M365_License_Report.csv" -ForegroundColor Cyan

# Disconnect
Disconnect-MsolService
