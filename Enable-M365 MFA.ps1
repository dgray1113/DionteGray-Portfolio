# Script: Enable-M365 MFA.ps1
# Description: Enables MFA for a specified Microsoft 365 user

# Install MSOnline module if not present (run once with admin rights)
if (-not (Get-Module -ListAvailable -Name MSOnline)) {
    Install-Module -Name MSOnline -Force -Scope CurrentUser
}

# Import module
Import-Module MSOnline

# Connect to MSOnline (enter admin credentials when prompted)
Connect-MsolService

# Enable MFA for a user (replace "user@domain.com" with a test user)
$userPrincipalName = "user@domain.com"
$mfaState = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$mfaState.RelyingParty = "*"
$mfaState.State = "Enabled"
Set-MsolUser -UserPrincipalName $userPrincipalName -StrongAuthenticationRequirements $mfaState

Write-Host "MFA enabled for $userPrincipalName" -ForegroundColor Green

# Disconnect
Disconnect-MsolService
