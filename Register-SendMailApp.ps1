<#
    .SYNOPSIS
    Register a new Azure App and assign Microsoft Graph permissions as prerequisites for Configure-SendMail.ps1.

    .DESCRIPTION
    - Creates an Azure App Registration using Microsoft Graph.
    - Creates a service principal for the app.
    - Assigns Microsoft Graph API permissions (Mail.Send, Application).
    - Outputs the AppId and TenantId for use in Configure-SendMail.ps1.
    - The `SignInAudience` parameter controls who can sign in to the app:
    - "AzureADMyOrg": Only users in your Azure AD tenant (single organization).
    - "AzureADMultipleOrgs": Users in any Azure AD tenant (multi-tenant).
    - "AzureADandPersonalMicrosoftAccount": Both Azure AD users and personal Microsoft accounts (e.g., Outlook.com).
    - "PersonalMicrosoftAccount": Only personal Microsoft accounts (no Azure AD).
    - Choose the audience based on your scenario: for most organizational apps, use "AzureADMyOrg"; for multi-tenant SaaS, use "AzureADMultipleOrgs"; for consumer-facing apps, use one of the personal account options.

    .NOTES
    Requires Microsoft Graph PowerShell SDK and admin consent for Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All.
#>

function Register-SendMailApp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppName,
        [Parameter(Mandatory = $false)]
        [string]$SignInAudience = "AzureADMyOrg"
    )

    Connect-MgGraph -Scopes "Application.ReadWrite.All AppRoleAssignment.ReadWrite.All" -ErrorAction Stop

    $app = New-MgApplication -DisplayName $AppName -SignInAudience $SignInAudience -IsFallbackPublicClient -ErrorAction Stop
    Write-Host "App registration created with AppId: $($app.AppId)" -ForegroundColor Cyan

    $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
    Write-Host "Service principal created with ObjectId: $($sp.Id)" -ForegroundColor Cyan

    # Assign Mail.Send (Application) permission
    $graphApp = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'" # Microsoft Graph SP
    $mailSendPermission = $graphApp.AppRoles | Where-Object { $_.Value -eq "Mail.Send" -and $_.AllowedMemberTypes -contains "Application" }
    if ($mailSendPermission) {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphApp.Id -AppRoleId $mailSendPermission.Id -ErrorAction Stop
        Write-Host "Assigned Mail.Send (Application) permission to app." -ForegroundColor Green
    }
    else {
        Write-Host "Could not find Mail.Send (Application) permission." -ForegroundColor Red
    }

    Write-Host "AppId: $($app.AppId)"
    Write-Host "TenantId: $((Get-MgContext).TenantId)"
    Disconnect-MgGraph | Out-Null
}

# Example usage:
Register-SendMailApp -AppName "SendMail"
