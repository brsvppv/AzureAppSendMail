
<#
    .SYNOPSIS
    Configure Exchange Online RBAC for Applications so an Azure app can only send mail as specific mailboxes.

    .DESCRIPTION
    - Tags allowed mailboxes (CustomAttribute1='SendMailApp').
    - Creates a Management Scope over those mailboxes.
    - Creates an Exchange Service Principal pointer for the Enterprise Application.
    - Assigns the "Application Mail.Send" role scoped to the scope.
    - Validates with Test-ServicePrincipalAuthorization.
    - Optional: grants SendAs from a specified source mailbox to selected allowed shared mailboxes.
    - Rollback removes role assignments, SP pointer, scope, optional SendAs grants, and clears tags.

    .PARAMETER AppClientId
    Application (client) ID of the Enterprise Application.

    .PARAMETER EnterpriseAppObjectId
    Object ID of the Enterprise Application service principal.

    .PARAMETER IdentityMailbox
    The mailbox that represents the app main identity.

    .PARAMETER AllowedMailboxes
    Array of SMTP addresses the app is allowed to send as.

    .PARAMETER SendAsSourceMailbox
    Optional mailbox to grant SendAs from (defaults to IdentityMailbox).

    .PARAMETER ScopeName
    Name of the Exchange Management Scope.

    .PARAMETER ServicePrincipalDisplayName
    Display name for the Exchange Service Principal pointer.

    .PARAMETER GrantSendAsFromIdentity
    If set, grants SendAs from -SendAsSourceMailbox to each other allowed mailbox.

    .PARAMETER Rollback
    Removes all configuration and clears tags (+ removes SendAs grants if applied).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [string]$AppClientId,

    [Parameter(Mandatory = $true)]
    [string]$EnterpriseAppObjectId,

    [Parameter(Mandatory = $true)]
    [string]$IdentityMailbox,

    [Parameter(Mandatory = $true)]
    [string[]]$AllowedMailboxes,

    [string]$SendAsSourceMailbox = $IdentityMailbox,

    [string]$ScopeName = "SendMail-App-Mailboxes",

    [string]$ServicePrincipalDisplayName = "SendMail SP",

    [switch]$GrantSendAsFromIdentity,

    [switch]$Rollback
)

function Get-ExchangeModule {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
    }
    Import-Module ExchangeOnlineManagement
}

function Connect-ExchangeSession {
    Get-ExchangeModule
    if (-not (Get-ConnectionInformation)) {
        Connect-ExchangeOnline -ShowBanner:$false
    }
}

function Confirm-Prerequisites {
    Write-Host "Confirming prerequisites..."
    Write-Host "1) App must have Microsoft Graph Mail.Send (Application) permission with admin consent."
    Write-Host "2) You must be Exchange Admin."
    Write-Host "3) Mailboxes must exist and be licensed."
    Write-Host "   IdentityMailbox: $IdentityMailbox"
    Write-Host "   AllowedMailboxes: $($AllowedMailboxes -join ', ')"
}

function Set-MailboxTags {
    param([string[]]$Mailboxes)
    foreach ($mbx in $Mailboxes) {
        Set-Mailbox -Identity $mbx -CustomAttribute1 "SendMailApp"
    }
}

function Clear-MailboxTags {
    param([string[]]$Mailboxes)
    foreach ($mbx in $Mailboxes) {
        Set-Mailbox -Identity $mbx -CustomAttribute1 $null
    }
}

function New-ManagementScopeIfMissing {
    param([string]$Name)
    $filter = "CustomAttribute1 -eq 'SendMailApp'"
    $existing = Get-ManagementScope | Where-Object { $_.Name -eq $Name }
    if (-not $existing) {
        New-ManagementScope -Name $Name -RecipientRestrictionFilter $filter
    }
}

function Remove-ManagementScopeIfExists {
    param([string]$Name)
    $scope = Get-ManagementScope | Where-Object { $_.Name -eq $Name }
    if ($scope) {
        Remove-ManagementScope -Identity $Name -Confirm:$false
    }
}

function New-ServicePrincipalIfMissing {
    param([string]$AppId, [string]$ObjectId, [string]$DisplayName)
    $sp = Get-ServicePrincipal | Where-Object { $_.AppId -eq $AppId -or $_.ObjectId -eq $ObjectId }
    if (-not $sp) {
        New-ServicePrincipal -AppId $AppId -ObjectId $ObjectId -DisplayName $DisplayName
    }
}

function Remove-ServicePrincipalIfExists {
    param([string]$DisplayName)
    $sp = Get-ServicePrincipal | Where-Object { $_.DisplayName -eq $DisplayName }
    if ($sp) {
        Remove-ServicePrincipal -Identity $sp.ObjectId -Confirm:$false
    }
}

function New-RoleAssignmentIfMissing {
    param([string]$AppIdentity, [string]$RoleName, [string]$ScopeName)
    $existing = Get-ManagementRoleAssignment -App $AppIdentity |
    Where-Object { $_.Role -eq $RoleName -and $_.CustomResourceScope -eq $ScopeName }
    if (-not $existing) {
        New-ManagementRoleAssignment -Role $RoleName -App $AppIdentity -CustomResourceScope $ScopeName
    }
}

function Remove-RoleAssignmentsForApp {
    param([string]$AppIdentity)
    $assignments = Get-ManagementRoleAssignment -App $AppIdentity
    foreach ($a in $assignments) {
        Remove-ManagementRoleAssignment -Identity $a.Identity -Confirm:$false
    }
}

function Add-SendAsPermissions {
    param([string]$SourceMailbox, [string[]]$Targets)
    foreach ($target in $Targets) {
        if ($target -ieq $SourceMailbox) { continue }
        $existing = Get-RecipientPermission -Identity $target |
        Where-Object { $_.Trustee -eq $SourceMailbox -and $_.AccessRights -contains "SendAs" }
        if (-not $existing) {
            Add-RecipientPermission -Identity $target -Trustee $SourceMailbox -AccessRights SendAs -Confirm:$false
        }
    }
}

function Remove-SendAsPermissions {
    param([string]$SourceMailbox, [string[]]$Targets)
    foreach ($target in $Targets) {
        if ($target -ieq $SourceMailbox) { continue }
        Remove-RecipientPermission -Identity $target -Trustee $SourceMailbox -AccessRights SendAs -Confirm:$false
    }
}

function Test-AppAuthorization {
    param([string]$AppIdentity, [string[]]$Allowed, [string[]]$DeniedSamples)
    foreach ($mbx in $Allowed) {
        $res = Test-ServicePrincipalAuthorization -Identity $AppIdentity -Resource $mbx
        if ($res.InScope) {
            Write-Host "[ALLOW] $mbx : OK"
        }
        else {
            Write-Host "[ALLOW] $mbx : FAILED"
        }
    }
    foreach ($mbx in $DeniedSamples) {
        $res = Test-ServicePrincipalAuthorization -Identity $AppIdentity -Resource $mbx
        if ($res.InScope) {
            Write-Host "[DENY] $mbx : FAILED"
        }
        else {
            Write-Host "[DENY] $mbx : OK"
        }
    }
}

Connect-ExchangeSession
Confirm-Prerequisites

if ($Rollback) {
    Remove-RoleAssignmentsForApp -AppIdentity $ServicePrincipalDisplayName
    Remove-ServicePrincipalIfExists -DisplayName $ServicePrincipalDisplayName
    Remove-ManagementScopeIfExists -Name $ScopeName
    if ($GrantSendAsFromIdentity) {
        Remove-SendAsPermissions -SourceMailbox $SendAsSourceMailbox -Targets $AllowedMailboxes
    }
    Clear-MailboxTags -Mailboxes $AllowedMailboxes
    Write-Host "Rollback complete."
    return
}

Set-MailboxTags -Mailboxes $AllowedMailboxes
New-ManagementScopeIfMissing -Name $ScopeName
New-ServicePrincipalIfMissing -AppId $AppClientId -ObjectId $EnterpriseAppObjectId -DisplayName $ServicePrincipalDisplayName
$roleName = (Get-ManagementRole | Where-Object { $_.Name -eq "Application Mail.Send" }).Name
New-RoleAssignmentIfMissing -AppIdentity $ServicePrincipalDisplayName -RoleName $roleName -ScopeName $ScopeName

if ($GrantSendAsFromIdentity) {
    Add-SendAsPermissions -SourceMailbox $SendAsSourceMailbox -Targets $AllowedMailboxes
}

Test-AppAuthorization -AppIdentity $ServicePrincipalDisplayName -Allowed $AllowedMailboxes -DeniedSamples @()
