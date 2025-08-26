# AzureAppSendMail

PowerShell scripts to automate Azure App Registration and configure Exchange Online RBAC for sending emails via Microsoft Graph API.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Scripts](#scripts)
- [License](#license)

---

## Overview

This repository provides scripts for:

- Configuring Exchange Online RBAC for applications so an Azure app can only send mail as specific mailboxes.
- Tagging allowed mailboxes, creating management scopes, service principal pointers, and assigning the "Application Mail.Send" role.
- Validating access and optionally granting SendAs permissions for advanced scenarios.

## Features

- Automated Azure App Registration
- Assigns Microsoft Graph API permissions
- Configures Exchange Online RBAC for mail-sending
- Optionally grants SendAs permissions from a main mailbox to others
- Preflight checklist for prerequisites
- Rollback support to remove all configuration

## Requirements

- PowerShell 7 or later
- ExchangeOnlineManagement module ([Install Guide](https://learn.microsoft.com/powershell/exchange/exchange-online-powershell-v2))
- Microsoft Graph PowerShell SDK ([Install Guide](https://learn.microsoft.com/powershell/microsoftgraph/installation))
- Microsoft Graph API permissions (Mail.Send, Application)
- Azure account with admin privileges
- Exchange Administrator permissions

## Setup

1. **Clone the repository:**
   ```pwsh
   git clone https://github.com/<your-org>/AzureAppSendMail.git
   cd AzureAppSendMail
   ```
2. **Install required PowerShell modules:**
   ```pwsh
   Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
   Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
   ```

## Usage

### 1. Configure Azure App and RBAC

Use the main script to configure RBAC for allowed mailboxes and grant permissions:

```pwsh
./Configure-SendMail.ps1 `
  -AppClientId "<app-client-id>" `
  -EnterpriseAppObjectId "<enterprise-app-object-id>" `
  -IdentityMailbox "no-reply@domain.com" `
  -AllowedMailboxes @("no-reply@domain.com", "shared@domain.com") `
  -SendAsSourceMailbox "no-reply@domain.com" `
  -ScopeName "SendMail-App-Mailboxes" `
  -ServicePrincipalDisplayName "SendMail SP" `
  -GrantSendAsFromIdentity
```

#### Parameter Explanations

- **AppClientId**: The Application (client) ID of your Azure Enterprise Application. Find this in Azure Portal under Entra ID > Enterprise Applications > [Your App] > Overview.
- **EnterpriseAppObjectId**: The Object ID of the Enterprise Application service principal. Also found in Azure Portal under Entra ID > Enterprise Applications > [Your App] > Overview.
- **IdentityMailbox**: The mailbox that represents the app’s main identity (e.g., no-reply@domain.com). This is the mailbox the app will use to send mail.
- **AllowedMailboxes**: Array of SMTP addresses the app is allowed to send as. Include all mailboxes you want the app to be able to send from.
- **SendAsSourceMailbox**: The mailbox that will be granted SendAs permissions to the other allowed mailboxes. Defaults to `IdentityMailbox`. Set this if you want a different mailbox to be able to send as others.
- **ScopeName**: Name of the Exchange Management Scope. Used to scope RBAC permissions to only the tagged mailboxes. You can use the default or set a custom name.
- **ServicePrincipalDisplayName**: Display name for the Exchange Service Principal pointer. Used for identification in Exchange. You can use the default or set a custom name.
- **GrantSendAsFromIdentity**: If set, grants SendAs from the source mailbox to each other allowed mailbox. Use this if you want the app to be able to send as other mailboxes (e.g., for shared mailboxes).

Where to get these values:

- All Azure-related IDs are found in the Azure Portal under Entra ID > Enterprise Applications > [Your App].
- Mailbox addresses must exist in Exchange Online and be licensed for sending mail.
- Scope and display names can be customized for your organization’s standards.

Why set these values:

- To restrict and control which mailboxes the app can send as, improving security and compliance.
- To enable advanced scenarios like sending as shared mailboxes or granting SendAs permissions for automation.

### What the script does

- Tags allowed mailboxes for RBAC
- Creates/updates management scope
- Creates/updates service principal pointer
- Assigns the Mail.Send role
- Optionally grants SendAs permissions
- Validates authorization
- Supports rollback to clean up configuration

## Scripts

### Configure-SendMail.ps1

Main entry point for all configuration and maintenance scenarios.

Example:

```pwsh
./Configure-SendMail.ps1 -AppClientId "<app-client-id>" -EnterpriseAppObjectId "<enterprise-app-object-id>" -IdentityMailbox "no-reply@domain.com" -AllowedMailboxes @("no-reply@domain.com", "shared@domain.com") -SendAsSourceMailbox "no-reply@domain.com" -GrantSendAsFromIdentity
```

## License

MIT
