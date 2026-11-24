<#
.SYNOPSIS
  Give the containment playbook's managed identity the Microsoft Graph permissions it needs.

.DESCRIPTION
  Run once after deploying the template, signed in as a Global Administrator or
  Privileged Role Administrator of the lab tenant. Requires the Microsoft.Graph module:
    Install-Module Microsoft.Graph -Scope CurrentUser

  Permissions granted (application, least privilege for what the playbook does):
    User.Read.All                  look up the user
    GroupMember.Read.All           check membership of the lab users group
    User.RevokeSessions.All        revoke sign-in sessions
    User.EnableDisableAccount.All  disable the account

.EXAMPLE
  .\Grant-PlaybookGraphPermissions.ps1 -TenantId <tenant-guid> -ManagedIdentityObjectId <identity-guid>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$ManagedIdentityObjectId
)

$permissions = @('User.Read.All', 'GroupMember.Read.All', 'User.RevokeSessions.All', 'User.EnableDisableAccount.All')

$ErrorActionPreference = 'Stop'

Connect-MgGraph -TenantId $TenantId -Scopes 'AppRoleAssignment.ReadWrite.All', 'Application.Read.All' -NoWelcome

$graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$identity = Get-MgServicePrincipal -ServicePrincipalId $ManagedIdentityObjectId
if ($identity.ServicePrincipalType -ne 'ManagedIdentity') {
    throw "The selected object is not a managed identity."
}

$existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $identity.Id
foreach ($permission in $permissions) {
    $role = $graph.AppRoles | Where-Object { $_.Value -eq $permission -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "Graph permission $permission not found." }
    if ($existing.AppRoleId -contains $role.Id) {
        Write-Host "Already granted: $permission"
        continue
    }
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $identity.Id `
        -PrincipalId $identity.Id -ResourceId $graph.Id -AppRoleId $role.Id | Out-Null
    Write-Host "Granted: $permission"
}
