<#
.SYNOPSIS
    Generates a report for on-prem and Azure AD UPN match and sync status.
.DESCRIPTION
    Generates a report for on-prem and Azure AD UPN match and sync status.
.PARAMETER DomainController
    Specify domain controller name.
.PARAMETER MsolUsername
    Specify Azure AD admin username.
.PARAMETER MsolSecurePasswordFile
    Specify Azure AD admin secure password file. Create the secure password file:
    Read-Host -Prompt "Enter Azure AD admin password" -AsSecureString | ConvertFrom-SecureString | Set-Content -Path "C:\Temp\pwd.txt"
.EXAMPLE
    .\Get-AzureADSyncReport.ps1 -DomainController dc.contoso.com -MsolUsername admin@contoso.onmicrosoft.com -MsolSecurePasswordFile "C:\Temp\pwd.txt"
.NOTES
    Script name: Get-AzureADSyncReport.ps1
    Author:      hsuantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2018-03-28
    Version:     1
#>

[CmdletBinding()]

Param
(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string]$DomainController,

    [Parameter(Position = 1, Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string]$MsolUsername,

    [Parameter(Position = 2, Mandatory = $true)]
    [ValidateScript({Test-Path -Path $_})]
    $MsolSecurePasswordFile
)

if (! (Get-ADDomain -ErrorAction SilentlyContinue) )
{
    $ADSession = New-PSSession -ComputerName $DomainController
    Import-PSSession -Session $ADSession -Module "ActiveDirectory"
}

if (! (Get-MsolDomain -ErrorAction SilentlyContinue) )
{
    $MsolSecurePwdText = Get-Content -Path $MsolSecurePasswordFile
    $MsolSecurePwd = $MsolSecurePwdText | ConvertTo-SecureString
    $MsolCred = New-Object System.Management.Automation.PSCredential -ArgumentList $MsolUsername, $MsolSecurePwd
    Connect-MsolService -Credential $MsolCred
}

<#
if (! (Get-Mailbox) )
{
    $EOLSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell -Credential $MsolCred -AllowRedirection -Authentication Basic
    Import-PSSession -Session $EOLSession
}
#>

$UnlinkedAzureADUsers = Get-MsolUser | Where-Object {$_.UserPrincipalName -notlike '*#EXT#*'}
Write-Host "Found $($UnlinkedAzureADUsers.Count) unlinked Azure AD user objects."

$array = @()

foreach ($AzureADUser in $UnlinkedAzureADUsers)
{
    $object = New-Object -TypeName PSCustomObject
    $object | Add-Member -MemberType NoteProperty -Name "Azure AD Display Name" -Value $AzureADUser.DisplayName
    $object | Add-Member -MemberType NoteProperty -Name "Azure AD UPN" -Value $AzureADUser.UserPrincipalName

    $object | Add-Member -MemberType NoteProperty -Name "Azure AD Immutable ID" -Value $AzureADUser.ImmutableId

    if ($AzureADUser.ProxyAddresses -ne $null)
    {
        foreach ($AzureADSMTPAddress in $AzureADUser.ProxyAddresses)
        {
            if ($AzureADSMTPAddress -cmatch "SMTP:")
            {
                $AzureADSMTPAddress = $AzureADSMTPAddress -replace ("SMTP:","")
                $object | Add-Member -MemberType NoteProperty -Name "Azure AD primary SMTP" -Value $AzureADSMTPAddress
                break
            }
        }
    }

    Write-Host "Searching for AD account with UPN $($AzureADUser.UserPrincipalName)..."
    $ADUser = Get-ADUser -Filter "UserPrincipalName -eq '$($AzureADUser.UserPrincipalName)'" -Properties * -ErrorAction SilentlyContinue

    if ($ADUser)
    {
        $object | Add-Member -MemberType NoteProperty -Name "On-prem Display Name" -Value $ADUser.Name
        $object | Add-Member -MemberType NoteProperty -Name "On-prem UPN" -Value $ADUser.UserPrincipalName

        if ($AzureADUser.ImmutableId)
        {
            Write-Host "Found immutable ID"
            $objADUserImmutableId = New-Object -TypeName System.Guid -ArgumentList $ADUser.ObjectGuid
            $ADUserImmutableId = [System.Convert]::ToBase64String($objADUserImmutableId.ToByteArray())

            $object | Add-Member -MemberType NoteProperty -Name "On-prem immutableId" -Value $ADUserImmutableId
            Write-Host "$($AzureADUser.ImmutableId) $ADUserImmutableId"
            if ($ADUserImmutableId -match $AzureADUser.ImmutableId)
            {
                $object | Add-Member -MemberType NoteProperty -Name "Synced to on-prem" -Value $true
            }
            else
            {
                $object | Add-Member -MemberType NoteProperty -Name "Synced to on-prem" -Value $false
            }
        }
        else
        {
            $object | Add-Member -MemberType NoteProperty -Name "Synced to on-prem" -Value $false
        }

        if ($ADUser.proxyAddresses -ne $null)
        {
            foreach ($ADUserSMTPAddress in $ADUser.proxyAddresses)
            {
                if ($ADUserSMTPAddress -cmatch "SMTP:")
                {
                    $ADUserSMTPAddress = $ADUserSMTPAddress -replace ("SMTP:","")
                    $object | Add-Member -MemberType NoteProperty -Name "On-prem primary SMTP" -Value $ADUserSMTPAddress
                    break
                }
            }
        }
    }

    if ($AzureADUser.UserPrincipalName -match $ADUser.UserPrincipalName)
    {
        $object | Add-Member -MemberType NoteProperty -Name "UPN Match" -Value $true
    }
    else
    {
        $object | Add-Member -MemberType NoteProperty -Name "UPN Match" -Value $false
    }

    if ($AzureADSMTPAddress -match $ADUserSMTPAddress)
    {
        $object | Add-Member -MemberType NoteProperty -Name "Primary SMTP match" -Value $true
    }
    else
    {
        $object | Add-Member -MemberType NoteProperty -Name "Primary SMTP match" -Value $false
    }

    $array += $object
}

$array | Export-CSV -NoTypeInformation -Path ".\report.csv"