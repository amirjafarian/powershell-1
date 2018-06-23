<#
.SYNOPSIS
    Get MS Online user report including MFA details.
.DESCRIPTION
    Get MS Online user report including MFA details.
.EXAMPLE
    .\Get-AzureMFAReport.ps1
.NOTES
    Script name: Get-AzureMFAReport.ps1
    Author:      hsuantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2018-05-4
    Version:     1
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $true, position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$MsolUsername,
    [Parameter(Mandatory = $true, position = 1)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_})]
    [string]$MsolSecurePasswordFile
)

# Define variables
$IsDebug = $false

if ($IsDebug)
{
    $MsolUsername = 'admin@tenant.onmicrosoft.com'
    $MsolSecurePasswordFile = 'C:\Temp\password.txt'
}

$MsolSecurePwdText = Get-Content -Path $MsolSecurePasswordFile
$MsolSecurePwd = $MsolSecurePwdText | ConvertTo-SecureString
$MsolCred = New-Object System.Management.Automation.PSCredential -ArgumentList $MsolUsername, $MsolSecurePwd

if ( ! (Get-MsolCompanyInformation -ErrorAction SilentlyContinue) )
{
    Write-Host "Connecting to MS Online..."
    Connect-MsolService -Credential $MsolCred -ErrorAction Stop
}

$MsolUsers = Get-MsolUser | Sort-Object DisplayName
$objarray = @()

foreach ($MsolUser in $MsolUsers)
{
    $object = New-Object -TypeName PSCustomObject
    $object | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $MsolUser.DisplayName
    $object | Add-Member -MemberType NoteProperty -Name "User Principal Name" -Value $MsolUser.UserPrincipalName
    $object | Add-Member -MemberType NoteProperty -Name "Is Licensed" -Value $MsolUser.IsLicensed
    $object | Add-Member -MemberType NoteProperty -Name "Sign-in Blocked" -Value $MsolUser.BlockCredential
    $object | Add-Member -MemberType NoteProperty -Name "MFA State" -Value $MsolUser.StrongAuthenticationRequirements.State

    $DefaultMFAMethod = ($MsolUser.StrongAuthenticationMethods | Where-Object {$_.IsDefault -eq $true}).MethodType
    $object | Add-Member -MemberType NoteProperty -Name "Default MFA Method" -Value $DefaultMFAMethod

    $AssignedLicenses = $MsolUser.Licenses.AccountSkuId -Join ','
    $object | Add-Member -MemberType NoteProperty -Name "Licenses" -Value $AssignedLicenses
    $object | Add-Member -MemberType NoteProperty -Name "MFA Phone" -Value $MsolUser.StrongAuthenticationUserDetails.PhoneNumber
    $object | Add-Member -MemberType NoteProperty -Name "MFA Alt Phone" -Value $MsolUser.StrongAuthenticationUserDetails.AlternativePhoneNumber
    $object | Add-Member -MemberType NoteProperty -Name "MFA E-mail" -Value $MsolUser.StrongAuthenticationUserDetails.Email
    $object | Add-Member -MemberType NoteProperty -Name "MFA PIN" -Value $MsolUser.StrongAuthenticationUserDetails.PIN
    $object | Add-Member -MemberType NoteProperty -Name "Old PIN" -Value $MsolUser.StrongAuthenticationUserDetails.OldPIN
    $objarray += $object
}

$objarray | Export-CSV -NoTypeInformation -Path '.\MFAReport.csv'