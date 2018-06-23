<#
.SYNOPSIS
    Get Office 365 accounts service plan report.
.DESCRIPTION
    Get Office 365 accounts service plan report.
.EXAMPLE
    .\Get-O365ServicePlans.ps1 -MsolUsername "admin@contoso.onmicrosoft.com" -MsolSecurePasswordFile "C:\Temp\securepassword.txt"
.NOTES
    Script name: Get-O365ServicePlans.ps1
    Author:      hsuantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2018-05-07
    Version:     1
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$MsolUsername,

    [Parameter(Mandatory=$true, Position=1)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript ({Test-Path $_})]
    [string]$MsolSecurePasswordFile,

    [Parameter(Mandatory=$false, Position=2)]
    [switch]$ForceLogin = $false
)

if ( (-Not (Get-Command Get-MsolUser -ErrorAction SilentlyContinue) ) -or (-Not (Get-Command Get-Mailbox -ErrorAction SilentlyContinue) ) -or $ForceLogin )
{
    Write-Host "Importing modules..."
    $MsolSecurePwdText = Get-Content -Path $MsolSecurePasswordFile
    $MsolSecurePwd = $MsolSecurePwdText | ConvertTo-SecureString
    $MsolCred = New-Object System.Management.Automation.PSCredential -ArgumentList $MsolUsername, $MsolSecurePwd
    Connect-MsolService -Credential $MsolCred
    $EOLSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.outlook.com/powershell-liveid -Authentication Basic -Credential $MsolCred -AllowRedirection
    Import-PSSession -Session $EOLSession
}

$objarray = @()
$MsolUsers = Get-MsolUser | Where-Object {$_.IsLicensed -eq $true} | Sort-Object DisplayName

foreach ($MsolUser in $MsolUsers)
{
    foreach ($License in ($MsolUser.Licenses))
    {
        if ($License.AccountSku.SkuPartNumber -match "ENTERPRISEPACK")
        {
            $object = New-Object -TypeName PSCustomObject
            $object | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $MsolUser.DisplayName
            foreach ($ServicePlan in $License.ServiceStatus)
            {
                $object | Add-Member -MemberType NoteProperty -Name $ServicePlan.ServicePlan.ServiceName -Value $ServicePlan.ProvisioningStatus
            }
            $objarray += $object
        }
    }
}

$objarray | Export-Csv -NoTypeInformation -Path 'C:\Temp\tenant-msolserviceplans.csv'