<#
.SYNOPSIS
    Create read-only Exchange online admin account.
.DESCRIPTION
    Create read-only Exchange online admin account with UPN roadmin@tenant.onmicrosoft.com.
.EXAMPLE
    .\Create-ExchangeOnlineAdmin.ps1
.NOTES
    Script name: Create-ExchangeOnlineAdmin.ps1
    Author:      hsuantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2017-09-21
    Version:     1
#>

$DebugPreference = "Continue"
$CurrentTime = Get-Date -Format yyyyMMdd-HHmmss
Write-Debug "Starting script on $CurrentTime..."

function Catch-Exception
{    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("ExceptionObject")]
        [Object[]]$CEExceptionObject,

        [Parameter(Mandatory=$false, Position=1)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($true,$false)]
        [Alias('ForceExit')]
        [bool]$CEForceExit = $false,
        
        [Parameter(Mandatory=$false, Position=2)]
        [ValidateNotNullOrEmpty()]
        [Alias("Message")]
        [string]$CECustomMessage
    )

        Write-Debug " Exception on $($CEExceptionObject.Exception.ItemName) with error $($CEExceptionObject.Exception.Message)"
        Write-Debug "Code trace: $($CEExceptionObject.InvocationInfo.PositionMessage)"

    if ($CEForceExit) {
        Write-Debug "Terminating program."
        exit
    }
}

# Specify global variables
$EOLPSURI = "https://ps.outlook.com/powershell-liveid"
$RoleGroupName = "View-Only Organization Management"
Write-Debug "Role group name: $RoleGroupName"
$FirstName = "Read-Only"
$LastName = "Admin"
$DisplayName = "Read-Only Admin"

try {
    $O365Credential = Get-Credential
}
catch {
    Catch-Exception -ExceptionObject $_ -ForceExit $true
}

try {
    Connect-MsolService -Credential $O365Credential -ErrorAction Stop
}
catch {
    Catch-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to connect to MS Online."
}

if ($?) {
    Write-Debug "Successfully connected to MS Online."
}

$MSDomain = (Get-MsolDomain | Where {$_.IsInitial -eq $true}).Name
Write-Debug "O365 initial domain name: $MSDomain"
$UPN = "roadmin@$MSDomain"
Write-Debug "User principal name: $UPN"

try {
    if ((Get-MsolUser -UserPrincipalName $UPN -ErrorAction SilentlyContinue) -eq $null) {
        $ROAdminPassword = Read-Host "Specify read-only admin password"
        if ($ROAdminPassword -eq $null) {
            Write-Debug "No read-only admin password is specified, terminating program."
            exit
        }
        New-MsolUser -UserPrincipalName $UPN -DisplayName $DisplayName -FirstName $FirstName -LastName $LastName -Password $ROAdminPassword -ForceChangePassword $false -ErrorAction Stop
        if ($?) {
            Write-Debug "Successfully created MS Online user: $UPN"
        }
        $WaitTime = 60
        Write-Debug "Synchronizing Azure AD accounts with Exchange Online..."
        Start-Sleep -Seconds $WaitTime
    }
    else {
        Write-Debug "MS Online user $UPN already exists. Skipping read-only admin account creation."
    }
}
catch {
    Catch-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to create to new MSOL user."
}

try {
    Write-Debug "Creating an Exchange Online Powershell session..."
    $O365Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $EOLPSURI -Authentication Basic -AllowRedirection -Credential $O365Credential -ErrorAction Stop
}
catch {
    Catch-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to create to Exchange Online Powershell session."
}

try {
    Write-Debug "Connecting to Exchange Online Powershell endpoint..."
    Import-PSSession $O365Session -AllowClobber -ErrorAction Stop
}
catch {
    Catch-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to connect to Exchange Online Powershell endpoint."
}

Write-Debug "Checking if $UPN is a member of $RoleGroupName"
if ( (Get-RoleGroupMember $RoleGroupName).WindowsLiveID -contains $UPN ) {
    Write-Debug "$UPN is already a member of $RoleGroupName, skipping adding this user as a member."
}
else {
    try {
        Write-Debug "$UPN is not a member of $RoleGroupname, adding $UPN to $RoleGroupName"
        Add-RoleGroupMember $RoleGroupName -Member $UPN -ErrorAction Stop
        if ($?) {
            Write-Debug "Successfully added $UPN to $RoleGroupName"
        }
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to add $UPN as a member of $RoleGroupName."
    }
}

try {
    Write-Debug "Removing remote session $O365Session"
    Remove-PSSession $O365Session
}
catch
{
    Catch-Exception -ExceptionObject $_
}
# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdA9faMz/uHulP8J/5NaWi5cq
# HUigggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
# MCwxKjAoBgNVBAMTIVBvd2Vyc2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9vdDAe
# Fw0xNzEwMjgyMTQyMzJaFw0zOTEyMzEyMzU5NTlaMCgxJjAkBgNVBAMTHVBvd2Vy
# c2hlbGwgU2NyaXB0IFNpZ25lciAtIEhTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAw4GUosNnfrLeWRI7X2LhL9L4+zcUrZTg/rQRcXenjLVMgFnkew4h
# PyMDiJxg4DiUXDL97hQLLQ6azMptbxM+MhrolNRHa1jNEqcTs2DaEhIQxFhdj+bQ
# 6h65X0k6wuGUBXiXDHLwXibS7Oy2HgMWoBtMG4sMEynMu5ywTptGpbBPq7cE2ahp
# k1VwW4dc2hiUvfsf4yCjq3bqGGDxPgzaUROYcjNzhxmaUsJsnFRrT/OB8CxfH1z7
# +noKl2yu5U3VlieIQTzMtMuglniz0wrHIOWNnp5qY4OHW5CLDDJcvgD27l39iRXW
# 4sUHiiUUxsLrjnqhVeFM8TDL4GH8LACuBQIDAQABo3YwdDATBgNVHSUEDDAKBggr
# BgEFBQcDAzBdBgNVHQEEVjBUgBCq5Uw6E3O/udrOsUNpd59HoS4wLDEqMCgGA1UE
# AxMhUG93ZXJzaGVsbCBMb2NhbCBDZXJ0aWZpY2F0ZSBSb290ghBMIIz9PMiLkEo/
# p2WcS5pnMAkGBSsOAwIdBQADggEBAFYYQ6RiXeecMezWqtmkcW6YPuBkai9yauEM
# L8X9G/Mgi1AyHSF5veZXuEoj4VT80cu9d2mWn5sWJ9Z72INYATdBd8iMGYwmggVs
# ghtTFGpqR3Bhw9GAKRJyKirTJqh4uBVLOXASyEb81cAyxE+UHRkP5LZ5UwbB1Egm
# +iEH9DdGBSJY7tucowXBAeXG82DluGaBkErkfuJt2ua9oRqUkRWOR+9M3Qvk/5Jf
# 3OmAmh8rvV33hSw35kMeSQvrASmdp2A+OOnHQs5RPU/24d//UcqFJzE6k8wgEUqI
# +f/7LO1iyimLHiabiU54myeSVRcoHyKT10LlhqAgEUl11u+mZLoxggHhMIIB3QIB
# ATBAMCwxKjAoBgNVBAMTIVBvd2Vyc2hlbGwgTG9jYWwgQ2VydGlmaWNhdGUgUm9v
# dAIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEK
# MAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUTQ8CLny+q1cdDaHK
# egTFHQjDkq4wDQYJKoZIhvcNAQEBBQAEggEAVLyPT9M1ZfMD/M4jgbBbrm2i753d
# sCjMQT3MnHYuO0z/pjTEclRnpC/Eq8jc12vhQt62HVgiodObTZFwFBgDRQ7/IenG
# tedKWVDTYubtFHE9n8CA17B0C58rCQeUBmx/0pwUDmqYZwDkNPZtmFVpeurgFX/Z
# Ev0Z8QJ0wUpvRuuZOHNNKlvBIFi+rumVI4ILA0FIxqnPYWOqI4KSM4rBnpsTGQYN
# YNiUXX3KCQABXxKB0pAQu8AXo9VnxLCRvYfkE85nE46gj9NKZWwyivLV/h6xj1aW
# +aBzgcFnraiOVcT/xB0rhjJH+Y1WjM9RJpHx5EEGS6MqynFknYnM57Cs2A==
# SIG # End signature block
