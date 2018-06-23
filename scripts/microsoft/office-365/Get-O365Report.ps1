$Credentials = Get-Credential
Import-Module msonline
Connect-MsolService -Credential $Credentials
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Credentials -Authentication Basic -AllowRedirection
Import-PSSession $Session
$Report=@()
$Mailboxes = Get-Mailbox -ResultSize Unlimited | where {$_.RecipientTypeDetails -ne "DiscoveryMailbox"}
$MSOLDomain = Get-MsolDomain | where {$_.Authentication -eq "Managed" -and $_.IsDefault -eq "True"}
$MSOLPasswordPolicy = Get-MsolPasswordPolicy -DomainName $MSOLDomain.name
$MSOLPasswordPolicy = $MSOLPasswordPolicy.ValidityPeriod.ToString()
foreach ($mailbox in $Mailboxes) {
$DaysToExpiry = @()
$DisplayName = $mailbox.DisplayName
$UserPrincipalName  = $mailbox.UserPrincipalName
$UserDomain = $UserPrincipalName.Split('@')[1]
$Alias = $mailbox.alias
$MailboxStat = Get-MailboxStatistics $UserPrincipalName
$LastLogonTime = $MailboxStat.LastLogonTime 
$TotalItemSize = $MailboxStat | select @{name="TotalItemSize";expression={[math]::Round(($_.TotalItemSize.ToString().Split("(")[1].Split(" ")[0].Replace(",","")/1MB),2)}}
$TotalItemSize = $TotalItemSize.TotalItemSize
$RecipientTypeDetails = $mailbox.RecipientTypeDetails
$MSOLUSER = Get-MsolUser -UserPrincipalName $UserPrincipalName
if ($UserDomain -eq $MSOLDomain.name) {$DaysToExpiry = $MSOLUSER |  select @{Name="DaysToExpiry"; Expression={(New-TimeSpan -start (get-date) -end ($_.LastPasswordChangeTimestamp + $MSOLPasswordPolicy)).Days}}; $DaysToExpiry = $DaysToExpiry.DaysToExpiry}
$Information = $MSOLUSER | select FirstName,LastName,@{Name='DisplayName'; Expression={[String]::join(";", $DisplayName)}},@{Name='Alias'; Expression={[String]::join(";", $Alias)}},@{Name='UserPrincipalName'; Expression={[String]::join(";", $UserPrincipalName)}},Office,Department,@{Name='TotalItemSize (MB)'; Expression={[String]::join(";", $TotalItemSize)}},@{Name='LastLogonTime'; Expression={[String]::join(";", $LastLogonTime)}},LastPasswordChangeTimestamp,@{Name="PasswordExpirationIn (Days)"; Expression={[String]::join(";", $DaysToExpiry)}},@{Name='RecipientTypeDetails'; Expression={[String]::join(";", $RecipientTypeDetails)}},islicensed,@{Name="Licenses"; Expression ={$_.Licenses.AccountSkuId}} 
$Report = $Report+$Information
}
$Report | export-csv O365Report.csv
Get-PSSession | Remove-PSSession

# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUqM2m2ChdYN1Bev5lNdZrBVyq
# ZkygggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
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
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUwdhctFN0s0yegiCq
# snX5TSQ2SNQwDQYJKoZIhvcNAQEBBQAEggEABZYHgXun+ojT15xEuGbgiDHnWwjL
# KXXgP5THLIWZDIa0hNaDJCqNH1qL04bGIaAVbvrKoJZs/ANuQtdpgvwRcV+qRVk5
# 5PGkoR0MD5ETEkMVrrzEPh4+ZLLtlSkHvuYG0gUhRrXCAb5c/C55TyD9Q9LXYtEg
# RR7ce7OIXsOvPMy/cLm29Y610h4YN6oAOswWp0BvxEzkMp53JSnZY4LTtRzx+DtB
# V0Q2/iwxC1Kw1IoTfe42PjoHEqB/sB7Q0fxLNAPs10TY9AD9fNLXY/GyF1uvrKiG
# CcCoIj0zOuh2aZk4WEYmmoihW4iBEZBw/c6l1smOg0ujryjV5GGM+o+G4g==
# SIG # End signature block
