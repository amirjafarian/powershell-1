$timestamp = get-date -Format yyyyMMdd_HHmmss
$isDevelopment = $true

if ($isDevelopment) {
}

$O365SecuredPassword = ConvertTo-SecureString $InputO365Password -AsPlainText -Force
$O365Credential = New-Object System.Management.Automation.PSCredential ($InputO365Username, $O365SecuredPassword)

connect-msolservice -credential $O365Credential

$LicensedUsers = get-msoluser -all | where {$_.islicensed -eq $true -and $_.licenses.accountskuid -eq "reseller-account:OFFICESUBSCRIPTION"} | sort displayname

$LicensedUsers | Foreach {
    $objarray = [ordered]@{}
    $msoluser = $_

    $objarray.add("Name", $msoluser.displayname)

    foreach ($proxyaddress in $msoluser.proxyaddresses) {
        if ($proxyaddress -clike "SMTP:*") {
            $data = $proxyaddress.Split(":")
            $objarray.add("Email", $data[1])
        }
    }

    foreach ($accountsku in $msoluser.licenses.accountskuid) {
        if ($accountsku -clike "reseller-account:OFFICESUBSCRIPTION") {
            $objarray.add("License", $accountsku)
        }
    }

    [pscustomobject]$objarray | export-csv -NoTypeInformation -Append -Force -Path C:\temp\export_$timestamp.csv
}

# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU/qzQsau7dDGWTOZ8Bq6Dkp9C
# mNqgggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
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
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUbM1ThoyRxqmpA77S
# n1kC+8h4KlowDQYJKoZIhvcNAQEBBQAEggEAWdw/v3/FlGhXnGAVC0PYd+E8iCQ7
# yLCiukZCiVlSQJrugI3CbeZZO4betsFqhrqyDvi82GJuMU3fnEOHekWCQAoG4em4
# emTLgD2xDbFfZycr9fTW58m2LiQBIkhYS30Bvw1sOYOwZzO0W9e8yHfemNv7Ilnv
# V0c3kjLU48aFEOA4E/43ffjRHAZRZcy2XctUSQaxQ2EGURmCvRMVH2SsuOY81OYU
# JYfH1poPLGCD6awtJmrK5djW476DEvwIixsVa3nKd73drz3IAt1qJarE4AX+PIgU
# Hg+aTE1myViLjoZnkTVz/Wsp3Olu9MyWS66fKsAKPRq1bSIWlzcYn0N8fQ==
# SIG # End signature block
