<#
.SYNOPSIS
    Send an email with csv attachment for mailbox statistics retrieved from Office 365.
.DESCRIPTION
    Send an email with csv attachment for mailbox statistics retrieved from Office 365.
.PARAMETER InputSMTPServer
    Specify an unauthenticated SMTP server details.
.PARAMETER InputRecipientEmailAddress
    Specify the recipient email address to receive report, separated by comma.
.PARAMETER InputReportPeriodDays
    Specify the active mailboxes within the last x days. Empty to return all mailboxes.
.EXAMPLE
    .\Get-O365MailboxReport.ps1 -SMTPServer smtp.domain.local -RecipientEmailAddress support@avante-group.com -InputReportPeriodDays 30
.NOTES
    Script name: Get-O365MailboxReport.ps1
    Author:      hsuantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2017-09-19
    Version:     1
#>

# Define global variables
$DebugPreference = "Continue"
$CurrentTime = Get-Date -Format yyyyMMdd-HHmmss
$SenderDomainName = "avante-group.com"
$SMTPPort = "25"
$EOLPSURI = "https://ps.outlook.com/powershell-liveid"
$EmailVerificationRegex = @"
^[a-zA-Z0-9.!£#$%&'^_`{}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$
"@

$isDevelopment = $false

Write-Debug "Starting script on $CurrentTime as $env:username"

# Development pre-populated values
if ($isDevelopment) {
    $InputReportPeriodDays = 30
    $InputSMTPServer = "avantegroup-com01e.mail.protection.outlook.com"
    $InputRecipientEmailAddress = "hendrik.suantio@avante-group.com, support.restricted@avante-group.com"
}

Write-Debug "Input parameters received:"
Write-Debug "SMTPServer: $InputSMTPServer"
Write-Debug "RecipientEmailAddress: $InputRecipientEmailAddress"
Write-Debug "Period Days: $InputReportPeriodDays"

$InputRecipientEmailAddress = $InputRecipientEmailAddress.Replace(' ','')
Write-Debug "Recipient Email Address after blank space trim: $InputRecipientEmailAddress"
$RecipientEmailAddressArray = $InputRecipientEmailAddress.Split(",")

foreach ($RecipientEmailAddress in $RecipientEmailAddressArray) {
    Write-Debug "Verifying email address: $RecipientEmailAddress"
    if ($RecipientEmailAddress -cmatch $EmailVerificationRegex -eq $false)
    {
        Write-Warning "Recipient email address $RecipientEmailAddress did not pass format validation check. Terminating program"
        exit
    }
    else {
        Write-Debug "Email adress $RecipientEmailAddress passed verification check."
    }
}

if ($InputSMTPServer -eq $null)
{
    Write-Warning "SMTP server is not specified. Terminating program..."
    exit
}

# Test connection to SMTP port
try{
    Write-Debug "Starting SMTP server test..."
    $tcpClient = New-Object System.Net.Sockets.TCPClient
    $tcpClient.Connect($InputSMTPServer,$SMTPPort)
    $SMTPConnectState = $tcpClient.Connected
    $tcpClient.Dispose()
}
catch
{ 
    Write-Warning "Failed SMTP server test to $InputSMTPServer on port $SMTPPort. Terminating program"
    #exit
}

if ($InputO365Username -eq $null -and $InputO365Password -eq $null) {
    if ($isDevelopment) {
        Write-Debug "No O365 credential provided, asking for one now..."
        try {
            $O365Credential = Get-Credential
        }
        catch {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
            exit
        }
    }
    else {
        Write-Debug "No O365 credential provided, existing program now."
        exit
    }
}
else {
    Write-Debug "Received O365 credential."
    $O365SecuredPassword = ConvertTo-SecureString $InputO365Password -AsPlainText -Force
    $O365Credential = New-Object System.Management.Automation.PSCredential ($InputO365Username, $O365SecuredPassword)
}

try {
    Write-Debug "Creating an Exchange Online Powershell session..."
    $O365Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $EOLPSURI -Authentication Basic -AllowRedirection -Credential $O365Credential -ErrorAction  Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Debug "Unable to create to Exchange Online Powershell session. Program terminated on $FailedItem with error $ErrorMessage"
    exit
}

try {
    Write-Debug "Connecting to Exchange Online Powershell endpoint..."
    Import-PSSession $O365Session -AllowClobber -ErrorAction Stop
}
catch {
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Debug "Unable to connect to Exchange Online Powershell endpoint. Program terminated on $FailedItem with error $ErrorMessage"
    exit
}

$DomainName = (Get-AcceptedDomain | Where-Object {$_.default -eq $true}).DomainName.ToString()

if ($InputReportPeriodDays -ne 0)
    {
        $MailReportFilePath = "C:\Windows\Temp\O365-$DomainName-ActiveMailbox-Last-$InputReportPeriodDays-Days-$CurrentTime.csv"
        Write-Debug $MailReportFilePath
        try
        {
            Write-Debug "Start generating active mailbox report within last $InputReportPeriodDays days..."
            $Mailboxes = Get-Mailbox -Resultsize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox
                $Mailboxes | Get-MailboxStatistics | Where {$_.LastLogonTime -gt (Get-Date).AddDays(-($InputReportPeriodDays))} |
                Sort -Property LastLogonTime -Descending |
                Select-Object DisplayName,LastLogonTime |
                Export-CSV -NoType -Path $MailReportFilePath
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
        }
    }
    else
    {
        $MailReportFilePath = "C:\Windows\Temp\O365-$DomainName-MailboxReport-$CurrentTime.csv"
        try
        {
            Write-Debug "Start generating report for all mailboxes..."
            $Mailboxes = Get-Mailbox -Resultsize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox
                $Mailboxes | Get-MailboxStatistics |
                Sort -Property LastLogonTime -Descending |
                Select-Object DisplayName,LastLogonTime |
                Export-CSV -NoType -Path $MailReportFilePath
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
        }
    }

    $EmailSubject = "Office 365 Mailbox Report $DomainName - $CurrentTime"
    Write-Debug "Email Subject: $EmailSubject"

    # Send email report
    $SenderEmailAddress = "noreply@$SenderDomainName"
    Write-Debug "Sender email address: $SenderEmailAddress"

    if ($InputReportPeriodDays -ne 0)
    {
        $EmailBody = "See attachment for mailbox report from $((Get-Date).AddDays(-($InputReportPeriodDays)).ToString('yyyyMMdd-HHmmss')) to $CurrentTime."
    }
    else
    {
        $EmailBody = "See attachment for all mailboxes last login report as of $CurrentTime."
    }

    try
    {
        $RecipientEmailAddressArray | ForEach-Object {
            Write-Debug "Sending email to $_"
            Send-MailMessage -To $_ -From $SenderEmailAddress `
                -Subject $EmailSubject -Body $EmailBody -SMTPServer $InputSMTPServer -Attachment $MailReportFilePath

            Write-Debug "Send email return code: $?"
        }
    }
    catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
    }

    try
    {
        Write-Debug "Removing file $MailReportFilePath"
        Remove-Item $MailReportFilePath
        if ($?)
        {
            Write-Debug "Successfully removed file $MailReportFilePath"
        }
    }
    catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
    }

try {
    Write-Debug "Removing remote session $O365Session"
    Remove-PSSession $O365Session
}
catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
}

Write-Debug "Script ends."
# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfdlUXtYapRU0PJKaIQbHkYVE
# we+gggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
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
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU+ve3UYeO7zhnbWNN
# AHykCRWCR3EwDQYJKoZIhvcNAQEBBQAEggEABfYDcswXDm8Rg0nUrkHAi0ynwyY/
# 3SOCzkyEk9ZcqIHp9fYYyhmOXY6cDlaK+b1K7rn2HgYd5V99KvnpgHXCYZFP7HDk
# VTubCbIQXhIwhuhGs3qUfyZa4KGo/U9S3B7PN0cSDEbSTFwS/WMwZPZA+6DHtcB1
# piDQNHEKuVzN5Ik2jqOEMACo027VCN4jmaDn7Y54ervXV663h8udqzfku336rYXQ
# XBmqOZH8BiuiyFMKpuWEj/trfSBm9EQPKwH+CWsSUD5rAv5g3YkSgMDDQ31E5NUp
# SYjfk4iO/wevKKoV1FMCM/dP9y9zgEhksoLdA1b/zAYwZipBdbCTjdkTzg==
# SIG # End signature block
