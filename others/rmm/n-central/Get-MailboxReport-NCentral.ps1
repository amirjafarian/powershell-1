<#
.SYNOPSIS
    Send an email with csv attachment for mailbox statistics retrieved from an Exchange server.
.DESCRIPTION
    Send an email with csv attachment for mailbox statistics retrieved from an Exchange server.
.PARAMETER SMTPServer
    Specify an unauthenticated SMTP server details.
.PARAMETER RecipientEmailAddress
    Specify the recipient email address to receive report, separated by comma.
.PARAMETER ReportPeriodDays
    Specify the active mailboxes within the last x days. Empty to return all mailboxes.
.EXAMPLE
    .\Get-MailboxReport.ps1 -SMTPServer smtp.domain.local -RecipientEmailAddress support@avante-group.com -ReportPeriodDays 30
.NOTES
    Script name: Get-MailboxReport.ps1
    Author:      hsuantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2017-09-17
    Version:     1
#>

# Import functions
function Write-Log
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path='C:\Logs\PowerShellLog.log',
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
    }
}

# Define global variables
$IsProduction = $true
$SMTPPort = "25"
$DebugPreference = "Continue"
#$ADForest = Get-ADDomain | Select -Expand Forest
$CurrentTime = Get-Date -Format yyyyMMdd-HHmmss
$EmailVerificationRegex = @"
^[a-zA-Z0-9.!£#$%&'^_`{}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$
"@

Write-Debug "Starting script on $CurrentTime as $env:username"
Write-Log -Message "Starting script on $CurrentTime as $env:username" -Path C:\Temp\log.txt

# Define input parameters
# 1. SMTP server
$SMTPServer = $inputSMTPServer
# 2. Recipient email address
$RecipientEmailAddress = $inputRecipientEmailAddress
# 3. Active mailbox within last x days. Empty for all.
if ($inputReportPeriodDays -eq "" -and $inputReportPeriodDays -eq [string]::Empty)
{
    $ReportPeriodDays = $null
}
else
{
    $ReportPeriodDays = $inputReportPeriodDays
}

# Verify input variables
Write-Debug "Input parameters received:"
Write-Debug "SMTPServer: $SMTPServer"
Write-Debug "RecipientEmailAddress: $RecipientEmailAddress"

if ($ReportPeriodDays -eq $null)
{
    Write-Debug "ReportPeriodDays: null"
}
else
{
    Write-Debug "ReportPeriodDays: $ReportPeriodDays"
}
Write-Debug "Finished printing out received input parameters"

$RecipientEmailAddress = $RecipientEmailAddress.Replace(' ','')
Write-Debug "Recipient Email Address after blank space trim: $RecipientEmailAddress"
$RecipientEmailAddressArray = $RecipientEmailAddress.Split(",")

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

if ($SMTPServer -eq $null)
{
    Write-Warning "SMTP server is not specified. Terminating program..."
    exit
}

# Test connection to SMTP port
try{
    Write-Debug "Starting SMTP server test..."
    $tcpClient = New-Object System.Net.Sockets.TCPClient
    $tcpClient.Connect($SMTPServer,$SMTPPort)
    $SMTPConnectState = $tcpClient.Connected
    $tcpClient.Dispose()
}
catch
{ 
    Write-Warning "Failed SMTP server test to $SMTPServer on port $SMTPPort. Terminating program"
    #exit
}

Write-Debug "Passed SMTP server test to $SMTPServer on port $SMTPPort"

# Dump variables
Write-Debug "PS version: $($PSVersionTable.PSVersion.ToString())"
Write-Debug "Recipient email address: $RecipientEmailAddress"

# Get FQDN
$Hostname = (Get-WMIObject Win32_ComputerSystem).name
$DomainName = (Get-WMIObject Win32_ComputerSystem).domain
$hostFQDN = $Hostname + "." + $DomainName
Write-Debug "FQDN: $hostFQDN"

try
{
    Write-Debug "Importing Active Directory Powershell module..."
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
    Exit
}

try
{
    $IsMemberOfExchangeAdmin = Get-ADGroupMember "Organization Management" | Where {$_.Name -like $Hostname}
}
Catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
}

if (!$IsMemberOfExchangeAdmin)
{
    Write-Debug "$Hostname is not a member of Organization Management. Adding $Hostname to the group now..."
    try {
        $MemberHostname = $Hostname + "$"
        Write-Debug "Member hostname: $MemberHostname"
        Add-ADGroupMember "Organization Management" -Members $MemberHostname
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
    }
}
else
{
    Write-Debug "$Hostname is a member of Organization Management group."
}

$connectionURI = "http://" + $hostFQDN + "/powershell"
Write-Debug "Connection URI: $connectionURI"

try
{

    $sessionoptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionURI $connectionURI -Authentication Kerberos -SessionOption $SessionOptions -ErrorAction Stop
    if ($?)
    {
        Write-Debug "Successfully created PS session $session"
    }
    else
    {
        Write-Debug "Unable to create PS session. Terminating program."   
        exit 
    }
}
catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
    exit
}

try
{
    Write-Debug "Importing PS session..."
    Import-PSSession -Session $session -AllowClobber
}
catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
    exit
}

# Add mail relay receive connector
if ((Get-ReceiveConnector | where {$_.name -like "LOCALHOST"}) -eq $null)
{
    Write-Debug "LOCALHOST receive connector does not exist."
    $EX15 = "15.00.000.00"
    try {
        Get-Command EXSETUP.EXE | Foreach {
            $ExSetupVersion = $_.FileVersionInfo.ProductVersion
        }
    }
    catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Debug "Unable to find EXSETUP.EXE. Program terminated on $FailedItem with error $ErrorMessage"
    }

    Write-Debug "Detected EXSETUP version: $ExSetupVersion"
    if ( [System.Version]$ExSetupVersion -lt [System.Version]$EX15 )
    {
        try
        {
            Write-Debug "Creating new receive connector for Exchange 2010 or 2007"
            New-ReceiveConnector -Name "LOCALHOST" -Usage Custom -AuthMechanism ExternalAuthoritative -Enabled $true `
                -FQDN $hostFQDN -RemoteIPRanges "127.0.0.1" -PermissionGroups AnonymousUsers,ExchangeServers -Bindings "127.0.0.1:25"
            
            if ($?)
            {
                Write-Debug "Successfully added receive connector."
            }
            else {
                Write-Debug "Unable to add receive connector."
            }
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            Write-Debug "Unable to create new receive connector. Program terminated on $FailedItem with error $ErrorMessage"
            exit
        }
    }
    else 
    {
        try
        {
            Write-Debug "Creating new receive connector for Exchange 2013 or above"
            New-ReceiveConnector -Name "LOCALHOST" -Usage Custom -AuthMechanism ExternalAuthoritative -Enabled $true `
            -FQDN $hostFQDN -RemoteIPRanges "127.0.0.1" -PermissionGroups AnonymousUsers,ExchangeServers -Bindings "127.0.0.1:25" -TransportRole FrontEndTransport
        
            if ($?)
            {
                Write-Debug "Successfully added receive connector."
            }
            else {
                Write-Debug "Unable to add receive connector."
            }
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            $FailedItem = $_.Exception.ItemName
            Write-Debug "Unable to create new receive connector. Program terminated on $FailedItem with error $ErrorMessage"
            exit
        }
    }


}
else
{
    Write-Debug "Receive connector LOCALHOST already exists."
}

# Get mailbox report
if ($IsProduction)
{
if ($ReportPeriodDays -ne $null)
    {
        $MailReportFilePath = "C:\Windows\Temp\$DomainName-ActiveMailbox-Last-$ReportPeriodDays-Days-$CurrentTime.csv"
        Write-Debug $MailReportFilePath
        try
        {
            Write-Debug "Start generating active mailbox report within last $ReportPeriodDays days..."
            $Mailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox
                $Mailboxes | Get-MailboxStatistics | Where {$_.LastLogonTime -gt (Get-Date).AddDays(-($ReportPeriodDays))} |
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
        $MailReportFilePath = "C:\Windows\Temp\$DomainName-MailboxReport-$CurrentTime.csv"
        try
        {
            Write-Debug "Start generating report for all mailboxes..."
            $Mailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox
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

    $EmailSubject = "Mailbox report $DomainName - $CurrentTime"
    Write-Debug $EmailSubject

    # Send email report
    $EmailDefaultDomain = (Get-AcceptedDomain | Where-Object {$_.default -eq $true}).DomainName.ToString()
    $SenderEmailAddress = "noreply@$EmailDefaultDomain"
    Write-Debug "Sender email address: $SenderEmailAddress"

    if ($ReportPeriodDays -ne $null)
    {
        $EmailBody = "See attachment for mailbox report from $((Get-Date).AddDays(-($ReportPeriodDays)).ToString('yyyyMMdd-HHmmss')) to $CurrentTime."
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

    Remove-PSSession $session
}
# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUNHcN4bYtBODzd/htMZ/+O9/q
# FWugggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
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
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUWE2aqNo9BVYNjkK/
# jiIvPYvJQ0QwDQYJKoZIhvcNAQEBBQAEggEAhqI7mx3OjXIb172FD5XohHAHMs7z
# wUfeaELUvmplxTTmvLj9RMW7MzVLhiL6gVRsFzb3AL0+UWsFFyfwRukakqjbNgf1
# QBL8P3YAdQtWpRUf7qI+G9aRgMpIK9PkhSLKW9u12nU5X0ELEPCuelI3z6ra/t7V
# 1lZDciLQYVVMBwuz+MSH+FbEs+n5XgtbmvpOG1wDA0SGVsh/HYPGlOqtJuh4ic3Y
# MD24vQE+eZ6gwxM3QV8JVfhjAt9b22h1ua6kfr/4OY4erpp1EhVbtcv0PjfRVrjT
# jLTCKrxLyWJkvj5Ha9yPKbVAg1C2oW6NxnWONGNLbUEr0PQy4dKFrfZAwQ==
# SIG # End signature block
