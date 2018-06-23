<#
.SYNOPSIS
    Reset calendar permission in Office 365.
.DESCRIPTION
    To fix broken calendar security permission for mailboxes in Office 365 by removing the permission and adding it back.
.PARAMETER User
    Compulsory. The user's primary SMTP address which the permission is granted to. This is the User.ADRecipient.PrimarySMTPAddress attribute in Get-MailboxFolderPermission:\Calendar.
.PARAMETER AccessRights
    Compulsory. The access rights granted to the user.
.PARAMETER Production
    Optional. The production switch to reset the calendar permission. The script is run in non-production scenario by default printing outputs on what would be done if run in production mode.
.EXAMPLE
    .\Reset-O365CalendarPermission.ps1 -User management@contoso.com -AccessRights Author -Production
    Reset calendar permission on all mailboxes that are granted to management@contoso.com with Author access rights.
    .\Reset-O365CalendarPermission.ps1 -User management@contoso.com -AccessRights Author
    Dry run to reset calendar permission on all mailboxes that are granted to management@contoso.com with Author access rights.
.NOTES
    Script name : Reset-O365CalendarPermission.ps1
    Author      : Hendrik Suantio
    Contact     : hsuantio <at> gmail.com
    DateCreated : 2017-10-19
    Version     : 1
    Disclaimer  : This script is provided as-is without guarantee. Please read the script to understand what it does prior to using it.
#>

[CmdletBinding()]

Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [Alias("User")]
    [ValidateNotNullorEmpty()]
    [string]$InputUser,

    [Parameter(Position = 1, Mandatory = $true)]
    [Alias("AccessRights")]
    [ValidateNotNullorEmpty()]
    [string]$InputAccessRights,

    [Parameter(Position = 2, Mandatory = $false)]
    [switch]
    $Production = $false
)

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
        [string]$Path='C:\Logs\Reset-O365CalendarPermission.log',
        
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

    if ($CECustomMessage)
    {
        Write-Log -Level Info "$CECustomMessage Exception on $($CEExceptionObject.Exception.ItemName) with error $($CEExceptionObject.Exception.Message)"
        Write-Log -Level Info "Code trace: $($CEExceptionObject.InvocationInfo.PositionMessage)"
    }
    else
    {
        Write-Log -Level Info " Exception on $($CEExceptionObject.Exception.ItemName) with error $($CEExceptionObject.Exception.Message)"
        Write-Log -Level Info "Code trace: $($CEExceptionObject.InvocationInfo.PositionMessage)"
    }
    if ($CEForceExit) 
    {
        Write-Log -Level Info "Terminating program."
        exit
    }
}

$VerbosePreference = "Continue"
Write-Log -Level Info -Message "Starting script..."
if ($Production)
{
    Write-Log -Level Warn -Message "Script runs in production mode."
}
else
{
    Write-Log -Level Info -Message "Script does not run in production mode."    
}

Write-Log -Level Info -Message "Input user: $InputUser"
Write-Log -Level Info -Message "Input access rights: $InputAccessRights"

try
{
    $O365Credential = Get-Credential -Message "Enter Office 365 tenant admin account" -ErrorAction Stop
}
catch
{
    Catch-Exception -CEExceptionObject $_ -CEForceExit $true -Message "No Office 365 credential is provided, terminating program."
}

try
{
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionURI https://ps.outlook.com/powershell-liveid -Authentication Basic -Allowredirection -Credential $O365Credential -ErrorAction Stop
}
catch
{
    Catch-Exception -CEExceptionObject $_ -CEForceExit $true -Message "Unable to create Exchange online implicit remoting session. Terminating program."
}

try 
{
    Import-PSSession -Session $Session -AllowClobber -ErrorAction Stop
}
catch
{
    Catch-Exception -CEExceptionObject $_ -CEForceExit $true -Message "Unable to import Exchange Online implicit remoting session. Terminating program."
}

try
{
    $Mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
}
catch
{
    Catch-Exception -CEExceptionObject $_ -CEForceExit $true -Message "Unable to get mailbox list"
}

Foreach ($Mailbox in $Mailboxes)
{
    $CalendarFolder = $Mailbox.PrimarySMTPAddress + ':\Calendar'
    $CalendarPermission = Get-MailboxFolderPermission $CalendarFolder -ErrorAction Stop | Where-Object {$_.User.ADRecipient.PrimarySMTPAddress -like $InputUser -and $_.AccessRights -like $InputAccessRights}

    Write-Log -Level Info -Message "Checking if $CalendarFolder has $($CalendarPermission.User.ADRecipient.PrimarySMTPAddress) with $InputAccessRights right..."

    if ($CalendarPermission -ne $null)
    {
        Write-Log -Level Info "Removing $($CalendarPermission.User.ADRecipient.PrimarySMTPAddress) permission on $($Mailbox.PrimarySMTPAddress):\calendar..."
        if ($Production)
        {
            try
            {
                Remove-MailboxFolderPermission $CalendarFolder -User $CalendarPermission.User.ADRecipient.PrimarySMTPAddress -Confirm:$false -ErrorAction Stop
            }
            catch
            {
                Catch-Exception -CEExceptionObject $_ -Message "Unable to remove $($CalendarPermission.User.ADRecipient.PrimarySMTPAddress) $InputAccessRights access on $($Mailbox.PrimarySMTPAddress)."
            }

            $error.clear()
            if (!$error)
            {
                Write-Log -Level Info "Successfully removed $($CalendarPermission.User.ADRecipient.PrimarySMTPAddress) $InputAccessRights permission to $($Mailbox.PrimarySMTPAddress)"
            }
        }
        else
        {
            try
            {
                Remove-MailboxFolderPermission $CalendarFolder -user $CalendarPermission.User.ADRecipient.PrimarySMTPAddress -Confirm:$false -ErrorAction Stop -WhatIf
            }
            catch
            {
                Catch-Exception -CEExceptionObject $_ -Message "Unable to remove $($CalendarPermission.User.ADRecipient.PrimarySMTPAddress) $InputAccessRights access on $($Mailbox.PrimarySMTPAddress)."
            }
        }

        $error.clear()
        if (!$error)
        {
            Write-Log -Level Info -Message "Adding $($CalendarPermission.User.ADRecipient.PrimarySMTPAddress) $InputAccessRights to $CalendarFolder)..."
            if ($Production)
            {
                try
                {
                    Add-MailboxFolderPermission $CalendarFolder -User $CalendarPermission.User.ADRecipient.PrimarySMTPAddress -AccessRights $InputAccessRights -ErrorAction Stop
                }
                catch {
                    Catch-Exception -CEExceptionObject $_ -Message "Unable to add $($CalendarPermission.User.ADRecipient.PrimarySMTPAddress) $InputAccessRights access to $CalendarFolder)"
                }

                $error.clear()
                if (!$error)
                {
                    Write-Log -Level Info "Successfully added $($CalendarPermission.User.ADRecipient.PrimarySMTPAddress) $InputAccessRights permission to $($Mailbox.PrimarySMTPAddress)"
                }
            }
            else
            {
                try
                {
                    Add-MailboxFolderPermission $CalendarFolder -User $CalendarPermission.User.ADRecipient.PrimarySMTPAddress -AccessRights $InputAccessRights -ErrorAction Stop -WhatIf
                }
                catch {
                    Catch-Exception -CEExceptionObject $_ -Message "Unable to add $($CalendarPermission.User.ADRecipient.PrimarySMTPAddress) $InputAccessRights access to $CalendarFolder"
                }
            }
        }
    }
    else
    {
        Write-Log -Level Info "$InputUser does not have $InputAccessRights access on $CalendarFolder. Skipping this object..."
    }
}

if ($Session)
{
    Write-Log -Level Info -Message "Removing Exchange Online implicit remoting session..."
    try
    {
        Remove-PSSession $Session
    }
    catch
    {
        Catch-Exception -CEExceptionObject $_ -Message "Unable to remove Exchange Online implicit remoting session"
    }
}

Write-Log -Level Info -Message "Script ends."
# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUWTxm2KUV9FwT1zQqe7XykR/J
# gB2gggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
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
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUOswLD7wpy4v4KmMs
# QAjeRQywVXcwDQYJKoZIhvcNAQEBBQAEggEACSOdeXX/3dt/BvnnG+li0BJHcQTM
# 8WZuxueqjACSF+/en07ndYWN+WXW4jTG3ptngFt1OrwxMpYVusvcebv7brNvymWC
# gXY1pcXXc2WzDXPfCx2zY31DR2KfrCsdjN8dcJ/1FrbY7cxxzuywvskymzUd+788
# c77dM8NnVpH1HT46zl4mObBx+B8AN/mkmbQxdjdFDjbfa0SZRmnJx0ExIeChLDcT
# r+u1lSO7y0nCLvtx/NrWC+UmzRijlX+uh20DqxxejKNVt5sVGOOd9d184wt2F/vS
# cmsBGHA1ESD+RGFEBdwGHwah7OPcpfm09cImxoP7bS4t3Xpww5OakehAqw==
# SIG # End signature block
