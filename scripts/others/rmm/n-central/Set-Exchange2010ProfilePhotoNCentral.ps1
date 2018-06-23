<#
.SYNOPSIS
    Add profile picture from a JPEG file to Active Directory for Exchange 2010.
.DESCRIPTION
    Add profile picture from a JPEG file to Active Directory for Exchange 2010.
.PARAMETER Username
    Specify username to add or update profile photo.
.PARAMETER FilePath
    Specify the full path to the JPEG file. JPEG file must be less than 10KB.
.PARAMETER Server
    Specify Exchange 2010 server FQDN.
.EXAMPLE
    .\Set-ProfilePhoto.ps1 -Username administrator -FilePath 'C:\photo.jpg' -Server srv-exch01
.NOTES
    Script name : Set-ProfilePhoto.ps1
    Author      : hsuantio
    Contact     : hsuantio <at> gmail.com
    Version     : 1
    Updated     : 2017-10-09
#>

<#
[CmdletBinding()]

Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [Alias("Username")]
    [ValidateNotNullorEmpty()]
    [string]$InputUsername,

    [Parameter(Position = 1, Mandatory = $true)]
    [Alias("FilePath")]
    [ValidateNotNullorEmpty()]
    [ValidateScript({Test-Path -Path $_})]
    [string]$InputFilePath,

    [Parameter(Position = 1, Mandatory = $true)]
    [Alias("Server")]
    [ValidateNotNullorEmpty()]
    [string]$InputServerFQDN
)
#>

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
        [string]$Path='C:\Logs\Set-ProfilePhoto.log',
        
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

$CurrentTime = Get-Date -Format yyyyMMdd_HHmmss
Write-Log -Level Info -Message "Starting script on $CurrentTime as $env:username..."

# Specify global variables
$MaxFileSize = 10kb
$isInteractive = $false

if ($isInteractive)
{
    $InputUsername = Read-Host -Prompt "Enter the username which profile photo to be added or updated"
    $InputFilePath = Read-Host -Prompt "Enter full path to photo file (less than 10KB)"
}

Write-Log -Level Info -Message "Input username: $InputUsername"
Write-Log -Level Info -Message "Input file path: $InputFilePath"
Write-Log -Level Info -Message "Input Exchange server FQDN: $InputServerFQDN"

try
{
    Write-Log -Level Info -Message "Creating new PS session..."
    $PSURI = "http://" + $InputServerFQDN + "/powershell"
    Write-Log -Level Info -Message "PS URI: $PSURI"
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $PSURI -Authentication Kerberos -ErrorAction Stop
}
catch
{
    Catch-Exception -CEExceptionObject $_ -CEForceExit $true -Message "Unable to create new PS session"
}

$error.clear()
if (!$error)
{
    $PSSessionImportStatus = $true
}

try
{
    Write-Log -Level Info -Message "Importing PS session..."
    Import-PSSession $Session -AllowClobber -ErrorAction Stop
}
catch
{
    Catch-Exception -CEExceptionObject $_ -CEForceExit $true -Message "Unable to import PS session"
}

try
{
    Write-Log -Level Info -Message "Checking if $InputFilePath exists..."
    $file = Get-Item $InputFilePath -ErrorAction Stop
}
catch
{
    Catch-Exception -CEExceptionObject $_ -CEForceExit $true -Message "Unable to access $InputFilePath"
}

$error.clear()
if (!$error)
{
    Write-Log -Level Info -Message "Able to access input file: $($file.FullName)"
}

Write-Log -Level Info -Message "Checking if photo file is larger than $MaxFileSize"

if((($file).length) -ige $MaxFileSize)
{
    Write-Log -Level Info -Message "Input photo file size is $($file.length) which is larger than $MaxFileSize, please reduce the file size"
    exit
}
else
{
    Write-Log -Level Info -Message "$InputFilePath passes file size check. File size: $($file.length)"
    try
    {
        Write-Log -Level Info "Importing photo from $InputFilePath to $InputUsername..."
        Import-RecipientDataProperty -identity $InputUsername -Picture -FileData ([Byte[]]$(Get-Content -Path $file.FullName -Encoding Byte -ReadCount 0)) -ErrorAction Stop
    }
    catch {
        Catch-Exception -CEExceptionObject $_ -Message "Unable to import photo"
    }
}

if ($PSSessionImportStatus)
{
    try
    {
        Write-Log -Level Info "Removing PS session..."
        Remove-PSSession $session -ErrorAction Stop
    }
    catch {
        Catch-Exception -CEExceptionObject $_ -Message "Unable to remove PS session"
    }
}
# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxBV9FlcZlXqe8fVXYOggrbkZ
# gL6gggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
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
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUTPYavEm8AQoZ0a8U
# epaQBrboSNMwDQYJKoZIhvcNAQEBBQAEggEAjtLXzmo6nXpVxGJb6+cf6W5W1I9l
# jZsYJBEYlcxX7o5Psa6oUPktJA6XIcKsEbSvK2aW8UrX/kmE4skSQv7BhTy9NPQn
# nyTdr39OWbDuJ8L4aAuWaWKNyt2jEye7cs/+yGdDtNkXBW6+/A1W65tYbWZGA9z5
# 96fyW027VHzLNE8thb9hw3LXcuYbbSpcxqO+XBv4ZZmuJM2Vd8HOUe7VSI1gdNXS
# 2QoLW0ln4gqYVhzIwBkk3ixTvoDtyHL6JmWgdKB1UVkrjT44ZTxAdZTtjwPbJGCI
# ps0F8AD/Blb9HnUjEdlbq/6tKMOec92qjwQ2MntMabA19w1EIi2q7rfJ3A==
# SIG # End signature block
