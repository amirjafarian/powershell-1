<#
.SYNOPSIS
    Backup Fortigate firewall configuration file provided in a csv file.
.DESCRIPTION
    This script will backup Fortigate firewall configuration file over SCP.
.PARAMETER FilePath
    Specify the full path to CSV file. CSV column header names: "HostAddress","SSHPort","ClientName","ClientSite","LastBackupStatus","LastBackupAttempt","LastSuccessBackupTime","LastBackupConfigFile"
    Example:
    "HostAddress","SSHPort","ClientName","ClientSite","LastBackupStatus","LastBackupAttempt","LastSuccessBackupTime","LastBackupConfigFile"
    "192.168.1.254","66","Contoso Inc","Sydney"
.PARAMETER Username
    Specify the firewall login username that has at least read-only privilege to the firewall.
    Fortigate setting:
    ####
    config system accprofile
        edit "read_profile"
            set mntgrp read
            set admingrp read
            set updategrp read
            set authgrp read
            set sysgrp read
            set netgrp read
            set loggrp read
            set routegrp read
            set fwgrp read
            set vpngrp read
            set utmgrp read
            set wanoptgrp read
            set endpoint-control-grp read
            set wifi read
        next
    end
    config system admin
        edit "config"
            set trusthost1 <specify trusted subnets>
            set accprofile "read_profile"
            set vdom "root"
            set password ENC <encrypted password>
        next
    end
    ####
.PARAMETER Password
    Specify the firewall login password.
.PARAMETER BackupDirectory
    Specify Fortigate firewall config backup directory path.
.PARAMETER SMTPServer
    Specify SMTP server address.
.PARAMETER RecipientEmailAddress
    Specify email addresses separated by comma to receive a list of firewalls failed to be backed up.
.EXAMPLE
    Syntax: .\Backup-FortigateConfig.ps1 [-FilePath <string>] [-Username <string>] [-Password <string>] [-BackupDirectory <string>] [-SMTPServer <string>] [-RecipientEmailAddress <string>]
    .\Backup-FortigateConfig.ps1 -FilePath "C:\Firewalls.csv" -Username "fortigate" -Password "fortigate" -BackupDirectory "C:\Fortigate"
    Backup all firewalls listed in C:\Firewalls.csv file using username and password value "fortigate" and retrieve "fgt-config" file.
.NOTES
    Script name : Backup-FortigateConfig.ps1
    Author      : hsuantio
    Contact     : hsuantio <at> gmail.com
    Version     : 2
    Updated     : 2017-10-06
#>

<# [CmdletBinding()]

Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [Alias("FilePath")]
    [ValidateNotNullorEmpty()]
    [ValidateScript({Test-Path -Path $_})]
    [string]$InputFilePath,

    [Parameter(Position = 1, Mandatory = $true)]
    [Alias("Username")]
    [ValidateNotNullorEmpty()]
    [string]$InputUsername,

    [Parameter(Position = 2, Mandatory = $true)]
    [Alias("Password")]
    [string]$InputPassword,

    [Parameter(Position = 3, Mandatory = $true)]
    [Alias("BackupDirectory")]
    [string]$InputBackupDirectory,

    [Parameter(Position = 4, Mandatory = $false)]
    [Alias("SMTPServer")]
    [string]$InputSMTPServer,

    [Parameter(Position = 5, Mandatory = $false)]
    [Alias("RecipientEmailAddress")]
    [string]$InputRecipientEmailAddress
) #>

$ScriptLogPath = 'C:\Logs\Backup-FortigateConfig.log'

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
        [string]$Path=$ScriptLogPath,
        
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

function Reset-Log 
{ 
    Param
    (
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true)]
        [Alias("LogFile")]
        [string]$FileName,

        [Parameter(Mandatory=$false)]
        [Alias("LogSize")]
        [int64]$FileSize = 200kb,

        [Parameter(Mandatory=$false)]
        [Alias("LogFileCount")]
        [int] $LogCount = 5
    )
     
    $LogRollStatus = $true
    Write-Log -Level Info "Starting log rotation function with log file $FileName, threshold size $FileSize, file count $LogCount..."

    if(Test-Path $FileName)
    {
        Write-Log -Level Info "Log maintenance: Found existing log file $FileName"
        $file = Get-ChildItem $FileName
        if((($file).length) -ige $FileSize)
        {
            Write-Log -Level Info "Log maintenance: Log file $FileName is greater than $($file.length), rolling log file..."
            $FileDir = $file.Directory
            $fn = $file.name
            $files = Get-ChildItem $FileDir | Where-Object {$_.name -like "$fn*"} | Sort-Object LastWriteTime
            $FileFullName = $file.FullName

            for ($i = ($files.count); $i -gt 0; $i--)
            {
                $files = Get-ChildItem $FileDir | Where-Object {$_.name -like "$fn*"} | Sort-Object LastWriteTime
                $OperatingFile = $files | Where-Object {($_.name).trim($fn) -eq $i}
                if ($OperatingFile)
                {
                    $OperatingFileNumber = ($files | Where-Object {($_.name).trim($fn) -eq $i}).name.trim($fn)
                }
                else
                {
                    $OperatingFileNumber = $null
                }
 
                if(($OperatingFileNumber -eq $null) -and ($i -ne 1) -and ($i -lt $logcount))
                {
                    $OperatingFileNumber = $i
                    $NewFileName = "$FileFullName.$OperatingFileNumber"
                    $OperatingFile = $files | Where-Object {($_.name).trim($fn) -eq ($i-1)}
                    Write-Log -Level Info "Moving $($OperatingFile.FullName) to $NewFileName"
                    try
                    {
                        Move-Item ($OperatingFile.FullName) -Destination $NewFileName -Force
                    }
                    catch
                    {
                        Catch-Exception -ExceptionObject $_ -Message "Unable to move $($OperatingFile.FullName) to $NewFileName."
                    }
                }
                elseif($i -ge $logcount)
                {
                    if($OperatingFileNumber -eq $null)
                    {
                        $OperatingFileNumber = $i - 1
                        $OperatingFile = $files | Where-Object {($_.name).trim($fn) -eq $OperatingFileNumber}
                    }
                    Write-Log -Level Info "Deleting $($OperatingFile.FullName)"
                    try
                    {
                        Remove-Item $($OperatingFile.FullName) -Force 
                    }
                    catch 
                    {
                        Catch-Exception -ExceptionObject $_ -Message "Unable to delete $($OperatingFile.FullName)."
                    }
                }
                elseif($i -eq 1)
                {
                    $OperatingFileNumber = 1
                    $NewFileName = "$FileFullName.$OperatingFileNumber"
                    Write-Log -Level Info "Moving to $FileFullName to $NewFileName"
                    try
                    {
                        Move-Item $FileFullName -Destination $NewFileName -Force 
                    }
                    catch
                    {
                        Catch-Exception -ExceptionObject $_ -Message "Unable to move $FileFullName) to $NewFileName."
                    }
                }
                else
                {
                    $OperatingFileNumber = $i +1
                    $NewFileName = "$FileFullName.$OperatingFileNumber"
                    $OperatingFile = $files | Where-Object {($_.name).trim($fn) -eq ($i-1)}
                    Write-Log -Level Info "Moving to $($OperatingFile.FullName) to $NewFileName"
                    try
                    {
                        Move-Item $($OperatingFile.FullName) -Destination $NewFileName -Force
                    }
                    catch {
                        Catch-Exception -ExceptionObject $_ -Message "Unable to move $($OperatingFile.FileFullName) to $NewFileName."
                    }   
                }     
            } 
        } 
        else 
        {
            Write-Log -Level Info "Log maintenance: Log file $FileName is smaller $($file.length) than log rotation threshold $FileSize "
            $LogRollStatus = $false
        } 
    }
    else 
    { 
        Write-Log -Level Info "Log maintenance: Unable to access log file $FileName"
        $LogRollStatus = $false 
    } 
}

function Get-FortiGateSSHResponse
{
    [OutputType([String])]
    param
    (
		[Parameter(Mandatory=$true)]
		[String]$HostAddress,
		[Parameter(Mandatory=$false)]
		[Int]$HostPort = 22,
		[Parameter(Mandatory=$true)]
		[PSCredential]$Credential,
		[Parameter(Mandatory=$false)]
		[Switch]$AcceptKey,
		[Parameter(Mandatory=$true)]
		[String]$Command,
		[Parameter(Mandatory=$false)]
		[String]$StripHeaderAt = $null
    )
    try 
    {
        $SSHSession = New-SSHSession -ComputerName $HostAddress -Port $HostPort -Credential $Credential -AcceptKey:$AcceptKey -ErrorAction Stop
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to create SSH session."
    }
    
    if ($SSHSession.Connected)
    {
        try
        {
            $SSHResponse = Invoke-SSHCommand -SSHSession $SSHSession -Command $Command
        }
        catch
        {
            Catch-Exception -ExceptionObject $_ -Message "Unable to invoke SSH command."
        }

        try
        {
            Remove-SSHSession -SSHSession $SSHSession -ErrorAction Stop | Out-Null
        }
        catch
        {
            Catch-Exception -ExceptionObject $_ -Message "Unable to remove SSH session."
        }

        $Result = $SSHResponse.Output | Out-String
        $StartIndex = 0
        if ($StripHeaderAt)
        {
            $StartIndex = $Result.IndexOf(" # $StripHeaderAt")
            if ($StartIndex -lt 0)
            {
                $StartIndex = $Result.IndexOf(" $ $StripHeaderAt")
            }

            if ($StartIndex -lt 0)
            {
                $StartIndex = 0
            }
            else 
            {
                $StartIndex += 3
            }
        }

        $Result = $Result.Substring($StartIndex).Trim()
        $EndIndex = $Result.LastIndexOf("`n")
		
        if ($EndIndex -gt 0)
        {
            $Result = $Result.Substring(0, $EndIndex + 1).Trim()
        }

      	return $Result.Replace("`n--More-- `r         `r", "`n")
    }
}

function Get-FortiGateConfig
{
    [OutputType([String])]
    param
    (
		[Parameter(Mandatory=$true)]
		[String]$HostAddress,
		[Parameter(Mandatory=$false)]
		[Int]$HostPort = 22,
		[Parameter(Mandatory=$true)]
		[PSCredential]$Credential,
		[Parameter(Mandatory=$false)]
		[Switch]$Full,
		[Parameter(Mandatory=$false)]
		[Switch]$AcceptKey
    )

    $Command = 'show'

    if ($Full)
    {
        $Command = 'show full-configuration'
    }

    return (Get-FortiGateSSHResponse -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -AcceptKey:$AcceptKey -Command $Command -StripHeaderAt '#config-')
}

function Backup-FortiGateConfig
{
    param
    (
		[Parameter(Mandatory=$true)]
		[String]$HostAddress,
		[Parameter(Mandatory=$false)]
		[Int]$HostPort = 22,
		[Parameter(Mandatory=$true)]
		[PSCredential]$Credential,
		[Parameter(Mandatory=$false)]
		[Switch]$Full,
		[Parameter(Mandatory=$false)]
		[Switch]$AcceptKey,
		[Parameter(Mandatory=$true)]
		[String]$FilePath
    )
    
    try
    {
        $FortigateConfigFile = Get-FortiGateConfig -HostAddress $HostAddress -HostPort $HostPort -Credential $Credential -Full:$Full -AcceptKey:$AcceptKey
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message
    }

    if ($FortigateConfigFile -ne $null)
    {
        $FortigateConfigFile | Out-File -FilePath $FilePath -Encoding ascii
        return $true
    }
    else
    {
        Write-Log -Level Info "Returned result is empty."
        return $false
    }
}

# Define global variables
$CurrentTime = Get-Date -Format yyyyMMdd_HHmmss
$InputConfigFileName = "fgt-config"
$IsProduction = $true

if (-Not $IsProduction)
 {
    $InputFilePath = "C:\Temp\ConfigBackups\firewalls.csv"
    $InputUserName = "fortigate"
    $InputPassword = "fortigate"
    $InputBackupDirectory = "C:\Temp\ConfigBackups"
    $InputSMTPServer = "smtp.domain.com"
    $InputRecipientEmailAddress = "it@domain.com"
}

Reset-Log -FileName $ScriptLogPath -FileSize 1MB -LogCount 5
Write-Log -Level Info "Starting script as $env:username on $CurrentTime"
Write-Log -Level Info 'Support: hsuantio <at> gmail.com'

## Verify input parameters
Write-Log -Level Info "Input parameters received..."
Write-Log -Level Info "Firewall list file path (required): $InputFilePath"
Write-Log -Level Info "Firewall read-only username (required): $InputUsername"
Write-Log -Level Info "Firewall read-only password (required): $InputPassword"
Write-Log -Level Info "Config backup directory path (required): $InputBackupDirectory"
Write-Log -Level Info "Firewall config file name: $InputConfigFileName"
Write-Log -Level Info "SMTP Server: $InputSMTPServer"
Write-Log -Level Info "Recipient email address: $InputRecipientEmailAddress"

if (($InputFilePath -ne $null) -and ($InputUserName -ne $null) -and ($InputPassword -ne $null) -and ($InputBackupDirectory -ne $null))
{
}
else
{
    Write-Log -Level Info "One or more of the input parameters is empty, please specify all the input parameters. Terminating program."
    exit
}

$InputRecipientEmailAddress = $InputRecipientEmailAddress.Replace(' ','')
Write-Log -Level Info "Recipient Email Address after blank space trim: $InputRecipientEmailAddress"
$RecipientEmailAddressArray = $InputRecipientEmailAddress.Split(",")

foreach ($RecipientEmailAddress in $RecipientEmailAddressArray) {
    Write-Log -Level Info "Verifying email address: $RecipientEmailAddress"
    if ($RecipientEmailAddress -cmatch $EmailVerificationRegex -eq $false)
    {
        Write-Log -Level Info "Recipient email address $RecipientEmailAddress did not pass format validation check. Terminating program"
    }
    else {
        Write-Log -Level Info "Email adress $RecipientEmailAddress passed verification check."
    }
}

if ($InputSMTPServer -eq $null -and $RecipientEmailAdress -ne $null)
{
    Write-Log -Level Info "SMTP server is not specified but at least one recipient email address is specified. Terminating program..."
    exit
}

try 
{
    Write-Log -Level Info "Importing Posh-SSH module..."
    Import-Module -Name Posh-SSH -ErrorAction Stop
}
catch 
{
    Catch-Exception -ExceptionObject $_ -Message "Unable to import Posh-SSH module."
    Write-Log -Level Info "Detected Powershell version: $($PSVersionTable.PSVersion.Major)"
    if ($PSVersionTable.PSVersion.Major -ge 3)
    {
        try
        {
            Write-Log -Level Info "Installing Posh-SSH module..."
            Install-Module Posh-SSH -Force
        }
        catch
        {
            Catch-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to install Posh-SSH module."
        }
    }
    else
    {
        Write-Log -Level Info "Detected Powershell version does not support automatic module installation. Please install Posh-SSH module and run the script again."
        exit    
    }
}

$SecureSSHPassword = $InputPassword | ConvertTo-SecureString -AsPlainText -Force
$SSHCredential = New-Object System.Management.Automation.PSCredential ($InputUsername, $SecureSSHPassword)

try 
{
    Write-Log -Level Info "Importing from CSV file..."
    $firewalls = Import-Csv -Path $InputFilePath
}
catch 
{
    Catch-Exception -ExceptionObject $_ -Message "Unable to import CSV file $InputFilePath"
}

Foreach ($device in $firewalls) 
{
    Write-Log -Level Info " "
    Write-Log -Level Info "Processing $($device.ClientName), site $($device.ClientSite) on IP address $($device.HostAddress), port $($device.SSHPort)..."
    $ClientBackupDirectory = Join-Path -Path $InputBackupDirectory -ChildPath $($device.ClientName)
    Write-Log -Level Info "Checking if this folder exists: $ClientBackupDirectory"

    if (-Not (Test-Path -Path $ClientBackupDirectory)) 
    {
        Write-Log -Level Info "Client folder does not exist, creating $ClientBackupDirectory"
        try 
        {
            New-Item -ItemType Directory -Path $ClientBackupDirectory -ErrorAction Stop
        }
        catch
        {
            Catch-Exception -ExceptionObject $_ -Message "Unable to connect to create directory $ClientBackupDirectory."
            continue
        }
    }
    else 
    {
        Write-Log -Level Info "$ClientBackupDirectory folder already exists"
    }

    $CurrentTime = Get-Date -Format yyyyMMdd_HHmmss
    $BackupFile = $($device.ClientName) + '_' + $($device.ClientSite) + '_' + $CurrentTime + '.conf'
    $ConfigFullPath = $ClientBackupDirectory + '\' + $BackupFile
    Write-Log -Level Info "Backing up config file to $ConfigFullPath"

    $error.clear()
    try
    {
        $ConfigBackupStatus = Backup-FortiGateConfig -HostAddress $($device.HostAddress) -HostPort $($device.SSHPort) -Credential $SSHCredential -FilePath $ConfigFullPath -AcceptKey:$true
    }
    catch 
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to execute backup config command."
    }
    
    if ($ConfigBackupStatus) 
    {
        Write-Log -Level Info "Successfully backed up config file for $($device.ClientName) site $($device.ClientSite) to $ConfigFullPath"
        $device.LastBackupStatus = "SUCCESS"
        $device.LastBackupAttempt = $CurrentTime
        $device.LastSuccessBackupTime = $CurrentTime
        $device.LastBackupConfigFile = $ConfigFullPath
    }
    elseif (!$ConfigBackupStatus)
    {
        Write-Log -Level Info "Unable to backup config"
        $device.LastBackupStatus = "FAIL"
        $device.LastBackupAttempt = $CurrentTime
    }

    Write-Log -Level Info "End of object processing."
}

try
{
    $BackupListFile = $InputFilePath + ".bak"
    Write-Log -Level Info "Backing up $InputFilePath to $BackupListFile..."
    Copy-Item $InputFilePath -Destination $BackupListFile -Force -ErrorAction Stop
}
catch
{
    Catch-Exception -ExceptionObject $_ -Message "Unable to backup existing firewall master file list to $BackupListFile."
}

$error.clear()
if (!$error)
{
    try
    {
        Write-Log -Level Info "Updating firewall master file list..."
        $firewalls | Export-CSV -NoType -Path $InputFilePath -Force -ErrorAction Stop
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to export updated list to $InputFilePath."
    }
}

$error.clear()
if (!$error)
{
    try
    {
        Write-Log -Level Info "Removing old firewall master list $BackupListFile..."
        Remove-Item $BackupListFile -Force -ErrorAction Stop
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to delete $BackupListFile."
    }
}

$FailedFirewallsList = $Firewalls | Where-Object {$_.LastBackupStatus -eq "FAIL"}

if ($FailedFirewallsList -ne $null)
{   
    $AllFirewallListCSVFile = "$env:temp\AllFirewallList_$CurrentTime.csv"
    $FailedFirewallListCSVFile = "$env:temp\FailedFirewallList_$CurrentTime.csv"
    try
    {
        Write-Log -Level Info "Exporting failed firewalls list to $FailedFirewallListCSVFile"
        $FailedFirewallsList | Export-CSV -NoType -Path $FailedFirewallListCSVFile -ErrorAction Stop
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to export failed firewall list to $FailedFirewallListCSVFile"
    }

    try
    {
        Write-Log -Level Info "Exporting all firewalls list to $AllFirewallListCSVFile"
        $firewalls | Export-CSV -NoType -Path $AllFirewallListCSVFile -ErrorAction Stop
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to export failed firewall list to $AllFirewallListCSVFile"
    }

    if ($RecipientEmailAddressArray -ne $null)
    {
        $RecipientEmailAddressArray | ForEach-Object {
            Write-Log -Level Info "Sending email to $_"
            try
            {
                Send-MailMessage -To $_ -From 'noreply@avante-group.com' `
                -Subject "Failed Firewall List - $CurrentTime" -Body "See attachment for list of failed firewall config backup." `
                -SMTPServer $InputSMTPServer -Attachments $FailedFirewallListCSVFile, $AllFirewallListCSVFile
            }
            catch
            {
                Catch-Exception -ExceptionObject $_ -Message "Unable to send email to $_"
            }
        }
    }

    try
    {
        Write-Log -Level Info "Removing file $FailedFirewallListCSVFile"
        Remove-Item -Path $FailedFirewallListCSVFile -Force -ErrorAction Stop
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to remove file $FailedFirewallListCSVFile"
    }

    try
    {
        Write-Log -Level Info "Removing file $AllFirewallListCSVFile"
        Remove-Item -Path $AllFirewallListCSVFile -Force -ErrorAction Stop
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to remove file $AllFirewallListCSVFile"
    }
}

Write-Log -Level Info "Script ends."
# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUE1M39bzAkQ4D0i2JpQGA0p4q
# HhqgggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
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
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUmY1uZV0B0UAnAL4R
# 7nCEYhOsDcswDQYJKoZIhvcNAQEBBQAEggEAFunAzU10G8pAmFtucjNYN8/7BpWG
# 0Zg4fNXiUUG+/zcjoZzlYKXDu4GQM0xr/EpyYQYBBOa6VyqXEbpqzPlqahJRasID
# pJ7i9T8sIbopVbyymxmjypazOIfsPYWZwdkh21hv/jR1068VQfDSg8BGucsMNZie
# Ij2bPY4uX7RoflH4HQW+dMe+pCm3YFjLlqAatGmhQVjjbWxb1nIpkRkvmtqAONBA
# spx4nwOkz24Ch9j55ffFCJ50uLU+BxZgYXrLIr9drRQ6DqLaIZ9mF+eWFgm7kN1u
# WIjSHBZMOtcxXuGw9aT5oPM4BeIjBXn6BhIWfNsy7iq3NhrqMmW7yhs4+w==
# SIG # End signature block
