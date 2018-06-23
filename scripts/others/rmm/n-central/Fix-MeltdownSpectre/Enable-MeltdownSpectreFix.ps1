<#
.SYNOPSIS
    Enable Meltdown and Spectre remediation check.
.DESCRIPTION
    Enable Meltdown and Spectre remediation check.
.EXAMPLE
    Syntax: .\Enable-MeltdownSpectreFix.ps1
.NOTES
    Script name : Enable-MeltdownSpectreFix.ps1
    Author      : Hendrik Suantio
    Contact     : hsuantio <at> gmail.com
    Version     : 1
    Updated     : 2018-01-16
    Disclaimer  : This script is provided as-is without guarantee. Please read the script to understand what it does prior to using it.
#>

function Write-Log
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path="C:\Logs\Fix-MeltdownSpectre.log",
        
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
        if ((Test-Path $Path) -AND $NoClobber)
        {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
        }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path))
        {
            Write-Verbose "Creating $Path."
            New-Item $Path -Force -ItemType File
        }

        else 
        {
            # Nothing to see here yet.
        }

        # Log file date format
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) 
        {
            'Error'
            {
                Write-Error $Message
                $LevelText = 'ERROR:'
            }
            'Warn'
            {
                Write-Warning $Message
                $LevelText = 'WARNING:'
            }
            'Info'
            {
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

function Get-Exception
{    
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$ExceptionObject,

        [Parameter(Mandatory=$false, Position=1)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($true,$false)]
        [bool]$ForceExit = $false,
        
        [Parameter(Mandatory=$false, Position=2)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    Process 
    {
        if ($Message)
        {
            # Add period to the custom error message if none exists.
            if ($Message.Substring($Message.Length - 1) -ne '.')
            {
                $Message = $Message + '.'
            }
    
            Write-Log -Level Info "$Message Exception on $($ExceptionObject.Exception.ItemName) with error: $($ExceptionObject.Exception.Message)"
            Write-Log -Level Info "Code trace: $($ExceptionObject.InvocationInfo.PositionMessage)"
        }
        else
        {
            Write-Log -Level Info "Exception on $($ExceptionObject.Exception.ItemName) with error: $($ExceptionObject.Exception.Message)"
            Write-Log -Level Info "Code trace: $($ExceptionObject.InvocationInfo.PositionMessage)"
        }
        if ($ForceExit) 
        {
            Write-Log -Level Info "Terminating program."
            Exit
        }
    }
}

function Download-File
{
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string]$URL
    )

    Begin
    {
        $DownloadedFiles = @()
        $WebClient = New-Object System.Net.WebClient
    }
    Process
    {
        try
        {
            $Uri = New-Object System.Uri $URL
            [string]$LocalFilePath =  "$($pwd.Path)\$($Uri.Segments[-1])"
            Write-Log "Downloading $URL to $LocalFilePath"
            $WebClient.DownloadFile($Uri,$LocalFilePath)
            if ((Test-Path -Path $LocalFilePath -ErrorAction Stop))
            {
                #$LocalFile = Get-Item -Path $LocalFilePath -ErrorAction Stop
                $DownloadedFiles += $LocalFilePath
            }
        }
        catch [Net.WebException]
        {
            Write-Log "Unable to download required module file. Error: $_.Exception.ToString(). Terminating program."
            Exit
        }
    }
    End 
    {
        return $DownloadedFiles
    }
}

Download-File 'https://raw.githubusercontent.com/hsuantio/posh/master/N-Central/Fix-MeltdownSpectre/Fix-MeltdownSpectre.ps1'
Download-File 'https://raw.githubusercontent.com/hsuantio/posh/master/N-Central/Fix-MeltdownSpectre/XML/CheckMeltdownandSpectreRemediationStatus.xml'

schtasks /CREATE /TN "CheckMeltdownandSpectreRemediationStatus" /XML ".\CheckMeltdownandSpectreRemediationStatus.xml" /RU "NT AUTHORITY\SYSTEM" /F

[string]$RandomHour = Get-Random -Maximum 24
if ($RandomHour.Length -ne 2)
{
    $RandomHour = '0' + $RandomHour
}

[string]$RandomMinute = Get-Random -Maximum 60
if ($RandomMinute.Length -ne 2)
{
    $RandomMinute = '0' + $RandomMinute
}

$RandomTime = $RandomHour + ':' + $RandomMinute
Write-Log "Generated random time: $RandomTime"
schtasks /TN "CheckMeltdownandSpectreRemediationStatus" /CHANGE /ST $RandomTime