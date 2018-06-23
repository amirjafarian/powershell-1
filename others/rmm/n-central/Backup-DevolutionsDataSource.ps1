<#
.SYNOPSIS
    Backup-DevolutionsDataSource.ps1
.DESCRIPTION
    To backup Devolutions Server data. Requires Devolutions Remote Desktop Manager 11.7.6.0 and tested with Devolutions Server 3.1.0.0
.PARAMETER ServerAddress
    Required. Specify DVLS server address.
.PARAMETER DataSourceName
    Required. Specify data source name to be created for data backup purpose.
.PARAMETER LoginUsername
    Required. Specify DVLS username with export privilege.
.PARAMETER LoginPassword
    Required. Specify DVLS password with export privilege.
.PARAMETER ExportPassword
    Required. Specify exported data source encryption password.
.PARAMETER ExportPath
    Required. Specify exported data path.
.EXAMPLE
    .\Backup-DevolutionsServer.ps1 -ServerAddress <DVLS Server Address> -DataSourceName <Meaningful Name> -LoginUsername <DVLS Username> -LoginPassword <DVLS Password> -ExportPassword <Password> -ExportPath <File to Path>
    .\Backup-DevolutionsServer.ps1 -ServerAddress "http://dvls.contoso.com" -DataSourceName "Finance Department" -LoginUsername "dvlsbackup" -LoginPassword "password" -ExportPassword "password" -ExportPath "C:\Temp"
.NOTES
    Script name : Backup-DevolutionsServer.ps1
    Author      : Hendrik Suantio
    Contact     : hsuantio <at> gmail.com
    DateCreated : 2017-12-13
    Version     : 2
    Disclaimer  : This script is provided as-is without guarantee. Please read the script to understand what it does prior to using it.
#>

<# 
[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServerAddress,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$DataSourceName,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$LoginUsername,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]$LoginPassword,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExportPassword,

    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExportPath
)
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
        [string]$Path="C:\Logs\Backup-DevolutionsDataSource.log",
        
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

function Set-CustomRDMDataSourceProperty
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        $DataSourceObject,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$PropertyName,
        
        [Parameter(Mandatory=$true, Position=2)]
        [ValidateNotNullOrEmpty()]
        [string]$PropertyValue
    )

    Write-Log "Setting $($DataSourceObject.Name) datasource $PropertyName property..."
    try
    {
        Set-RDMDataSourceProperty -DataSource $DataSourceObject -Property $PropertyName -Value $PropertyValue -ErrorAction Stop
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to set $PropertyValue property on $($DataSourceObject.Name)"
    }

    Write-Log "Successfully set $($DataSource.Name) datasource $PropertyName property."
}

$VerbosePreference = "Continue"
$FormattedDate = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Log "Starting script as $ENV:USERNAME..."

$InstallUtilPath = "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\InstallUtil.exe"
$RDMSnapinPath = "C:\Program Files (x86)\Devolutions\Remote Desktop Manager\RemoteDesktopManager.PowerShell.dll"
#Set-Alias InstallUtil "$([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\InstallUtil.exe" -ErrorAction Stop
Write-Log "Executing $InstallUtilPath on $RDMSnapinPath..."
& $InstallUtilPath $RDMSnapinPath 2"&"1 >> ""C:\Logs\Backup-DevolutionsDataSource.log""

Write-Log "Looking for RDM Powershell snapins..."
try
{
    $FoundSnapIns = Get-PSSnapin -Name *Remote.Desktop* -Registered -ErrorAction Stop
}
catch
{
    Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to find any RDM Powershell snapins."
}

$error.clear()
if (!$error)
{
    $FoundSnapIns | ForEach-Object {
        if ((Get-PSSnapin -Name $_ -ErrorAction SilentlyContinue) -eq $null)
        {
            Write-Log "Adding $($_.Name) Powershell snapin..."
            try
            {
                Add-PsSnapin $_ -ErrorAction Stop
            }
            catch
            {
                Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to add $($_.Name) Powershell snap-in"
            }
        }
        else
        {
            Write-Log "$($_.Name) snapin is installed and loaded."
        } 
    }
    
    Write-Log "Creating new $DataSourceName datasource..."
    try
    {
        $DataSource = New-RDMDataSource -Name $DataSourceName -Type "RDMS" -ErrorAction Stop
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to create new data source $DatasourceName"
    }

    Write-Log "Successfully created datasource $($DataSource.Name)."
    Set-CustomRDMDataSourceProperty -DataSourceObject $DataSource -PropertyName "Server" -PropertyValue $ServerAddress
    Set-CustomRDMDataSourceProperty -DataSourceObject $DataSource -PropertyName "UserName" -PropertyValue $LoginUsername
    Set-CustomRDMDataSourceProperty -DataSourceObject $DataSource -PropertyName "Password" -PropertyValue $LoginPassword

    Write-Log "Saving $($DataSource.Name) datasource settings..."
    try
    {
        Set-RDMDataSource -DataSource $DataSource -ErrorAction Stop
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to save $($DataSource.Name)"
    }
    
    Write-Log "Setting active RDM data source to $($DataSource.Name) with ID $($DataSource.ID)..."
    try
    {
        Set-RDM-DataSource -ID $DataSource.ID -ErrorAction Stop
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Failed to set RDM datasource to $($DataSource.Name) with ID $($DataSource.ID)."
    }
    
    Write-Log "Successfully set active datasource to $($DataSource.Name) with ID $($DataSource.ID)."
    Write-Log "Retrieving sessions from $($DataSource.Name) data source..."
    try
    {
        $Sessions = Get-RDMSession -ErrorAction Stop
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -Message "Failed to retrieve RDM session objects fom $($DataSource.Name) data source."
    }

    $EncryptedExportPassword = ConvertTo-SecureString -String $ExportPassword -AsPlainText -Force
    $XMLExportFilePath = "$ExportPath\RDM-$($DataSource.Name)-$FormattedDate.xml"

    Write-Log "Exporting $($DataSource.Name) data source with ID $($DataSource.ID) to $XMLExportFilePath"
    try
    {
        Export-RDMSession -Path $XMLExportFilePath -Sessions $Sessions -ExportType "XML" -Password $EncryptedExportPassword -IncludeCredentials -ErrorAction Stop
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -Message "Failed to export sessions from $($DataSource.Name) data source."
    }

    $error.clear()
    if(!$error)
    {
        Write-Log "Successfully exported sessions from $($DataSource.Name) with total of $($Sessions.Count) objects."
    }

    Write-Log "Removing datasource $($DataSource.Name)..."
    try
    {
        Remove-RDMCurrentDataSource -DataSource $DataSource -ErrorAction Stop
    }
    catch
    {
        Write-Log "Unable to remove $($DataSource.Name) datasource."
    }

    $error.clear()
    if (!$error)
    {
        Write-Log "Successfully removed $($DataSource.Name)."
    }
}

Write-Log "Script ends."