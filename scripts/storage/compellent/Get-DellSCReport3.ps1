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
        [string]$Path="C:\Logs\Get-CompellentReport.log",
        
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

# Main code
$IsDebug = $true
if ($IsDebug)
{
    $DellStorageAPIPath = 'C:\Temp\DellStoragePowerShellSDK_v3_5_1_9\DellStorage.ApiCommandSet.psd1'
    $DSMHostname = '10.0.0.1'
    $DSMUsername = 'admin'
    $DSMPasswordFile = 'C:\Temp\dellencrypted.txt'
    $ScName = 'san'
    $DSMPassword = Get-Content -Path $DSMPasswordFile | ConvertTo-SecureString
    $CSVExportPath = 'C:\Temp\CML-Export.csv'
}

if ( !(Get-Module -Name 'DellStorage.ApiCommandSet' -ErrorAction SilentlyContinue) )
{
    try
    {
        $DellStorageApiModule = Import-Module $DellStorageApiPath -ErrorAction Stop -PassThru
    }
    catch
    {
        Get-Exception -ForceExit $true -ExceptionObject $_ -Message "Error importing $DellStorageApiPath."
    }
    
    Write-Log "Imported Dell Storage API module version $($DellStorageApiModule.Version)."
}
else
{
    Write-Log "Dell Storage API version $((Get-Module -Name 'DellStorage.ApiCommandSet' -ErrorAction SilentlyContinue).Version) has been imported. "    
}

try
{
    $DSMConnection = Connect-DellApiConnection -HostName $DSMHostname -User $DSMUsername -Password $DSMPassword -Default -Save 'Default'
}
catch
{
    Get-Exception -ForceExit $true -ExceptionObject $_ -Message "Unable to establish Dell API connection to $DSMHostname."
}


$ScVolumes = Get-DellScVolume -ScName $ScName

$objarray = @()

foreach ($ScVolume in $ScVolumes)
{
    $ScMappingProfiles = Get-DellScMappingProfile -ScName $ScName -Volume $ScVolume
    if ($ScMappingProfiles)
    {
        foreach ($ScMappingProfile in $ScMappingProfiles)
        {
            $ScServer = Get-DellScServer -Instance $ScMappingProfile.Server

            if ($ScServer)
            {
                $object = New-Object -TypeName PSObject
                $object | Add-Member -MemberType NoteProperty -Name 'SC Serial Number' -Value $ScVolume.ScSerialNumber
                $object | Add-Member -MemberType NoteProperty -Name 'SAN Name' -Value $ScVolume.ScName
                $object | Add-Member -MemberType NoteProperty -Name 'Volume Name' -Value $ScVolume.Name
                $object | Add-Member -MemberType NoteProperty -Name 'Device ID' -Value $ScVolume.DeviceId
                $object | Add-Member -MemberType NoteProperty -Name 'Serial Number' -Value $ScVolume.SerialNumber
                $object | Add-Member -MemberType NoteProperty -Name 'In Recycle Bin' -Value $ScVolume.InRecycleBin
                $object | Add-Member -MemberType NoteProperty -Name 'Configured Size' -Value $ScVolume.ConfiguredSize
                $object | Add-Member -MemberType NoteProperty -Name 'Mapped Server' -Value $ScServer.Name
                $object | Add-Member -MemberType NoteProperty -Name 'LUN Requested' -Value $ScMappingProfile.LunRequested
                $objarray += $object
            }
        }
    }
}

$objarray | Export-CSV -NoTypeInformation -Path $CSVExportPath