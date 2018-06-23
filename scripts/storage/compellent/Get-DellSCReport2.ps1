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

# Main code
$IsDebug = $true
if ($IsDebug)
{
    $DellStorageAPIPath = 'C:\Temp\DellStoragePowerShellSDK_v3_5_1_9\DellStorage.ApiCommandSet.psd1'
    $DSMHostname = 'server'
    $DSMUsername = 'roadmin'
    $DSMPasswordFile = 'C:\Temp\dellencrypted.txt'
    $ScName = 'san'
    $DSMPassword = Get-Content -Path $DSMPasswordFile | ConvertTo-SecureString
    $CSVExportPath = 'C:\Temp\CML-Export.csv'
}

if ( !(Get-Module -Name 'DellStorage.ApiCommandSet' -ErrorAction SilentlyContinue) )
{
    $DellStorageApiModule = Import-Module $DellStorageAPIPath -PassThru
    Write-Log "Imported Dell Storage API module version $($DellStorageApiModule.Version)."
}
else
{
    Write-Log "Dell Storage API version $((Get-Module -Name 'DellStorage.ApiCommandSet' -ErrorAction SilentlyContinue).Version) has been imported. "    
}

$DSMConnection = Connect-DellApiConnection -HostName $DSMHostname -User $DSMUsername -Password $DSMPassword -Default -Save 'Default'

$objarray = @()

$ScStorageTiers = Get-DellScStorageTypeTier -ScName $ScName

foreach ($ScStorageTier in $ScStorageTiers)
{
    $object = New-Object -TypeName PSObject
    $object | Add-Member -MemberType NoteProperty -Name 'SC Serial Number' -Value $ScStorageTier.ScSerialNumber
    $object | Add-Member -MemberType NoteProperty -Name 'SC Name' -Value $ScStorageTier.ScName
    $object | Add-Member -MemberType NoteProperty -Name 'Available Disk Classes' -Value $ScStorageTier.AvailableDiskClasses
    $object | Add-Member -MemberType NoteProperty -Name 'Disk Tier' -Value $ScStorageTier.DiskTier
    $object | Add-Member -MemberType NoteProperty -Name 'Redundancy' -Value $ScStorageTier.Redundancy

    $objarray += $object
}

$objarray