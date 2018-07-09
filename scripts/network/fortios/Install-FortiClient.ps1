<#
.SYNOPSIS
    Install Fortinet FortiClient SSL VPN.
.DESCRIPTION
    Install Fortinet FortiClient SSL VPN.
.EXAMPLE
    .\Install-FortiClient.ps1
.NOTES
    Script name: Install-FortiClient.ps1
    Author:      hsuantio
    Contact     : hsuantio <at> gmail.com
    Version     : 1
    Updated     : 2018-07-09
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
        [string]$Path="C:\Logs\Install-FortiClient.log",
        
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
        [string]$URL #Parameter mapping by variable type from $FilesToDownload variable.
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
                $LocalFile = Get-Item -Path $LocalFilePath -ErrorAction Stop
                $DownloadedFiles += $LocalFile
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

function Get-RemoteProgram
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param
    (
        [Parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [string[]]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Position=0)]
        [string[]]$Property,
        [switch]$ExcludeSimilar,
        [int]$SimilarWord
    )

    begin
    {
        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
        $HashProperty = @{}
        $SelectProperty = @('ProgramName','ComputerName')
        if ($Property) {
            $SelectProperty += $Property
        }
    }

    process
    {
        foreach ($Computer in $ComputerName) {
            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
            $RegistryLocation | ForEach-Object {
                $CurrentReg = $_
                if ($RegBase) {
                    $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                    if ($CurrentRegKey) {
                        $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                            if ($Property) {
                                foreach ($CurrentProperty in $Property) {
                                    $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue($CurrentProperty)
                                }
                            }
                            $HashProperty.ComputerName = $Computer
                            $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayName'))
                            if ($DisplayName) {
                                New-Object -TypeName PSCustomObject -Property $HashProperty |
                                Select-Object -Property $SelectProperty
                            } 
                        }
                    }
                }
            } | ForEach-Object -Begin {
                if ($SimilarWord) {
                    $Regex = [regex]"(^(.+?\s){$SimilarWord}).*$|(.*)"
                } else {
                    $Regex = [regex]"(^(.+?\s){3}).*$|(.*)"
                }
                [System.Collections.ArrayList]$Array = @()
            } -Process {
                if ($ExcludeSimilar) {
                    $null = $Array.Add($_)
                } else {
                    $_
                }
            } -End {
                if ($ExcludeSimilar) {
                    $Array | Select-Object -Property *,@{
                        name       = 'GroupedName'
                        expression = {
                            ($_.ProgramName -split $Regex)[1]
                        }
                    } |
                    Group-Object -Property 'GroupedName' | ForEach-Object {
                        $_.Group[0] | Select-Object -Property * -ExcludeProperty GroupedName
                    }
                }
            }
        }
    }
}

function Check-Elevated
{
    $WindowsIdentity = [system.security.principal.windowsidentity]::GetCurrent()
    $Principal = New-Object System.Security.Principal.WindowsPrincipal($WindowsIdentity)
    $AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    if ($Principal.IsInRole($AdminRole))
    {
        Write-Log "Elevated PowerShell session detected. Continuing."
    }
    else
    {
        Write-Log "This application/script must be run in an elevated PowerShell window. Please launch an elevated session and try again."
        Exit
    }
}

function Install-MSI
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        $File
    )

    $MSILogFile = 'C:\Logs\msi_install.log'
    $MSIArguments = @(
        "/i"
        $File
        "/L*VX"
        $MSILogFile
        "/qn"
        "/norestart"
    )
    try
    {
        Write-Log "Installing $File with arguments $MSIArguments..."
        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Installing $File failed."
    }
}

function New-RegistryKey
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        $RegistryKeyPath,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        $RegistryKeyName
    )

    Write-Log "Creating $RegistryKeyPath\$RegistryKeyName key..."
    try
    {
        New-Item -Path $RegistryKeyPath -Name $RegistryKeyName -ErrorAction Stop  
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to create $RegistryKeyPath\$RegistryKeyName key."
    }
    $error.clear()
    if (!$error)
    {
        Write-Log "Successfully created $RegistryKeyPath\$RegistryKeyName key."
    }
}

$SSLVPN32InstallFileURL = "https://raw.githubusercontent.com/hsuantio/powershell/master/libraries/files/fortinet/sslvpn/4.0.2332/SslvpnClient_4.0.2332_x86.msi"
$SSLVPN64InstallFileURL = "https://raw.githubusercontent.com/hsuantio/powershell/master/libraries/files/fortinet/sslvpn/4.0.2332/SslvpnClient_4.0.2332_x64.msi"

Write-Log "Starting script as $env:USERNAME..."
Check-Elevated

try
{
    $IsFortiClientInstalled = Get-RemoteProgram -Property DisplayVersion, VersionMajor -ErrorAction Stop | Where-Object {$_.ProgramName -Like "*FortiClient*"}
}
catch
{
    Get-Exception -ExceptionObject $_ -Message "Failed to get list of installed programs."
}

if ($IsFortiClientInstalled -ne $null)
{
    Write-Log "Found $($IsFortiClientInstalled.ProgramName) version $($IsFortiClientInstalled.DisplayVersion)..."
    Write-Log "Exiting script now."
    Exit
}
else
{
    Write-Log "No FortiClient detected. Initiating FortiClient installation..."    
}

Write-Log "Checking if HKLM:\SOFTWARE\Microsoft\Windows\Installer key exists..."
if ( (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Installer' -ErrorAction SilentlyContinue) )
{
    Write-Log "HKLM:\SOFTWARE\Microsoft\Windows\Installer exists."
}
else
{
    New-RegistryKey -RegistryKeyPath "HKLM:\SOFTWARE\Microsoft\Windows" -RegistryKeyName "Installer"
}

Write-Log "Checking if HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI exists..."
if ( (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Installer' -Name 'DisableMSI' -ErrorAction SilentlyContinue).DisableMSI -eq $null )
{
    Write-Log "HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI is null."
    Write-Log "Creating HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI as DWORD with value 0..."
    try
    {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Installer' -Name 'DisableMSI' -PropertyType 'DWORD' -Value '0' -ErrorAction Stop  
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to create HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI with value 0."
    }
}

if ( ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Installer' -Name 'DisableMSI' -ErrorAction SilentlyContinue).DisableMSI -ne $null) -and ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Installer' -Name 'DisableMSI' -ErrorAction SilentlyContinue).DisableMSI -ne 0) )
{
    $CurrentDisabledMSI = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Installer' -Name 'DisableMSI' -ErrorAction SilentlyContinue).DisableMSI
    Write-Log "HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI is not 0, it is $CurrentDisabledMSI."
    Write-Log "Setting HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI with value 0..."
    try
    {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Installer' -Name 'DisableMSI' -Value '0' -ErrorAction Stop  
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to set HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI as 0."
    }
}

try
{
    $ProcessorArchitecture = (Get-WmiObject -Class Win32_Processor).AddressWidth
}
catch
{
    Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to get CPU architecture"
}

$error.clear()
if (!$error)
{
    Write-Log "Detected CPU architecture: $ProcessorArchitecture."
}

if ($ProcessorArchitecture -eq 32)
{
    Write-Log "Downloading 32-bit SSL VPN client..."
    $DownloadedFiles = Download-File $SSLVPN32InstallFileURL
}
elseif ($ProcessorArchitecture -eq 64)
{
    Write-Log "Downloading 64-bit SSL VPN client..."
    $DownloadedFiles = Download-File $SSLVPN64InstallFileURL
}

if ($DownloadedFiles)
{
    Write-Log "Starting SSL VPN installation..."
    try
    {
        Install-MSI $DownloadedFiles -ErrorAction Stop
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Installing $DownloadedFiles failed. See log file for more details."
    }

    $error.clear()
    if (!$error)
    {
        if ($CurrentDisabledMSI)
        {
            Write-Log "Setting HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI with value $CurrentDisabledMSI..."
            try
            {
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Installer' -Name 'DisableMSI' -Value $CurrentDisabledMSI -ErrorAction Stop  
            }
            catch
            {
                Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to set HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI as $CurrentDisabledMSI."
            }
        }
        else
        {
            Write-Log "Removing HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI..."
            try
            {
                Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Installer' -Name 'DisableMSI' -ErrorAction Stop  
            }
            catch
            {
                Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to remove HKLM:\SOFTWARE\Microsoft\Windows\Installer\DisableMSI."
            }
        }
    }

    $IsFortiClientInstalled = Get-RemoteProgram -Property DisplayVersion, VersionMajor -ErrorAction Stop | Where-Object {$_.ProgramName -Like "*FortiClient*" }
    Write-Log "After SSL VPN list $($IsFortiClientInstalled.ProgramName) version $($IsFortiClientInstalled.DisplayVersion)"
}

if ($IsFortiClientInstalled)
{
    if ( !(Test-Path -Path 'HKCU:\Software\Fortinet\SslvpnClient\Tunnels' -ErrorAction SilentlyContinue) )
    {
        New-RegistryKey -RegistryKeyPath "HKCU:\Software\Fortinet\SslvpnClient" -RegistryKeyName "Tunnels"
    }
    if ( !(Test-Path -Path 'HKCU:\Software\Fortinet\SslvpnClient\Tunnels\PRP Diagnostic Imaging' -ErrorAction SilentlyContinue) )
    {
        New-RegistryKey -RegistryKeyPath "HKCU:\Software\Fortinet\SslvpnClient\Tunnels" -RegistryKeyName "PRP Diagnostic Imaging"
    }
    try
    {
        New-ItemProperty -Path 'HKCU:\Software\Fortinet\SslvpnClient\Tunnels\PRP Diagnostic Imaging' -Name 'DATA1' -PropertyType 'String' -Value $null -ErrorAction Stop
        New-ItemProperty -Path 'HKCU:\Software\Fortinet\SslvpnClient\Tunnels\PRP Diagnostic Imaging' -Name 'DATA2' -PropertyType 'String' -Value $null -ErrorAction Stop
        New-ItemProperty -Path 'HKCU:\Software\Fortinet\SslvpnClient\Tunnels\PRP Diagnostic Imaging' -Name 'DATA3' -PropertyType 'String' -Value $null -ErrorAction Stop
        New-ItemProperty -Path 'HKCU:\Software\Fortinet\SslvpnClient\Tunnels\PRP Diagnostic Imaging' -Name 'Description' -PropertyType 'String' -Value $null -ErrorAction Stop
        New-ItemProperty -Path 'HKCU:\Software\Fortinet\SslvpnClient\Tunnels\PRP Diagnostic Imaging' -Name 'Server' -PropertyType 'String' -Value 'sslvpn.prpimaging.com.au:443' -ErrorAction Stop
        New-ItemProperty -Path 'HKCU:\Software\Fortinet\SslvpnClient\Tunnels\PRP Diagnostic Imaging' -Name 'ServerCert' -PropertyType 'String' -Value '1' -ErrorAction Stop
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -Message "Unable to create SSL VPN profile."
    }    
}

Write-Log "Script ends."