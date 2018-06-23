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
        [Alias('Path')]
        [string]$ScriptLogPath='C:\Logs\NCentralAgentInstall.log',
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        #$VerbosePreference = 'Continue'
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $ScriptLogPath) -AND $NoClobber) {
            Write-Error "Log file $ScriptLogPath already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $ScriptLogPath)) {
            Write-Verbose "Creating $ScriptLogPath."
            $NewLogFile = New-Item $ScriptLogPath -Force -ItemType File
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
        
        # Write log entry to $ScriptLogPath
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $ScriptLogPath -Append
    }
    End
    {
    }
}

$CurrentTime = Get-Date -Format yyyyMMdd-HHmmss
Write-Log -Message "Starting script on $CurrentTime as $env:username..."
$ScriptLogPath='C:\Logs\NCentralAgentInstall.log'
if ((Test-Path -Path $ScriptLogPath)) {
    Write-Verbose "Removing $ScriptLogPath"
    try {
        Remove-Item $ScriptLogPath -ErrorAction Stop
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Debug "Program terminated on $FailedItem with error $ErrorMessage"
        Exit
    }
}

$NetRegKey = Get-Childitem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -EA SilentlyContinue
$Net40RegKey = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4' -EA SilentlyContinue

if ($NetRegKey -ne $null) {
    $Release = $NetRegKey.GetValue("Release")

    Switch ($Release) {
       30319  {$NetFrameworkVersion = "4.0"}
       378389 {$NetFrameworkVersion = "4.5"}
       378675 {$NetFrameworkVersion = "4.5.1"}
       378758 {$NetFrameworkVersion = "4.5.1"}
       379893 {$NetFrameworkVersion = "4.5.2"}
       393295 {$NetFrameworkVersion = "4.6"}
       393297 {$NetFrameworkVersion = "4.6"}
       394254 {$NetFrameworkVersion = "4.6.1"}
       394271 {$NetFrameworkVersion = "4.6.1"}
       394802 {$NetFrameworkVersion = "4.6.2"}
       394806 {$NetFrameworkVersion = "4.6.2"}
       460798 {$NetFrameworkVersion = "4.7"}
       Default {$NetFrameworkVersion = "Net Framework Four or later is not installed."}
    }
    Write-Log -Message "Detected NETFX version: $NetFrameworkVersion"
    if ($Release -ge 378389) { $NetFX4Installed = $true } else { $NetFX4Installed = $false}
}
else {
    $NetFrameworkVersion = "Net Framework Four or later is not installed."
    Write-Log -Message $NetFrameworkVersion
    $NetFX4Installed = $false
}

if ($Net40RegKey -ne $null) {
    $NetFX4Installed = $true
    Write-Log -Message "NETFX4 is installed."
}

$netfxinstaller = "NDP452-x86-x64-AllOS.exe"
$domainName = (Get-WmiObject Win32_ComputerSystem).Domain
$path = "\\$domainName\NETLOGON\NOCAgent\"
$fullnetfxinstallerpath = $path + $netfxinstaller
$netfxinstallparameter = "/q"
$netfxinstallcommand = "$fullnetfxinstallerpath $netfxinstallparameter"
Write-Log -Message "netfx install command: $netfxinstallcommand"

if ($NetFX4Installed -eq $false) {
    Write-Log -Message "Could not find NETFX4 in this machine, starting netfx4 install..."
    CMD /C $netfxinstallcommand 2>&1 | Out-Null
    if ($?)
    {
        Write-Log -Message "Successfully installed NETFX4."
    }
    else
    {
        Write-Log -Message "Failed to install NETFX4."
    }
}

$agentService = Get-WmiObject -Class Win32_Service -Filter "Name='Windows Agent Service'"
$requiredAgentVersion = '11.0.0.1110'
$installerFileName = "WindowsAgentSetup.exe"
$destinationFolder = "$env:windir\Temp\NAgent"
$installParamater = "/q"
$installerfolderpath = "\\$domainName\NETLOGON\NOCAgent\"
Write-Log -Message "Required minimum N-Central agent version: $requiredAgentVersion."

Function Install-App
{
    if(-not (Test-Path -Path "$env:windir\Temp"))
    {
        New-Item -Path $env:windir\Temp -ItemType Directory
    }

    if(-not (Test-Path -Path $destinationFolder))
    {
        New-Item -Path $destinationFolder -ItemType Directory
    }

    #$copyCommand = "robocopy $installerFolderPath  $env:windir\Temp $installerFileName /is"
    Copy-Item -Path "$installerFolderPath\*.*" -Destination $destinationFolder -Force -Recurse
    #CMD /C $copyCommand 2>&1 | Out-Null
    $installCommand = "$destinationFolder\$installerFileName $installParamater"
    Write-Log -Message "N-Central agent install command: $installCommand"
    Write-Log -Message "Installing N-Central agent $requiredAgentVersion"
    CMD /C $installCommand 2>&1 | Out-Null

    if ($?)
    {
        Write-Log -Message "Successfully installed N-Central agent."
    }
    else
    {
        Write-Log -Message "Failed to install N-Central agent."
    }
}


if($agentService -ne $null -or $agentService -eq "")
{
    Write-Log -Message "N-Central agent is present. Checking if it is the latest version."
    $agentFilePath = $agentService.PathName
    $agentFileInfo = Get-Item $agentFilePath.Replace('"',"")

    $agentVersion = $agentFileInfo.VersionInfo.FileVersion
    Write-Log -Message "Detected N-Central agent version in this machine: $agentVersion"

    if([System.Version]$requiredAgentVersion -gt [System.Version]$agentVersion)
    {
        Write-Log -Message "Upgrading N-Central agent from $agentVersion to $requiredAgentVersion"
        Install-App
    }
    else
    {
        Write-Log -Message "N-Central agent is already the latest version $AgentVersion"    
    }
}
else
{
    Write-Log -Message "No N-Central agent is detected, initiating agent installation now."
    Install-App
}

Write-Log -Message "Script ends."