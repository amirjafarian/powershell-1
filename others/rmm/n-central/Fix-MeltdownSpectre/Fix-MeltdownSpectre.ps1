<#
.SYNOPSIS
    Applies Meltdown and Spectre Windows OS remediation.
.DESCRIPTION
    Applies Meltdown and Spectre Windows OS remediation.
.EXAMPLE
    Syntax: .\Fix-MeltdownSpectre.ps1
.NOTES
    Script name : Fix-MeltdownSpectre.ps1
    Author      : Hendrik Suantio
    Contact     : hsuantio <at> gmail.com
    Version     : 1
    Updated     : 2018-01-11
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

# Get system information
function Get-SystemInformation
{
    Write-Log "Retrieving system information..."
    $ComputerName = $env:COMPUTERNAME
    $Win32_ComputerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $Win32_OperatingSystem = Get-WmiObject -Class Win32_OperatingSystem
    $ComputerManufacturer = $Win32_ComputerSystem.Manufacturer
    $ComputerModel = $Win32_ComputerSystem.Model
    $ProductType = $Win32_OperatingSystem.ProductType
    $BIOS = (Get-WmiObject -Class Win32_BIOS).Name
    $Processor = (Get-WmiObject -Class Win32_Processor).Name
    $ProcessorArchitecture = (Get-WmiObject -Class Win32_Processor).AddressWidth
    $OperatingSystem = $Win32_OperatingSystem.Caption
    $OSVersion = $Win32_OperatingSystem.Version
    $OSReleaseId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).ReleaseId
    $LastReboot = [Management.ManagementDateTimeConverter]::ToDateTime($Win32_OperatingSystem.LastBootUptime)
    $Uptime = ((Get-Date) - $LastReboot).ToString()
    $Hotfixes = Get-WmiObject -Class Win32_QuickFixEngineering | 
        Select-Object HotFixId, Description, InstalledOn, @{
        Name       = 'ComputerName'; 
        Expression = {$env:COMPUTERNAME}
    } | Sort-Object HotFixId
    $ExecutionDate = Get-Date -Format d

    $vmms = Get-Service -Name vmms -ErrorAction SilentlyContinue
    if ($vmms.Status -eq 'Running')
    {
        $isHyperV = $true
    }
    else
    {
        $isHyperV = $false
    }

    $TerminalServerMode = (Get-WmiObject -Namespace root\CIMV2/TerminalServices -Class Win32_TerminalServiceSetting).TerminalServerMode
    if ($TerminalServerMode -eq 1)
    {
        $isTerminalServer = $true
    }
    else {
        $isTerminalServer = $false
    }

    # Test for Docker
    if ($env:Path -match 'docker')
    {
        $isDocker = $true
    }
    else
    {
        $isDocker = $false
    }

    # Test for Chrome 
    # WMI Class Win32_Product does not show Chrome for me.
    # Win32_InstalledWin32Program requies administrative privileges and Windows 7
    $isChrome = Test-Path -Path 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'  

    # Test for Edge
    if ($OSReleaseId)
    {
        # Is Windows 10
        if (Get-AppxPackage -Name Microsoft.MicrosoftEdge)
        {
            $isEdge = $true
        }
        else
        {
            $isEdge = $false
        }
    }
    else
    {
        $isEdge = $false
    }

    # Test for IE
    $isIE = Test-Path -Path 'C:\Program Files\Internet Explorer\iexplore.exe'

    # Test for Firefox
    $isFirefox = (Test-Path -Path 'C:\Program Files\Mozilla Firefox\firefox.exe') -or
    (Test-Path -Path 'C:\Program Files (x86)\Mozilla Firefox\firefox.exe')

    <#
    Customers need to enable mitigations to help protect against speculative execution side-channel vulnerabilities.

    Enabling these mitigations may affect performance. The actual performance impact will depend on multiple factors such as the specific chipset in your physical host and the workloads that are running. Microsoft recommends customers assess the performance impact for their environment and make the necessary adjustments if needed.

    Your server is at increased risk if your server falls into one of the following categories:

    Hyper-V hosts
    Remote Desktop Services Hosts (RDSH)
    For physical hosts or virtual machines that are running untrusted code such as containers or untrusted extensions for database, untrusted web content or workloads that run code that is provided from external sources.
    #>
    if ($ProductType -ne 1) 
    {
        # Product Type = Workstation
        $FeatureSettingsOverride = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue).FeatureSettingsOverride # must be 0
        $FeatureSettingsOverrideMask = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask # must be 3
        if (($FeatureSettingsOverride -eq 0) -and ($FeatureSettingsOverrideMask -eq 3)) 
        {
            $OSMitigationRegKeySet = $true
        }
        else
        {
            $OSMitigationRegKeySet = $false
        }
    }

    # https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms
    if ($isHyperV) 
    {
        $MinVmVersionForCpuBasedMitigations = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -ErrorAction SilentlyContinue).MinVmVersionForCpuBasedMitigations
        if (-not $MinVmVersionForCpuBasedMitigations) 
        {
            if ($OSReleaseId) 
            {
                $MinVmVersionForCpuBasedMitigations = '8.0'
            }
            else 
            {
                $MinVmVersionForCpuBasedMitigations = $false
            }
        }
    }

    <#
    Customers without Anti-Virus
    Microsoft recommends all customers protect their devices by running a supported anti-virus program. Customers can also take advantage of built-in anti-virus protection, Windows Defender for Windows 10 devices or Microsoft Security Essentials for Windows 7 devices. These solutions are compatible in cases where customers can’t install or run anti-virus software. Microsoft recommends manually setting the registry key in the following section to receive the January 2018 security updates.
    #>
    $AVRegKeyValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat' -ErrorAction SilentlyContinue).'cadca5fe-87d3-4b96-b7fb-a231484277cc' # must be 0
    if ($AVRegKeyValue -eq 0) 
    {
        $AVCompatibility = $true
    }
    else 
    {
        $AVCompatibility = $false
    }

    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -MemberType NoteProperty -Name ComputerName -Value $ComputerName
    $output | Add-Member -MemberType NoteProperty -Name Manufacturer -Value $ComputerManufacturer
    $output | Add-Member -MemberType NoteProperty -Name Model -Value $ComputerModel
    $output | Add-Member -MemberType NoteProperty -Name BIOS -Value $BIOS
    $output | Add-Member -MemberType NoteProperty -Name CPU -Value $Processor
    $output | Add-Member -MemberType NoteProperty -Name Architecture -Value $ProcessorArchitecture
    $output | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $OperatingSystem
    $output | Add-Member -MemberType NoteProperty -Name ProductType -Value $ProductType
    $output | Add-Member -MemberType NoteProperty -Name OSReleaseId -Value $OSReleaseId
    $output | Add-Member -MemberType NoteProperty -Name OSVersion -Value $OSVersion
    $output | Add-Member -MemberType NoteProperty -Name isHyperV -Value $isHyperV
    $output | Add-Member -MemberType NoteProperty -Name isTerminalServer -Value $isTerminalServer
    $output | Add-Member -MemberType NoteProperty -Name isDocker -Value $isDocker
    $output | Add-Member -MemberType NoteProperty -Name isEdge -Value $isEdge
    $output | Add-Member -MemberType NoteProperty -Name isIE -Value $isIE
    $output | Add-Member -MemberType NoteProperty -Name isChrome -Value $isChrome
    $output | Add-Member -MemberType NoteProperty -Name isFirefox -Value $isFirefox        
    $output | Add-Member -MemberType NoteProperty -Name OSMitigationRegKeySet -Value $OSMitigationRegKeySet
    $output | Add-Member -MemberType NoteProperty -Name AVCompatibility -Value $AVCompatibility
    $output | Add-Member -MemberType NoteProperty -Name MinVmVersionForCpuBasedMitigations -Value $MinVmVersionForCpuBasedMitigations
    $output | Add-Member -MemberType NoteProperty -Name InstalledUpdates -Value $Hotfixes
    $output | Add-Member -MemberType NoteProperty -Name Uptime -Value $Uptime
    $output | Add-Member -MemberType NoteProperty -Name ExecutionDate -Value $ExecutionDate
    $output
}

function Download-WindowsUpdates
{
    # Download Windows patch
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

function Get-KBURL ($KB, $SystemInfo)
{
    # Meltdown (CVE-2017-5754) and Spectre variant 1 (CVE-2017-5753) patches
    # Windows Server 2008 - 15/01/2018 No updates available yet.
    # Windows 8 - 15/01/2018 No updates available yet.
    $KBArrayURL = New-Object -TypeName System.Collections.ArrayList
    if ($SystemInfo.Architecture -eq 32)
    {
        switch ($KB)
        {
            # x86 Windows 7
            "KB4056897" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/01/windows6.1-kb4056897-x86_bb612f57e082c407b8cdad3f4900275833449e71.msu")) }
            # x86 Windows 8.1
            "KB4056898" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/01/windows8.1-kb4056898-v2-x86_f0781f0b1d96c7b12a18c66f99cf94447b2fa07f.msu")) }
            # x86 Windows 10 1507
            "KB4056893" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows10.0-kb4056893-x86_b2a28dc6845c85fd32dcd511e3f73f82e46d355f.msu")) }
            # x86 Windows 10 1511
            "KB4056888" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows10.0-kb4056888-x86_0493b29664aec0bfe7b934479afb45fe83c59cbe.msu")) }
            # x86 Windows 10 1607
            "KB4056890" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows10.0-kb4056890-x86_078b34bfdc198bee26c4f13e2e45cb231ba0d843.msu")) }
            # x86 Windows 10 1703
            "KB4056891" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows10.0-kb4056891-x86_5e2d98a5cc9d8369a4acd3b3115789a6b1342159.msu")) }
            # x86 Windows 10 1709
            "KB4056892" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/01/windows10.0-kb4056892-x86_d3aaf1048d6f314240b8c6fe27932aa52a5e6733.msu")) }
            # x86 IE 11 for Windows 8.1
            "KB4056568_IE11_63" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows8.1-kb4056568-x86_a5294130778ad17c8ebca16c93f5092f47c9c6f1.msu")) }
            # x86 IE 11 for Windows 7
            "KB4056568_IE11_62" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/ie11-windows6.1-kb4056568-x86_5525b2c7dff9f4eddb0913bad2dfe7c6114a71eb.msu")) }
        }
    }
    elseif ($SystemInfo.Architecture -eq 64)
    {
        switch ($KB)
        {
            # x64 Windows Server 2008 R2 and Windows 7
            "KB4056897" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/01/windows6.1-kb4056897-x64_2af35062f69ce80c4cd6eef030eda31ca5c109ed.msu")) }
            # x64 Windows Server 2012 R2 and Windows 8.1
            "KB4056898" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows8.1-kb4056898-v2-x64_754f420c1d505f4666437d06ac97175109631bf2.msu")) }
            # x64 Windows 10 1507
            "KB4056893" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/01/windows10.0-kb4056893-x64_d2873bb43413d31871ccb8fea213a96a714a6f87.msu")) }
            # x64 Windows 10 1511
            "KB4056888" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/d/msdownload/update/software/secu/2018/01/windows10.0-kb4056888-x64_4477b9725a819afd8abc3e5b1f6302361005908d.msu")) }
            # x64 Windows Server 2016 1607 and Windows 10 1607
            "KB4056890" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows10.0-kb4056890-x64_1d0f5115833be3d736caeba63c97cfa42cae8c47.msu")) }
            # x64 Windows 10 1703
            "KB4056891" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows10.0-kb4056891-x64_59726a743b65a221849572757d660f624ed6ca9e.msu")) }
            # x64 Windows Server 2016 1709 and Windows 10 1709
            "KB4056892" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows10.0-kb4056892-x64_a41a378cf9ae609152b505c40e691ca1228e28ea.msu")) }
            # x64 IE 11 for Windows 8.1 and Windows Server 2012 R2
            "KB4056568_IE11_63" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/windows8.1-kb4056568-x64_e93e9e9d52d36bc209a0376e926b6e53c657ef3b.msu")) }
            # x64 IE 11 for Windows 7 and Windows Server 2008 R2
            "KB4056568_IE11_62" { $KBArrayURL.AddRange(@("http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/01/ie11-windows6.1-kb4056568-x64_f4b6afadf114dc3bd5498a64256e4cdc5e7e7576.msu")) }
        }
    }

    $KBArrayURL
}

# Check if AV is installed.
function Get-InstalledAV
{
    $AVNamespaces = New-Object -TypeName System.Collections.ArrayList
    $AVNamespaces.AddRange(@("root\SecurityCenter","root\SecurityCenter2"))

    $ThirdPartyAVInstalled = $false
    
    Foreach ($AVNamespace in $AVNamespaces)
    {
        try
        {
            $InstalledAV += Get-WmiObject -NameSpace $AVNamespace -Class AntivirusProduct -ErrorAction SilentlyContinue 
        }
        catch {}
    }

    if ($InstalledAV -ne $null)
    {
        Foreach ($AV in $InstalledAV)
        {
            Write-Log "Testing $($AV.DisplayName)..."
            if ($AV.DisplayName -notmatch 'Windows Defender')
            {
                $ThirdPartyAVInstalled = $true
                Write-Log "Found non-default AV installed: $($AV.DisplayName)"
                break
            }
        }
    
        $ThirdPartyAVInstalled
    }
    else
    {
        Write-Log "No AV detected under root\SecurityCenter and root\SecurityCenter2."
        $ThirdPartyAVInstalled
    }
}

# https://support.microsoft.com/en-au/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
# https://support.microsoft.com/en-us/help/4072699/january-3-2018-windows-security-updates-and-antivirus-software
# Create the required registry item if it's eligible.
function Fix-AVCompatibilityRegistry ($SystemInfo)
{
    Write-Log "Fixing AV registry compatibility..."
    $output = $false

    if (($SystemInfo.AVCompatibility) -eq $false)
    {
        Write-Log "Creating HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat..."
        try
        {
            New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' -Name QualityCompat -ErrorAction Stop
        }
        catch
        {
            Get-Exception -ExceptionObject $_ -Message "Unable to create HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat key."
        }
    }
    else
    {
        Write-Log "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat already exists"
    }

    $error.clear()
    if (!$error)
    {
        if ( (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat' -Name 'cadca5fe-87d3-4b96-b7fb-a231484277cc' -ErrorAction SilentlyContinue).'cadca5fe-87d3-4b96-b7fb-a231484277cc' -ne 0 )
        {
            Write-Log "Creating or modifying 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat\cadca5fe-87d3-4b96-b7fb-a231484277cc with value 0..."
            try
            {
                New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat' -Name 'cadca5fe-87d3-4b96-b7fb-a231484277cc' -PropertyType DWord -Value '0x00000000' -ErrorAction Stop
            }
            catch
            {
                Get-Exception -ExceptionObject $_ -Message "Unable to create HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat\cadca5fe-87d3-4b96-b7fb-a231484277cc registry item"
            }
        }
        else
        {
            Write-Log "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat\cadca5fe-87d3-4b96-b7fb-a231484277cc already exists."
        }

        $error.clear()
        if (!$error)
        {
            $output = $true
        }
    }

    $output
}

# Check if AV has added HKLM:\Software\Microsoft\Windows\CurrentVersion\QualityCompat\cadca5fe-87d3-4b96-b7fb-a231484277cc registry item.
function Check-WindowsUpdateEligibility ($SystemInfo, $AVDefenderInstalled)
{
    Write-Log "Checking Windows update compatibility..."
    if (($SystemInfo.AVCompatibility) -eq $true -and (Get-InstalledAV) -eq $true) #AV compatibility key exists and AV is installed.
    {
        Write-Log "Passed AV compatibility check"
        $DoWindowsPatch = $true
    }
    elseif (($SystemInfo.AVCompatibility) -eq $true -and ($AVDefenderInstalled -eq $true)) #AV Defender is installed
    {
        Write-Log "AV Defender is installed and it passed AV compatibility check."
        $DoWindowsPatch = $true
    }
    else
    {
        if ( ((Get-InstalledAV) -eq $false) -and ($AVDefenderInstalled -eq $false) -and (($SystemInfo.ProductType) -eq 1) ) #There is no third-party AV installed on Windows client OS.
        {
            $AVCompatibilityFixStatus = Fix-AVCompatibilityRegistry $SystemInfo
            if ($AVCompatibilityFixStatus -eq $true)
            {
                Write-Log "AV registry compatibility fix success"
                $DoWindowsPatch = $true
            }
            else #Unable to add AV compatibility registry item.
            {
                Write-Log "AV registry compatibility fix failed"
                $DoWindowsPatch = $false
            }
        }
        else #AV compatibility key does not exist and AV is present.
        {
            Write-Log "Does not pass AV compatibility check"
            Write-Log "Please ensure AV is up to date to ensure AV compatibility with Microsoft patches for Meltdown and Spectre"
            $DoWindowsPatch = $false
        }
    }
    $DoWindowsPatch
}

# TODO: Change this to hashtable array
# Get list of Windows updates to be applied
function Get-KBList ($SystemInfo)
{
    Write-Log "Getting list of KBs to be applied..."

    $KBArrayList = New-Object -TypeName System.Collections.ArrayList
    $AppliedKBs = New-Object -TypeName System.Collections.ArrayList

    if ($SystemInfo.OSVersion -like "6.*")
    {
        if ($SystemInfo.Architecture -eq 32)
        {
            switch -wildcard ($SystemInfo.OSVersion)
            {
                "6.3*" # Windows 8.1 and Windows Server 2012 R2
                {
                    Write-Log "Adding x86 KB4056898 and KB4056568 to patch list"
                    $KBArrayList.AddRange(@("KB4056898","KB4056568_IE11_63"))
                    #$KBArrayURL.AddRange(@($KB4056898_x86))
                }
                "6.1*" # Windows 7 and Windows Server 2008 R2
                {
                    Write-Log "Adding x86 KB4056897 and KB4056568 to patch list"
                    $KBArrayList.AddRange(@("KB4056897","KB4056568_IE11_62"))
                    #$KBArrayURL.AddRange(@($KB4056897_x86))
                }
                Default {}
            }
        }
        elseif ($SystemInfo.Architecture -eq 64)
        {
            switch -wildcard ($SystemInfo.OSVersion)
            {
                "6.3*" # Windows 8.1 and Windows Server 2012 R2
                {
                    Write-Log "Adding x64 KB4056898 to patch list"
                    $KBArrayList.AddRange(@("KB4056898","KB4056568_IE11_63"))
                    #$KBArrayURL.AddRange(@($KB4056898_x64))
                } 
                "6.1*" # Windows 7 and Windows Server 2008 R2
                {
                    Write-Log "Adding x64 KB4056897 to patch list"
                    $KBArrayList.AddRange(@("KB4056897","KB4056568_IE11_62"))
                    #$KBArrayURL.AddRange(@($KB4056897_x64))
                }
                Default {}
            }
        }
    }
    elseif ($SystemInfo.OSVersion -like "10.*")
    {
        if ($SystemInfo.Architecture -eq 32)
        {
            switch ($SystemInfo.OSReleaseId)
            {
                "1507"
                {
                    Write-Log "Adding x86 KB4056893 to patch list"
                    $KBArrayList.AddRange(@("KB4056893"))
                    #$KBArrayURL.AddRange(@($KB4056893_x86))
                }
                "1511"
                {
                    Write-Log "Adding x86 KB4056888 to patch list"
                    $KBArrayList.AddRange(@("KB4056888"))
                    #$KBArrayURL.AddRange(@($KB4056888_x86))
                }
                "1607"
                {
                    Write-Log "Adding x86 KB4056890 to patch list"
                    $KBArrayList.AddRange(@("KB4056890"))
                    #$KBArrayURL.AddRange(@($KB4056890_x86))
                }
                "1703"
                {
                    Write-Log "Adding x86 KB4056891 to patch list"
                    $KBArrayList.AddRange(@("KB4056891"))
                    #$KBArrayURL.AddRange(@($KB4056891_x86))
                }
                "1709"
                {
                    Write-Log "Adding x86 KB4056892 to patch list"
                    $KBArrayList.AddRange(@("KB4056892"))
                    #$KBArrayURL.AddRange(@($KB4056892_x86))
                }
            }
        }
        elseif ($SystemInfo.Architecture -eq 64)
        {
            switch ($SystemInfo.OSReleaseId)
            {
                "1507"
                {
                    Write-Log "Adding x86 KB4056893 to patch list"
                    $KBArrayList.AddRange(@("KB4056893"))
                    #$KBArrayURL.AddRange(@($KB4056893_x64))
                }
                "1511"
                {
                    Write-Log "Adding x86 KB4056888 to patch list"
                    $KBArrayList.AddRange(@("KB4056888"))
                    #$KBArrayURL.AddRange(@($KB4056888_x64))
                }
                "1607"
                {
                    Write-Log "Adding x86 KB4056890 to patch list"
                    $KBArrayList.AddRange(@("KB4056890"))
                    #$KBArrayURL.AddRange(@($KB4056890_x64))
                }
                "1703"
                {
                    Write-Log "Adding x86 KB4056891 to patch list"
                    $KBArrayList.AddRange(@("KB4056891"))
                    #$KBArrayURL.AddRange(@($KB4056891_x64))
                }
                "1709"
                {
                    Write-Log "Adding x86 KB4056892 to patch list"
                    $KBArrayList.AddRange(@("KB4056892"))
                    #$KBArrayURL.AddRange(@($KB4056892_x64))
                }
            }
        }
    }
    Foreach ($KB in $KBArrayList)
    {
        Write-Log "Checking if $KB is installed..."
        if ( (Get-HotFix -ErrorAction SilentlyContinue | Where-Object {$_.HotFixID -match $KB}).HotFixID -ne $null)
        {
            Write-Log "$KB is installed."
        }
        else
        {
            Write-Log "$KB is not installed."
            $AppliedKBs.AddRange(@($KB))
        }
    }

    $AppliedKBs
}

function Get-SpeculationControlSettings
{
    <# 

.SYNOPSIS 
This function queries the speculation control settings for the system. 

.DESCRIPTION 
This function queries the speculation control settings for the system. 

Version 1.3. 

#>

    [CmdletBinding()]
    param (

    )
    begin { Write-Log "Getting speculation control protection settings... " }
    process {

        $NtQSIDefinition = @' 
[DllImport("ntdll.dll")] 
public static extern int NtQuerySystemInformation(uint systemInformationClass, IntPtr systemInformation, uint systemInformationLength, IntPtr returnLength); 
'@

        $ntdll = Add-Type -MemberDefinition $NtQSIDefinition -Name 'ntdll' -Namespace 'Win32' -PassThru


        [System.IntPtr]$systemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
        [System.IntPtr]$returnLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

        $object = New-Object -TypeName PSObject

        try {

            #
            # Query branch target injection information.
            #

            #Write-Host "Speculation control settings for CVE-2017-5715 [branch target injection]" -ForegroundColor Cyan
            #Write-Host

            $btiHardwarePresent = $false
            $btiWindowsSupportPresent = $false
            $btiWindowsSupportEnabled = $false
            $btiDisabledBySystemPolicy = $false
            $btiDisabledByNoHardwareSupport = $false

            [System.UInt32]$systemInformationClass = 201
            [System.UInt32]$systemInformationLength = 4

            $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

            if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
                # fallthrough
            }
            elseif ($retval -ne 0) {
                throw (("Querying branch target injection information failed with error {0:X8}" -f $retval))
            }
            else {

                [System.UInt32]$scfBpbEnabled = 0x01
                [System.UInt32]$scfBpbDisabledSystemPolicy = 0x02
                [System.UInt32]$scfBpbDisabledNoHardwareSupport = 0x04
                [System.UInt32]$scfHwReg1Enumerated = 0x08
                [System.UInt32]$scfHwReg2Enumerated = 0x10
                [System.UInt32]$scfHwMode1Present = 0x20
                [System.UInt32]$scfHwMode2Present = 0x40
                [System.UInt32]$scfSmepPresent = 0x80

                [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

                $btiHardwarePresent = ((($flags -band $scfHwReg1Enumerated) -ne 0) -or (($flags -band $scfHwReg2Enumerated)))
                $btiWindowsSupportPresent = $true
                $btiWindowsSupportEnabled = (($flags -band $scfBpbEnabled) -ne 0)

                if ($btiWindowsSupportEnabled -eq $false) {
                    $btiDisabledBySystemPolicy = (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                    $btiDisabledByNoHardwareSupport = (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
                }

                if ($PSBoundParameters['Verbose']) {
                    #Write-Host "BpbEnabled :" (($flags -band $scfBpbEnabled) -ne 0)
                    #Write-Host "BpbDisabledSystemPolicy :" (($flags -band $scfBpbDisabledSystemPolicy) -ne 0)
                    #Write-Host "BpbDisabledNoHardwareSupport :" (($flags -band $scfBpbDisabledNoHardwareSupport) -ne 0)
                    #Write-Host "HwReg1Enumerated :" (($flags -band $scfHwReg1Enumerated) -ne 0)
                    #Write-Host "HwReg2Enumerated :" (($flags -band $scfHwReg2Enumerated) -ne 0)
                    #Write-Host "HwMode1Present :" (($flags -band $scfHwMode1Present) -ne 0)
                    #Write-Host "HwMode2Present :" (($flags -band $scfHwMode2Present) -ne 0)
                    #Write-Host "SmepPresent :" (($flags -band $scfSmepPresent) -ne 0)
                }
            }

            #Write-Host "Hardware support for branch target injection mitigation is present:"($btiHardwarePresent) -ForegroundColor $(If ($btiHardwarePresent) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
            #Write-Host "Windows OS support for branch target injection mitigation is present:"($btiWindowsSupportPresent) -ForegroundColor $(If ($btiWindowsSupportPresent) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
            #Write-Host "Windows OS support for branch target injection mitigation is enabled:"($btiWindowsSupportEnabled) -ForegroundColor $(If ($btiWindowsSupportEnabled) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })

            if ($btiWindowsSupportPresent -eq $true -and $btiWindowsSupportEnabled -eq $false) {
                #Write-Host -ForegroundColor Red "Windows OS support for branch target injection mitigation is disabled by system policy:"($btiDisabledBySystemPolicy)
                #Write-Host -ForegroundColor Red "Windows OS support for branch target injection mitigation is disabled by absence of hardware support:"($btiDisabledByNoHardwareSupport)
            }
    
            $object | Add-Member -MemberType NoteProperty -Name BTIHardwarePresent -Value $btiHardwarePresent
            $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportPresent -Value $btiWindowsSupportPresent
            $object | Add-Member -MemberType NoteProperty -Name BTIWindowsSupportEnabled -Value $btiWindowsSupportEnabled
            $object | Add-Member -MemberType NoteProperty -Name BTIDisabledBySystemPolicy -Value $btiDisabledBySystemPolicy
            $object | Add-Member -MemberType NoteProperty -Name BTIDisabledByNoHardwareSupport -Value $btiDisabledByNoHardwareSupport

            #
            # Query kernel VA shadow information.
            #

            #Write-Host
            #Write-Host "Speculation control settings for CVE-2017-5754 [rogue data cache load]" -ForegroundColor Cyan
            #Write-Host    

            $kvaShadowRequired = $true
            $kvaShadowPresent = $false
            $kvaShadowEnabled = $false
            $kvaShadowPcidEnabled = $false

            $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -First 1 #Fix for the case of multiple objects returned

            if ($cpu.Manufacturer -eq "AuthenticAMD") {
                $kvaShadowRequired = $false
            }
            elseif ($cpu.Manufacturer -eq "GenuineIntel") {
                $regex = [regex]'Family (\d+) Model (\d+) Stepping (\d+)'
                $result = $regex.Match($cpu.Description)
        
                if ($result.Success) {
                    $family = [System.UInt32]$result.Groups[1].Value
                    $model = [System.UInt32]$result.Groups[2].Value
                    $stepping = [System.UInt32]$result.Groups[3].Value
            
                    if (($family -eq 0x6) -and 
                        (($model -eq 0x1c) -or
                            ($model -eq 0x26) -or
                            ($model -eq 0x27) -or
                            ($model -eq 0x36) -or
                            ($model -eq 0x35))) {

                        $kvaShadowRequired = $false
                    }
                }
            }
            else {
                throw ("Unsupported processor manufacturer: {0}" -f $cpu.Manufacturer)
            }

            [System.UInt32]$systemInformationClass = 196
            [System.UInt32]$systemInformationLength = 4

            $retval = $ntdll::NtQuerySystemInformation($systemInformationClass, $systemInformationPtr, $systemInformationLength, $returnLengthPtr)

            if ($retval -eq 0xc0000003 -or $retval -eq 0xc0000002) {
            }
            elseif ($retval -ne 0) {
                throw (("Querying kernel VA shadow information failed with error {0:X8}" -f $retval))
            }
            else {

                [System.UInt32]$kvaShadowEnabledFlag = 0x01
                [System.UInt32]$kvaShadowUserGlobalFlag = 0x02
                [System.UInt32]$kvaShadowPcidFlag = 0x04
                [System.UInt32]$kvaShadowInvpcidFlag = 0x08

                [System.UInt32]$flags = [System.UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32($systemInformationPtr)

                $kvaShadowPresent = $true
                $kvaShadowEnabled = (($flags -band $kvaShadowEnabledFlag) -ne 0)
                $kvaShadowPcidEnabled = ((($flags -band $kvaShadowPcidFlag) -ne 0) -and (($flags -band $kvaShadowInvpcidFlag) -ne 0))

                if ($PSBoundParameters['Verbose']) {
                    #Write-Host "KvaShadowEnabled :" (($flags -band $kvaShadowEnabledFlag) -ne 0)
                    #Write-Host "KvaShadowUserGlobal :" (($flags -band $kvaShadowUserGlobalFlag) -ne 0)
                    #Write-Host "KvaShadowPcid :" (($flags -band $kvaShadowPcidFlag) -ne 0)
                    #Write-Host "KvaShadowInvpcid :" (($flags -band $kvaShadowInvpcidFlag) -ne 0)
                }
            }
    
            #Write-Host "Hardware requires kernel VA shadowing:"$kvaShadowRequired

            if ($kvaShadowRequired) {

                #Write-Host "Windows OS support for kernel VA shadow is present:"$kvaShadowPresent -ForegroundColor $(If ($kvaShadowPresent) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })
                #Write-Host "Windows OS support for kernel VA shadow is enabled:"$kvaShadowEnabled -ForegroundColor $(If ($kvaShadowEnabled) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Red })

                if ($kvaShadowEnabled) {
                    #Write-Host "Windows OS support for PCID performance optimization is enabled: $kvaShadowPcidEnabled [not required for security]" -ForegroundColor $(If ($kvaShadowPcidEnabled) { [System.ConsoleColor]::Green } Else { [System.ConsoleColor]::Blue })
                }
            }

    
            $object | Add-Member -MemberType NoteProperty -Name KVAShadowRequired -Value $kvaShadowRequired
            $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportPresent -Value $kvaShadowPresent
            $object | Add-Member -MemberType NoteProperty -Name KVAShadowWindowsSupportEnabled -Value $kvaShadowEnabled
            $object | Add-Member -MemberType NoteProperty -Name KVAShadowPcidEnabled -Value $kvaShadowPcidEnabled

            #
            # Provide guidance as appropriate.
            #

            $actions = @()
    
            if ($btiHardwarePresent -eq $false) {
                $actions += "Install BIOS/firmware update provided by your device OEM that enables hardware support for the branch target injection mitigation."
            }

            if ($btiWindowsSupportPresent -eq $false -or $kvaShadowPresent -eq $false) {
                $actions += "Install the latest available updates for Windows with support for speculation control mitigations."
            }

            if (($btiHardwarePresent -eq $true -and $btiWindowsSupportEnabled -eq $false) -or ($kvaShadowRequired -eq $true -and $kvaShadowEnabled -eq $false)) {
                $guidanceUri = ""
                $guidanceType = ""

        
                $os = Get-WmiObject Win32_OperatingSystem

                if ($os.ProductType -eq 1) {
                    # Workstation
                    $guidanceUri = "https://support.microsoft.com/help/4073119"
                    $guidanceType = "Client"
                }
                else {
                    # Server/DC
                    $guidanceUri = "https://support.microsoft.com/help/4072698"
                    $guidanceType = "Server"
                }

                $actions += "Follow the guidance for enabling Windows $guidanceType support for speculation control mitigations described in $guidanceUri"
            }

            if ($actions.Length -gt 0) {

                #Write-Host
                #Write-Host "Suggested actions" -ForegroundColor Cyan
                #Write-Host 

                foreach ($action in $actions) {
                    #Write-Host " *" $action
                }
            }


            return $object

        }
        finally {
            if ($systemInformationPtr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($systemInformationPtr)
            }

            if ($returnLengthPtr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($returnLengthPtr)
            }
        }    
    }
}

function Get-CVE-2017-5754 ($SpeculationControlSettings, $SystemInformation)
{
    if ($SpeculationControlSettings.KVAShadowRequired -eq $false) {
        $mitigated = $true
    }
    elseif (($SpeculationControlSettings.KVAShadowWindowsSupportPresent -eq $true) -and 
        ($SpeculationControlSettings.KVAShadowWindowsSupportEnabled -eq $true)) {
        $mitigated = $true
    }
    else {
        $mitigated = $false
    }
    $mitigated        
}

# CVE-2017-5715 (Spectre)
function Get-CVE-2017-5715 ($SpeculationControlSettings, $SystemInformation)
{
    # probably more -and then required, but better safe then sorry
    if (($SpeculationControlSettings.BTIHardwarePresent -eq $true) -and 
        ($SpeculationControlSettings.BTIWindowsSupportPresent -eq $true) -and
        ($SpeculationControlSettings.BTIWindowsSupportEnabled -eq $true)) {
        $mitigated = $true
    }
    else {
        $mitigated = $false
    }
    $mitigated
}   

# CVE-2017-5753 (Spectre)
function Get-CVE-2017-5753 ($SystemInformation)
{
    function IsHotfixInstalled ($ListOfRequiredKBs, $ListOfInstalledKBs) {
        <#
        .SYNOPSIS
            If any of the required KBs is installed, the function returns true
        #>
        foreach ($KB in $ListOfRequiredKBs) {
            if ($ListOfInstalledKBs -contains $KB) {
                $installed = $true
                break
            }
        }
        if ($installed) {
            $true
        }
        else {
            $false
        }
    }

    # Chrome
    # https://www.chromium.org/Home/chromium-security/site-isolation 
    if ($SystemInformation.isChrome) {
        $ChromeVersion = (Get-Item 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe').VersionInfo.ProductVersion -as [version]
        if ($ChromeVersion.Major -gt 63) {
            $ChromeMitigated = $true
        }
        elseif ($ChromeVersion.Major -eq 63) {
            $ChromeSitePerProcessSetting = (Get-ItemProperty -Path HKLM:\Software\Policies\Google\Chrome -ErrorAction SilentlyContinue).SitePerProcess # must be 1
            if ($ChromeSitePerProcessSetting -eq 1) {
                $ChromeMitigated = $true
            }
            else {
                $ChromeMitigated = $false
            }
        }
        else {
            $ChromeMitigated = $false
        }
    } 

    # Microsoft Browser (https://blogs.windows.com/msedgedev/2018/01/03/speculative-execution-mitigations-microsoft-edge-internet-explorer/)
    # From my understanding, the patch is effective as soon as the patch is installed

    # Edge
    if ($SystemInformation.isEdge) {
        #KBs from https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002
        $EdgeUpdates = 'KB4056893', 'KB4056890', 'KB4056891', 'KB4056892', 'KB4056888'
        $Hotfixes = $SystemInformation.InstalledUpdates | Select-Object -ExpandProperty HotFixId
        $EdgeMitigated = IsHotfixInstalled $EdgeUpdates $Hotfixes
    } 

    # Internet Explorer 
    if ($SystemInformation.isIE) {
        # KBs from https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002
        $IEUpdates = 'KB4056890', 'KB4056895', 'KB4056894', 'KB4056568', 'KB4056893', 'KB4056891', 'KB4056892'
        $Hotfixes = $SystemInformation.InstalledUpdates | Select-Object -ExpandProperty HotFixId
        $IEMitigated = IsHotfixInstalled $IEUpdates $Hotfixes
    } 

    # Firefox
    if ($SystemInformation.isFirefox) {
        # See https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/
        $Firefox = (Get-Item -Path 'C:\Program Files\Mozilla Firefox\firefox.exe', 
            'C:\Program Files (x86)\Mozilla Firefox\firefox.exe' -ErrorAction SilentlyContinue)
        $FirefoxVersion = ($Firefox.VersionInfo.ProductVersion | Sort-Object | Select-Object -First 1) -as [version]
        if ($FirefoxVersion -ge [version]'57.0.4') {
            $FirefoxMitigated = $true
        }
        else {
            $FirefoxMitigated = $false
        }
    }

    $output = New-Object -TypeName PSCustomObject
    $output | Add-Member -MemberType NoteProperty -Name EdgeMitigated -Value $EdgeMitigated
    $output | Add-Member -MemberType NoteProperty -Name IEMitigated -Value $IEMitigated
    $output | Add-Member -MemberType NoteProperty -Name ChromeMitigated -Value $ChromeMitigated
    $output | Add-Member -MemberType NoteProperty -Name FirefoxMitigated -Value $FirefoxMitigated
    $output
}    

function Get-RemoteProgram {
    <#
    .Synopsis
    Generates a list of installed programs on a computer
    
    .DESCRIPTION
    This function generates a list by querying the registry and returning the installed programs of a local or remote computer.
    
    .NOTES   
    Name       : Get-RemoteProgram
    Author     : Jaap Brasser
    Version    : 1.3
    DateCreated: 2013-08-23
    DateUpdated: 2016-08-26
    Blog       : http://www.jaapbrasser.com
    
    .LINK
    http://www.jaapbrasser.com
    
    .PARAMETER ComputerName
    The computer to which connectivity will be checked
    
    .PARAMETER Property
    Additional values to be loaded from the registry. Can contain a string or an array of string that will be attempted to retrieve from the registry for each program entry
    
    .PARAMETER ExcludeSimilar
    This will filter out similar programnames, the default value is to filter on the first 3 words in a program name. If a program only consists of less words it is excluded and it will not be filtered. For example if you Visual Studio 2015 installed it will list all the components individually, using -ExcludeSimilar will only display the first entry.
    
    .PARAMETER SimilarWord
    This parameter only works when ExcludeSimilar is specified, it changes the default of first 3 words to any desired value.
    
    .EXAMPLE
    Get-RemoteProgram
    
    Description:
    Will generate a list of installed programs on local machine
    
    .EXAMPLE
    Get-RemoteProgram -ComputerName server01,server02
    
    Description:
    Will generate a list of installed programs on server01 and server02
    
    .EXAMPLE
    Get-RemoteProgram -ComputerName Server01 -Property DisplayVersion,VersionMajor
    
    Description:
    Will gather the list of programs from Server01 and attempts to retrieve the displayversion and versionmajor subkeys from the registry for each installed program
    
    .EXAMPLE
    'server01','server02' | Get-RemoteProgram -Property Uninstallstring
    
    Description
    Will retrieve the installed programs on server01/02 that are passed on to the function through the pipeline and also retrieves the uninstall string for each program
    
    .EXAMPLE
    'server01','server02' | Get-RemoteProgram -Property Uninstallstring -ExcludeSimilar -SimilarWord 4
    
    Description
    Will retrieve the installed programs on server01/02 that are passed on to the function through the pipeline and also retrieves the uninstall string for each program. Will only display a single entry of a program of which the first four words are identical.
    #>
        [CmdletBinding(SupportsShouldProcess=$true)]
        param(
            [Parameter(ValueFromPipeline              =$true,
                        ValueFromPipelineByPropertyName=$true,
                        Position=0
            )]
            [string[]]
                $ComputerName = $env:COMPUTERNAME,
            [Parameter(Position=0)]
            [string[]]
                $Property,
            [switch]
                $ExcludeSimilar,
            [int]
                $SimilarWord
        )
    
        begin {
            $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                                'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'
            $HashProperty = @{}
            $SelectProperty = @('ProgramName','ComputerName')
            if ($Property) {
                $SelectProperty += $Property
            }
        }
    
        process {
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
    
function Check-AVDefenderInstalled
{
    Write-Log "Checking if AV Defender is installed..."
    try
    {
        $InstalledPrograms = Get-RemoteProgram -ErrorAction Stop
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -Message "Unable to get list of installed programs"
    }

    $error.clear()
    if (!$error)
    {
        if ( ($InstalledPrograms | Where-Object {$_.ProgramName -Like "*Security Manager AV Defender*"}) -ne $null )
        {
            Write-Log "Detected AV Defender is installed."
            $AVDefenderInstalled = $true
        }
        else
        {
            Write-Log "No AV Defender installed."
            $AVDefenderInstalled = $false
        }

        $AVDefenderInstalled
    }
}

function Check-WURebootPending
{
    $WURebootPending = $false
    if ( (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue) -or (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue) )
    {
        Write-Log "Pending reboot from previous Windows update is detected. Please reboot this machine."
        $WURebootPending = $true
    }
    else
    {
        Write-Log "No pending reboot is detected."
    }
    $WURebootPending
}

function Apply-WindowsUpdates
{
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        $UpdatePath
    )

    Begin
    {
        Write-Log "Starting Windows update..."
    }
    Process
    {
        Write-Log "Applying $UpdatePath update..."
        $FilePath = 'wusa.exe'
        $ArgumentList = @($UpdatePath, "/quiet", "/norestart" )
        #wusa.exe $UpdatePath /quiet /norestart | Out-Null
        $ExitCode = (Start-Process -FilePath:$filePath -ArgumentList:$ArgumentList -Wait -ErrorAction Stop -PassThru).ExitCode
        Write-Log "$UpdatePath update status: $ExitCode"
    }
    End
    {
        $ExitCode
    }
}

function Activate-MeltdownSpectrePatch
{
    Write-Log "Starting Meltdown/Spectre patch activation..."
    Write-Log "Checking if HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride exists..."
    if ( ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverride -ErrorAction SilentlyContinue).FeatureSettingsOverride -ne $null) -and ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverride -ErrorAction SilentlyContinue).FeatureSettingsOverride -ne 0) )
    {
        Write-Log "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride exists but not 0. Setting its value to 0."
        try
        {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverride -Value 0
        }
        catch
        {
            Get-Exception -ExceptionObject $_ -Message "Unable to set HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride to 0."
        }
        
    }
    elseif ( ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverride -ErrorAction SilentlyContinue).FeatureSettingsOverride) -eq $null )
    {
        Write-Log "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride does not exist. Adding it now."
        try
        {
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -PropertyType 'DWORD' -Value '0'  -Name 'FeatureSettingsOverride'
        }
        catch
        {
            Get-Exception -ExceptionObject $_ -Message "Unable to create HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride with value 0."
        }
    }

    Write-Log "Checking if HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask exists..."
    if ( ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverrideMask -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask -ne $null) -and ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverrideMask -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask -ne 3) )
    {
        Write-Log "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask exists but not 3. Setting its value to 3."
        try
        {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverrideMask -Value 3
        }
        catch
        {
            Get-Exception -ExceptionObject $_ -Message "Unable to set HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask to 3."
        }
        
    }
    elseif ( ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name FeatureSettingsOverrideMask -ErrorAction SilentlyContinue).FeatureSettingsOverrideMask) -eq $null )
    {
        Write-Log "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask does not exist. Adding it now."
        try
        {
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -PropertyType 'DWORD' -Value '3'  -Name 'FeatureSettingsOverrideMask'
        }
        catch
        {
            Get-Exception -ExceptionObject $_ -Message "Unable to create HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask with value 3."
        }
    }
}

function Fix-ChromeCVE20175753
{
    $ChromeVersion = (Get-Item 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe').VersionInfo.ProductVersion -as [version]
    if ($ChromeVersion.Major -eq 63)
    {
        Write-Log "Applying fix for Chrome v63.x..."
        if ((Test-Path -Path 'HKLM:\SOFTWARE\Policies\Google' -ErrorAction SilentlyContinue) -eq $false)
        {
            Write-Log "Creating HKLM:\SOFTWARE\Policies\Google..."
            try
            {
                New-Item -Path 'HKLM:\SOFTWARE\Policies' -Name Google -ErrorAction Stop
            }
            catch
            {
                Get-Exception -ExceptionObject $_ -Message "Unable to create HKLM:\SOFTWARE\Google\Policies\Google"
            }
        }
        if ((Test-Path -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -ErrorAction SilentlyContinue) -eq $false)
        {
            Write-Log "Creating HKLM:\SOFTWARE\Policies\Google\Chrome"
            try
            {
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Google' -Name Chrome -ErrorAction Stop
            }
            catch
            {
                Get-Exception -ExceptionObject $_ -Message "Unable to create HKLM:\SOFTWARE\Policies\Google\Chrome"
            }
        }
        if ( ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name SitePerProcess -ErrorAction SilentlyContinue).SitePerProcess -eq $null) -or ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name SitePerProcess -ErrorAction SilentlyContinue).SitePerProcess) -ne 1 )
        {
            Write-Log "Starting Chrome fix..."
            Write-Log "Creating HKLM:\SOFTWARE\Policies\Google\SitePerProcess with value 1..."
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Google\Chrome' -PropertyType 'DWORD' -Value '1' -Name 'SitePerProcess' -ErrorAction Stop
        }
    }
}

function Fix-FirefoxCVE20175753
{
    #Nothing yet.
}

function Disable-ScheduledTask ($CVE20175715mitigated, $CVE20175754mitigated, $CVE20175753mitigated )
{
    Write-Log "Checking if scheduled task job should be disabled..."
    if (($CVE20175753mitigated.ChromeMitigated) -eq $null)
    {
        Write-Log "CVE-2017-5753 Chrome is null. Changing to true."
        $CVE20175753mitigated.ChromeMitigated = $true
    }
    if ($CVE20175753mitigated.FirefoxMitigated -eq $null)
    {
        Write-Log "CVE-2017-5753 Firefox is null. Changing to true."
        $CVE20175753mitigated.FirefoxMitigated = $true
    }
    if ($CVE20175753mitigated.IEMitigated -eq $null)
    {
        Write-Log "CVE-2017-5753 IE is null. Changing to true."
        $CVE20175753mitigated.IEMitigated = $true
    }
    if ($CVE20175753mitigated.EdgeMitigated -eq $null)
    {
        Write-Log "CVE-2017-5753 Edge is null. Changing to true."
        $CVE20175753mitigated.EdgeMitigated = $true
    }
    Write-Log "Checking if all Meltdown and Spectre vulnerabilities have been remediated..."
    if ( ($CVE20175715mitigated) -and ($CVE20175754mitigated) -and ($CVE20175753mitigated.ChromeMitigated) -and ($CVE20175753mitigated.FirefoxMitigated) -and ($CVE20175753mitigated.IEMitigated) -and ($CVE20175753mitigated.EdgeMitigated) )
    {
        Write-Log "All Meltdown and Spectre vulnerabilities have been remediated. You're all good now."
        Write-Log "Disabling scheduled task."
        schtasks /TN "CheckMeltdownandSpectreRemediationStatus" /CHANGE /DISABLE
    }
}

# Main code
$VerbosePreference = "Continue"
$IsDebug = $false
$ScriptLogPath = 'C:\Logs\Fix-MeltdownSpectre.log'
Reset-Log -FileName $ScriptLogPath -FileSize 100KB -LogCount 5
Write-Log "Starting script as $env:username..."

$SystemInfo = Get-SystemInformation
$AVDefenderInstalled = Check-AVDefenderInstalled

# Check speculation control status
try
{
    $SpeculationControlSettings = Get-SpeculationControlSettings -ErrorAction Stop
}
catch
{
    Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to get speculation control setting. Terminating program."
}

$DoWindowsUpdate = Check-WindowsUpdateEligibility $SystemInfo $AVDefenderInstalled

if ($IsDebug)
{
    Write-Log "Debug mode"
    $DoWindowsUpdate = $true
}

$WURebootPending = Check-WURebootPending
$CVE20175754mitigated = Get-CVE-2017-5754 $SpeculationControlSettings $SystemInfo
$CVE20175715mitigated = Get-CVE-2017-5715 $SpeculationControlSettings $SystemInfo
$CVE20175753mitigated = Get-CVE-2017-5753 $SystemInfo

Write-Log "System info: $SystemInfo"
Write-Log "Speculation control status: $SpeculationControlSettings"
Write-Log "Meltdown (CVE-2017-5754) mitigated: $CVE20175754mitigated"
Write-Log "Spectre variant 2 (CVE-2017-5715) mitigated: $CVE20175715mitigated"
Write-Log "Spectre variant 1 (CVE-2017-5753 mitigated): $CVE20175753mitigated"

if ($DoWindowsUpdate -and ($WURebootPending -eq $false))
{
    Write-Log "Computer is eligible for Windows update."

    #$CVE20175754mitigated = $false
    if ($CVE20175754mitigated -eq $false)
    {  
        Write-Log "Remediating CVE-2017-5754..."
        $KBArrayList = Get-KBList $SystemInfo

        if ($IsDebug)
        {
            Write-Log "Debug mode"
            $KBArrayList = New-Object -TypeName System.Collections.ArrayList
            $KBArrayList.AddRange(@("KB4056892"))  
        }

        if ($KBArrayList -ne $null)
        {
            Write-Log "All required patches: $KBArrayList"
            Foreach ($KB in $KBArrayList)
            {
                $UpdateStatus = Get-KBURL $KB $SystemInfo | Download-WindowsUpdates | Apply-WindowsUpdates
                Write-Log "Update status returned: $UpdateStatus"
            }
        }
        else
        {
            Write-Log "No patch required for CVE-2017-5754"
        }

        if ($UpdateStatus -eq 0 -or $UpdateStatus -eq 3010)
        {
            # https://support.microsoft.com/en-hk/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
            # Activate speculative execution side-channel vulnerabilities protection.
            Write-Log "Please reboot the server to activate KVA."
        }
        if ($SystemInfo.ProductType -ne 1) #Only applies for Windows server OS
        {
            Activate-MeltdownSpectrePatch
        }
    }
    else
    {
        Write-Log "CVE-2017-5754 has been mitigated."
    }

    if ($CVE20175715mitigated -eq $false)
    {
        Write-Log "Check OEM for CPU microcode firmware update. It is usually released with BIOS update."
    }
    else
    {
        Write-Log "CVE-2017-5715 has been mitigated."
    }
}

<#
if ($IsDebug)
{
    $CVE20175753mitigated.ChromeMitigated = $false
}
#>

if ($CVE20175753mitigated.ChromeMitigated -ne $null -and $CVE20175753mitigated.ChromeMitigated -eq $false)
    {
        Write-Log "Remediating Chrome CVE-2017-5753..."
        Fix-ChromeCVE20175753
    }
    else
    {
        Write-Log "No Chrome mitigation is required"
    }

    
if ($CVE20175753mitigated.FirefoxMitigated -ne $null -and $CVE20175753mitigated.FirefoxMitigated -eq $false)
    {
        Write-Log "Firefox is not up-to-update, required min version 57.0.4. It should update automatically."
        Fix-FirefoxCVE20175753
    }
    else
    {
        Write-Log "No Firefox mitigation is required"
    }

Disable-ScheduledTask $CVE20175715mitigated $CVE20175754mitigated $CVE20175753mitigated

Write-Log "Script ends."