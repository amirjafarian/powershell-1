<#
.SYNOPSIS
    Get vmdk association with Windows disk.
.DESCRIPTION
    Get vmdk association with Windows disk.
.PARAMETER Server
    Compulsory. Specify vCenter server to connect to.
.PARAMETER VM
    Compulsory. The Windows server to get disk information from.
.Parameter Credential
    Optional. To enable custom credential prompt.
.Parameter OutputToGUI
    Optional. To enable output to GUI.
.EXAMPLE
    .\Get-VMDiskInfo.ps1 -Server vcenter.contoso.com -VM dc.contoso.com
    Get dc.contoso.com VM disks detail through vcenter.contoso.com
.EXAMPLE
    .\Get-VMDiskInfo.ps1 -Server vcenter.contoso.com -VM dc.contoso.com -Credential -OutputToGUI
    Get dc.contoso.com VM disks detail through vcenter.contoso.com by manually specificying credential through prompt and send the output to GUI.
.NOTES
    Script name : Get-VMDiskInfo.ps1
    Author      : Hendrik Suantio
    Contact     : hsuantio <at> gmail.com
    DateCreated : 2017-11-27
    Version     : 1
    Disclaimer  : This script is provided as-is without guarantee. Please read the script to understand what it does prior to using it.
#>

[CmdletBinding()]

Param
(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string]$Server,

    [Parameter(Position = 1, Mandatory = $true)]
    [ValidateNotNullorEmpty()]
    [string]$VM,

    [Parameter(Position = 2, Mandatory = $false)]
    [switch]$Credential = $false,

    [Parameter(Position = 2, Mandatory = $false)]
    [switch]$OutputToGUI = $false
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
        [string]$Path='C:\Logs\Get-VMDiskInfo.log',
        
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

function Initialize-PowerCLI
{
    if ( !(Get-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) )
    {
        Write-Log -Message "Initializing VMware vSphere PowerCLI environment"
        $PowerCLIDir = (Get-Module -ListAvailable -Name VMware.VimAutomation.Core).ModuleBase
        if ($PowerCLIDir -eq $null)
        {
            Write-Log -Message "Error initializing VMWare PowerCLI environment. Cannot find path to VMWare PowerCLI in Registry. Make sure VMWare PowerCLI is installed on this host."
            Exit
        }
        
        try
        {
            . "$PowerCLIDir\..\..\Scripts\Initialize-PowerCLIEnvironment.ps1"
        }
        catch
        {
            Catch-Exception -ExceptionObject $_ -ForceExit $true -Message "PowerCLI module found but unable to initialize successfully. "
        }
        
    }
}

#$VerbosePreference = "Continue"
Write-Log "Starting script"

# Define variables
$DiskInfo= @()
[int]$i=0

if ($Credential)
{
    try
    {
        $CustomCredential = Get-Credential -Message "Enter credentials  to access vCenter and Windows servers" -ErrorAction Stop
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -ForceExit $true -Message "Error retrieving credentials"
    }
}

# Import PowerCLI modules
if (Get-Command Connect-VIServer -ErrorAction SilentlyContinue)
{
    Write-Log -Level Warn "PowerCLI is already loaded"
}
else
{
    Initialize-PowerCLI
}

try
{
    if ($Credential)
    {
        Connect-VIServer -Server $Server -Credential $CustomCredential -ErrorAction Stop | Out-Null
    }
    else
    {
        Connect-VIServer -Server $Server -ErrorAction Stop | Out-Null
    }
}
catch
{
    Catch-Exception -ForceExit $true -ExceptionObject $_ -Message "Unable to connect to vCenter"
}

$error.clear()
if (!$error)
{
    Write-Log -Level Info "Connected to vCenter"
    [boolean]$IsvCenterConnected = $true
}

Write-Log -Level Info "Getting disks info..."
$Disks = Get-VM $VM | Get-HardDisk -DiskType "RawPhysical","RawVirtual"
$LogtoPart = Get-WmiObject -Class Win32_LogicalDiskToPartition -ComputerName $VM -Credential $CustomCredential
$DisktoPart = Get-WmiObject -Class Win32_DiskDriveToDiskPartition -ComputerName $VM -Credential $CustomCredential
$Logical = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $VM -Credential $CustomCredential
$Volume = Get-WmiObject -Class Win32_Volume -ComputerName $VM -Credential $CustomCredential
$Partition = Get-WmiObject -Class Win32_DiskPartition -ComputerName $VM -Credential $CustomCredential

if (($VMView = Get-View -ViewType VirtualMachine -Filter @{"Name" = $VM})) 
{
    $WinDisks = Get-WmiObject -Class Win32_DiskDrive -ComputerName $VMView.Name -Credential $CustomCredential
    foreach ($VirtualSCSIController in ($VMView.Config.Hardware.Device | Where-Object {$_.DeviceInfo.Label -match "SCSI Controller"}))
    {
        foreach ($VirtualDiskDevice in ($VMView.Config.Hardware.Device | Where-Object {$_.ControllerKey -eq $VirtualSCSIController.Key})) 
        {
            $VirtualDisk = "" | Select-Object ComputerName, SCSIController, DiskName, SCSI_Id, DiskFile, DiskSize, WindowsDisk, NAA, Drive, VolumeName
            $VirtualDisk.Computername = $VM
            $VirtualDisk.SCSIController = $VirtualSCSIController.DeviceInfo.Label
            $VirtualDisk.DiskName = $VirtualDiskDevice.DeviceInfo.Label
            $VirtualDisk.SCSI_Id = "$($VirtualSCSIController.BusNumber) : $($VirtualDiskDevice.UnitNumber)"
            $VirtualDisk.DiskFile = $VirtualDiskDevice.Backing.FileName
            $VirtualDisk.DiskSize = $VirtualDiskDevice.CapacityInKB * 1KB / 1GB
            $virtualdisk.naa=$disks | Where-Object {$_.name -like $VirtualDiskDevice.DeviceInfo.Label} | Select-Object -expand scsicanonicalname

            # Match disks based on SCSI ID
            $DiskMatch = $WinDisks | Where-Object {($_.SCSIPort -2 ) -eq $VirtualSCSIController.BusNumber -and $_.SCSITargetID -eq $VirtualDiskDevice.UnitNumber}
            if ($DiskMatch)
            {
                $VirtualDisk.WindowsDisk = "Disk $($DiskMatch.Index)"
                $i++
            }
            else
            {
                Write-Host "No matching Windows disk found for SCSI id $($VirtualDisk.SCSI_Id)"
            }
 
            $MatchDisktoPart = $DisktoPart | Where-Object {$_.Antecedent -eq $DiskMatch.__Path}
            $MatchLogtoPart = $LogtoPart | Where-Object {$_.Antecedent -eq $MatchDisktoPart.Dependent}
            $LogicalMatch = $Logical| Where-Object {$_.path.path -eq $MatchLogtoPart.dependent}
            $VirtualDisk.VolumeName = $LogicalMatch.VolumeName
            $VirtualDisk.Drive = $LogicalMatch.DeviceID
 
            $DiskInfo += $VirtualDisk
        }
    }
    if ($OutputToGUI)
    {
        $DiskInfo | Out-GridView -Title "VM Disks Report"
    }
    else
    {
        $DiskInfo | Format-Table ComputerName, WindowsDisk, Drive, VolumeName, DiskName, DiskSize
    }
}
else
{
    Write-Host "VM $VM not found"
}

if ($IsvCenterConnected)
{
    try
    {
        Disconnect-VIServer -Server $Server -Force -Confirm:$false -ErrorAction Stop | Out-Null
    }
    catch
    {
        Catch-Exception -ExceptionObject $_ -Message "Unable to disconnect from vCenter"
    }
}
# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxKOeDIRfh2Q7Cad2uDD07VKR
# A3egggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
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
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUSH1n9JhCpT997sci
# GsKPOxPHJGQwDQYJKoZIhvcNAQEBBQAEggEAgGV5gRXHXH2TdnmbGphqlrGsTdqq
# Y8lMYSGR2l8Sev8PDV3aoZJPpVhENZcQyHZgT9vihLrRN1GHfLt0M+uFszoM2Htn
# WUxOS37OhQH0E6/DUrlOmxlufvQXT8LBz1LSkEmn5yautd51b8Vaj3XJTz7c5AIJ
# LQW5arl7OLoxKC8euXoYCI1YqRIjn92YbYmIaZlTQXEDidk8TfOdN+n1BPquxaRo
# k0mubxG+4ELfjV9XAtZtaMiWDpDlFUTTcSru2Rnj/U2/4e1bjiRqeBBg0biBEFjG
# IajasYZlMvGo8sZhcFnnxV+dG7Yq8GOKQZP5l/CieLCbUZKVKDk/Tepwew==
# SIG # End signature block
