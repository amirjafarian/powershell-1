# Updated as of Jan 2018 Compellent BP.
# MPIO Registry Settings script
# This script will apply recommended Dell Storage registry settings
# on Windows Server 2008 R2 or newer, including Nano Server
#
# THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND.
# THE ENTIRE RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE
# REMAINS WITH THE USER.
# Assign variables

$MpioRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mpio\Parameters"
$IscsiRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\"
$IscsiRegPath += "{4d36e97b-e325-11ce-bfc1-08002be10318}\000*"

# General settings
Set-ItemProperty -Path $MpioRegPath -Name "PDORemovePeriod" -Value 120 -EA SilentlyContinue
Set-ItemProperty -Path $MpioRegPath -Name "PathRecoveryInterval" -Value 25 -EA SilentlyContinue
Set-ItemProperty -Path $MpioRegPath -Name "UseCustomPathRecoveryInterval" -Value 1 -EA SilentlyContinue
Set-ItemProperty -Path $MpioRegPath -Name "PathVerifyEnabled" -Value 1 -EA SilentlyContinue

# Apply OS-specific general settings
$OsVersion = ( Get-WmiObject -Class Win32_OperatingSystem ).Caption
If ( $OsVersion -match "Windows Server 2008 R2" )
    {
    New-ItemProperty -Path $MpioRegPath -Name "DiskPathCheckEnabled" -Value 1 -PropertyType DWORD -Force -EA SilentlyContinue
    New-ItemProperty -Path $MpioRegPath -Name "DiskPathCheckInterval" -Value 25 -PropertyType DWORD -Force -EA SilentlyContinue
    }
Else
    {
    Set-ItemProperty -Path $MpioRegPath -Name "DiskPathCheckInterval" -Value 25 -EA SilentlyContinue
    }

# iSCSI settings
If ( ( Get-Service -Name "MSiSCSI" ).Status -eq "Running" )
    {
    # Get the registry path for the Microsoft iSCSI initiator parameters
    $IscsiParam = Get-Item -Path $IscsiRegPath | Where-Object { ( Get-ItemProperty $_.PSPath ).DriverDesc -eq "Microsoft iSCSI Initiator" } `
    | Get-ChildItem | Where-Object { $_.PSChildName -eq "Parameters" }
    
    # Set the Microsoft iSCSI initiator parameters
    Set-ItemProperty -Path $IscsiParam.PSPath -Name "MaxRequestHoldTime" -Value 90 -EA SilentlyContinue
    Set-ItemProperty -Path $IscsiParam.PSPath -Name "LinkDownTime" -Value 35 -EA SilentlyContinue
    Set-ItemProperty -Path $IscsiParam.PSPath -Name "EnableNOPOut" -Value 1 -EA SilentlyContinue
    }
Else
    {
    Write-Host "iSCSI Service is not running."
    Write-Host "iSCSI registry settings have NOT been configured."
    }

Write-Host "MPIO registry settings have been configured successfully."
Write-Host "The system must be restarted for the changes to take effect."