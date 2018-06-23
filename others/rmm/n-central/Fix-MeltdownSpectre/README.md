# Fix-MeltdownSpectre.ps1
Updated 15/02/2018
Support: hendrik dot suantio at avante dash group dot com

Supported systems:
* Windows 7
* Windows 8.1
* Windows 10
* Windows Server 2008 R2
* Windows Server 2012 R2
* Windows Server 2016

Requirements:
* Unauthenticated internet access to https://raw.githubusercontent.com and https://download.windowsupdate.com.
* Powershell v2 and above.

This script checks if the following vulnerabilities have been remediated:
* Meltdown: CVE-2017-5754
* Spectre variant 1: CVE-2017-5753
* Spectre variant 2: CVE-2017-5715

# Meltdown - CVE-2017-5754
The script checks if the following registry item is present and set as 0: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat\cadca5fe-87d3-4b96-b7fb-a231484277cc. Antivirus should add this registry item if it has verified that the AV will work well with the relevant Windows patch. The script will add this registry key if no AV is present in the system.

No updates will be applied until the machine has rebooted if there is pending reboot triggered by Windows update. The updates applied are listed below if it's not already present:
* Windows 7 and Windows Server 2008 R2: KB4056897
* Windows 8.1 and Windows Server 2012 R2: KB4056898
* Windows 10 Build 1507: KB4056893
* Windows 10 Build 1511: KB4056888
* Windows 10 Build 1607 and Windows Server 2016 Build 1607: KB4056890
* Windows 10 Build 1703: KB4056891
* Windows 10 Build 1709 and Windows Server 2016 Build 1709: KB4056892

Meltdown and Spectre variant 2 vulnerabilities have this enabled by default on client OS. This fix needs to be manually enabled on server OS by applying the following registry items--this is taken care by the remediation script:
* HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride:REG_DWORD:0
* HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask:REG_DWORD:3

Update 30/01/2018:
Microsoft has released KB4078130 to deactivate this fix through the registry items due to reported issues related to unexpected reboots and other unpredictable system behavior. See https://support.microsoft.com/en-us/help/4078130/update-to-disable-mitigation-against-spectre-variant-2 for more details.

# Spectre variant 1 - CVE-2017-5753
The script checks the following browsers for vulnerabilities:
* Internet Explorer 11:
  * Windows 7 and Windows Server 2008 R2: KB4056568
  * Windows 8.1 and Windows Server 2012 R2: KB4056568
  * Windows 10 Build 1507: KB4056893
  * Windows 10 Build 1511: KB4056888
  * Windows 10 Build 1607 and Windows Server 2016 Build 1607: KB4056890, need KB4074590 for Windows 10 1607 32-bit review
  * Windows 10 Build 1703: KB4056891, need KB4074592 for Windows 10 1703 32-bit review
  * Windows 10 Build 1709 and Windows Server 2016 Build 1709: KB4056892, need KB4073291 for Windows 10 1709 32-bit review, KB4073291 for Windows 10 1709 32-bit.
* Microsoft Edge: This is addressed in Meltdown Windows update.
* Google Chrome: If Chrome is v63, this value of this registry item has to be 1: HKLM:\Software\Policies\Google\Chrome\SitePerProcess. It adds this registry item if it's not the case. If Chrome is v64 and above, no action is needed. If Chrome is v62 and below, Chrome should update itself.
* Mozilla Firefox: It passes the check if Firefox is v57.0.4 and above.

# Spectre variant 2 - CVE-2017-5715
Please update CPU microcode which usually included in OEM BIOS update. If it is a virtual machine, ensure the hypervisor is patched as well.

Meltdown and Spectre variant 2 vulnerabilities have this enabled by default on client OS. This fix needs to be manually enabled on server OS by applying the following registry items--this is taken care by the remediation script:
* HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride:REG_DWORD:0
* HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask:REG_DWORD:3

Microsoft has released KB4078130 to deactivate this fix through the registry items due to reported issues related to unexpected reboots and other unpredictable system behavior. See https://support.microsoft.com/en-us/help/4078130/update-to-disable-mitigation-against-spectre-variant-2 for more details.

# Misc
The script will disable itself once it detects that CVE-2017-5754, CVE-2017-5753 and CVE-2017-5715 have been remediated.

# Solarwindows N-Central Deployment
Requirements:
* N-Central Professional license assigned.
* Windows OS listed in Fix-MeltdownSpectre.ps1 requirements.
* Scheduled task enable in N-Central object.

Deployment steps:
* Create a new automation policy that runs Powershell script in https://raw.githubusercontent.com/hsuantio/posh/master/N-Central/Fix-MeltdownSpectre/Enable-MeltdownSpectreFix.ps1
* Run the automation policy on all Windows machines.

This will download two files:
* The main remediation script: https://raw.githubusercontent.com/hsuantio/posh/master/N-Central/Fix-MeltdownSpectre/Fix-MeltdownSpectre.ps1
* An XML for scheduled task: https://raw.githubusercontent.com/hsuantio/posh/master/N-Central/Fix-MeltdownSpectre/XML/CheckMeltdownandSpectreRemediationStatus.xml

A daily scheduled task will be created that runs Fix-MeltdownSpectre.ps1 with an execution time that is randomly generated. This is to prevent saturating the internet link at a site when downloading the required Windows updates. The task is run as soon as the machine is operational if the previous scheduled task is missed.

# Group Policy
Requirements:
* Active Directory environment
* Domain-joined computers

Deployment steps:
* Create a new group policy scheduled task that runs https://raw.githubusercontent.com/hsuantio/posh/master/N-Central/Fix-MeltdownSpectre/Enable-MeltdownSpectreFix.ps1 only once.

# Support requirement
Provide C:\Logs\Fix-MeltdownSpectre.log file.

# References
* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002
* https://support.microsoft.com/en-us/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution
* https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
* https://support.microsoft.com/en-us/help/4072699/january-3-2018-windows-security-updates-and-antivirus-software
* https://blogs.windows.com/msedgedev/2018/01/03/speculative-execution-mitigations-microsoft-edge-internet-explorer/
* https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms
* https://cloudblogs.microsoft.com/microsoftsecure/2018/01/09/understanding-the-performance-impact-of-spectre-and-meltdown-mitigations-on-windows-systems/

# Change History
* 16/01/2018: Initial version
* 15/02/2018: Added KB4056568 for IE 11 on Windows Server 2012 R2, Windows 8.1, Windows Server 2008 R2 and Windows 7