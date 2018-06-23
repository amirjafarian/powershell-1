Set-ExecutionPolicy Unrestricted -Scope Process -Confirm:$false
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Confirm:$false
$scriptPath = (Get-Item -Path ".\").FullName

$filesToDownload = (
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/DefaultConfiguration.xml",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Dynamic-UpdateSource.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Edit-OfficeConfigurationFile.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/EnvironmentalFilter.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Generate-ODTConfigurationXML.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Generate-ODTLanguagePackXML.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Get-OfficeVersion.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Install-OfficeClickToRun.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Move-Office365ClientShortCuts.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/OffScrub03.vbs",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/OffScrub07.vbs",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/OffScrub10.vbs",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/OffScrub_O15msi.vbs",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/OffScrub_O16msi.vbs",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/OffScrubc2r.vbs",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Office2013Setup.exe",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Office2016Setup.exe",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Remove-OfficeClickToRun.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/Remove-PreviousOfficeInstalls.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/SharedFunctions.ps1",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/SourcePathLookup.csv",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/o365client_32bit.xml",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/o365client_64bit.xml",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/proofingtools2016_en-us-x64.exe",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/proofingtools2016_en-us-x86.exe",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/configurationbp.xml",
"https://raw.githubusercontent.com/hsuantio/posh/master/Deploy-OfficeClickToRun/configurationpp.xml"
)
$webClient = New-Object System.Net.WebClient

$filesToDownload | % {
    $uri = New-Object System.Uri $_ ;
    $localPath =  "$($pwd.path)\$($uri.Segments[-1])"; 
    Write-Host "Writing $localPath" ;
    $webClient.DownloadFile($uri,$localPath); 
}

#Sets whether to use Volume Licensing for Project and Visio
$UseVolumeLicensing = $false

#Importing all required functions
. $scriptPath\Generate-ODTConfigurationXML.ps1
. $scriptPath\Install-OfficeClickToRun.ps1
. $scriptPath\Remove-PreviousOfficeInstalls.ps1
. $scriptPath\Remove-OfficeClickToRun.ps1
. $scriptPath\SharedFunctions.ps1
. $scriptPath\Edit-OfficeConfigurationFile.ps1

$targetFilePath = "$env:temp\configuration.xml"

if ($productID -eq "BusinessPremium") {
    copy-item "$scriptpath\configurationbp.xml" "$env:temp\configuration.xml"
}
if ($productID -eq "ProfessionalPlus") {
    copy-item "$scriptpath\configurationpp.xml" "$env:temp\configuration.xml"
}

#This example will create an Office Deployment Tool (ODT) configuration file and include all of the Languages currently in use on the computer
#from which the script is run.  It will then remove the Version attribute from the XML to ensure the installation gets the latest version
#when updating an existing install and then it will initiate a install

#This script additionally sets the "AcceptEULA" to "True" and the display "Level" to "None" so the install is silent.

$officeProducts = Get-OfficeVersion -ShowAllInstalledProducts | Select *

$Office2016C2RExists = $officeProducts | Where {$_.ClickToRun -eq $true -and $_.Version -like '16.*' -and $_.DisplayName -NotLike '*Home and Business*'}

if ($sourcePath) {
    $SourcePath = $sourcePath
    if ($sourcePath -eq "none") {
        $SourcePath = $scriptPath
    }
        
}

if((Validate-UpdateSource -UpdateSource $SourcePath -ShowMissingFiles $false) -eq $false) {
    $SourcePath = $NULL    
}

if ($Office2016C2RExists) {
  Write-Host "Office 2016 Click-To-Run is already installed"
} else {
    if (!(Test-Path -Path $targetFilePath)) {
       Generate-ODTConfigurationXml -Languages AllInUseLanguages -TargetFilePath $targetFilePath | Set-ODTAdd -Version $NULL -SourcePath $SourcePath -Channel Deferred | Set-ODTDisplay -Level None -AcceptEULA $true | Out-Null

       $products = Get-ODTProductToAdd -TargetFilePath $targetFilePath -All
       if ($products) { $languages = $products.Languages } else { $languages = @("en-us") }
       $visioAdded = $products | Where { $_.ProductID -like 'VisioProRetail' }
       $projectAdded = $products | Where { $_.ProductID -like 'ProjectProRetail' }
       
       $VisioPro = $officeProducts | Where { $_.DisplayName -like '*Visio Professional*' -and $_.ClickToRun -eq $false }
       $VisioStd = $officeProducts | Where { $_.DisplayName -like '*Visio Standard*' -and $_.ClickToRun -eq $false }
       $ProjectPro = $officeProducts | Where { $_.DisplayName -like '*Project Professional*' -and $_.ClickToRun -eq $false }
       $ProjectStd = $officeProducts | Where { $_.DisplayName -like '*Project Standard*' -and $_.ClickToRun -eq $false }

       if ($UseVolumeLicensing) {
           if ($visioAdded) { Remove-ODTProductToAdd -ProductId 'VisioProRetail' -TargetFilePath $targetFilePath }
           if ($projectAdded) { Remove-ODTProductToAdd -ProductId 'ProjectProRetail' -TargetFilePath $targetFilePath }

           if ($VisioPro.Count -gt 0) { Add-ODTProductToAdd -ProductId VisioProXVolume -TargetFilePath $targetFilePath -LanguageIds $languages | Out-Null }
           if ($VisioStd.Count -gt 0) { Add-ODTProductToAdd -ProductId VisioStdXVolume -TargetFilePath $targetFilePath -LanguageIds $languages | Out-Null }
           if ($ProjectPro.Count -gt 0) { Add-ODTProductToAdd -ProductId ProjectProXVolume -TargetFilePath $targetFilePath -LanguageIds $languages | Out-Null }
           if ($ProjectStd.Count -gt 0) { Add-ODTProductToAdd -ProductId ProjectStdXVolume -TargetFilePath $targetFilePath -LanguageIds $languages | Out-Null }
       }
    }else {
        Set-ODTAdd -SourcePath $SourcePath -TargetFilePath $TargetFilePath | Out-Null
    }

    Remove-OfficeClickToRun 

    Remove-PreviousOfficeInstalls

    Install-OfficeClickToRun -TargetFilePath $targetFilePath
}
Set-ExecutionPolicy Restricted -Scope Process -Confirm:$false
Set-ExecutionPolicy Restricted -Scope CurrentUser -Confirm:$false