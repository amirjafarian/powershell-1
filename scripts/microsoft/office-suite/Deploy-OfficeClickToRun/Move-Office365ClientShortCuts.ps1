function Move-Office365ClientShortCuts {
    [CmdletBinding()]
    Param(
       [Parameter(ValueFromPipelineByPropertyName=$true, Position=0)]
       [string]$FolderName = "Microsoft Office 2016",
       
       [Parameter(ValueFromPipelineByPropertyName=$true, Position=1)]
       [bool]$MoveToolsFolder = $false                                                                        
    )

    $sh = New-Object -COM WScript.Shell
    $programsPath = $sh.SpecialFolders.Item("AllUsersStartMenu")

    #Create new subfolder                                                                       
    if(!(Test-Path -Path "$programsPath\Programs\$FolderName")){
        New-Item -ItemType directory -Path "$programsPath\Programs\$FolderName"  -ErrorAction Stop | Out-Null
    }    

    if ($MoveToolsFolder) {
        $toolsPath = "$programsPath\Programs\Microsoft Office 2016 Tools"
        if(Test-Path -Path $toolsPath){
            Move-Item -Path $toolsPath -Destination "$programsPath\Programs\$FolderName\Microsoft Office 2016 Tools"  -ErrorAction Stop | Out-Null
        }    
    }
    
    $items = Get-ChildItem -Path "$programsPath\Programs"

    $OfficeInstallPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun" -Name "InstallPath").InstallPath
    
    $itemsToMove = $false
    foreach ($item in $items) {
       if ($item.Name -like "*.lnk") {

           $itemName = $item.Name
           
           $targetPath = $sh.CreateShortcut($item.fullname).TargetPath

           if ($targetPath -like "$OfficeInstallPath\root\*") {
              $itemsToMove = $true
              $movePath = "$programsPath\Programs\$FolderName\$itemName"

              Move-Item -Path $item.FullName -Destination $movePath -Force -ErrorAction Stop

              Write-Host "$itemName Moved"
           }
       }
    }    

    if (!($itemsToMove)) {
       Write-Host "There are no Office 365 ProPlus client ShortCuts to Move"
    }
}


