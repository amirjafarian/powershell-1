<#
.SYNOPSIS
    Retrieves email attachments using EWS API and save the file into a folder.
.DESCRIPTION
    Retrieves email attachments using EWS API and save the file into a folder.
.PARAMETER EWSPath
    Optional. Full path to EWS API. Default is "C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll".
.PARAMETER ScriptLogPath
    Optional. Full path to log file. Default is "C:\Logs\Get-EmailAttachment.log".
.PARAMETER TrustAllCerts
    Optional. Bypass SSL cert validation check. Default is to validate SSL certificate.
.PARAMETER MsolUsername
    Required. Specify Azure AD user principal name. Ensure UPN and email address match.
.PARAMETER MsolSecurePasswordFile
    Required. Specify Azure AD secure password file. To create the secure password file:
    Read-Host -Prompt "Enter Azure AD user password" -AsSecureString | ConvertFrom-SecureString | Set-Content -Path "C:\Temp\pwd.txt"
.PARAMETER DownloadDirectory
    Required. Full path to attachment destination directory.
.PARAMETER EWSEndpoint
    Optional. Specify custom EWS endpoint in case autodiscover failed. Default is "https://outlook.office365.com/ews/Exchange.asmx"
.PARAMETER ArchiveFolder
    Optional. Specify a folder under Inbox to move processed emails to. Default is PROCESSED under Inbox. Create this folder if it doesn't exist.
.PARAMETER BypassAutodiscover
    Optional. Reserved for development purpose. Specify this to bypass autodiscover.
.EXAMPLE
    .\Get-EmailAttachment.ps1 -MsolUsername scanner@contoso.com -MsolSecurePasswordFile "C:\Temp\scanner_secure.txt" -DownloadDirectory "C:\Downloads" -BypassAutodiscover
.NOTES
    Script name     : Get-EmailAttachment.ps1
    Author          : hsuantio
    Contact         : hsuantio <at> gmail.com
    Date created    : 2018-08-02
    Version         : 1
    Disclaimer      : This script is provided as-is without guarantee. Please read the script to understand what it does prior to using it.
#>

[CmdletBinding()]
Param
(
    [Parameter(Position = 0, Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [ValidateScript({Test-Path -Path $_})]
    [string]$EWSPath = 'C:\Program Files\Microsoft\Exchange\Web Services\2.2\Microsoft.Exchange.WebServices.dll',

    [Parameter(Position = 1, Mandatory = $false)]
    [ValidateNotNullorEmpty()]
    [string]$ScriptLogPath = 'C:\Logs\Get-EmailAttachment.log',

    [Parameter(Position = 2, Mandatory = $false)]
    [switch]$TrustAllCerts = $false,

    [Parameter(Position = 3, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$MsolUsername,

    [Parameter(Position = 4, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_})]
    [string]$MsolSecurePasswordFile,

    [Parameter(Position = 5, Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({Test-Path $_})]
    [string]$DownloadDirectory,

    [Parameter(Position = 6, Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    $EWSEndpoint = 'https://outlook.office365.com/ews/Exchange.asmx',

    [Parameter(Position = 7, Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    $ArchiveFolder = "PROCESSED",

    [Parameter(Position = 8, Mandatory = $false)]
    [switch]$BypassAutodiscover = $false
)

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
        [string]$Path="C:\Logs\Get-EmailAttachment.log",

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
        [int64]$FileSize = 1024kb,

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
                    catch
                    {
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

Reset-Log -FileName $ScriptLogPath -FileSize 5MB -LogCount 5
Write-Log "Starting script as $env:USERNAME..."
Write-Log "Received run parameters: EWSPath: $EWSPath, ScriptLogPath = $ScriptLogPath, TrustAllCerts = $TrustAllCerts, MsolUsername = $MsolUsername, MsolSecurePasswordFile = $MsolSecurePasswordFile, DownloadDirectory = $DownloadDirectory, EWSEndpoint = $EWSEndpoint, ArchiveFolder = $ArchiveFolder, BypassAutodiscover = $BypassAutodiscover"

if ($TrustAllCerts)
{
    Write-Log "Accepting all certs presented by EWS endpoint."
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $False
    $Params.GenerateInMemory = $True
    $Params.IncludeDebugInformation = $False
    $Params.ReferencedAssemblies.Add("System.DLL") | Out-Null

    $TASource=@'
    namespace Local.ToolkitExtensions.Net.CertificatePolicy
    {
        public class TrustAll : System.Net.ICertificatePolicy
        {
            public TrustAll()
            {
            }
        
            public bool CheckValidationResult(System.Net.ServicePoint sp,
            System.Security.Cryptography.X509Certificates.X509Certificate cert,
            System.Net.WebRequest req, int problem)
            {
                return true;
            }
        }
    }
'@
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    $TrustAll=$TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy=$TrustAll
}

Write-Log "Loading EWS API from $EWSPath..."
try
{
    Add-Type -Path $EWSPath -ErrorAction Stop
}
catch
{
    Get-Exception -ExceptionObject $_ -ForceExit $true -Message "Unable to load EWS API from $EWSPath."
}

$ExchangeVersion = [Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2016
$service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService($ExchangeVersion)
$MsolSecurePwdText = Get-Content -Path $MsolSecurePasswordFile
$MsolSecurePwd = $MsolSecurePwdText | ConvertTo-SecureString
$creds = New-Object System.Net.NetworkCredential($MsolUsername, $MsolSecurePwd)
$service.Credentials = $creds

if ($BypassAutodiscover -ne $true)
{
    Write-Log "Searching EWS endpoint using autodiscover for $MsolUsername..."
    $error.clear()
    try
    {
        $service.AutodiscoverUrl($MsolUsername,{$true})
    }
    catch
    {
        Get-Exception -ExceptionObject $_ -Message "Unable to find EWS endpoint using autodiscover."
    }
}

if ($error -or $BypassAutodiscover)
{
    $service.URL = [system.URI]$EWSEndpoint
    Write-Log "Using hardcoded $($service.URL) EWS endpoint due to failed autodiscover or autodiscover bypass is enabled."
}

if ($service.URL -ne $null)
{
    Write-Log "EWS endpoint: $($service.URL)"

    $EmailFilterWithAttachment = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::HasAttachments, $true)
    $FolderID = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox, $MsolUsername)
    $Inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($service,$FolderID)

    $ivItemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView(100)
    $findItemsResults = $Inbox.FindItems($EmailFilterWithAttachment,$ivItemView)

    $ItemCount = ($findItemsResults | Measure-Object).Count
    Write-Log "Found $ItemCount mail items to be processed."

    $ItemIndex = 1
    foreach ($miMailItems in $findItemsResults.Items)
    {
        Write-Log "Processing $ItemIndex out of $ItemCount..."
        $miMailItems.Load()
        $from = $miMailItems.From

        Write-Log "Processing mail item from $($miMailItems.From) on $($miMailItems.DateTimeReceived) with subject $($miMailItems.Subject). Full mail item dump: "
        $miMailItems | Out-File -FilePath $ScriptLogPath -Append

        if ($from -like "*scanner*")
        {
            $subjectd = 'SCAN'
        }
        elseif ($from -like "*cloud.pbx*")
        {
            $subjectd = "FAX"
        }
        else
        {
            $subjectd = "OTHER"
        }
        
        $AttachmentIndex = 1
        $AttachmentCount = ($miMailItems.Attachments).Count
        foreach($attach in $miMailItems.Attachments)
        {
            $AttachmentWriteStatus = $false
            Write-Log "Processing attachment $AttachmentIndex of $AttachmentCount..."
            $attach.Load()
            $DestinationPath = $DownloadDirectory + "\" + $subjectd + "-" + $attach.Name.ToString()
            Write-Log "Attachment name $($attach.Name), size $($attach.Content.Length) to $DestinationPath."
            $fiFile = New-Object System.IO.FileStream($DestinationPath, [System.IO.FileMode]::Create)
            $error.clear()

            try
            {
                $fiFile.Write($attach.Content, 0, $attach.Content.Length)
                Write-Log "File path: $($fiFile.Name)."
                $fiFile.Close()
            }
            catch
            {
                Get-Exception -ExceptionObject $_ -Message "Failed to save $DestinationPath. Further investigation needed"
                $AttachmentWriteStatus = $false
            }
            
            if (-Not $error)
            {
                Write-Log "Successfully downloaded attachment $AttachmentIndex : $DestinationPath"
                $AttachmentWriteStatus = $true
            }
            $AttachmentIndex++
        }
        Write-Log " "
        $ItemIndex++

        if ($AttachmentWriteStatus -eq $true)
        {
            $fvFolderView =  New-Object Microsoft.Exchange.WebServices.Data.FolderView(100)
            $fvFolderView.Traversal = [Microsoft.Exchange.WebServices.Data.FolderTraversal]::Shallow;
            $SfSearchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName,$ArchiveFolder)
            $findFolderResults = $Inbox.FindFolders($SfSearchFilter,$fvFolderView)
            
            $error.clear()
            try
            {
                $miMailItems.Move($findFolderResults.Folders[0].Id)
            }
            catch
            {
                Get-Exception -ExceptionObject $_ -Message "Unable to move mail item to archive folder."
            }

            if (-Not $error)
            {
                Write-Log "Sucessfully moved $($miMailItems.Id.UniqueId) to $ArchiveFolder folder."
            }
        }
    }
}

Write-Log "Script ends."