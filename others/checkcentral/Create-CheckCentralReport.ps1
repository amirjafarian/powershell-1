<#
.SYNOPSIS
    Create CheckCentral failure report.
.DESCRIPTION
    Create CheckCentral failure report.
.PARAMETER APIToken
    Specify CheckCentral API token. This can be found on CheckCentral organization portal. 
.PARAMETER APIEndpoint
    Specify API FQDN if it's not the default one: api.checkcentral.cc.
.PARAMETER RecipientAddress
    Specify recipient email address.
.PARAMETER DefaultSenderAddress
    Specify sender email address if no email address mapping is found from the mapping file specified in MappingFile parameter.
.PARAMETER SMTPServer
    Specify unauthenticated relay SMTP server address.
.PARAMETER MappingFile
    Specify full path to a CSV file that maps the CheckCentral group name to the sender email address. Example:
    "Group","EmailDomain"
    "Contoso Ltd","contoso.com"
.PARAMETER SendEmail
    Specify this switch paramater to send out emails.
.EXAMPLE
    .\Create-CheckCentralReport.ps1`
        -APIToken "apitoken"`
        -APIEndpoint "api.checkcentral.cc"`
        -RecipientAddress "admin@contoso.com"`
        -DefaultSenderAddress "backup@contoso.com"`
        -SMTPServer "smtp.contoso.com"`
        -MappingFile "C:\Temp\mapping.csv"`
        -SendEmail
.NOTES
    Script name: Create-CheckCentralReport.ps1
    Author:      hsuantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2018-05-07
    Version:     2
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true,Position=0)] #
    [ValidateNotNullOrEmpty()]
    [string]$APIToken,

    [Parameter(Mandatory=$false, Position=1)]
    [string]$APIEndPoint = "api.checkcentral.cc",

    [Parameter(Mandatory=$true, Position=2)] #
    [ValidateNotNullOrEmpty()]
    [string]$RecipientAddress,

    [Parameter(Mandatory=$true, Position=3)] #
    [ValidateNotNullOrEmpty()]
    [string]$DefaultSenderAddress,

    [Parameter(Mandatory=$true, Position=4)] #
    [ValidateNotNullOrEmpty()]
    [string]$SMTPServer,

    [Parameter(Mandatory=$true, Position=5)] #
    [ValidateNotNullOrEmpty()]
    [ValidateScript ( {Test-Path $_} )]
    [string]$MappingFile,

    [Parameter(Mandatory=$false, Position=6)]
    [switch]$SendEmail = $false
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
        [string]$Path="C:\Logs\$((Get-ChildItem $MyInvocation.PSCommandPath | Select-Object -Expand Name).Trim('.ps1')).log",
        
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
        [int64]$FileSize = 10240kb,

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
                        Get-Exception -ExceptionObject $_ -Message "Unable to move $($OperatingFile.FullName) to $NewFileName."
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
                        Get-Exception -ExceptionObject $_ -Message "Unable to delete $($OperatingFile.FullName)."
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
                        Get-Exception -ExceptionObject $_ -Message "Unable to move $FileFullName) to $NewFileName."
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
                        Get-Exception -ExceptionObject $_ -Message "Unable to move $($OperatingFile.FileFullName) to $NewFileName."
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

$DefaultRequestBody = @{
    "apiToken" = $APIToken
}

Write-Log "Starting script as $env:USERNAME"
$ScriptLogPath = 'C:\Logs\Create-CheckCentralReport.log'
Reset-Log -FileName $ScriptLogPath -FileSize 10240KB -LogCount 5
Write-Log "Accepted inputs: API token: $APIToken, API endpoint: $APIEndpoint, recipient address: $RecipientAddress, default sender address: $DefaultSenderAddress, SMTP server $SMTPServer, CSV mapping file: $MappingFile, send email: $SendEmail"
$CurrentDate = Get-Date -Format "dd-MM-yyyy"

Write-Log "Getting CheckCentral organization overview..."
try
{
    $OrgOverview = Invoke-RestMethod -Uri "https://$APIEndPoint/getOverview" -Method GET -Body $DefaultRequestBody -ErrorAction Stop
}
catch
{
    Write-Log "StatusCode: $($_.Exception.Response.StatusCode.value__)"
    Write-Log "StatusDescription: $($_.Exception.Response.StatusDescription)"
    Write-Log "Connect to GetOverview API Endpoint failed. Terminating program."
    Exit
}

if ($OrgOverview.Error.Id -eq $null)
{
    $OrgName = $OrgOverview.Organization.Name
    Write-Log "Getting all CheckCentral checks..."
    try
    {
        $AllChecks = Invoke-RestMethod -Uri "https://$APIEndPoint/getChecks" -Method GET -Body $DefaultRequestBody -ErrorAction Stop
    }
    catch
    {
        Write-Log "StatusCode: $($_.Exception.Response.StatusCode.value__)"
        Write-Log "StatusDescription: $($_.Exception.Response.StatusDescription)"
        Write-Log "Connect to GetChecks API Endpoint failed. Terminating program."
        Exit
    }

    if ($AllChecks.Error.Id -ne $null)
    {
        Write-Log "Connect to GetChecks API Endpoint failed with error $($AllChecks.Error.Id): $($AllChecks.Error.Message). Terminating program."
    }
    else
    {
        Write-Log "Getting all check groups that have failed checks..."
        $CheckGroups = ($AllChecks.checks | Where-Object {$_.status -match "Failure"} | Select-Object -Unique Group).Group
        Write-Log "Found $($CheckGroups.count) groups with failed checks:"
        $CheckGroupsString = $CheckGroups -Join ', '
        Write-Log "$CheckgroupsString"
        Write-Log "Importing CSV mapping file from $MappingFile..."
        try
        {
            [bool]$CSVError = $false
            $EmailMappings = Import-CSV -Path $MappingFile -ErrorAction Stop
        }
        catch
        {
            Get-Exception -ExceptionObject $_ -Message "Unable to import $MappingFile CSV file."
            [bool]$CSVError = $true
        }
        
        foreach ($CheckGroup in $CheckGroups)
        {
            Write-Log "Processing $Checkgroup checks..."
            $DestinationHTMLFile = "CheckCentral Report - $CheckGroup - $CurrentDate.html"
            $HTMLStart = "<!DOCTYPE html>
            <html>
            <head>
            <title>CheckCentral Failure Report - $CheckGroup</title>
            <style>
            table {border: solid 1px black; border-collapse: collapse; }
            th, td { border: solid 1px black; padding: 3px; }
            th { background-color: #dde9ff; }

            .Success { color: green; }
            .Warning { color: orange; }
            .Failure { color: red; }

            * {font-family: Sans-serif;}
            </style>
            </head>"

            # Build the table header
            $tableColGroup = "<colgroup><col/><col/><col/><col/><col/><col/><col/></colgroup>"
            $tableHeaderTitles = "<tr><th>ID</th><th>Name</th><th>Description</th><th>Email Address</th><th>Group</th><th>Status</th><th>Updated</th></tr>"
            $tableHeader = [System.Text.StringBuilder]::new()
            [void]$tableHeader.Append("<table>")
            [void]$tableHeader.Append($tableColGroup)
            [void]$tableHeader.Append($tableHeaderTitles)

            # Generate the HTML body with the table and check data
            $HTMLBody = [System.Text.StringBuilder]::new()

            [void]$HTMLBody.Append("<body>
            <h2>$OrgName`: $CheckGroup</h2>")

            [void]$HTMLBody.Append($tableHeader)

            $AllChecksInGroup = $AllChecks.checks | Where-Object {$_.Group -match $CheckGroup}
            $AllFailedChecksInGroup = $AllChecksInGroup | Where-Object {$_.Status -match "Failure"}
            Write-Log "Found $(($AllFailedChecksInGroup | Measure-Object).Count) failed checks out of $(($AllChecksInGroup | Measure-Object).Count) checks."
            foreach ($check in $AllChecksInGroup)
            {
                Write-Log "Processing group: $CheckGroup, check: $($check.Name), status: $($check.Status), updated: $($check.Updated)..."
                $checkID = $check.Id
                $checkName = $check.Name
                $checkDescription = $check.Description
                $checkEmail = $check.Email
                $checkGroup = $check.Group
                $checkStatus = $check.Status
                $checkUpdated = $check.Updated

                [void]$HTMLBody.Append("<tr><td>$checkId</td><td>$checkName</td><td>$checkDescription</td><td>$checkEmail</td><td>$checkGroup</td><td class=`"$checkStatus`">$checkStatus</td><td>$checkUpdated</td></tr>`n")
            }

            [void]$HTMLBody.Append("</table>
            </body>")

            # Close out the HTML
            $HTMLEnd = "</html>"

            # Output the data to the HTML file
            $HTMLFinal = [System.Text.StringBuilder]::new()

            [void]$HTMLFinal.Append($HTMLStart)
            [void]$HTMLFinal.Append($HTMLBody)
            [void]$HTMLFinal.Append($HTMLEnd)

            Write-Log "Exporting $DestinationHTMLFile..."
            try
            {
                [bool]$HTMLFileError = $false
                $HTMLFinal.ToString() | Out-File $DestinationHTMLFile -ErrorAction Stop
            }
            catch
            {
                Get-Exception -ExceptionObject $_ -Message "Unable to export $DestinationHTMLFile."
                [bool]$HTMLFileError = $true
            }

            if ($CSVError -eq $false)
            {
                Write-Log "Finding email domain match for $CheckGroup..."
                $SenderDomain = ($EmailMappings | Where-Object {$_.Group -Match $CheckGroup}).EmailDomain
                if ($SenderDomain)
                {
                    Write-Log "Found $SenderDomain email domain match for $CheckGroup."
                    $SenderAddress = "backup@" + $SenderDomain
                }
            }
            else
            {
                $SenderAddress = $DefaultSenderAddress   
            }
            Write-Log "Sender email address: $SenderAddress"
            
            if ($SendEmail)
            {
                Write-Log "Sending email from $SenderAddress to $RecipientAddress using $SMTPServer"
                try
                {
                    Send-MailMessage -From $SenderAddress -To $RecipientAddress -Subject "CheckCentral Report - $CheckGroup - $CurrentDate" -BodyAsHtml $HTMLFinal -SmtpServer $SMTPServer -ErrorAction Stop
                }
                catch
                {
                    Get-Exception -ExceptionObject $_ -Message "Failed sending email from $SenderAddress to $RecipientAddress"
                }

                $error.clear()
                if (-Not $error)
                {
                    Write-Log "Successfully sent email from $SenderAddress to $RecipientAddress"
                }
            }

            if ($HTMLFileError -eq $false)
            {
                Write-Log "Removing $DestinationHTMLFile..."
                try
                {
                    Remove-Item $DestinationHTMLFile -ErrorAction Stop
                }
                catch
                {
                    Get-Exception -ExceptionObject $_ -Message "Unable to remove $DestinationHTMLFile."    
                }

                $error.clear()
                if (-Not $error)
                {
                    Write-Log "Successfully removed $DestinationHTMLFile."
                }
            }
        }
    }
    Write-Log "Script ends."
}
