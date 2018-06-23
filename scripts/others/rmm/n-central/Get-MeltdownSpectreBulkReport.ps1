<#
.SYNOPSIS
    My Powershell standard template that imports common functions.
.DESCRIPTION
    This template imports common functions from a module file in Github.
.PARAMETER
    Add script parameter documentation here.
.EXAMPLE
    PSTemplate.ps1 -Verbose
.NOTES
    Script name: Get-MeltdownSpectreBulkReport.ps1
    Author:      Hendrik Suantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2018-01-11
    Version:     1
#>

<#
[CmdletBinding()]
Param 
(
    # Nothing yet.
)
#>

# Import common functions
# Declare helper functions
function CFRemove-File
{
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$Path #Parameter mapping from Import-Module's Path property.
    )
    
    Begin {}
    Process
    {
        try
        {
            Write-Verbose "Removing $Path"
            Remove-Item -Path $Path -ErrorAction Stop
        }
        catch 
        {
            Write-Warning "Unable to remove $Path. Error: $_.Exception.ToString()"
        }
    }
    End {}
}

function CFDownload-File
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
            Write-Verbose "Downloading $_ to $LocalFilePath"
            $WebClient.DownloadFile($Uri,$LocalFilePath)
            if ((Test-Path -Path $LocalFilePath -ErrorAction Stop))
            {
                $LocalFile = Get-Item -Path $LocalFilePath -ErrorAction Stop
                $DownloadedFiles += $LocalFile
            }
        }
        catch [Net.WebException]
        {
            Write-Verbose "Unable to download required module file. Error: $_.Exception.ToString(). Terminating program."
            Exit
        }
    }
    End 
    {
        return $DownloadedFiles
    }
}

# Start processing common functions
$FilesToDownload =
(
    'https://raw.githubusercontent.com/hsuantio/posh/master/Misc/MeltdownSpectreReport.ps1'
)

$FilesToRemove = $FilesToDownload | CFDownload-File
# Finished import common functions
# Main code goes here
Import-Module ActiveDirectory

$ComputerName = Get-ADComputer -Filter * -Properties * | 
    Where-Object {$_.OperatingSystem -like "Windows*" -and [DateTime]::FromFileTime($_.LastLogonTimeStamp) -ge (Get-Date).AddDays(-30)} | 
    Select-Object -Expand Name

New-Item -Path 'C:\' -Name 'Temp' -ItemType "Directory" -ErrorAction SilentlyContinue | Out-Null

.\MeltdownSpectreReport.ps1 -ComputerName $ComputerName -ErrorAction SilentlyContinue | Export-CSV -NoTypeInformation -Path 'C:\Temp\SpectreMeltdownReport.csv'
CFRemove-File -Path .\MeltdownSpectreReport.ps1
# End of code. Clean up downloaded files
# $FilesToRemove | Remove-Module
# $FilesToRemove | CFRemove-File
