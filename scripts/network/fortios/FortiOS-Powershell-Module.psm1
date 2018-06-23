<#
.SYNOPSIS
    Powershell module based on FortiOS REST API.
.DESCRIPTION
    This script provides cmdlets to manage FortiOS using REST API.
.EXAMPLE
    .\FortiOS-Powershell-Module.psm1
.NOTES
    Script name: FortiOS-Powershell-Module.psm1
    Author:      hsuantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2018-05-05
    Version:     1
#>
function Connect-Fortigate
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [Int32]$Port = 443,
        [Parameter(Mandatory=$true, Position=2)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        [Parameter(Mandatory=$true, Position=3)]
        [ValidateNotNullOrEmpty()]
        [string]$Password
    )

    $Credential = @{
        "username" = $Username
        "secretkey" = $Password
    }
    
    $URL = "https://" + $IPAddress + ":" + $Port + "/logincheck"
    Invoke-RestMethod -Uri $URL -Method POST -Body $Credential -SessionVariable FortigateSession -ErrorAction Stop | Out-Null
    $FortigateSession
}

function Disconnect-Fortigate
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [Int32]$Port = 443,
        [Parameter(Mandatory=$true, Position=2)]
        $Session
    )

    $URL = "https://" + $IPAddress + ":" + $Port + "/logout"
    Invoke-RestMethod -Uri $URL -WebSession $Session | Out-Null
}

function Get-API
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        $Session,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,
        [Parameter(Mandatory=$true, Position=2)]
        [ValidateNotNullOrEmpty()]
        [Int32]$Port = 443,
        [Parameter(Mandatory=$true, Position=3)]
        [ValidateNotNullOrEmpty()]
        [string]$APIURL
    )
    
    $ExceptionDetected
    $APIPrefix = "https://" + $IPAddress + ":" + $Port + "/api/v2"
    $APIURL = $APIPrefix + $APIURL
    Write-Host "API URL: $APIURL"
    
    try
    {
        $Result = (Invoke-RestMethod -Uri $APIURL -Method GET -WebSession $Session -ContentType "application/json" -ErrorAction Stop)
    }
    catch
    {
        $ExceptionDetected = $true
        [Int32]$ExceptionStatusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "StatusCode:" $ExceptionStatusCode
        $ExceptionStatusDescription = $_.Exception.Response.StatusDescription
        Write-Host "StatusDescription:" $ExceptionStatusDescription
    }

    if ($ExceptionDetected -eq $null)
    {
        return $Result
    }
    elseif ($ExceptionDetected -eq $true)
    {
        Write-Host "ExceptionDetected"
    }    
}