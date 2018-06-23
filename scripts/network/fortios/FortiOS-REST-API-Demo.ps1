<#
.SYNOPSIS
    FortiOS REST API Demo in Powershell.
.DESCRIPTION
    This script is to demo FortiOS 5.2 and above REST API capabilities.
.PARAMETER IPAddress
    Enter firewall IP address that has HTTPS management enabled.
.PARAMETER Username
    Enter firewall admin username that has at least read-only permission to the object.
.PARAMETER Password
    Enter the firewall admin account's password.
.PARAMETER IsDebug
    Reserved for development purpose.
.EXAMPLE
    .\FortiOS-REST-API-Demo.ps1
.NOTES
    Script name: FortiOS-REST-API-Demo.ps1
    Author:      hsuantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2018-05-05
    Version:     1
#>

[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$true,Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$IPAddress,

    [Parameter(Mandatory=$false, Position=1)]
    [string]$Port = "442",

    [Parameter(Mandatory=$true, Position=2)]
    [string]$Username,
    
    [Parameter(Mandatory=$true, Position=3)]
    [string]$Password,

    [Parameter(Mandatory=$false, Position=4)]
    [bool]$IsDebug = $false
)

# Ignore invalid SSL cert
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
# Ignore invalid SSL cert

# Define variables
$APIPrefix = "https://" + $IPAddress + ":" + $Port + "/api/v2"

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

    Write-Host "IP: $IP, Port: $Port, username: $Username, password: $Password"

    $Credential = @{
        "username" = $Username
        "secretkey" = $Password
    }
    
    $URL = "https://" + $IPAddress + ":" + $Port + "/logincheck"

    Invoke-RestMethod -Uri $URL -Method POST -Body $Credential -SessionVariable FortigateSession | Out-Null
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
        [string]$APIURL
    )

    $APIURL = $APIPrefix + $APIURL
    Write-Host "API URL: $APIURL"
    $Result = (Invoke-RestMethod -Uri $APIURL -Method GET -WebSession $Session -ErrorAction Continue).Results
    $Result
}


Write-Host "Starting script as $ENV:username"

$Session = Connect-Fortigate -IPAddress $IPAddress -Port $Port -Username $Username -Password $Password

$Admins = Get-API -Session $Session -APIURL "/cmdb/system/admin"
Write-Host "List of admins:"
$Admins | Format-Table Name, AccProfile, TrustHost1, TrustHost2 -AutoSize

$Interfaces = Get-API -Session $Session -APIURL "/cmdb/system/interface"
Write-Host "List of interfaces:"
$Interfaces | Format-Table Name, IP, Type, VLANID -AutoSize

$Phase1Interfaces = Get-API -Session $Session -APIURL "/cmdb/vpn.ipsec/phase1-interface"
Write-Host "List of interface-based IPsec tunnels phase 1:"
$Phase1Interfaces | Format-Table Name, Interface, Remote-GW, DHGRP -Auto

$Phase2Interfaces = Get-API -Session $Session -APIURL "/cmdb/vpn.ipsec/phase2-interface"
Write-Host "List of interface-based IPsec tunnels phase 2:"
$Phase2Interfaces | Format-Table Name, Phase1Name, Src-Subnet, Dst-Subnet -AutoSize

$Addresses = Get-API -Session $Session -APIURL "/cmdb/firewall/address"
Write-Host "List of firewall addresses:"
$Addresses | Format-Table Name, Type, Visibility -AutoSize

$AddressGroups = Get-API -Session $Session -APIURL "/cmdb/firewall/addrgrp"
Write-Host "List of address groups:"
$AddressGroups | Format-Table Name, @{n="Member";e={$_.Member.Name}}, Visibility -AutoSize

$VIPs = Get-API -Session $Session -APIURL "/cmdb/firewall/vip"
Write-Host "List of virtual IPs:"
$VIPs | Format-Table Name, Type, ExtIP, @{n="MappedIP";e={$_.MappedIP.Range}} -AutoSize

$TrafficShapers = Get-API -Session $Session -APIURL "/cmdb/firewall.shaper/traffic-shaper"
Write-Host "List of shapers:"
$TrafficShapers | Format-Table Name, Maximum-Bandwidth, Priority, Per-Policy -AutoSize

$Services = Get-API -Session $Session -APIURL "/cmdb/firewall.service/custom"
Write-Host "List of custom services:"
$Services | Format-Table Name, Category, TCP-PortRange, UDP-PortRange -AutoSize

$ServiceGroups = Get-API -Session $Session -APIURL "/cmdb/firewall.service/group"
Write-Host "List of service groups:"
$ServiceGroups | Format-Table Name, @{n="Member";e={$_.Member.Name}}, Comment -AutoSize

$Policies = Get-API -Session $Session -APIURL "/cmdb/firewall/policy"
Write-Host "List of interfaces:"
$Policies | Format-Table PolicyID, @{n="SrcIntf";e={$_.SrcIntf.Name}}, @{n="DstIntf";e={$_.DstIntf.Name}}, @{n="SrcAddr";e={$_.SrcAddr.Name}}, @{n="DstAddr";e={$_.DstAddr.Name}} -AutoSize

$StaticRoutes = Get-API -Session $Session -APIURL "/cmdb/router/static"
Write-Host "List of static routes:"
$StaticRoutes | Format-Table Dst, Distance, Priority, Device -AutoSize

$PolicyRoutes = Get-API -Session $Session -APIURL "/cmdb/router/policy"
Write-Host "List of route policies:"
$PolicyRoutes | Format-Table Seq-Num, @{n="Src";e={$_.Src.Subnet}}, @{n="Dst";e={$_.Dst.Subnet}}, Output-Device -AutoSize

$LocalUsers = Get-API -Session $Session -APIURL "/cmdb/user/local"
Write-Host "List of local users:"
$LocalUsers | Format-Table Name, Type, Two-Factor, Status -AutoSize

$LocalGroups = Get-API -Session $Session -APIURL "/cmdb/user/group"
Write-Host "List of local groups:"
$LocalGroups | Format-Table Name, Member -AutoSize

$VDOMs = Get-API -Session $Session -APIURL "/cmdb/system/vdom"
Write-Host "List of VDOMs:"
$VDOMs | Format-Table Name -AutoSize

Disconnect-Fortigate -IPAddress $IPAddress -Port $Port -Session $Session