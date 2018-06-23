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
    Script name: PSTemplate.ps1
    Author:      Hendrik Suantio
    Contact:     hsuantio <at> gmail.com
    DateCreated: 2017-10-29
    Version:     1
#>

[CmdletBinding()]
Param 
(
    # Nothing yet.
)

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
    'https://raw.githubusercontent.com/hsuantio/posh/master/Modules/CommonFunctions.psm1',
    'https://raw.githubusercontent.com/hsuantio/posh/master/Modules/DummyModules.psm1'
)

$FilesToRemove = $FilesToDownload | CFDownload-File | Import-Module -Force -ErrorAction Stop -PassThru
# Finished import common functions
# Main code goes here
Write-Log "This is a test message"
try
{
    Get-Item -Path 'C:\Temp\file.txt' -ErrorAction Stop
}
catch
{
    Get-Exception -ExceptionObject $_ -Message "Unable to find this file"
}

# End of code. Clean up downloaded files
$FilesToRemove | Remove-Module
$FilesToRemove | CFRemove-File
# SIG # Begin signature block
# MIIFxwYJKoZIhvcNAQcCoIIFuDCCBbQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU27RYMaVjUAFP3G6wTpzRakzI
# Z8ugggNQMIIDTDCCAjigAwIBAgIQ7sFnkqgpNaFDhtq3zaZnujAJBgUrDgMCHQUA
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
# AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUAwlPDYQYXWlnACk0
# /QWFtKbisQ0wDQYJKoZIhvcNAQEBBQAEggEAoDTRrcz21fe6iaRV0Ypm3xhpp2EJ
# 167An5E3PjQK6oAPt5anGarB5b3Au9UXgTSzS3+p9WaVfbHt/Aqyt8ZUJESca5d/
# uPEPnBJuDlcK7rmzoSPvLaKbXT7Ti8c5iERJQB84chj2psCbclgAxv/yuvR/nWJC
# cYuaqLUvxvCUgNGcEX1dTIvqGxEjqefsC4F/0Lxt3qFaGXWrBmAVGP2s01Mt6Nrv
# i+JzfeHsvksWUbfhy0bcQYB1QAKGeorT/AetA7E5hoZyWz+8Mh3Al3GCuoxzgWpV
# i7e2FdVq0lUoV0IMgkyBA/nvLJaeUrYisECbubhfrwfSUj7NAvXt63uXDw==
# SIG # End signature block
