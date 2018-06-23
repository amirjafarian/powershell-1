$CollObjects=Get-ADObject -LDAPFilter "(&(legacyExchangeDN=*)(objectClass=user))" -Properties ProxyAddresses,distinguishedName,userPrincipalName

$array = @()
foreach ($object in $CollObjects)
{
    $user = New-Object -TypeName PSCustomObject
    $user | Add-Member -MemberType NoteProperty -Name "Display Name" -Value $object.Name
    $user | Add-Member -MemberType NoteProperty -Name "User Principal Name" -Value $object.UserPrincipalName

    $Addresses = ""
    $DN=""
    $UserPrincipalName=""
    $Addresses = $object.proxyAddresses
    $ProxyArray=""
    $DN=$object.distinguishedName

    foreach ($Address In $Addresses)
    {
        $ProxyArray=($ProxyArray + "," + $Address)
        If ($Address -cmatch "SMTP:")
        {
            $PrimarySMTP = $Address
            $UserPrincipalName=$Address -replace ("SMTP:","")

            $user | Add-Member -MemberType NoteProperty -Name "Primary Email Address" -Value $UserPrincipalName

            #Found the object validating UserPrincipalName
            If ($object.userPrincipalName -notmatch $UserPrincipalName)
            {
                $user | Add-Member -MemberType NoteProperty -Name "Match" -Value $false
            }
            else
            {
                $user | Add-Member -MemberType NoteProperty -Name "Match" -Value $true    
            }
        }
    }

    $array += $user
}

$array | Export-CSV -NoTypeInformation -Path '.\UPNReport.csv'