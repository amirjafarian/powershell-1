$URI = 'https://noc.avante-group.com/dms/services/ServerEI?wsdl'

$Username = 'user@domain.com'
$Password = 'yourpassword'
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$NameSpace = "NC" + ([guid]::NewGuid()).ToString().Substring(25)

$Credential = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)

$Endpoint = New-WebServiceProxy -Uri $URI -Credential $Credential -Namespace $NameSpace

$KeyPairs = @()

$KeyPair = New-Object "$NameSpace.T_KeyPair"
$KeyPair.Key = "CustomerID"
$KeyPair.Value = "116"
$KeyPairs += $KeyPair

$Result = $Endpoint.CustomerList($Username, $Password, $KeyPairs)
Write-Host "Total result: $($Result.Count)"

$array = @()

foreach ($Device in $Result)
{
    $props = @{}
    foreach ($item in $Device.info)
    {
        $props.add($item.key.split('.')[1],$item.Value)
    }
    $obj = New-Object -TypeName PSCustomObject -Property $props
    $array += $obj
}

$array
$array | Export-CSV -NoTypeInformation -Path 'C:\Temp\CustomerList.csv'