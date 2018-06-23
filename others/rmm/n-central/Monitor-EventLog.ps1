# MSP554271
<#
$EventID1 = 4625
$EventID2 = 4771
$Interval = 60
$EventID1CountThreshold = 10
$EventID2CountThreshold = 10
$EventID1LogName = "Security"
$EventID2LogName = "Security"
#>

<#
Write-Host "EventID1: $EventID1"
Write-Host "EventID2: $EventID2"
Write-Host "EventID1LogName: $EventID1LogName"
Write-Host "EventID2LogName: $EventID2LogName"
Write-Host "EventID1CountThreshold: $EventID1CountThreshold"
Write-Host "EventID2CountThreshold: $EventID2CountThreshold"
Write-Host "Interval: $Interval"
#>

$EventID1Count = (Get-EventLog -LogName $EventID1LogName -InstanceId $EventID1 -After (Get-Date).AddMinutes(-$Interval) -ErrorAction SilentlyContinue | Measure-Object).Count
$EventID2Count = (Get-EventLog -LogName $EventID2LogName -InstanceId $EventID2 -After (Get-Date).AddMinutes(-$Interval) -ErrorAction SilentlyContinue | Measure-Object).Count

if ($EventID1Count)
{
    if ($EventID1Count -ge $EventID1CountThreshold)
    {
        $EventID1CountThresholdReached = 1
    }
    else
    {
        $EventID1CountThresholdReached = 0 
    }
}
else
{
    $EventID1CountThresholdReached = 0 
}

if ($EventID2Count)
{
    if ($EventID2Count -ge $EventID2CountThreshold)
    {
        $EventID2ThresholdReached = 1
    }
    else
    {
        $EventID2ThresholdReached = 0
    }
}
else
{
    $EventID2ThresholdReached = 0
}

Write-Host "EventID1Count: $EventID1Count"
Write-Host "EventID2Count: $EventID2Count"