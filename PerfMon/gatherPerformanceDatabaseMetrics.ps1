# Good place to copy ideas from:
#	http://sqlblog.com/blogs/allen_white/archive/2012/03/02/setup-perfmon-with-powershell-and-logman.aspx

#Run commands on remote system:
# * Create a WinRM listener on HTTP://* to accept WS-Man requests to any IP on this machine.
# * Enable the WinRM firewall exception.
# * Configure LocalAccountTokenFilterPolicy to grant administrative rights remotely to local users.
#
# TODO ru: Figure out how to do this in a programmatic way
# Run this on the remote system: 'winrm quickconfig'

# Get appropriate credentials (will prompt for password)
$computerName = "<enter IP Address here>"
$dataCollectorSet = "SqlServerAndSystemPerformance"
$counters = ("\Memory\Available MBytes",
             "\Memory\Pages/sec",
             "\Paging File\% Usage",
             "\PhysicalDisk(0 C:)\Avg. Disk sec/Read",
             "\PhysicalDisk(0 C:)\Avg. Disk sec/Write",
             "\PhysicalDisk(0 C:)\Disk Reads/sec",
             "\PhysicalDisk(0 C:)\Disk Writes/sec",
             "\Process(sqlservr)\% Privileged Time",
             "\Process(sqlservr)\% Processor Time",
             "\Processor(0)\% Privileged Time",
             "\Processor(1)\% Privileged Time",
             "\Processor(2)\% Privileged Time",
             "\Processor(3)\% Privileged Time",
             "\Processor(4)\% Privileged Time",
             "\Processor(5)\% Privileged Time",
             "\Processor(6)\% Privileged Time",
             "\Processor(7)\% Privileged Time",
             "\Processor(0)\% Processor Time",
             "\Processor(1)\% Processor Time",
             "\Processor(2)\% Processor Time",
             "\Processor(3)\% Processor Time",
             "\Processor(4)\% Processor Time",
             "\Processor(5)\% Processor Time",
             "\Processor(6)\% Processor Time",
             "\Processor(7)\% Processor Time",
             "\SQLServer:Access Methods\Forwarded Records/sec",
             "\SQLServer:Access Methods\Full Scans/sec",
             "\SQLServer:Access Methods\Index Searches/sec",
             "\SQLServer:Buffer Manager\Free list stalls/sec",
             "\SQLServer:Buffer Manager\Lazy writes/sec",
             "\SQLServer:Buffer Manager\Page life expectancy",
             "\SQLServer:Buffer Manager\Page reads/sec",
             "\SQLServer:Buffer Manager\Page writes/sec",
             "\SQLServer:General Statistics\User Connections",
             "\SQLServer:Latches\Latch Waits/sec",
             "\SQLServer:Locks(_Total)\Lock Waits/sec",
             "\SQLServer:Locks(_Total)\Number of Deadlocks/sec",
             "\SQLServer:Memory Manager\Target Server Memory (KB)",
             "\SQLServer:Memory Manager\Total Server Memory (KB)",
             "\SQLServer:SQL Statistics\Batch Requests/sec",
             "\SQLServer:SQL Statistics\SQL Compilations/sec",
             "\SQLServer:SQL Statistics\SQL Re-Compilations/sec",
             "\System\Processor Queue Length")
# "Secure" way that does not require password in clear text...
#Read-Host "emperfdb-w2k8\administrator" -AsSecureString | ConvertFrom-SecureString | Out-File C:\Temp\PerfMon\administratorPassword.txt
#$Password = Get-Content C:\Temp\PerfMon\administratorPassword.txt | convertto-securestring 
$Username = "emperfdb-w2k8\administrator" 
$Password = "<enter password here>" | ConvertTo-SecureString -asPlainText -Force
$Credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $Username, $Password 

Write-Output "Creating Data Collector Set"
$counterExists = Invoke-Command -ComputerName $computerName -Credential $Credential -ScriptBlock { param($dataCollectorSet) logman query $dataCollectorSet > $ENV:TEMP\notImportant.txt; Return $LASTEXITCODE } -ArgumentList $dataCollectorSet
if ($counterExists -eq 0) {
    Write-Output "Deleting Data Collector Set because it already exists"
    Invoke-Command -ComputerName $computerName -Credential $Credential -ScriptBlock { param($dataCollectorSet) logman delete $dataCollectorSet } -ArgumentList $dataCollectorSet
    Start-Sleep -Seconds 2
}
$now = Get-Date -Format yyyy.MM.dd_hh-mm-ss
Invoke-Command -ComputerName $computerName -Credential $Credential -ScriptBlock { param($dataCollectorSet, $counters, $now) logman create counter $dataCollectorSet -o "C:\PerfLogs\Admin\$now" -si 1 -c $counters } -ArgumentList $dataCollectorSet, $counters, $now
Start-Sleep -Seconds 2
Write-Output "Starting $dataCollectorSet Data Collector Set"
Invoke-Command -ComputerName $computerName -Credential $Credential -ScriptBlock { param($dataCollectorSet) logman start $dataCollectorSet } -ArgumentList $dataCollectorSet
$delay = 8*60*60 # seconds from hours
Write-Output "Gathering $delay seconds of data"
Start-Sleep -Seconds $delay
Write-Output "Stopping $dataCollectorSet Data Collector Set"
Invoke-Command -ComputerName $computerName -Credential $Credential -ScriptBlock { param($dataCollectorSet) logman stop $dataCollectorSet } -ArgumentList $dataCollectorSet
$loc = ((Invoke-Command -ComputerName $computerName -Credential $Credential -ScriptBlock { param($dataCollectorSet) logman query $dataCollectorSet } -ArgumentList $dataCollectorSet)[10] -split '\s+')[2]
Write-Output "Grabbing results blg file at $loc to $ENV:TEMP"
New-PSDrive -Name S -Root \\$computerName\c$ -PSProvider FileSystem -Credential $Credential
Copy-Item -Path "S$($loc.substring(1))" -Destination $ENV:TEMP
net use \\$computerName\c$ /delete /y
Remove-PSDrive -Name S
exit
