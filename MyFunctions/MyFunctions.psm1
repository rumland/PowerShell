function Test-TCPPortConnection {
	<#
	.SYNOPSIS
	 Test the response of a computer to a specific TCP port

	.DESCRIPTION
	 Test the response of a computer to a specific TCP port

	.PARAMETER  ComputerName
	 Name of the computer to test the response for

	.PARAMETER  Port
	 TCP Port number(s) to test

	.INPUTS
	 System.String.
	 System.Int.

	.OUTPUTS
	 None

	.EXAMPLE
	 PS C:\> Test-TCPPortConnection -ComputerName Server01

	.EXAMPLE
	 PS C:\> Get-Content Servers.txt | Test-TCPPortConnection -Port 22,443
	#>

	[CmdletBinding()][OutputType('System.Management.Automation.PSObject')]

	param(
		[Parameter(Position=0,Mandatory=$true,HelpMessage="Name of the computer to test",
		ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$true)]
		[Alias('CN','__SERVER','IPAddress','Server')]
		[String[]]$ComputerName,
		[Parameter(Position=1)]
		[ValidateRange(1,65535)]
		[Int[]]$Port = 3389
	)

	begin {
		$TCPObject = @()
	}

	process {
		foreach ($Computer in $ComputerName){
			foreach ($TCPPort in $Port){
				$Connection = New-Object Net.Sockets.TcpClient
				try {
					$Connection.Connect($Computer,$TCPPort)
					if ($Connection.Connected) {
						$Response = “Open”
						$Connection.Close()
					}
				} catch [System.Management.Automation.MethodInvocationException] {
					$Response = “Closed / Filtered”
				}

				$Connection = $null
				$hash = @{
					ComputerName = $Computer
					Port = $TCPPort
					Response = $Response
				}
				$Object = New-Object PSObject -Property $hash
				$TCPObject += $Object
			}
		}
	}

	end {
		Write-Output $TCPObject
	}
}

function Test-IPRange {
	<# 
	.SYNOPSIS
	 ICMP scan range of IP addresses
	
	.DESCRIPTION
	 Test the response of a computer to a specific TCP port

	.PARAMETER  FirstThree
	 First three bytes of IP address. For example, 172.17.84.

	.PARAMETER  StartRange
	 First byte to start at after FirstThree.

	.PARAMETER  EndRange
	 Last byte to end on at after FirstThree.

	.PARAMETER  InputFile
	 Rather than specify FirstThree, StartRange and EndRange, give input file containing
	 all IP addresses you wish to scan.

	.INPUTS
	 System.String.
	 System.Int.
	 System.Int.
	 System.String.

	.OUTPUTS
	 None
	
	.EXAMPLE
	 Scan-IPRange -FirstThree "172.17.84" -StartRange 1 -EndRange 22
	
	.EXAMPLE
	 Scan-IPRange -InputFile "C:\temp\databaseIpsUniqueSorted.txt"
	#>
	
	param ( 
		[string]$FirstThree,
		[int]$StartRange,
		[int]$EndRange,
		[string]$InputFile
	)

	end {
		$groupMax = 50

		$ScanRange = @()
		if ($PSBoundParameters.ContainsKey('FirstThree')) {
			$ScanRange = $StartRange..$EndRange
		} else {
			$ScanRange = Get-Content $InputFile
		}
		# start the range scan as jobs
		$count = 1
		$ScanRange | %{
			# start a test-connection job for each IP in the range, return the IP and boolean result from test-connection
			start-job -ArgumentList "$FirstThree`.$_" -scriptblock { $test = test-connection $args[0] -count 2 -quiet; return $args[0],$test } | out-null
			# sleep for 3 seconds once groupMax is reached. This code helps prevent security filters from flagging port traffic as malicious for large IP ranges.
			if ($count -gt $groupMax) {
				sleep 3
				$count = 1
			} else {
				$count++
			}
		}

		# wait for all the jobs to finish
		get-job | wait-job | out-null
		 
		# store the jobs into an array
		$jobs = get-job
		# holds the results of the jobs
		$results = @()
		foreach ($job in $jobs) {
			# grab the job output
			$temp = receive-job -id $job.id -keep
			$results += ,($temp[0],$temp[1])
		}

		# stop and remove all jobs
		get-job | stop-job
		get-job | remove-job

		# sort the results
		$results = $results | sort @{Expression={$_[0]}; Ascending=$false}

		# report the results
		foreach ($result in $results) {
			if ($result[1]) {
				write-host -f Green "$($result[0]) is responding"
			} else {
				write-host -f Red "$($result[0]) is not responding"
			}
		}
	}
}

function Get-IPrange
{
	<# 
	.SYNOPSIS
	 Get the IP addresses in a range
	
	.EXAMPLE
	 Get-IPrange -start 192.168.8.2 -end 192.168.8.20
	
	.EXAMPLE
	 Get-IPrange -ip 192.168.8.2 -mask 255.255.255.0
	
	.EXAMPLE
	 Get-IPrange -ip 192.168.8.3 -cidr 24
	#>
	 
	param ( 
		[string]$start, 
		[string]$end, 
		[string]$ip, 
		[string]$mask, 
		[int]$cidr 
	)
	
	function IP-toINT64 () { 
		param ($ip) 
	
		$octets = $ip.split(".") 
		return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
	} 
	 
	function INT64-toIP() { 
		param ([int64]$int) 

		return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
	} 
	 
	if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
	if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
	if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)} 
	if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
	if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 
	 
	if ($ip) { 
	  $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
	  $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
	} else { 
	  $startaddr = IP-toINT64 -ip $start 
	  $endaddr = IP-toINT64 -ip $end 
	} 


	for ($i = $startaddr; $i -le $endaddr; $i++) 
	{ 
		INT64-toIP -int $i 
	}
}

function Sort-IPAddress {
	<#
	.SYNOPSIS
	 Sort IP addresses in the way you would expect. Sort-Object does not do what you want :-(

	.DESCRIPTION
	 Sort IP addresses in the way you would expect. Sort-Object does not do what you want. The example shown below
	 demonstrates this.

	.PARAMETER  IPAddresses
	 Set of IP addresses to sort

	.INPUTS
	 System.String.

	.OUTPUTS
	 System.String.

	.EXAMPLE
	 PS C:\> Sort-IPAddress -IPAddresses "172.17.64.130", "172.17.64.15", "172.17.64.17"
	
	.EXAMPLE
	 PS C:\> Sort-IPAddress -IPAddresses (Get-Content -Path C:\temp\snmpBeforeMetricsApplied\listOfIps.txt)
	#>

	[CmdletBinding()][OutputType('System.Management.Automation.PSObject')]

	param(
		[Parameter(Position=0,Mandatory=$true,HelpMessage="Set of IP addresses",
		ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false)]
		[Alias('Addresses','IPs')]
		[String[]]$IPAddresses
	)

	begin {
		$SortedIPs = @()
	}

	#On a rainy day it would be great to figure out how to get piped input to work with this function.
	process {
		[string[]]$SortedIPs = [system.version[]]($IPAddresses) | Sort-Object
	}

	end {
		Write-Output $SortedIPs
	}
}

function Convert-BinarySubnetMaskToDecimal {
	<#
	.SYNOPSIS
	 Convert binary subnet mask to decimal

	.DESCRIPTION
	 Convert binary subnet mask to decimal

	.PARAMETER  BinarySubnetMask
	 String representation of binary subnet mask

	.INPUTS
	 System.String.

	.OUTPUTS
	 System.String.

	.EXAMPLE
	 PS C:\> Convert-BinarySubnetMaskToDecimal -BinarySubnetMask "11111111.11111111.11111000.00000000"

	.EXAMPLE
	 PS C:\> Convert-BinarySubnetMaskToDecimal -BinarySubnetMask "11111111.11111111.11111000.00000000","11111111.11111111.11111111.00000000"
	#>

	[CmdletBinding()][OutputType('System.Management.Automation.PSObject')]

	param(
		[Parameter(Position=0,Mandatory=$true,HelpMessage="Binary subnet mask",
		ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$true)]
		[Alias('Mask','SubnetMask')]
		[String[]]$BinarySubnetMask
	)

	begin {
		$DecimalSubnetMasks = @()
	}

	process {
		foreach ($SubnetMask in $BinarySubnetMask){
			$a=$i=$null
			$SubnetMask.Split('.') | % {
				$i++
				[string]$a += [convert]::ToInt32($_,2)
				if($i-le 3) {
					[string]$a += "."
				}
			}
			$DecimalSubnetMasks += $a
		}
	}

	end {
		Write-Output $DecimalSubnetMasks
	}
}

function Convert-DecimalSubnetMaskToBinary {
	<#
	.SYNOPSIS
	 Convert decimal subnet mask to binary

	.DESCRIPTION
	 Convert decimal subnet mask to binary

	.PARAMETER  DecimalSubnetMask
	 String representation of decimal subnet mask

	.INPUTS
	 System.String.

	.OUTPUTS
	 System.String.

	.EXAMPLE
	 PS C:\> Convert-DecimalSubnetMaskToBinary -DecimalSubnetMask "255.255.255.0"

	.EXAMPLE
	 PS C:\> Convert-DecimalSubnetMaskToBinary -DecimalSubnetMask "255.255.255.0","255.255.248.0"
	#>

	[CmdletBinding()][OutputType('System.Management.Automation.PSObject')]

	param(
		[Parameter(Position=0,Mandatory=$true,HelpMessage="Decimal subnet mask",
		ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$true)]
		[Alias('Mask','SubnetMask')]
		[String[]]$DecimalSubnetMask
	)

	begin {
		$BinarySubnetMasks = @()
	}

	process {
		foreach ($SubnetMask in $DecimalSubnetMask){
			$a=$i=$null
			$SubnetMask.Split('.') | % {
				$i++
				$octet = "{0:D8}" -f [int][convert]::ToString([int32]$_,2)
				[string]$a += $octet
				if($i-le 3) {
					[string]$a += "."
				}
			}
			$BinarySubnetMasks += $a
		}
	}

	end {
		Write-Output $BinarySubnetMasks
	}
}

function Get-ElementManagementTableInfo {
	<#
	.SYNOPSIS
	 Gather element management related table row count and size. If call to Invoke-Sqlcmd fails run 'Import-Module SqlPs'
	
	.PARAMETER  ServerInstance
	 IP address of sql server database
	 
	.PARAMETER Database
	 Name of database
	 
	.PARAMETER User
	 User that can run sp_spaceused
	 
	.PARAMETER  Password
	 Password for named user
	
	.EXAMPLE
	 Get-ElementManagementTableInfo
	 
	.EXAMPLE
	 Get-ElementManagementTableInfo -serverInstance=10.238.40.19 -database=CA_UIM
	
	.EXAMPLE
	 Get-ElementManagementTableInfo -serverInstance=10.238.40.19 -database=CA_UIM -user=george -password=jungle
	#>

	param(
		[string]$ServerInstance="10.238.40.19",
		[string]$Database="CA_UIM",
		[string]$User="sa",
		[string]$Password = "t3sti9"
	)

	end {
		Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Username $User -Password $Password -Query "EXEC sp_spaceused;" | Format-Table
		"EXEC sp_spaceused datomic_kvs;",
		"EXEC sp_spaceused CM_COMPUTER_SYSTEM;",
		"EXEC sp_spaceused CM_COMPUTER_SYSTEM_ATTR;",
		"EXEC sp_spaceused CM_CONFIGURATION_ITEM;",
		"EXEC sp_spaceused CM_CONFIGURATION_ITEM_ATTRIBUTE;",
		"EXEC sp_spaceused CM_CONFIGURATION_ITEM_METRIC;",
		"EXEC sp_spaceused CM_DEVICE;",
		"EXEC sp_spaceused CM_DEVICE_ATTRIBUTE;" | ForEach-Object {
			Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $Database -Username $User -Password $Password -Query "$_"
		} | Format-Table -Property "name", "rows", "data"
	}
}

function Get-Weekday {
	<#
	.SYNOPSIS
	 Ever wanted to know how many days you need to work this month? Here's a clever function that lists all the weekdays you want that are in a month. By default, Get-WeekDay returns all Mondays through Fridays in the current month. You can specify different months (and years), too, if you want to. (http://powershell.com/cs/blogs/tips/archive/2012/03/21/counting-work-days.aspx)
	
	.PARAMETER  Month
	 Numerical representation of month(s) of interest
	 
	.PARAMETER Year
	 Year in question
	 
	.PARAMETER User
	 Numerical representation of day(s) of interest
	
	.EXAMPLE
	 Get-Weekday -Year 2016 -Month 1 | Measure-Object | Select-Object -ExpandProperty Count
	 
	.EXAMPLE
	 Get-Weekday -Year 2016 -Month 1 -Day 2
	
	.EXAMPLE
	 Get-Weekday -Year 2016 -Month 1
	#>

	param(
		$Month = $(Get-Date -format 'MM'),
		$Year = $(Get-Date -format 'yyyy'),
		$Days = 1..5
	)

	$MaxDays = [System.DateTime]::DaysInMonth($Year, $Month)

	1..$MaxDays | ForEach-Object {
		Get-Date -day $_ -Month $Month -Year $Year |
		  Where-Object { $Days -contains $_.DayOfWeek }  
	}
}