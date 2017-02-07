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

Function ConvertTo-FlatObject {
    <#
    .SYNOPSIS
        Flatten an object to simplify discovery of data

    .DESCRIPTION
        Flatten an object.  This function will take an object, and flatten the properties using their full path into a single object with one layer of properties.

        You can use this to flatten XML, JSON, and other arbitrary objects.

        This can simplify initial exploration and discovery of data returned by APIs, interfaces, and other technologies.

        NOTE:
            Use tools like Get-Member, Select-Object, and Show-Object to further explore objects.
            This function does not handle certain data types well.  It was original designed to expand XML and JSON.

    .PARAMETER InputObject
        Object to flatten

    .PARAMETER Exclude
        Exclude any nodes in this list.  Accepts wildcards.

        Example:
            -Exclude price, title

    .PARAMETER ExcludeDefault
        Exclude default properties for sub objects.  True by default.

        This simplifies views of many objects (e.g. XML) but may exclude data for others (e.g. if flattening a process, ProcessThread properties will be excluded)

    .PARAMETER Include
        Include only leaves in this list.  Accepts wildcards.

        Example:
            -Include Author, Title

    .PARAMETER Value
        Include only leaves with values like these arguments.  Accepts wildcards.

    .PARAMETER MaxDepth
        Stop recursion at this depth.

    .INPUTS
        Any object

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .EXAMPLE

        #Pull unanswered PowerShell questions from StackExchange, Flatten the data to date a feel for the schema
        Invoke-RestMethod "https://api.stackexchange.com/2.0/questions/unanswered?order=desc&sort=activity&tagged=powershell&pagesize=10&site=stackoverflow" |
            ConvertTo-FlatObject -Include Title, Link, View_Count

            $object.items[0].owner.link : http://stackoverflow.com/users/1946412/julealgon
            $object.items[0].view_count : 7
            $object.items[0].link       : http://stackoverflow.com/questions/26910789/is-it-possible-to-reuse-a-param-block-across-multiple-functions
            $object.items[0].title      : Is it possible to reuse a &#39;param&#39; block across multiple functions?
            $object.items[1].owner.link : http://stackoverflow.com/users/4248278/nitin-tyagi
            $object.items[1].view_count : 8
            $object.items[1].link       : http://stackoverflow.com/questions/26909879/use-powershell-to-retreive-activated-features-for-sharepoint-2010
            $object.items[1].title      : Use powershell to retreive Activated features for sharepoint 2010
            ...

    .EXAMPLE

        #Set up some XML to work with
        $object = [xml]'
            <catalog>
               <book id="bk101">
                  <author>Gambardella, Matthew</author>
                  <title>XML Developers Guide</title>
                  <genre>Computer</genre>
                  <price>44.95</price>
               </book>
               <book id="bk102">
                  <author>Ralls, Kim</author>
                  <title>Midnight Rain</title>
                  <genre>Fantasy</genre>
                  <price>5.95</price>
               </book>
            </catalog>'

        #Call the flatten command against this XML
            ConvertTo-FlatObject $object -Include Author, Title, Price

            #Result is a flattened object with the full path to the node, using $object as the root.
            #Only leaf properties we specified are included (author,title,price)

                $object.catalog.book[0].author : Gambardella, Matthew
                $object.catalog.book[0].title  : XML Developers Guide
                $object.catalog.book[0].price  : 44.95
                $object.catalog.book[1].author : Ralls, Kim
                $object.catalog.book[1].title  : Midnight Rain
                $object.catalog.book[1].price  : 5.95

        #Invoking the property names should return their data if the orginal object is in $object:
            $object.catalog.book[1].price
                5.95

            $object.catalog.book[0].title
                XML Developers Guide

    .EXAMPLE

        #Set up some XML to work with
            [xml]'<catalog>
               <book id="bk101">
                  <author>Gambardella, Matthew</author>
                  <title>XML Developers Guide</title>
                  <genre>Computer</genre>
                  <price>44.95</price>
               </book>
               <book id="bk102">
                  <author>Ralls, Kim</author>
                  <title>Midnight Rain</title>
                  <genre>Fantasy</genre>
                  <price>5.95</price>
               </book>
            </catalog>' |
                ConvertTo-FlatObject -exclude price, title, id

        Result is a flattened object with the full path to the node, using XML as the root.  Price and title are excluded.

            $Object.catalog                : catalog
            $Object.catalog.book           : {book, book}
            $object.catalog.book[0].author : Gambardella, Matthew
            $object.catalog.book[0].genre  : Computer
            $object.catalog.book[1].author : Ralls, Kim
            $object.catalog.book[1].genre  : Fantasy

    .EXAMPLE
        #Set up some XML to work with
            [xml]'<catalog>
               <book id="bk101">
                  <author>Gambardella, Matthew</author>
                  <title>XML Developers Guide</title>
                  <genre>Computer</genre>
                  <price>44.95</price>
               </book>
               <book id="bk102">
                  <author>Ralls, Kim</author>
                  <title>Midnight Rain</title>
                  <genre>Fantasy</genre>
                  <price>5.95</price>
               </book>
            </catalog>' |
                ConvertTo-FlatObject -Value XML*, Fantasy

        Result is a flattened object filtered by leaves that matched XML* or Fantasy

            $Object.catalog.book[0].title : XML Developers Guide
            $Object.catalog.book[1].genre : Fantasy

    .EXAMPLE
        #Get a single process with all props, flatten this object.  Don't exclude default properties
        Get-Process | select -first 1 -skip 10 -Property * | ConvertTo-FlatObject -ExcludeDefault $false

        #NOTE - There will likely be bugs for certain complex objects like this.
                For example, $Object.StartInfo.Verbs.SyncRoot.SyncRoot... will loop until we hit MaxDepth. (Note: SyncRoot is now addressed individually)

    .NOTES
        I have trouble with algorithms.  If you have a better way to handle this, please let me know!

    .FUNCTIONALITY
        General Command
    #>
    [cmdletbinding()]
    param(

        [parameter( Mandatory = $True,
                    ValueFromPipeline = $True)]
        [PSObject[]]$InputObject,

        [string[]]$Exclude = "",

        [bool]$ExcludeDefault = $True,

        [string[]]$Include = $null,

        [string[]]$Value = $null,

        [int]$MaxDepth = 10
    )
    Begin
    {
        #region FUNCTIONS

            #Before adding a property, verify that it matches a Like comparison to strings in $Include...
            Function IsIn-Include {
                param($prop)
                if(-not $Include) {$True}
                else {
                    foreach($Inc in $Include)
                    {
                        if($Prop -like $Inc)
                        {
                            $True
                        }
                    }
                }
            }

            #Before adding a value, verify that it matches a Like comparison to strings in $Value...
            Function IsIn-Value {
                param($val)
                if(-not $Value) {$True}
                else {
                    foreach($string in $Value)
                    {
                        if($val -like $string)
                        {
                            $True
                        }
                    }
                }
            }

            Function Get-Exclude {
                [cmdletbinding()]
                param($obj)

                #Exclude default props if specified, and anything the user specified.  Thanks to Jaykul for the hint on [type]!
                    if($ExcludeDefault)
                    {
                        Try
                        {
                            $DefaultTypeProps = @( $obj.gettype().GetProperties() | Select -ExpandProperty Name -ErrorAction Stop )
                            if($DefaultTypeProps.count -gt 0)
                            {
                                Write-Verbose "Excluding default properties for $($obj.gettype().Fullname):`n$($DefaultTypeProps | Out-String)"
                            }
                        }
                        Catch
                        {
                            Write-Verbose "Failed to extract properties from $($obj.gettype().Fullname): $_"
                            $DefaultTypeProps = @()
                        }
                    }

                    @( $Exclude + $DefaultTypeProps ) | Select -Unique
            }

            #Function to recurse the Object, add properties to object
            Function Recurse-Object {
                [cmdletbinding()]
                param(
                    $Object,
                    [string[]]$path = '$Object',
                    [psobject]$Output,
                    $depth = 0
                )

                # Handle initial call
                    Write-Verbose "Working in path $Path at depth $depth"
                    Write-Debug "Recurse Object called with PSBoundParameters:`n$($PSBoundParameters | Out-String)"
                    $Depth++

                #Exclude default props if specified, and anything the user specified.
                    $ExcludeProps = @( Get-Exclude $object )

                #Get the children we care about, and their names
                    $Children = $object.psobject.properties | Where {$ExcludeProps -notcontains $_.Name }
                    Write-Debug "Working on properties:`n$($Children | select -ExpandProperty Name | Out-String)"

                #Loop through the children properties.
                foreach($Child in @($Children))
                {
                    $ChildName = $Child.Name
                    $ChildValue = $Child.Value

                    Write-Debug "Working on property $ChildName with value $($ChildValue | Out-String)"
                    # Handle special characters...
                        if($ChildName -match '[^a-zA-Z0-9_]')
                        {
                            $FriendlyChildName = "'$ChildName'"
                        }
                        else
                        {
                            $FriendlyChildName = $ChildName
                        }

                    #Add the property.
                        if((IsIn-Include $ChildName) -and (IsIn-Value $ChildValue) -and $Depth -le $MaxDepth)
                        {
                            $ThisPath = @( $Path + $FriendlyChildName ) -join "."
                            $Output | Add-Member -MemberType NoteProperty -Name $ThisPath -Value $ChildValue
                            Write-Verbose "Adding member '$ThisPath'"
                        }

                    #Handle null...
                        if($ChildValue -eq $null)
                        {
                            Write-Verbose "Skipping NULL $ChildName"
                            continue
                        }

                    #Handle evil looping.  Will likely need to expand this.  Any thoughts on a better approach?
                        if(
                            (
                                $ChildValue.GetType() -eq $Object.GetType() -and
                                $ChildValue -is [datetime]
                            ) -or
                            (
                                $ChildName -eq "SyncRoot" -and
                                -not $ChildValue
                            )
                        )
                        {
                            Write-Verbose "Skipping $ChildName with type $($ChildValue.GetType().fullname)"
                            continue
                        }

                    #Check for arrays
                        $IsArray = @($ChildValue).count -gt 1
                        $count = 0

                    #Set up the path to this node and the data...
                        $CurrentPath = @( $Path + $FriendlyChildName ) -join "."

                    #Exclude default props if specified, and anything the user specified.
                        $ExcludeProps = @( Get-Exclude $ChildValue )

                    #Get the children's children we care about, and their names.  Also look for signs of a hashtable like type
                        $ChildrensChildren = $ChildValue.psobject.properties | Where {$ExcludeProps -notcontains $_.Name }
                        $HashKeys = if($ChildValue.Keys -notlike $null -and $ChildValue.Values)
                        {
                            $ChildValue.Keys
                        }
                        else
                        {
                            $null
                        }
                        Write-Debug "Found children's children $($ChildrensChildren | select -ExpandProperty Name | Out-String)"

                    #If we aren't at max depth or a leaf...
                    if(
                        (@($ChildrensChildren).count -ne 0 -or $HashKeys) -and
                        $Depth -lt $MaxDepth
                    )
                    {
                        #This handles hashtables.  But it won't recurse...
                            if($HashKeys)
                            {
                                Write-Verbose "Working on hashtable $CurrentPath"
                                foreach($key in $HashKeys)
                                {
                                    Write-Verbose "Adding value from hashtable $CurrentPath['$key']"
                                    $Output | Add-Member -MemberType NoteProperty -name "$CurrentPath['$key']" -value $ChildValue["$key"]
                                    $Output = Recurse-Object -Object $ChildValue["$key"] -Path "$CurrentPath['$key']" -Output $Output -depth $depth
                                }
                            }
                        #Sub children?  Recurse!
                            else
                            {
                                if($IsArray)
                                {
                                    foreach($item in @($ChildValue))
                                    {
                                        Write-Verbose "Recursing through array node '$CurrentPath'"
                                        $Output = Recurse-Object -Object $item -Path "$CurrentPath[$count]" -Output $Output -depth $depth
                                        $Count++
                                    }
                                }
                                else
                                {
                                    Write-Verbose "Recursing through node '$CurrentPath'"
                                    $Output = Recurse-Object -Object $ChildValue -Path $CurrentPath -Output $Output -depth $depth
                                }
                            }
                        }
                    }

                $Output
            }

        #endregion FUNCTIONS
    }
    Process
    {
        Foreach($Object in $InputObject)
        {
            #Flatten the XML and write it to the pipeline
                Recurse-Object -Object $Object -Output $( New-Object -TypeName PSObject )
        }
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
