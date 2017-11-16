PowerShell
========

This repository has a collection of PowerShell scripts that have been created over time.

## Current scripts
* Perfmon - gather remote SQL Server performance metrics

## Power-CLI common tasks
How to get information about VM:
	Connect-VIServer -Server <vcenter fqdn>
	$guest = Get-VM -Name <vm name>
	$guestView = Get-View $guest.Id
	$guestView | ConvertTo-FlatObject -ExcludeDefault $false -Exclude AlarmActionsEnabled, AvailableField, Client, ConfigIssue, ConfigStatus, DeclaredAlarmState, DisabledMethod, EffectiveRole, GuestHeartbeatStatus, Layout, LayoutEx, LinkedView, MoRef, Parent, ParentVApp, Permission, RecentTask, RootSnapshot, Runtime, Snapshot, Tag, TriggeredAlarmState, Value | Tee-Object -FilePath C:\temp\guestData.txt

List all VMs by IP address:
	Get-VM | Select Name, @{N="IP Address";E={@($_.guest.IPAddress[0])}}
	
Generate CSV of VM used spaced in GB:
get-vm | foreach { $_.name + ", " + $_.UsedSpaceGB } > C:\Temp\vCenterVmDiskUsage.csv
