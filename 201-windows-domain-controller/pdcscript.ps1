Set-DnsClientServerAddress -interfacealias "ethernet 1" -resetserveraddresses
Set-DnsClientServerAddress -interfacealias "ethernet 2" -resetserveraddresses
Set-DnsClientServerAddress -interfacealias "ethernet 3" -resetserveraddresses

# work out the name of the reverse zone
$ip = $args[0]
$ipbits = $ip.Split('.')
$zone = "$($ipbits[2]).$($ipbits[1]).$($ipbits[0]).in-addr.arpa." 
dnscmd.exe /ZoneAdd $zone /DsPrimary
dnscmd.exe /Config $zone /AllowUpdate 1
if ($LastExitCode -ne 0)
{
    "exit code configuring reverse zone ($args[0]) was non-zero ($LastExitCode), bailing..."
    exit $LastExitCode
}
Set-DnsServerScavenging -ScavengingState $true -RefreshInterval "7" -NoRefreshInterval "7" -ApplyOnAllZones 
