# Configuring dhclient to discover CAPPORT URI

This document explains how to configure dhclient to capture the
information from the RFC7710 Captive Portal Option.

Instructions for Ubuntu dhclient.
(These instructions currently only configure IPv4.)

## Tell dhclient how to interpret the option number.

Determine the relevant configuration file. An easy way is to use "ps"
and see the ```-cf``` command-line arg:
```
$ ps -wax | grep dhclient
  1231 ?        S      0:00 /sbin/dhclient -d -sf /usr/lib/NetworkManager/nm-dhcp-client.action -pf /run/sendsigs.omit.d/network-manager.dhclient-eth0.pid -lf /var/lib/NetworkManager/dhclient-03c3ee51-f4e2-4ba5-89bd-5a9908a264ab-eth0.lease -cf /var/lib/NetworkManager/dhclient-eth0.conf eth0
```

Add to dhclient.conf:
```
option rfc7710-captive-portal code 160 = string;
```

*Restart or HUP dhclient?*

## Invoke CAPPORT work-flow when DHCP has updated the license file.

*There seems to be a way to configure dhclient to call a script when lease has been updated.*


## Interpreting the license file.

By using "ps" as above, note the lease file.
In general the lease file contains a history of leases. Only use the
most recent one.

*Is there a better way to find this file name?*

