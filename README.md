# unrealircd-modules
These are additional modules for [UnrealIRCD](https://www.unrealircd.org/). The modules are currently being used
on the unrealircd-4.2.0 version.

## m_geoip_whois
This one appends swhois info to all users, unless they are not listed in the input data.

This module needs to be loaded on only single server on the network.

The module looks for a config block:
```C
geoip-whois {
	ipv4-blocks-file "GeoLite2-Country-Blocks-IPv4.csv";
	ipv6-blocks-file "GeoLite2-Country-Blocks-IPv6.csv";
	countries-file "GeoLite2-Country-Locations-en.csv";
	display-name; // Poland
	display-code; // PL
//	display-continent; // Europe
	info-string "connected from "; // remember the trailing space!
};
```

If one of blocks files is missing, the address type is ignored by the module. If more files can't be loaded, the module fails. Display option left out means that this info won't be displayed. (Keep at least one enabled.) No info-string text will cause the module to default to "connected from ".

If this block is not given, it works like the old version, defaulting to the options in example above, and looking for three files in conf/:
GeoLite2-Country-Blocks-IPv4.csv, GeoLite2-Country-Locations-en.csv, GeoLite2-Country-Blocks-IPv6.csv.
These can be downloaded from [here](https://dev.maxmind.com/geoip/geoip2/geolite2/#Downloads) (get GeoLite2 Country in CSV format).

## m_unauthban
This one is created as an attempt of making behaviour of the +R chanmode more selective. It allows things like:

`~I:*!*@*.someisp.com` - lets users from someisp in only when they are registered - this is the particular target
of creating this module.

`~I:~q:~c:#channel` - allows users coming from #channel to talk only when they are registered.

## m_showwebirc
*Not stable, needs testing!*

This one appends swhois info to users that are connected with WEBIRC authorization.
