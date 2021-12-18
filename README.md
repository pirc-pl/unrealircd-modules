# unrealircd-modules
These are additional modules for [UnrealIRCD](https://www.unrealircd.org/). The modules contained in the directory "unreal6" are developed for the unrealircd-6.0.0 version.

There are also older modules, known to work on the unrealircd-4.2.0 version, in the directory "unreal4", and on unrealircd-5.2.0, in "unreal5". These are unsupported. That means you can try to download and use them, but nobody will help you with these versions (unless it's a bug in unreal5 module).

## Unreal 6.x.x modules

### metadata
NOTE: [unreal 5 version is documented here](#metadata-u5)

This one implements the METADATA command, allowing users to set their avatars, message colouring, status texts etc. It is currently based on the "Work In Progress" (that means the spec can change and then the module and clients will need updating) specification available here: [metadata specification](https://gist.github.com/k4bek4be/92c2937cefd49990fbebd001faf2b237). It is known to work with the [PIRC web client](https://github.com/pirc-pl/pirc-gateway) and [IRCcloud](https://www.irccloud.com/). There's no widespread support for METADATA and no one seems to want to change this. I find this functionality useful, so I am maintaining it though.

For compatibility, the module uses two CAPs: `draft/metadata` and `draft/metadata-notify-2`, and also an ISUPPORT tag of `METADATA`.

The module looks for a config block:
```C
metadata {
	max-user-metadata 10;	// maximum metadata count for a single user
	max-channel-metadata 10;	// maximum metadata count for a single channel
	max-subscriptions 10;	// maximum number of metadata keys an user can subscribe to
};
```
If the config is not specified, the above defaults are used.

Short usage explanation (for "avatar" metadata key name):

- Set the avatar URL for your nick: `/metadata * set avatar :https://example.com/example.png`
- Remove your avatar: `/metadata * set avatar`
- Subscribe to avatars of users (so server will send them for you): `/metadata * sub avatar`
- The notification sent by the server: `:irc.example.com METADATA someone avatar * :https://example.com/example.png`

Please keep these * signs intact.

### metadata-db
NOTE: [unreal 5 version is documented here](#metadata-db-u5)

WARNING: this is untested! Any feedback will be appreciated.

This one stores metadata for registered users (based on their account names) coming from the metadata module, and restores it for them at logon. User data will expire after specified time (in days). You probably want to set this to a value similar to your services account expiration. Metadata is also stored for +P channels.

Of course, the `metadata` module is required to be loaded for it to work.

This module needs to be loaded on only single server on the network. (You may keep it active on a second one for redundancy, it won't break anything.)

The module looks for a config block:
```C
metadata-db {	
	database "metadata.db";
	expire-after 365; // days
};
```
If the config is not specified, the above defaults are used.

## Unreal 5.x.x modules

### geoip-base
This one provides data for other "geoip" modules (currently there is only one available, "geoip-whois").

This module needs to be loaded on only single server on the network. (You may keep it active on a second one for redundancy, it won't break anything.)

The module looks for a config block:
```C
geoip {
	ipv4-blocks-file "GeoLite2-Country-Blocks-IPv4.csv";
	ipv6-blocks-file "GeoLite2-Country-Blocks-IPv6.csv";
	countries-file "GeoLite2-Country-Locations-en.csv";
};
```
If one of blocks files is missing, the address type is ignored by the module. If more files can't be loaded, the module fails.

If this config block is not given, it defaults to looking for three files in conf/:
GeoLite2-Country-Blocks-IPv4.csv, GeoLite2-Country-Locations-en.csv, GeoLite2-Country-Blocks-IPv6.csv.
These can be downloaded from [here](https://dev.maxmind.com/geoip/geoip2/geolite2/#Downloads) (get GeoLite2 Country in CSV format). We are notified that the download method may change soon.

### geoip-whois

This one appends swhois info to all users, unless they are not listed in the geoip data.

This module needs to be loaded on only single server on the network (it'll serve the whole network), and requires the "geoip-base" module loaded on same server.

The module looks for a config block:
```C
geoip-whois {
	display-name; // Poland
	display-code; // PL
//	display-continent; // Europe
	info-string "connected from "; // remember the trailing space!
};
```

Display option left out means that this info won't be displayed. (Keep at least one enabled.) No info-string text will cause the module to default to "connected from ".

### geoip-chanban

This one allow banning users from certain countries on a channel. Exceptions and invite exceptions are also possible.

`/mode #channel +b ~C:FR` - will prevent all users from France from joining.

`/mode #channel +iI ~C:RO` - only users from Romania will be able to join.

`/mode #channel +be *4*!*@* ~C:PL` - only users from Poland are allowed to have a number "4" in their nick.

Load this module on every server, together with geoip-base (on two servers for redundancy) or geoip-transfer (on remaining ones).

### geoip-connect-notice

This one sends geoip information to a far connect (+F) snomask.

Do not load this module on more than one server on the network. Correctly configured `geoip-base` or `geoip-transfer` is required.

### geoip-transfer

This one transfers data that come from the geoip-base module loaded on other server, so you don't have to use the resource-intensive geoip-base everywhere. It may be needed by the "geoip-chanban".

### unauthban
This one is created as an attempt of making behaviour of the +R chanmode more selective. It allows things like:

`~I:*!*@*.someisp.com` - lets users from someisp in only when they are registered - this is the particular target
of creating this module.

`~I:~q:~c:#channel` - allows users coming from #channel to talk only when they are registered.

### showwebirc
This one appends swhois info to users that are connected with WEBIRC authorization.

### wwwstats

This one allows Unreal to cooperate with a web statistics system. This is the simpler version; see below for an extended module with MySQL support, unfortunately not installable with Unreal's module manager. Do NOT install them both.

A single interface is used: UNIX socket. The socket is created on a path specified in config block. When you connect to the socket, the module "spits out" all the current data in JSON format and closes. You can test it with the shell command `socat - UNIX-CONNECT:/tmp/wwwsocket.sock`. It can be used to generate channel lists, server lists, view user counts etc in realtime. Example data:
```json
{
	"clients": 19,
	"channels": 4,
	"operators": 18,
	"servers": 2,
	"messages": 1459,
	"serv": [{
		"name": "test1.example.com",
		"users": 2
	}],
	"chan": [{
		"name": "#help",
		"users": 1,
		"messages": 0
	}, {
		"name": "#services",
		"users": 8,
		"messages": 971
	}, {
		"name": "#opers",
		"users": 1,
		"messages": 0,
		"topic": "This channel has some topic"
	}, {
		"name": "#aszxcvbnm",
		"users": 2,
		"messages": 485
	}]
}
```
+p / +s channels are always ignored.

Message counters are not very precise, as the module counts only messages going through the server it is loaded on. That means that some channels at some time can not be counted.

The module looks for a config block:
```C
wwwstats {
	socket-path "/tmp/wwwstats.sock";	// this option is REQUIRED
};
```

### wwwstats-mysql
**Note: this module is yet unreleased. Please wait or ask for it.**

This one replaces the "wwwstats" module (do NOT install them both), allowing Unreal to cooperate with a web statistics system. Two interfaces are used:

1. UNIX socket. The socket is created on a path specified in config block. When you connect to the socket, the module "spits out" all the current data in JSON format and closes. You can test it with the shell command `socat - UNIX-CONNECT:/tmp/wwwsocket.sock`. It can be used to generate channel lists, server lists, view user counts etc in realtime. Example data:
```json
{
	"clients": 19,
	"channels": 4,
	"operators": 18,
	"servers": 2,
	"messages": 1459,
	"serv": [{
		"name": "test1.example.com",
		"users": 2
	}],
	"chan": [{
		"name": "#help",
		"users": 1,
		"messages": 0
	}, {
		"name": "#services",
		"users": 8,
		"messages": 971
	}, {
		"name": "#opers",
		"users": 1,
		"messages": 0,
		"topic": "This channel has some topic"
	}, {
		"name": "#aszxcvbnm",
		"users": 2,
		"messages": 485
	}]
}
```
2. MySQL database.

Due to incompatibility with the Unreal's module manager, this module must be installed manually.

The module periodically inserts new data to the database, unless the data had not changed since the last insert. This can be used to generate graphs, view previous channel topics etc. You should specify database host (localhost is recommended), user, password and database name. Table structure will be created automatically. The structure is:
```sql
CREATE TABLE IF NOT EXISTS `chanlist` (`id` int(11) NOT NULL AUTO_INCREMENT, `date` int(11), `name` char(64), `topic` text, `users` int(11),  `messages` int(11), PRIMARY KEY (`id`), UNIQUE KEY `name` (`name`,`users`,`messages`), KEY `name_3` (`name`), KEY `date` (`date`) )
CREATE TABLE IF NOT EXISTS `stat` (`id` int(11) NOT NULL AUTO_INCREMENT, `date` int(11), `clients` int(11), `servers` int(11), `messages` int(11), `channels` int(11), PRIMARY KEY (`id`), UNIQUE KEY `changes` (`clients`,`servers`,`messages`,`channels`), KEY `date` (`date`) )
```
For obvious reasons you should not enable MySQL on more than one server on your network.

Compiling with mysql support needs mysql client libraries installed on your system. The module is compiled with the command `EXLIBS="-lmysqlclient" make`. If you happen to compile without the EXLIBS option, the module won't load. In such case you should `rm src/modules/third/m_wwwstats.so` and then retry.

+p / +s channels are always ignored.

Message counters are not very precise, as the module counts only messages going through the server it is loaded on. That means that some channels at some time can not be counted.

The module looks for a config block:
```C
wwwstats {
	socket-path "/tmp/wwwstats.sock";	// do not specify if you don't want the socket
	use-mysql;	// remove this line if you don't want mysql
	mysql-interval "900"; // time in seconds, default is 900 (15 minutes)
	mysql-host "localhost";
	mysql-db "database";
	mysql-user "username";
	mysql-pass "password";
};
```

### findchmodes

This one allows IRCoperators to check which channels use certain channel mode. You can use it to check, for example, who has the Channel History enabled.

Usage example:

`/findchmodes +H`

### metadata (u5)

This one implements the METADATA command, allowing users to set their avatars, message colouring, status texts etc. It is currently based on the "Work In Progress" (that means the spec can change and then the module and clients will need updating) specification available here: [metadata specification](https://gist.github.com/k4bek4be/92c2937cefd49990fbebd001faf2b237). It is known to work with the [PIRC web client](https://github.com/pirc-pl/pirc-gateway) and [IRCcloud](https://www.irccloud.com/).

For compatibility, the module uses two CAPs: `draft/metadata` and `draft/metadata-notify-2`, and also an ISUPPORT tag of `METADATA`.

The module looks for a config block:
```C
metadata {
	max-user-metadata 10;	// maximum metadata count for a single user
	max-channel-metadata 10;	// maximum metadata count for a single channel
	max-subscriptions 10;	// maximum number of metadata keys an user can subscribe to
	enable-debug 0; // set to 1 for ircops to receive all METADATA commands (floody)
};
```
If the config is not specified, the above defaults are used.

Short usage explanation (for "avatar" metadata key name):

- Set the avatar URL for your nick: `/metadata * set avatar :https://example.com/example.png`
- Remove your avatar: `/metadata * set avatar`
- Subscribe to avatars of users (so server will send them for you): `/metadata * sub avatar`
- The notification sent by the server: `:irc.example.com METADATA someone avatar * :https://example.com/example.png`

Please keep these * signs intact.

### metadata-db (u5)

This one stores metadata for registered users (based on their account names) coming from the metadata module, and restores it for them at logon. User data will expire after specified time (in days). You probably want to set this to a value similar to your services account expiration. Metadata is also stored for +P channels.

Of course, the `metadata` module is required to be loaded for it to work.

This module needs to be loaded on only single server on the network. (You may keep it active on a second one for redundancy, it won't break anything.)

The module looks for a config block:
```C
metadata-db {	
	database "metadata.db";
	expire-after 365; // days
};
```
If the config is not specified, the above defaults are used.

### setname

This one implements the IRCv3 [SETNAME capability](https://ircv3.net/specs/extensions/setname).

### monitor

This one implements the IRCv3 [MONITOR command](https://ircv3.net/specs/core/monitor-3.2). It's independent from the built-in WATCH.

### bot-tag

This one adds an `inspircd.org/bot` message tag to each message sent by a bot (marked with +B flag). This is compatible with more than one existing server software, and can be used bots to avoid replying to other bots. In my opinion, a metadata key is the superior solution, but so far message tags are much more universally supported.

### extjwt

This one provides an `EXTJWT` command to generate tokens for authenticating to external web services. It is currently based on the "Work In Progress" (that means the spec can change and then the module and clients will need updating) specification available here: [EXTJWT specification](https://github.com/ircv3/ircv3-specifications/blob/f3facfbe5f2686f2ab2a3322cadd31dacd3f5177/extensions/extjwt.md).

To use the `vfy` claim (`verify-url` option) you must provide your own verification facility, separate for each service (and for the default JWT when applicable). See the specification for details.

The module looks for a config block:
```C
extjwt {
	method "HS256"; // must be one of: NONE (not recommended), HS256, HS384, HS512, ES256, ES384, ES512, RS256, RS384, RS512
	expire-after 30; // seconds
	secret "somepassword"; // do not set when using ES*, RS* or NONE method, required for HS* method
//	key "somefile.pem"; // path to the private key PEM file placed in conf/ - do not set when using HS* or NONE method, required for ES* and RS* method
	service "test" { // optional service block
		method "ES512"; // supported: HS256, HS384, HS512, ES256, ES384, ES512, RS256, RS384, RS512
//		secret "anotherpassword"; // required for HS methods
		key "someotherfile.pem"; // required for ES and RS methods
		expire-after 60; // seconds, will be inherited from default if not given
		verify-url "https://example.com/verify/?t=%s"; // optional, won't be inherited, must be http or https, must contain %s
	};
	service "test2" {
		method "HS384";
		secret "yetanotherpassword";
	};
};
```

#### How to create ES and RS keys
These methods allow you to pass your public key to someone verifying your tokens, without giving them chance to generate their own signed tokens (they would need to have the private key for that). Below is a quick reference for generating the key pairs.

To generate RS256, RS384 or RS512 private key (to add to your IRCd):
```
openssl genrsa -out privkey.pem 4096
```

To generate matching public key (to use for token verification):
```
openssl rsa -in privkey.pem -pubout > pubkey.pem
```


To generate ES256, ES384 or ES512 private key (to add to your IRCd):
```
openssl ecparam -genkey -name secp521r1 -noout -out privkey.pem
```

To generate matching public key (to use for token verification):
```
openssl ec -in privkey.pem -pubout -out pubkey.pem
```

Of course, substitute your preferred file names for `pubkey.pem` and `privkey.pem`.

## Unreal 4.x.x modules

Remember that modules listed below are now unsupported.

### m_geoip_whois
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

### m_unauthban
This one is created as an attempt of making behaviour of the +R chanmode more selective. It allows things like:

`~I:*!*@*.someisp.com` - lets users from someisp in only when they are registered - this is the particular target
of creating this module.

`~I:~q:~c:#channel` - allows users coming from #channel to talk only when they are registered.

### m_showwebirc
This one appends swhois info to users that are connected with WEBIRC authorization.

### m_wwwstats

This one allows the Unreal to cooperate with a web statistics system. Two interfaces are used:

1. UNIX socket. The socket is created on a path specified in config block. When you connect to the socket, the module "spits out" all the current data in JSON format and closes. You can test it with the shell command `socat - UNIX-CONNECT:/tmp/wwwsocket.sock`. It can be used to generate channel lists, server lists, view user counts etc in realtime. Example data:
```json
{
	"clients": 19,
	"channels": 4,
	"operators": 18,
	"servers": 2,
	"messages": 1459,
	"serv": [{
		"name": "test1.example.com",
		"users": 2
	}],
	"chan": [{
		"name": "#help",
		"users": 1,
		"messages": 0
	}, {
		"name": "#services",
		"users": 8,
		"messages": 971
	}, {
		"name": "#opers",
		"users": 1,
		"messages": 0,
		"topic": "This channel has some topic"
	}, {
		"name": "#aszxcvbnm",
		"users": 2,
		"messages": 485
	}]
}
```
2. MySQL database. The module periodically inserts new data to the database, unless the data had not changed since the last insert. This can be used to generate graphs, view previous channel topics etc. You should specify database host (localhost is recommended), user, password and database name. Table structure will be created automatically. The structure is:
```sql
CREATE TABLE IF NOT EXISTS `chanlist` (`id` int(11) NOT NULL AUTO_INCREMENT, `date` int(11), `name` char(64), `topic` text, `users` int(11),  `messages` int(11), PRIMARY KEY (`id`), UNIQUE KEY `name` (`name`,`users`,`messages`), KEY `name_3` (`name`), KEY `date` (`date`) )
CREATE TABLE IF NOT EXISTS `stat` (`id` int(11) NOT NULL AUTO_INCREMENT, `date` int(11), `clients` int(11), `servers` int(11), `messages` int(11), `channels` int(11), PRIMARY KEY (`id`), UNIQUE KEY `changes` (`clients`,`servers`,`messages`,`channels`), KEY `date` (`date`) )
```
For obvious reasons you should not enable MySQL on more than one server on your network.

Compiling with mysql support needs mysql client libraries installed on your system. The module is compiled with the command `EXLIBS="-lmysqlclient" make`. If you happen to compile without the EXLIBS option, the module won't load. In such case you should `rm src/modules/third/m_wwwstats.so` and then retry.

Optionally, MySQL support can be completely removed (when you don't want to use it, and don't have the client libraries installed). Do this by changing the line `#define USE_MYSQL` to `#undef USE_MYSQL` in the module source.

+p / +s channels are always ignored.

Message counters are not very precise, as the module counts only messages going through the server it is loaded on. That means that some channels at some time can not be counted.

The module looks for a config block:
```C
wwwstats {
	socket-path "/tmp/wwwstats.sock";	// do not specify if you don't want the socket
	use-mysql;	// remove this line if you don't want mysql
	mysql-host "localhost";
	mysql-db "database";
	mysql-user "username";
	mysql-pass "password";
};
```

## Licensing information

You can use, modify and share the modules according to the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html) license, unless it's stated differently inside the source code file.
