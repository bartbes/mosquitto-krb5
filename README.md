mosquitto-krb5
==============

*mosquitto-krb5* is a project that contains both an authentication plugin for
the [mosquitto][] broker, and a library that can be injected into processes
using libmosquitto.

This has so far been a weekend project, and my first foray into the land of
libkrb5, I make no guarantees about the correctness of the implementation, and
dare not claim the plugin does not have a critical flaw that allows an attacker
to bypass authentication.

This library is released under the Simplified BSD License. For the full license
text, please see the `LICENSE` file.


auth-plugin
-----------

The authentication plugin for mosquitto is very limited, dealing only with basic
kerberos 5 (libkrb5) authentication. The restrictive plugin architecture in
mosquitto means there is no way to do ACL checking, TLS-PSK authentication
and/or authentication using other mechanisms. My intention is to either work
around this, get mosquitto to support multiple plugins, or integrate with
another plugin that has support for other backends (like jpmens'
[mosquitto-auth-plug][]).

In its current state, the plugin allows setting a keytab location (defaulting to
the system default) that contains the broker's key, belonging to principal
`mqtt/fqdn@DOMAIN`, for example `mqtt/test.mosquitto.org@MOSQUITTO.ORG`. It also
allows to set a `principal_format`, which is a printf-style format (only allows
`%s` and only allows it once) used to convert the given username into a
principal. The default pattern `%s` means user `mosq` in the `EXAMPLE.COM`
kerberos domain would require the principal `mosq@EXAMPLE.COM` to authenticate
to the broker.

This plugin introduces two configuration options:

 - `auth_opt_keytab`: The location of the keytab file
 - `auth_opt_principal_format`: The format string to transform a username into a
	   principal name.


client-preload
--------------

In lieu of a custom libmosquitto build, this library, when built, can be used
together with `LD_PRELOAD` to convert an existing libmosquitto-based program to
use krb5 authentication with the mosquitto broker. This library is probably
rough around the edges, and has no configuration, relying on the normal libkrb5
configuration.

Note that it uses the hostname passed to mosquitto_connect and friends to obtain
the principal name for the broker, and depending on your krb5 configuration,
this may then be expanded into a fqdn and resolved using reverse dns.

Also note that the hostname passed to mosquitto_connect_srv is also the one
used, meaning that the principal requested may not be the one belonging to the
actual host connected to.


Compilation
-----------

To compile this project you will need:

 - A C99-compatible C compiler
 - pkg-config
 - libkrb5 (only tested with MIT kerberos so far)
 - [mosquitto][]/libmosquitto
 - A kerberos domain, preferably one you are an admin of

The commands `make` or `make all` build both the auth-plugin and the
client-preload. The `clean` target will, as per usual, remove the output files.
Similarly, using the output file names as targets will build only that
particular module.

For testing purposes `make server` starts a mosquitto broker with extra
verbosity enabled, and using the `mosquitto.conf` also in this repository, it
presumes that a keytab `mqtt.keytab` has been placed in this directory, contain
the key(s) for the broker.

Similarly, `make client` verbosely publishes a message to the broker running on
localhost (typically corresponding to the fqdn `localhost.localdomain`) using
your own user name.

[mosquitto]: http://mosquitto.org
[mosquitto-auth-plug]: https://github.com/jpmens/mosquitto-auth-plug
