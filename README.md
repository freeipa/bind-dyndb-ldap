1. Introduction
===============
The dynamic LDAP back-end is a plug-in for BIND that provides an LDAP
database back-end capabilities. It requires dyndb interface which is present
in BIND versions >= 9.11.0rc1.


2. Features
===========

* support for dynamic updates
* SASL authentication
* SyncRepl (RFC 4533) for run-time synchronization with LDAP server
* read-query performance nearly same as with plain BIND
* AXFR and IXFR zone transfers are supported
* DNSSEC in-line signing is supported, including dynamic updates


3. Installation
===============

To install the LDAP back-end, extract the tarball and go to the unpacked
directory. Then follow these steps:

	$ ./configure --libdir=<libdir>
	$ make

Where `<libdir>` is a directory where your libdns is installed. This is
typically going to be `/usr/lib` or `/usr/lib64` on 64 bit systems.

If configure script complains that it `Can't obtain libdns version`,
please verify you have installed bind development files (package bind9-dev
or bind-devel) and you exported correct CPPFLAGS via

	$ export CPPFLAGS=`isc-config.sh --cflags`

Then, to install, run this as root:

	$ make install

This will install the file `ldap.so` into the `<libdir>/bind/` directory.

Alternatively, the latest version can be obtained from Git repository.
You can use following commands to prepare latest source tree for compilation:

	$ git clone https://git.fedorahosted.org/git/bind-dyndb-ldap.git
	$ cd bind-dyndb-ldap
	$ autoreconf -fvi

4. LDAP schema
==============

You can find the complete LDAP schema in the documentation directory. An
example zone ldif is available in the doc directory.

4.1 Master zone (idnsZone)
--------------------------
Object class `idnsZone` is equivalent to type `master` statement in `named.conf`.

### Attributes
* idnsAllowDynUpdate

	Allow dynamic update of records in this zone. If attribute doesn't exist,
	value `dyn_update` from plugin configuration will be used.

* idnsAllowQuery

	Specifies BIND9 zone ACL element as one string.

	* Example 1: `idnsAllowQuery: 192.0.2.1;`
	
		In the first example above, only the client with 192.0.2.1
		IP address is allowed to query records from the zone.

	* Example 2: `idnsAllowQuery: !192.0.2.33; 192.0.2.0/24;`
	
		In the second example, queries from client 192.0.2.33
		are refused but queries from all other clients in
		the 192.0.2.0/24 network are allowed.

	You can specify IPv4/IPv6 address, IPv4/IPv6 network address in CIDR
	format, and `any` or `none` keywords. The `!` prefix (for example
	`!192.0.2.33`) means negation of the ACL element.

	If not set, then zone inherits global allow-query from named.conf.

* idnsAllowTransfer

	Uses same format as `idnsAllowQuery`. Allows zone transfers for matching
	clients.

	If not set then zone inherits global allow-transfer from named.conf.

* idnsAllowSyncPTR

	Allow synchronization of A/AAAA records in zone with PTR records in reverse
	zone. Reverse zone must have Dynamic update allowed. 
	(See `idnsAllowDynUpdate` attribute and `dyn_update` configuration parameter.)

* idnsForwardPolicy (default `first`)

	Specifies BIND9 zone forward policy. Proprietary value `none`
	is equivalent to `forwarders {};` in BIND configuration,
	i.e. effectively disables forwarding and ignores `idnsForwarders`
	attribute.

	Values `first` and `only` are relevant in conjunction with a valid
	idnsForwarders attribute. Their meaning is same as in BIND9.

* idnsForwarders

	Defines multiple IP addresses to which recursive queries will be
	forwarded. This is equivalent to `forwarders` statement in `master`
	zone configuration.

	I.e. local BIND replies authoritatively to queries when possible
	(including authoritative NXDOMAIN answers) so forwarding affects only
	queries made by BIND to answer recursive queries which cannot be
	answered locally. Please see
	https://lists.isc.org/pipermail/bind-users/2006-January/060810.html
	https://lists.isc.org/pipermail/bind-users/2011-March/083244.html

	It is multi-value attribute: Each IP address (and optional port) has to
	be in own value. BIND9 syntax for `forwarders` is required.
	Optional port can be specified by adding ` port <number>` after IP 
	address. IPv4 and IPv6 addresses are supported.
	Examples:
	* `1.2.3.4`
	* `1.2.3.4 port 553`
	* `A::B`
	* `A::B port 553`

* idnsName

	Absolute name of DNS zone. It is recommended to use names with trailing
	period, e.g. `example.com.`

* idnsSecInlineSigning (default `FALSE`)

	DNSSEC in-line signing configuration. Value TRUE is equivalent to
	following zone configuration in named.conf (default BIND values):

		auto-dnssec maintain;
		sig-validity-interval 2592000; # 30 days
		# re-sign interval will be 648000 seconds = 7.5 days
		sig-signing-signatures 10;
		sig-signing-nodes 10;
		sig-signing-type 65534;
		update-check-ksk yes;
		dnssec-loadkeys-interval 60;   # minutes
		key-directory "<plugin-instance-dir>/<zone-name>/keys";

	There is no way to change those values at this moment.

* idnsSOAserial

	SOA serial number. It is automatically incremented after each change
	in LDAP. External changes done by other LDAP clients are detected via
	RFC 4533 (so-called syncrepl).

	If serial number is lower than current UNIX timestamp, then
	it is set to the timestamp value. If SOA serial is greater or equal
	to current timestamp, then the serial is incremented by one.
	(This is equivalent to BIND option 'serial-update-method unix'.)

	In multi-master LDAP environments it is recommended to make
	idnsSOAserial attribute non-replicated (locally significant).
	It is recommended not to use multiple masters for single slave zone
	if SOA serial is locally significant because serial numbers between
	masters	aren't synchronized. It will cause problems with zone
	transfers from multiple masters to single slave.

* idnsZoneActive

	Boolean which speicifies if particular DNS zone should be visible
	to clients or not. This attribute can be changed at run-time.

	Inactive zones are loaded into memory in the same way as active zones.
	The only difference is that inactive zones are not added to DNS view
	used by bind-dyndb-ldap.

	Zone will be re-added to DNS view if idnsActiveZone attribute is
	changed to TRUE so the change should be almost immediate.

	Usual zone maintenance (serial number maintenance, DNSSEC in-line
	signing etc.) is done for all zones, no matter if the zone
	is active or not. This allows us to maintain zone journal so IXFR
	works correctly even after zone re-activation.

* nSEC3PARAMRecord

	NSEC3PARAM resource record definition according to RFC5155.
	Zone without NSEC3PARAM RR will use NSEC by default.


4.2 Forward zone (idnsForwardZone)
----------------------------------
Object class `idnsForwardZone` is equivalent to type `forward` statement
in named.conf.

### Attributes
* idnsForwarders

	Defines multiple IP addresses to which all queries for sub-tree of DNS
	will be forwarded. This is equivalent to `forwarders` statement in
	`forward` zone configuration.

	It is multi-value attribute: Each IP address (and optional port) has to
	be in own value. BIND9 syntax for `forwarders` is required.
	Optional port can be specified by adding ` port <number>` after IP 
	address. IPv4 and IPv6 addresses are supported.
	Examples:
	* `1.2.3.4`
	* `1.2.3.4 port 553`
	* `A::B`
	* `A::B port 553`

* idnsForwardPolicy (default `first`)

	Specifies BIND9 zone forward policy. Proprietary value `none`
	is equivalent to `forwarders {};` in BIND configuration,
	i.e. effectively disables forwarding and ignores `idnsForwarders`
	attribute.

	Values `first` and `only` are relevant in conjunction with a valid
	`idnsForwarders` attribute. Their meaning is same as in BIND9.

* idnsName

	Absolute name of DNS zone. It is recommended to use names with trailing
	period, e.g. `example.com.`

Forward zones may conflict with automatic empty zones (defined in RFC 6303)
because empty zones are authoritative and thus have higher priority
than forwarding.
Bind-dyndb-ldap will automatically unload empty zones which are super/sub
domains of a forward zones if the forwarding policy is `only`.
A warning will be issued (and zone not unloaded) if the policy is `first`
because this policy does not guarantee that queries will not leak to
the public Internet.

Unloaded empty zones will not be loaded back even if the forward zone is later
deleted. The empty zones will be loaded on each BIND reload.


4.3 Global configuration object (idnsConfigObject)
--------------------------------------------------
Object class idnsConfigObject provides global configuration common
for all zones.

### Attributes
* idnsAllowSyncPTR

	Semantics is equivalent to `sync_ptr` option described in plugin's
	config and to `idnsAllowSyncPTR` attribute in `idnsZone`.

* idnsForwarders
* idnsForwardPolicy

	Semantics is equivalent to `forward` statement in `named.conf`.
	Syntax is the same as in forward zone, please see previous section.


4.4 Per-server configuration object (idnsServerConfigObject)
------------------------------------------------------------
Object class idnsConfigObject provides global configuration common
for all zones. A plugin instance will read configuration
only from entries with matching idnsServerId.

### Attributes
* idnsServerId

	Configuration identifier (arbitrary string).
	A plugin instance will use only objects whose `idnsServerId` value
	matches `server_id` value in plugin's config.

* idnsForwarders
* idnsForwardPolicy

	Same meaning as in global configuration object (`idnsConfigObject`).

* idnsSOAmName

	Equivalent to `fake_mname` option in plugin's config.

* idnsSubstitutionVariable

	This attribute associates string value with user-defined name.
	These named variables can be used later in record template processing.
	Variable name is specified as LDAP sub-type. (The attribute cannot be
	used without sub-type. Exactly one instance of each sub-type
	is required.)
	For further information please see
	https://fedorahosted.org/bind-dyndb-ldap/wiki/Design/RecordGenerator

	LIMITATION: Current plugin version supports only `ipalocation` variable


4.5 Record template (idnsTemplateObject)
----------------------------------------
Object class idnsTemplateObject provides facility for dynamic resource record
generation. The template entry must contain idnsTemplateAttribute with
string template.

Optionally the same entry can contain statically defined resource records
in *Record attributes. All statically defined record values are ignored
when template is present and substitution into template is successful.
The substitution is successful only if all variables used
by the template string are defined.

### Attributes
* idnsTemplateAttribute
	String subtitution template. All occurrences of \{variable_name\}
	are replaced with respective strings from plugin configuration.
	Remaining parts of the original string are just copied into the output.

	Double-escaped strings \\{ \\} do not trigger substitution.
	Nested references will expand only innermost variable: \{\{var1\}\}
	Non-matching parentheses and other garbage will be copied verbatim
	without triggering an error.

	Resulting resource record type is specified as LDAP sub-type.
	(The attribute cannot be used without sub-type.
	Exactly one instance of each sub-type is required.)

	Example - LDIF snippet:
	
		idnsSubstitutionVariable;ipalocation: brno
		idnsTemplateAttribute;CNAMERecord: server.\{substitutionvariable_ipalocation\}
	will generate CNAME record: `server.brno`
		
	For further information please see
	https://fedorahosted.org/bind-dyndb-ldap/wiki/Design/RecordGenerator


5. Configuration
================

To configure dynamic loading of back-end, you must put a `dyndb`
clause into your named.conf. The clause must then be followed by a
string denoting the name of the instance and path to dyndb library.

The name is not that much important, it is passed to the plug-in
and is used for logging purposes and for naming working directories.

Library path must point to a shared object file that will be opened and loaded.

Name and library path have to be followed by set of options enclosed between
curly brackets. Example:

	dyndb "example-ldap" "/usr/lib64/bind/ldap.so" {
		uri "ldap://ldap.example.com";
		base "cn=dns, dc=example,dc=com";
		auth_method "none";
	};

5.1 Configuration options
-------------------------
List of configuration options follows:

5.1.1 LDAP connection
---------------------
* uri

	The Uniform Resource Identifier pointing to the LDAP server we
	wish to connect to. This string is directly passed to the
	ldap_initialize(3) function. This option is mandatory.
	Example: "ldap://ldap.example.com"

* connections (default 2)

	Number of connections the LDAP driver should try to establish to
	the LDAP server. It's best if this matches the number of threads
	BIND creates, for performance reasons. However, your LDAP server
	configuration might only allow certain number of connections per
	client.

* base
	This is the search base that will be used by the LDAP back-end
	to search for DNS zones. This option is mandatory.
	Example: "cn=dns, dc=example,dc=com";

* auth_method (default "none")

	The method used to authenticate to the LDAP server. Currently
	supported methods are "none", "simple" and "sasl". The none
	method is effectively a simple authentication without password.

* bind_dn (default "")

	Distinguished Name used to bind to the LDAP server. If this is
	empty and the auth_method is set to "simple", the LDAP back-end
	will fall-back and use the "none" authentication method.

* password (default "")

	Password for simple and SASL authentication. If the authentication
	method is set to "simple" and the password is empty, the LDAP
	driver will fall-back to the "none" authentication method.

* sasl_mech (default "GSSAPI")

	Name of the SASL mechanism to be used for negotiation.

* sasl_auth_name

	The user name to be used for SASL authentication.

* sasl_user

	The user name to be used for SASL proxy authorization.

* sasl_password

	The password to use for the SASL authentication.

* sasl_realm

	The SASL realm name.

* krb5_keytab

	Path to the kerberos keytab containing service credentials to be used
	for SASL authentication. Append the "FILE:" prefix to the file path.
	Example: "FILE:/etc/named.keytab"

* krb5_principal

	Kerberos principal of the service, used for SASL authentication.
	If not set then it is copied from "sasl_user" option. Principal
	is loaded from file specified in "krb5_keytab" option.

* timeout (default 10)

	Timeout (in seconds) of the queries to the LDAP server. If the LDAP
	server don't respond before this timeout then lookup is aborted and
	BIND returns SERVFAIL. Value "0" means infinite timeout (no timeout).

* reconnect_interval (default 60)

	Time (in seconds) after that the plugin should try to connect to LDAP 
	server again in case connection is lost and immediate reconnection 
	fails.

* ldap_hostname (default "")

	Sets hostname of the LDAP server. When it is set to "", actual
	`/bin/hostname` is used. Please prefer `uri` option, this option should be
	used only in special cases, for example when GSSAPI authentication
	is used and named service has Kerberos principal different from
	`/bin/hostname` output.


5.1.2 Special DNS features
--------------------------
* fake_mname

	Ignore value of the idnsSOAmName (primary master DNS name) attribute
	and use this value instead. This allows multiple BIND processes to share
	one LDAP database and every BIND reports itself as a primary master in
	SOA record, for example.

* sync_ptr (default no)

	Set this option to `yes` if you would like to keep PTR record 
	synchronized with coresponding A/AAAA record for all zones.
	If this option is set to `no`, the LDAP driver will check
	the idnsAllowSyncPTR attribute which specifies the synchronization
	policy for PTR records in a zone. When an A/AAAA record is deleted 
	the PTR record must point to the same hostname. 
	
* dyn_update (default no)

	Set this option to `yes` if you would like to allow dynamic zone updates.
	This setting can be overridden for each zone individually
	by idnsAllowDynUpdate attribute.


5.1.3 Plumbing
--------------
* verbose_checks (default no)

	Set this option to `yes` if you would like to log all failures
	in internal CHECK() macros. This option is recommended only for
	debugging purposes. It could produce huge amount of log messages
	on a loaded system!

* directory (default is
             `dyndb-ldap/<current instance name from dynamic-db directive>`)
        
	Specifies working directory for plug-in. The path has to be writeable
	by named because plug-in will create sub-directory for each zone.
	These sub-directories will contain temporary files like zone dump, zone
	journal, zone keys etc.
	The path is relative to `directory` specified in BIND options.
	See section 6 (DNSSEC) for examples.

5.2 Sample configuration
------------------------
Let's take a look at a sample configuration:

	options {
		directory "/var/named/";
	};
	
	dyndb "my_db_name" "/usr/lib64/bind/ldap.so" {
		uri "ldap://ldap.example.com";
		base "cn=dns, dc=example,dc=com";
		auth_method "none";
	};

With this configuration, the LDAP back-end will try to connect to server
ldap.example.com with simple authentication, without any password. It
will then use RFC 4533 refresh&persist search in the `cn=dns,dc=example,dc=com`
base for entries with object class `idnsZone` and `idnsRecord`.
For each idnsZone entry it will find, it will register a new zone with BIND.
For each idnsRecord entry it will create domain name in particular zone.
The LDAP back-end will keep each record it gets from LDAP in its memory.

Working directory for the plug-in will be `/var/named/dyndb-ldap/my_db_name/`,
so hypothetical zone `example.com` will use sub-directory
`/var/named/dyndb-ldap/my_db_name/master/example.com/`.

5.3 Configuration in LDAP
-------------------------
Some options can be configured in LDAP as `idnsConfigObject` attributes.
Value configured in LDAP has priority over value in configuration file.
(This behavior will change in future versions!)

Following options are supported (option = attribute equivalent):
option     | LDAP attribute
-----------| --------------
forwarders | idnsForwarders (BIND native option)
forward    | idnsForwardPolicy (BIND native option)
sync_ptr   | idnsAllowSyncPTR

Forward policy option cannot be set without setting forwarders at the same time.


6. DNSSEC support
=================

In-line signing support in this plugin allows to use this BIND feature
for zones in LDAP.

Signatures are automatically generated by plugin during zone loading
and signatures are never written back to LDAP. DNSKEY, RRSIG, NSEC and NSEC3
records in LDAP are ignored because they are automatically managed by BIND.

NSEC3 can be enabled by writting NSEC3PARAM RR to particular zone object
in LDAP.

Dynamic updates made to in-line signed zones are written back to LDAP as usual
and respective signatures are automatically re-generated as necessary.

Key management has to be handled by user, i.e. user has to
generate/delete keys and configure key timestamps as appropriate.

Key directory for particular DNS zone is automatically configured to value:
	<plugin-instance-dir>/master/<zone-name>/keys

`<plugin-instance-dir>` is described in section 5.1.3 of this file.
`<zone-name>` is (transformed) textual representation of zone name without
trailing period.

Zone name will be automatically transformed before usage:
- root zone is translated to `@` to prevent collision with filesystem `.`
- digits, hyphen and underscore are left intact
- letters of English alphabet are downcased
- all other characters are escaped using %ASCII_HEX form, e.g. `/` => `%2F`
- final dot is omited
- labels are separated with `.`

Example:
* BIND directory: `/var/named`
* bind-dyndb-ldap directory: `dyndb-ldap`
* LDAP instance name: `ipa`
* DNS zone: `example.com.`
* Resulting keys directory: `/var/named/dyndb-ldap/ipa/master/example.com/keys`

* DNS zone: `TEST.0/1.a.`
* Resulting keys directory: `/var/named/dyndb-ldap/ipa/master/test.0%2F1.a/keys`

Make sure that keys directory and files is readable by user used for BIND.


7. License
==========

This package is licensed under the GNU General Public License, version 2
only. See file COPYING for more information.
