%define VERSION %{version}

%define bind_version 32:9.11.11-1

Name:           bind-dyndb-ldap
Version:        11.2
Release:        0%{?dist}
Summary:        LDAP back-end plug-in for BIND

Group:          System Environment/Libraries
License:        GPLv2+
URL:            https://releases.pagure.org/bind-dyndb-ldap
Source0:        https://releases.pagure.org/%{name}/%{name}-%{VERSION}.tar.bz2
Source1:        https://releases.pagure.org/%{name}/%{name}-%{VERSION}.tar.bz2.asc
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  bind-devel >= %{bind_version}, bind-lite-devel >= %{bind_version}
BuildRequires:  krb5-devel
BuildRequires:  openldap-devel
BuildRequires:  libuuid-devel
BuildRequires:  automake, autoconf, libtool

Requires:       bind >= %{bind_version}

%description
This package provides an LDAP back-end plug-in for BIND. It features
support for dynamic updates and internal caching, to lift the load
off of your LDAP server.


%prep
%setup -q -n %{name}-%{VERSION}

%build
autoreconf -fiv
%configure
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
mkdir -m 770 -p %{buildroot}/%{_localstatedir}/named/dyndb-ldap

# Remove unwanted files
rm %{buildroot}%{_libdir}/bind/ldap.la
rm -r %{buildroot}%{_datadir}/doc/%{name}

%post
# SELinux boolean named_write_master_zones has to be enabled
# otherwise the plugin will not be able to write to /var/named.
# This scriptlet enables the boolean after installation or upgrade.
# SELinux is sensitive area so I want to inform user about the change.
if [ -x "/usr/sbin/setsebool" ] ; then
        echo "Enabling SELinux boolean named_write_master_zones"
        /usr/sbin/setsebool -P named_write_master_zones=1 || :
fi

# Transform named.conf if it still has old-style API.
PLATFORM=$(uname -m)

if [ $PLATFORM == "x86_64" ] ; then
    LIBPATH=/usr/lib64
else
    LIBPATH=/usr/lib
fi

# The following sed script:
#   - scopes the named.conf changes to dynamic-db
#   - replaces arg "name value" syntax with name "value"
#   - changes dynamic-db header to dyndb
#   - uses the new way the define path to the library
#   - removes no longer supported arguments (library, cache_ttl,
#       psearch, serial_autoincrement, zone_refresh)
while read -r PATTERN
do
    SEDSCRIPT+="$PATTERN"
done <<EOF
/^\s*dynamic-db/,/};/ {

  s/\(\s*\)arg\s\+\(["']\)\([a-zA-Z_]\+\s\)/\1\3\2/g;

  s/^dynamic-db/dyndb/;

  s@\(dyndb "[^"]\+"\)@\1 "$LIBPATH/bind/ldap.so"@;
  s@\(dyndb '[^']\+'\)@\1 '$LIBPATH/bind/ldap.so'@;

  /\s*library[^;]\+;/d;
  /\s*cache_ttl[^;]\+;/d;
  /\s*psearch[^;]\+;/d;
  /\s*serial_autoincrement[^;]\+;/d;
  /\s*zone_refresh[^;]\+;/d;
}
EOF

sed -i.bak -e "$SEDSCRIPT" /etc/named.conf


# This scriptlet disables the boolean after uninstallation.
%postun
if [ "0$1" -eq "0" ] && [ -x "/usr/sbin/setsebool" ] ; then
        echo "Disabling SELinux boolean named_write_master_zones"
        /usr/sbin/setsebool -P named_write_master_zones=0 || :
fi


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc NEWS README.md COPYING doc/{example,schema}.ldif
%dir %attr(770, root, named) %{_localstatedir}/named/dyndb-ldap
%{_libdir}/bind/ldap.so


%changelog
* Tue Nov 05 2019 Alexander Bokovoy <abokovoy@redhat.com>
- Bump BIND version

* Tue Jun 27 2017 Tomas Krizek <tkrizek@redhat.com>
- Bump BIND version

* Fri Apr 07 2017 Tomas Krizek <tkrizek@redhat.com>
- Removed unnecessary bind-pkcs11 dependency

* Mon Mar 13 2017 Tomas Krizek <tkrizek@redhat.com>
- Fixed sed script regex error
- Re-synced specfile with fedora

* Thu Jan 26 2017 Tomas Krizek <tkrizek@redhat.com>
- Added named.conf API transofrmation script
- Bumped the required BIND version to 9.11.0-6.P2

* Tue Jan 28 2014 Petr Spacek <pspacek redhat com>
- package /var/named/dyndb-ldap directory

* Mon Nov 14 2011 Adam Tkac <atkac redhat com>
- specfile to build bind-dyndb-ldap
