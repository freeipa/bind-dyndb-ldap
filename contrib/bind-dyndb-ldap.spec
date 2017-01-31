%define VERSION %{version}

Name:           bind-dyndb-ldap
Version:        11.0
Release:        0%{?dist}
Summary:        LDAP back-end plug-in for BIND

Group:          System Environment/Libraries
License:        GPLv2+
URL:            https://fedorahosted.org/bind-dyndb-ldap
Source0:        https://fedorahosted.org/released/%{name}/%{name}-%{VERSION}.tar.bz2
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  bind-devel >= 32:9.9.0, bind-lite-devel >= 32:9.9.0
BuildRequires:  krb5-devel
BuildRequires:  openldap-devel
BuildRequires:  libuuid-devel
BuildRequires:  automake, autoconf, libtool

Requires:       bind-pkcs11 >= 32:9.9.6, bind-pkcs11-utils >= 32:9.9.6

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


# SELinux boolean named_write_master_zones has to be enabled
# otherwise the plugin will not be able to write to /var/named.
# This scriptlet enables the boolean after installation or upgrade.
# SELinux is sensitive area so I want to inform user about the change.
%post
if [ -x "/usr/sbin/setsebool" ] ; then
        echo "Enabling SELinux boolean named_write_master_zones"
        /usr/sbin/setsebool -P named_write_master_zones=1 || :
fi


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
%doc NEWS README COPYING doc/{example,schema}.ldif
%dir %attr(770, root, named) %{_localstatedir}/named/dyndb-ldap
%{_libdir}/bind/ldap.so


%changelog
* Tue Jan 28 2014 Petr Spacek <pspacek redhat com>
- package /var/named/dyndb-ldap directory

* Mon Nov 14 2011 Adam Tkac <atkac redhat com>
- specfile to build bind-dyndb-ldap
