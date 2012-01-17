#%define PATCHVER P4
%define PREVER a1
#%define VERSION %{version}
#%define VERSION %{version}-%{PATCHVER}
%define VERSION %{version}%{PREVER}

Name:           bind-dyndb-ldap
Version:        1.1.0
Release:        0.1.%{PREVER}%{?dist}
Summary:        LDAP back-end plug-in for BIND

Group:          System Environment/Libraries
License:        GPLv2+
URL:            https://fedorahosted.org/bind-dyndb-ldap
Source0:        https://fedorahosted.org/released/%{name}/%{name}-%{VERSION}.tar.bz2
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  bind-devel >= 32:9.6.1-0.3.b1
BuildRequires:  krb5-devel
BuildRequires:  openldap-devel

Requires:       bind >= 32:9.6.1-0.3.b1

%description
This package provides an LDAP back-end plug-in for BIND. It features
support for dynamic updates and internal caching, to lift the load
off of your LDAP server.


%prep
%setup -q -n %{name}-%{VERSION}

%build
export CFLAGS="`isc-config.sh --cflags dns` $RPM_OPT_FLAGS"
%configure
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

# Remove unwanted files
rm %{buildroot}%{_libdir}/bind/ldap.la
rm -r %{buildroot}%{_datadir}/doc/%{name}


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc NEWS README COPYING doc/{example.ldif,schema}
%{_libdir}/bind/ldap.so


%changelog
* Mon Nov 14 2011 Adam Tkac <atkac redhat com>
- specfile to build bind-dyndb-ldap
