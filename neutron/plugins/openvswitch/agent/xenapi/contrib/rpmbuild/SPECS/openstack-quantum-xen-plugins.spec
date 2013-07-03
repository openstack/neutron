Name:           openstack-neutron-xen-plugins
Version:        %{version}
Release:        1
Summary:        Files for XenAPI support.
License:        ASL 2.0
Group:          Applications/Utilities
Source0:        openstack-neutron-xen-plugins.tar.gz
BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%define debug_package %{nil}

%description
This package contains files that are required for XenAPI support for Neutron.

%prep
%setup -q -n openstack-neutron-xen-plugins

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc
cp -r xapi.d $RPM_BUILD_ROOT/etc
chmod a+x $RPM_BUILD_ROOT/etc/xapi.d/plugins/*

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
/etc/xapi.d/plugins/*
