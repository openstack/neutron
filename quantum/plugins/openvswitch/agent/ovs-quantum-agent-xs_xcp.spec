Name:           ovs-quantum-agent
Version:        VERSION
Release:        1
License:        Apache2
Group:          System Environment/Base
Summary:        Ovs Quantum Agent
Source:         %{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root
BuildArch:      noarch
Requires:       python python-sqlalchemy

%description
OVS Quantum Agent

%prep
%setup

%install
rm -rf --preserve-root %{buildroot}
install -d -m 755 %{buildroot}
cp -af * %{buildroot}
pushd %{buildroot}
find ./usr ./etc -type f -o -type l | sed "s/\.//" > %{_builddir}/%{name}-%{version}/%{name}-%{version}-%{release}-filelist
popd

%clean
[ %{buildroot} != / ] && rm -rf %{buildroot}

%files -f %{_builddir}/%{name}-%{version}/%{name}-%{version}-%{release}-filelist

%changelog
* Thu Jun 14 2012 Juliano Martinez <juliano.martinez@locaweb.com.br> - VERSION
- Creating quantum ovs agent package
