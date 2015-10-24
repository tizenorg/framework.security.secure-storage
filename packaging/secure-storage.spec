%define secure_storage_build_test 0

Name:       secure-storage
Summary:    Secure storage
Version:    0.12.13
Release:    1
Group:      System/Security
License:    Apache-2.0
Source0:    secure-storage-%{version}.tar.gz
Source1001:    ss-server.manifest
Source1002:    libss-client.manifest
Source1003:    ss-client-tests.manifest
BuildRequires: cmake
BuildRequires: pkgconfig(openssl)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(capi-base-common)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(security-server)
BuildRequires: pkgconfig(db-util)
BuildRequires: pkgconfig(sqlite3)

%description
Secure storage package


%package -n ss-server
Summary:    Secure storage  (ss-server)
Group:      Development/Libraries
Requires(preun): /usr/bin/systemctl
Requires(post):  /usr/bin/systemctl
Requires(postun): /usr/bin/systemctl
Requires:   systemd

%description -n ss-server
Secure storage package (ss-server)


%package -n libss-client
Summary:    Secure storage  (client)
Group:      Development/Libraries
Provides:   libss-client.so
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires:   ss-server

%description -n libss-client
Secure storage package (client)


%package -n libss-client-devel
Summary:    Secure storage  (client-devel)
Group:      Development/Libraries
Requires:   libss-client = %{version}-%{release}

%description -n libss-client-devel
Secure storage package (client-devel)


%package -n ss-client-tests
Summary:   Internal test for ss-client
Group:     Development
Requires:  libss-client = %{version}-%{release}

%description -n ss-client-tests


%prep
%setup -q
cp -a %{SOURCE1001} .
cp -a %{SOURCE1002} .
cp -a %{SOURCE1003} .


%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%define build_type DEBUG

cmake . -DVERSION=%{version} \
        -DCMAKE_INSTALL_PREFIX=%{_prefix} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
%if 0%{?secure_storage_build_test}
        -DSECURE_STORAGE_BUILD_TEST=1 \
%endif
        -DSYSTEMD_UNIT_DIR=%{_unitdir}


make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE %{buildroot}%{_datadir}/license/ss-server
cp LICENSE %{buildroot}%{_datadir}/license/libss-client

%make_install
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
mkdir -p %{buildroot}%{_unitdir}/sockets.target.wants
ln -s ../secure-storage.service %{buildroot}%{_unitdir}/multi-user.target.wants/
ln -s ../ss-server.socket %{buildroot}%{_unitdir}/sockets.target.wants/

%preun -n ss-server
if [ $1 == 0 ]; then
    systemctl stop secure-storage.service
fi

%post -n ss-server
systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart secure-storage.service
fi

%postun -n ss-server
systemctl daemon-reload

%post -n libss-client -p /sbin/ldconfig


%postun -n libss-client -p /sbin/ldconfig

%files -n ss-server
%manifest ss-server.manifest
%caps(cap_chown,cap_dac_override,cap_lease=eip) %{_bindir}/ss-server
%defattr(-,system,system,-)
%{_unitdir}/secure-storage.service
%{_unitdir}/ss-server.socket
%{_unitdir}/multi-user.target.wants/secure-storage.service
%{_unitdir}/sockets.target.wants/ss-server.socket
%{_datadir}/secure-storage/config
%{_datadir}/license/ss-server
%dir /opt/share/secure-storage
/opt/share/secure-storage/salt

%files -n libss-client
%manifest libss-client.manifest
%defattr(-,system,system,-)
%{_libdir}/libss-client.so.*
%{_datadir}/license/libss-client

%files -n libss-client-devel
%defattr(-,system,system,-)
%{_includedir}/ss_manager.h
%{_libdir}/pkgconfig/secure-storage.pc
%{_libdir}/libss-client.so

%if 0%{?secure_storage_build_test}
%files -n ss-client-tests
%defattr(-,system,system,-)
%manifest ss-client-tests.manifest
%{_bindir}/ss-client-tests-ss-manager
%endif
