Name:       secure-storage
Summary:    Secure storage
Version:    0.12.12
Release:    1
Group:      System/Security
License:    Apache 2.0
Source0:    secure-storage-%{version}.tar.gz
Source1:    non-tz-secure-storage.service
Source2:    ss-server.socket
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(libsystemd-daemon)
BuildRequires:  pkgconfig(security-server)
BuildRequires:  cmake
BuildRequires:  libcryptsvc-devel
BuildRequires:	pkgconfig(dukgenerator)
BuildRequires:  pkgconfig(db-util)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(capi-base-common)

%description
Secure storage package

%package -n libss-client
Summary:    Secure storage  (client)
Group:      Development/Libraries
Provides:   libss-client.so
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libss-client
Secure storage package (client)

%package -n libss-client-devel
Summary:    Secure storage  (client-devel)
Group:      Development/Libraries
Requires:   libss-client = %{version}-%{release}

%description -n libss-client-devel
Secure storage package (client-devel)

%package -n ss-server
Summary:    Secure storage  (ss-server)
Group:      Development/Libraries
Requires(preun): /usr/bin/systemctl
Requires(post):  /usr/bin/systemctl
Requires(postun): /usr/bin/systemctl
Requires:   systemd
Requires:   libss-client = %{version}-%{release}
Requires:   libcryptsvc

%description -n ss-server
Secure storage package (ss-server)

%prep
%setup -q


%build

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
export CFLAGS="$CFLAGS -DSECURE_STORAGE_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DSECURE_STORAGE_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DSECURE_STORAGE_DEBUG_ENABLE"

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix}


make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
mkdir -p %{buildroot}%{_libdir}/systemd/system/sockets.target.wants

install -m 0644 %{SOURCE1} %{buildroot}%{_libdir}/systemd/system/secure-storage.service
install -m 0644 %{SOURCE2} %{buildroot}%{_libdir}/systemd/system/
ln -s ../secure-storage.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/
ln -s ../ss-server.socket %{buildroot}%{_libdir}/systemd/system/sockets.target.wants/

mkdir -p %{buildroot}/usr/share/license
cp LICENSE.APLv2 %{buildroot}/usr/share/license/ss-server
cp LICENSE.APLv2 %{buildroot}/usr/share/license/libss-client

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
%defattr(-,root,root,-)
%{_bindir}/ss-server
%{_libdir}/systemd/system/secure-storage.service
%{_libdir}/systemd/system/ss-server.socket
%{_libdir}/systemd/system/multi-user.target.wants/secure-storage.service
%{_libdir}/systemd/system/sockets.target.wants/ss-server.socket
%{_datadir}/secure-storage/config
/usr/share/license/ss-server

%files -n libss-client
%manifest libss-client.manifest
%defattr(-,root,root)
%{_libdir}/libss-client.so.*
/usr/share/license/libss-client
/opt/share/secure-storage/salt/*

%files -n libss-client-devel
%defattr(-,root,root,-)
%{_includedir}/ss_manager.h
%{_libdir}/pkgconfig/secure-storage.pc
%{_libdir}/libss-client.so

