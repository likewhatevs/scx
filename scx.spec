%global debug_package %{nil}

Name: 		scx
Version:	1%{?dist}
Release:        %autorelease
Summary:	sched-ext/scx scheds


License:	GPLv2
URL:		https://github.com/likewhatevs/scx
Source0:	${nil}

BuildRequires: cargo, rust, elfutils-devel, clang

%description
scx schedulers packaged to simplify perf testing

%prep
%setup -q

%build
export RUSTFLAGS="%build_rustflags"
cargo build --release -p scx_*
rm -f target/release/*.d

%install
mkdir -p %{buildroot}/usr/bin
install -m 0755 target/release/scx_* %{buildroot}/usr/bin/
install -m 0644 scheds/include/scx/*.h %{buildroot}/usr/include/scx/


%files
/usr/bin/scx_*
/usr/include/scx/*.h

%changelog
* Thu Apr 03 2025 Pat Somaru <patso@likewhatevs.io> 1.0.11-1
- new package built with tito

%autochangelog

