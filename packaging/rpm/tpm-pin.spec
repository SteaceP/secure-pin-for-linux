Name:           tpm-pin
Version:        1.0.2
Release:        1%{?dist}
Summary:        Windows Hello-style TPM 2.0 PIN authentication for Linux

License:        GPL-3.0-or-later
URL:            https://github.com/steacep/secure-pin-for-linux
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  cmake
BuildRequires:  pkgconfig
BuildRequires:  openssl-devel
BuildRequires:  pam-devel
BuildRequires:  tpm2-tss-devel
Requires:       pam
Requires:       tpm2-tss
Requires:       python3
Requires:       python3-gobject
Requires:       libadwaita

%description
Hardware-backed PIN authentication using TPM 2.0. Integrates with PAM
for login screen (GDM/SDDM), lock screen, sudo, and desktop keyring auto-unlock.
Includes a native GTK4/Libadwaita settings application.

%prep
%autosetup

%build
%cmake -DCMAKE_BUILD_TYPE=Release
%cmake_build

%install
%cmake_install

%files
%license LICENSE
%doc README.md
%{_bindir}/tpm-pin-ctl
%{_bindir}/tpm-pin-settings
%attr(4755,root,root) %{_libexecdir}/tpm-pin-verify
%{_libdir}/security/pam_tpm_pin.so
%{_datadir}/applications/io.github.securepin.Settings.desktop
%{_datadir}/icons/hicolor/*/apps/*
%{_datadir}/metainfo/io.github.securepin.Settings.metainfo.xml
%{_datadir}/polkit-1/actions/io.github.securepin.policy
%{_prefix}/lib/udev/rules.d/70-tpm-pin.rules
%dir %attr(0700,root,root) %{_sharedstatedir}/tpm-pin
%dir %attr(0755,root,root) %{_sysconfdir}/tpm-pin

%changelog
* Fri Oct 23 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.2-1
- Define pam_info and pam_error as macros and enforce link safety in PAM module
- Check chown return values and handle system call results cleanly
- Add uaccess udev rule for TPM access and document user permissions
- Add application icons, build packaging script, and desktop integration
- Update GNOME Shell extension metadata, UUID, URL, and Shell 51 support

* Fri Oct 23 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.1-1
- Security hardening: PCR 7 policy enforcement, AES-128-CFB encrypted sessions
- Add Microsoft Pluton, AMD PSP, and Intel PTT hardware fTPM detection
- Fix privilege escalation, file I/O security, and empty PIN input handling
- Multi-distro CI/CD release packaging updates

* Wed Oct 21 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.0-1
- Initial release for Fedora / RHEL
