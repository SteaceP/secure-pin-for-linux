Name:           tpm-pin
Version:        1.0.4
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
mkdir -p %{buildroot}%{_sharedstatedir}/tpm-pin
mkdir -p %{buildroot}%{_sysconfdir}/tpm-pin
rm -rf %{buildroot}%{_datadir}/pam-configs

%post
if [ $1 -eq 1 ]; then
    # Initial installation
    if [ -x %{_bindir}/tpm-pin-ctl ]; then
        %{_bindir}/tpm-pin-ctl pam enable >/dev/null 2>&1 || :
    fi
fi

%preun
if [ $1 -eq 0 ]; then
    # Package is being uninstalled, not upgraded
    if [ -x %{_bindir}/tpm-pin-ctl ]; then
        %{_bindir}/tpm-pin-ctl pam disable >/dev/null 2>&1 || :
    fi
fi

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
%{_prefix}/lib/systemd/system/polkit-agent-helper@.service.d/50-tpm-pin.conf
%dir %attr(0700,root,root) %{_sharedstatedir}/tpm-pin
%dir %attr(0755,root,root) %{_sysconfdir}/tpm-pin

%changelog
* Fri Oct 23 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.4-1
- Fix Arch Linux packaging by bundling tpm-pin.install in Docker build context
- Ensure PAM module compatibility on RPM distros by symlinking /usr/lib64/security
- Sync RPM spec install and filelist targets with CMake install definitions
- Harden TPM 2.0 presence detection and disable PIN setup when device is missing
- Fix GNOME Keyring auto-unlock stashing and relative jump handling in PAM manager

* Fri Oct 23 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.3-1
- Add Flatpak packaging manifest with GNOME 50 runtime support
- Add standalone Flatpak build helper script with bundle export and install options
- Support host portal delegation via flatpak-spawn in GTK4 settings app
- Integrate Flatpak package generation into build script and CI/CD workflow
- Add AppStream metainfo XML metadata for software centers
- Add %preun removal scriptlet and PAM open_err=ignore hardening to prevent uninstall lockouts
- Add contribution guidelines and GitHub issue templates

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
