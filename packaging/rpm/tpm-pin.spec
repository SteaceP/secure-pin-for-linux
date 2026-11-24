Name:           tpm-pin
Version:        1.0.10
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
rm -f /etc/udev/rules.d/70-tpm-pin.rules
if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload >/dev/null 2>&1 || :
    udevadm trigger --action=change --subsystem-match=tpmrm >/dev/null 2>&1 || :
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create %{_prefix}/lib/tmpfiles.d/tpm-pin.conf >/dev/null 2>&1 || :
fi
if [ -d %{_sharedstatedir}/tpm-pin ]; then
    find %{_sharedstatedir}/tpm-pin -maxdepth 2 -type d -exec chown 0:0 {} + 2>/dev/null || :
fi
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
        %{_bindir}/tpm-pin-ctl pam disable --uninstall >/dev/null 2>&1 || :
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
%{_prefix}/lib/systemd/system/polkit-agent-helper@.service.d/50-tpm-pin.conf
%{_prefix}/lib/tmpfiles.d/tpm-pin.conf
%{_mandir}/man1/tpm-pin-ctl.1*
%{_mandir}/man8/pam_tpm_pin.8*
%{_datadir}/bash-completion/completions/tpm-pin-ctl
%{_datadir}/zsh/site-functions/_tpm-pin-ctl
%{_datadir}/fish/vendor_completions.d/tpm-pin-ctl.fish
%{_datadir}/gnome-shell/extensions/secure-pin@coderage.pro/
%dir %attr(0755,root,root) %{_sharedstatedir}/tpm-pin
%dir %attr(0755,root,root) %{_sysconfdir}/tpm-pin

%changelog
* Tue Nov 24 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.10-1
- Track stale sealed keyring passwords via pam_sm_chauthtok and add sync-keyring command and GUI SyncKeyringDialog
- Add LOG_AUTHPRIV pam_syslog auditing across PAM PIN authentication and password updates
- Add bounded TPM transient error retries (RETRY/TESTING/YIELDED), UEFI Secure Boot & PCR 7 checks, and hierarchy auth diagnostics
- Fix openSUSE PAM removal on disable/uninstall and preserve Arch Linux PAM opt-out across package upgrades

* Tue Nov 24 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.9-1
- Add PIN rotation (change-pin), enrolled user listing (list), config listing, --version, and doctor diagnostics
- Verify local login passwords against shadow hashes before sealing for keyring auto-unlock
- Separate Polkit scope (enable_polkit) from sudo and reject simple sequential/repeating PINs
- Upgrade GTK4/Libadwaita Settings app with Test PIN, Change PIN, DA policy controls, actionable banners, Diagnostics tab, and About dialog
- Add live status polling in GNOME Shell Quick Settings extension, man pages, and bash/zsh/fish completions

* Mon Nov 23 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.8-1
- Remove unprivileged udev uaccess rule on /dev/tpmrm* and require root for DA reset/config
- Fix GUI PIN enrollment stdin protocol regression and make GUI CLI execution asynchronous
- Canonicalize sealed blob serialization via libtss2-mu (v2), enforce root-owned directories, and fix PCR 7 policy RC matching
- Harden PAM module (PAM_RHOST check, thread-safe env, service allowlist/Polkit scope, sufficient->success=done), CLI, and setuid verify helper
- Fix packaging uninstall /dev/null mask leaks, Debian dh_fixperms setuid stripping, and GNOME extension cleanup

* Fri Nov 13 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.7-1
- Bind sealed blob headers and UID into AES-256-GCM AAD and enforce 0600 root-only sealed.blob with sealed.meta status file
- Remove cleartext ESYS_TR_PASSWORD and broken TPM2_ALG_NULL fallbacks during TPM sealing/unsealing
- Fix pam_kwallet5.so heap over-read and avoid poisoning PAM_AUTHTOK on failed PIN verification
- Replace system() calls with sanitized execve(), resolve symlinks safely, and mask packaged overrides on disable
- Harden CLI/GUI secret handling, JSON output escaping, RPM tmpfiles packaging, and test suite coverage

* Tue Nov 03 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.6-1
- Enhance Fedora, RHEL, and Bazzite PAM stack compatibility and preserve authselect profile symlinks
- Integrate native Makefile fallback support with automatic directory creation and packaging targets
- Harden PAM manager rule insertion to protect relative jump offsets and sanitize execution
- Expand automated test harness with Fedora/Bazzite PAM stack, idempotency, and symlink verification

* Tue Nov 03 2026 Secure PIN Maintainers <steace@coderage.pro> - 1.0.5-1
- Enforce best coding practices, compiler security flags, and static analysis recommendations
- Securely cleanse sensitive cryptographic structures, derived PIN auth, and plaintext keys from memory
- Overwrite credential blobs with zeroes before unlinking to eliminate raw storage remnants
- Enforce strict 0700 file and directory permissions and atomic creation with O_EXCL
- Expand PAM service deny-list to reject remote authentication protocols (telnet, dropbear, xrdp, vnc)
- Preserve original PAM configuration file modes and secure PAM backups
- Polish GTK4/Libadwaita settings app with focus advancement on Enter and sanitize secret entries

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
