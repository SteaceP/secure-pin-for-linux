# Secure PIN for Linux (`tpm-pin`)

A Windows Hello–style, hardware-backed PIN authentication system for Linux using **TPM 2.0**.

It integrates with **PAM** (login screen, lock screen, `sudo`, and Polkit), automatically unseals and unlocks the desktop **GNOME Keyring / KWallet**, enforces TPM **Dictionary Attack (anti-hammering) lockout**, supports **Secure Boot (PCR 7)** integrity binding, and includes a native **GTK4 / Libadwaita Settings Application**.

---

## Features

- **Hardware-Backed Security (TPM 2.0)**:
  - Master encryption keys sealed inside a TPM 2.0 `KEYEDHASH` object under the Primary Storage Hierarchy (`TPM2_RH_OWNER`).
  - Hardware **Dictionary Attack (DA) protection**: TPM rate-limits and hardware-locks attempts on repeated incorrect PIN entries.
  - Optional **PCR 7 binding**: Pin validity bound to UEFI Secure Boot firmware and bootloader integrity.
- **Unified Authentication Experience**:
  - Unified `"PIN or Password: "` prompt across `sudo`, GDM/SDDM login screen, and screen locker.
  - Intelligent fallback: typing your standard system password does not waste TPM DA attempts and seamlessly authenticates via standard PAM (`pam_unix.so try_first_pass`) without asking twice.
  - **Desktop Keyring Auto-Unlock**: Sealing your login password in the TPM enables automatic GNOME Keyring / KWallet unlocking on boot login.
- **Native GTK4 / Libadwaita Settings App**:
  - Matches the GNOME Settings look and feel (`AdwPreferencesWindow`).
  - Configure PIN enrollment, change/remove PIN, per-service toggles (`sudo`, login screen, lock screen, keyring auto-unlock), PIN complexity policies (digits-only vs. alphanumeric, min/max length), and reset TPM lockout counters.
  - Registers under `Settings;System;Security;` in application launchers.
- **Cross-Distribution Support**:
  - Debian / Ubuntu (`.deb`, `pam-auth-update` profile).
  - Fedora / RHEL / CentOS (`.rpm`, `system-auth` / `password-auth`).
  - Arch Linux (`PKGBUILD`).
  - Universal CMake build system.

---

## Directory Structure

```text
secure-pin-for-linux/
├── CMakeLists.txt                # Universal CMake build & CPack configuration
├── include/                      # Core APIs and TSS2/PAM compatibility headers
│   ├── tpm_pin.h
│   ├── security/                 # PAM headers
│   └── tss2/                     # TPM 2.0 ESYS & TCTI headers
├── src/
│   ├── common/
│   │   ├── crypto.c              # OpenSSL AES-256-GCM & PBKDF2-HMAC-SHA256
│   │   ├── policy.c              # PIN validation & candidate policy filtering
│   │   ├── config.c              # /etc/tpm-pin/config.conf parser & writer
│   │   ├── pam_config_manager.c  # Distro-aware PAM manager & safe backups
│   │   └── user_manager.c        # User enrollment, TPM sealing & unsealing
│   ├── tpm/
│   │   └── tpm_engine.c          # ESYS primary key creation, sealing & DA control
│   ├── pam/
│   │   └── pam_tpm_pin.c         # PAM module (authenticate, setcred, chauthtok)
│   └── cli/
│       ├── tpm_pin_ctl.c         # Command-line control & admin tool
│       └── tpm_pin_verify.c      # Minimal lockscreen verification helper
├── gui/
│   ├── tpm-pin-settings          # GTK4 / Libadwaita settings application
│   ├── io.github.securepin.Settings.desktop
│   ├── io.github.securepin.policy
│   └── gnome-extension/          # GNOME Shell quick-settings toggle
├── packaging/
│   ├── pam-configs/tpm-pin       # pam-auth-update profile for Debian/Ubuntu
│   ├── debian/                   # Debian package metadata
│   ├── rpm/tpm-pin.spec          # RPM spec file for Fedora/RHEL
│   └── arch/PKGBUILD             # Arch Linux PKGBUILD
└── tests/
    ├── test_pam_harness.c        # Automated unit & integration tests
    └── run_tests.sh              # swtpm/TPM test runner
```

---

## Building & Testing

### 1. Prerequisites

- **Debian / Ubuntu**:

  ```bash
  sudo apt install cmake gcc pkg-config libssl-dev libpam0g python3 python3-gi gir1.2-adw-1 libtss2-esys-3.0.2-0t64 swtpm
  ```

- **Fedora / RHEL**:

  ```bash
  sudo dnf install cmake gcc pkgconfig openssl-devel pam-devel tpm2-tss-devel python3 python3-gobject libadwaita swtpm
  ```

- **Arch Linux**:

  ```bash
  sudo pacman -S cmake gcc pkgconf openssl pam tpm2-tss python python-gobject libadwaita swtpm
  ```

- **TPM 2.0 User Permissions (`tss` group)**:

  To query TPM status or run CLI commands as a non-root user, ensure your account is in the `tss` group:

  ```bash
  sudo usermod -aG tss $USER
  newgrp tss # or log out and log back in
  ```

  *(Note: Installing `.deb`, `.rpm`, or Arch packages automatically configures a `uaccess` udev rule for desktop sessions).*

### 2. Build & Package Locally

Use the build script to compile the project and generate distribution packages into `dist/`:

```bash
# Build binaries and all release packages (.deb, .rpm, .tar.gz) into ./dist
./build.sh

# Or compile binaries only without packaging:
./build.sh --no-package

# Or clean build outputs and rebuild:
./build.sh --clean
```

Alternatively, you can build manually with CMake:

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### 3. Run Automated Tests

The test suite runs against your hardware TPM (if `/dev/tpmrm0` is available) or automatically starts an isolated `swtpm` TPM 2.0 instance:

```bash
./tests/run_tests.sh
```

---

## Usage

### 1. View Status

```bash
./build/tpm-pin-ctl status
```

Or JSON format (used by the settings GUI):

```bash
./build/tpm-pin-ctl status --json
```

### 2. Enroll a PIN

```bash
./build/tpm-pin-ctl enroll
```

You will be prompted for your current login password (to seal for desktop keyring auto-unlock) and your new PIN.

### 3. Verify PIN against TPM 2.0

```bash
./build/tpm-pin-ctl verify
```

### 4. Launch the GUI Settings Application

```bash
./gui/tpm-pin-settings
```

### 5. Enable System-Wide PAM Integration

To safely activate TPM PIN authentication across login, lockscreen, and `sudo`:

```bash
sudo ./build/tpm-pin-ctl pam enable
```

To disable and revert PAM configuration:

```bash
sudo ./build/tpm-pin-ctl pam disable
```

---

## Distribution Packaging

The easiest way to generate all packages locally is via the build script, which outputs to `dist/` and computes SHA-256 checksums:

```bash
./build.sh
```

To build individual packages manually:

  ```bash
  cd build && cpack -G DEB
  ```

- **Build `.tar.gz` package**:

  ```bash
  cd build && cpack -G TGZ
  ```

- **Build `.rpm` package** (on Fedora/RHEL):

  ```bash
  cd build && cpack -G RPM
  # or using rpmbuild:
  rpmbuild -ba packaging/rpm/tpm-pin.spec
  ```

- **Build on Arch Linux**:

  ```bash
  cd packaging/arch && makepkg -si
  ```

- **Automated CI/CD & GitHub Releases**:

  Pushing a version tag (e.g. `git tag v1.0.1 && git push origin v1.0.1`) or running the **Publish Packages** action manually triggers the GitHub Actions workflow, which automatically compiles and publishes `.deb`, `.rpm`, `.pkg.tar.zst`, `.tar.gz`, and `SHA256SUMS.txt` to GitHub Releases.

---

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) for details.
