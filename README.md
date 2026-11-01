# Secure PIN for Linux (`tpm-pin`)

> [!WARNING]
> **Early Development / Use at Your Own Risk**
> This project is in an early stage of development and directly modifies low-level PAM authentication stacks and system security settings. Use at your own risk. It is strongly recommended to test inside a virtual machine or non-production environment first, and to always have alternative root access or recovery media available.

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
- **Cross-Distribution & Packaging Support**:
  - Debian / Ubuntu (`.deb`, `pam-auth-update` profile).
  - Fedora / RHEL / CentOS (`.rpm`, `system-auth` / `password-auth`).
  - Arch Linux (`PKGBUILD`).
  - Flatpak bundle (`io.github.securepin.Settings`) for sandboxed desktop environments.
  - Universal CMake build system.

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

Alternatively, you can build and install manually with CMake:

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```

> [!NOTE]
> **PAM Activation on New Installs**:
>
> - **Distribution packages (`.deb`, `.rpm`, Arch `PKGBUILD`)**: Package maintainer scripts automatically register and activate the PAM configuration with safe relative jumps on installation.
> - **Installed from source (`make install`)**: PAM integration is not enabled automatically. You must activate it after installation using either:
>
>   ```bash
>   sudo tpm-pin-ctl pam enable
>   ```
>
>   or by toggling **"Enable TPM PIN in PAM"** in the GTK Settings application (`tpm-pin-settings`).

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

*(Note: Automatically activated when installed via `.deb`, `.rpm`, or Arch package).*

When installed from source, safely activate TPM PIN authentication across login, lockscreen, and `sudo` using:

```bash
sudo tpm-pin-ctl pam enable
# or from build tree: sudo ./build/tpm-pin-ctl pam enable
```

To disable and revert PAM configuration:

```bash
sudo ./build/tpm-pin-ctl pam disable
```
---

## Contributing

Contributions, bug reports, and pull requests are welcome. Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing workflows, and coding standards.

---

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) for details.
