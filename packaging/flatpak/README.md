# Flatpak Packaging for Secure PIN Settings

This directory contains the Flatpak manifest and build scripts for packaging the Secure PIN Settings graphical application (`io.github.securepin.Settings`).

---

## Architecture & Integration Model

Secure PIN for Linux consists of two components:

1. **Core System Services & PAM Module**: The TPM 2.0 security engine, PAM module (`pam_tpm_pin.so`), and CLI utility (`tpm-pin-ctl`) run directly on the host operating system to handle authentication during boot, desktop lock, and terminal `sudo`.
2. **Graphical Settings Application**: A native GTK4 / Libadwaita preferences application (`tpm-pin-settings`) that can be distributed as a sandboxed Flatpak.

### How Sandbox Host Integration Works

Because PAM modules cannot be loaded into host services from inside a sandbox, the Flatpak application uses the standard FreeDesktop Flatpak portal:

- Manifest grants `--talk-name=org.freedesktop.Flatpak`.
- The GUI detects its containerized environment via `/.flatpak-info` or `FLATPAK_ID`.
- System queries (`tpm-pin-ctl status --json`) and root configurations (`pkexec tpm-pin-ctl ...`) are executed on the host system via `flatpak-spawn --host`.
- Polkit authentication prompts are handled seamlessly by the host desktop session.

---

## Files

- `io.github.securepin.Settings.yml`: Standard Flatpak builder manifest using GNOME runtime.
- `build-flatpak.sh`: Automation script for building, testing, installing, and bundling.

---

## Building Locally

### 1. Prerequisites

Ensure `flatpak` and `flatpak-builder` are installed:

- **Debian / Ubuntu**:

  ```bash
  sudo apt install flatpak flatpak-builder
  ```

- **Fedora / RHEL**:

  ```bash
  sudo dnf install flatpak flatpak-builder
  ```

- **Arch Linux**:

  ```bash
  sudo pacman -S flatpak flatpak-builder
  ```

### 2. Install GNOME Runtime & SDK

```bash
flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install --user flathub org.gnome.Platform//50 org.gnome.Sdk//50
```

### 3. Build & Install Using Helper Script

Build and install directly into user applications:

```bash
./packaging/flatpak/build-flatpak.sh --install
```

Build and generate a distributable `.flatpak` single-file bundle:

```bash
./packaging/flatpak/build-flatpak.sh --bundle
```

Launch the installed Flatpak:

```bash
flatpak run io.github.securepin.Settings
```

### 4. Manual Build with `flatpak-builder`

```bash
# Build into local directory
flatpak-builder --user --install --force-clean build-flatpak packaging/flatpak/io.github.securepin.Settings.yml

# Or export to repository and create bundle
flatpak-builder --force-clean --repo=flatpak-repo build-flatpak packaging/flatpak/io.github.securepin.Settings.yml
flatpak build-bundle flatpak-repo dist/io.github.securepin.Settings.flatpak io.github.securepin.Settings
```
