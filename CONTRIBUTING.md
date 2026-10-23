# Contributing to Secure PIN for Linux

Thank you for your interest in contributing to Secure PIN for Linux (`tpm-pin`). This project provides a hardware-backed authentication system for Linux leveraging TPM 2.0 and PAM.

Because this project touches security-sensitive PAM authentication flows, cryptographic key management, and hardware security modules, contributions must adhere to rigorous security, testing, and reliability standards.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Development Setup](#development-setup)
  - [Prerequisites](#prerequisites)
  - [TPM Access & Permissions](#tpm-access--permissions)
- [Building and Testing](#building-and-testing)
  - [Compiling from Source](#compiling-from-source)
  - [Running the Automated Test Suite](#running-the-automated-test-suite)
  - [Building Release Packages](#building-release-packages)
- [Code & Security Guidelines](#code--security-guidelines)
  - [C Code Standards](#c-code-standards)
  - [Memory and Cryptographic Safety](#memory-and-cryptographic-safety)
  - [PAM Module Safety](#pam-module-safety)
  - [Python / GUI Standards](#python--gui-standards)
- [Commit Message Conventions](#commit-message-conventions)
- [Pull Request Process](#pull-request-process)

---

## Code of Conduct

All contributors and participants are expected to maintain a constructive, respectful, and professional environment. Focus on constructive feedback, technical excellence, and collaborative problem-solving.

---

## Reporting Issues

Before opening a new issue:

1. Search existing issues and pull requests to ensure the problem has not already been reported or resolved.
2. Verify that your system's TPM 2.0 is functional (`/dev/tpmrm0` exists and user is in the `tss` group).
3. If reporting a bug, provide:
   - Linux distribution, version, and kernel release (`uname -r`).
   - TPM hardware vendor, model, or emulator status (`tpm-pin-ctl status`).
   - Desktop environment and display manager (e.g., GNOME / GDM, KDE / SDDM).
   - Clear steps to reproduce the issue.
   - Relevant sanitized logs (`journalctl`, auth logs).

> [!CAUTION]
> Never post raw cryptographic secrets, unencrypted memory dumps, or actual passwords/PINs in public issue trackers.

---

## Security Vulnerabilities

Please **do not** report security vulnerabilities via public GitHub issues.

If you discover a potential vulnerability (e.g., authentication bypass, privilege escalation, secret leakage, or timing side-channel), report it privately through GitHub Private Vulnerability Reporting or contact the maintainers directly through private security channels. Provide a proof of concept and detailed reproduction steps so a fix can be verified before disclosure.

---

## Development Setup

### Prerequisites

Install the required build tools, cryptographic libraries, PAM development headers, and TPM 2.0 libraries for your distribution:

- **Debian / Ubuntu**:

  ```bash
  sudo apt install cmake gcc pkg-config libssl-dev libpam0g-dev libtss2-dev swtpm swtpm-tools python3 python3-gi gir1.2-adw-1
  ```

- **Fedora / RHEL**:

  ```bash
  sudo dnf install cmake gcc pkgconfig openssl-devel pam-devel tpm2-tss-devel python3 python3-gobject libadwaita swtpm
  ```

- **Arch Linux**:

  ```bash
  sudo pacman -S cmake gcc pkgconf openssl pam tpm2-tss python python-gobject libadwaita swtpm
  ```

### TPM Access & Permissions

For non-root interaction with TPM hardware during development, ensure your user belongs to the `tss` group:

```bash
sudo usermod -aG tss $USER
newgrp tss
```

The automated test suite will automatically prefer `swtpm` (software TPM) when available to prevent consuming hardware TPM Dictionary Attack attempts during rapid iteration.

---

## Building and Testing

### Compiling from Source

Using the provided build script:

```bash
# Build binaries in debug mode without packaging:
./build.sh --no-package

# Or clean and rebuild:
./build.sh --clean
```

Or manually using CMake:

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### Running the Automated Test Suite

Always execute the automated test suite prior to submitting any pull request:

```bash
./tests/run_tests.sh
```

The test runner will:

1. Compile the latest code in debug mode.
2. Perform syntax validation on the Python GTK4 settings application.
3. Launch an isolated TPM 2.0 instance via `swtpm` on localhost.
4. Execute `test_pam_harness` verifying crypto operations, TPM sealing/unsealing, policy checks, and PAM flows.
5. Run smoke tests on the CLI utility (`tpm-pin-ctl`).

### Building Release Packages

To verify package creation across formats:

```bash
./build.sh
```

Generated packages (`.deb`, `.rpm`, `.tar.gz`) will be placed into the `dist/` directory.

---

## Code & Security Guidelines

### C Code Standards

- Write clean, standards-compliant C (C99 / C11).
- Compile without warnings (`-Wall -Wextra -Werror`).
- Ensure all resources (memory allocations, file descriptors, TSS2 contexts, OpenSSL contexts) are freed along every return and error path.
- Check return codes on all system calls, library invocations, and I/O operations.
- Avoid variable-length arrays (VLAs) on the stack for untrusted input sizes.

### Memory and Cryptographic Safety

- Always wipe sensitive data (PINs, passwords, derived keys, AES keys, plaintext buffers) using `tpm_pin_zero()` or `OPENSSL_cleanse()` before freeing or exiting the scope.
- Use constant-time comparison (`CRYPTO_memcmp`) when comparing cryptographic hashes or authentication tokens.
- Secure file operations: state directories (`/var/lib/tpm-pin`) and configurations (`/etc/tpm-pin`) must be created with strict permissions (`0700` and `0600`) owned by root.
- Never write credentials, PIN candidates, or plaintext authentication material to log files, standard output, or syslog.

### PAM Module Safety

- Code within `src/pam/pam_tpm_pin.c` executes inside host processes (login managers, `sudo`, screen lockers). It must be crash-resilient and never terminate the host process (`exit()`, `abort()`).
- Always preserve PAM fallback semantics: if a candidate is not a PIN or if PIN verification fails, control must flow safely back to fallback modules (`pam_unix.so try_first_pass`) without crashing or leaving the terminal in a broken state.
- Keep the PAM module minimal and free of unnecessary external runtime dependencies.

### Python / GUI Standards

- The settings application (`gui/tpm-pin-settings`) is written in Python with GTK4 and Libadwaita.
- Follow PEP 8 style standards.
- Run `python3 -m py_compile gui/tpm-pin-settings` to verify syntax.
- Ensure privileged actions use Polkit (`pkexec`) and handle failure or cancellation gracefully without hanging the UI.

---

## Commit Message Conventions

Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```text
<type>(<scope>): <short description>
```

### Common Types

- `feat`: A new feature or user-facing enhancement.
- `fix`: A bug fix or security patch.
- `docs`: Documentation changes.
- `refactor`: Code reorganization without functional changes.
- `test`: Adding or improving tests.
- `chore`: Build system, packaging, or maintenance updates.

### Examples

- `feat(pam): add candidate policy heuristic for alphanumeric PINs`
- `fix(tpm): clear auth session context on unseal failure`
- `chore: bump version to 1.0.4`

---

## Pull Request Process

1. Fork the repository and create a feature branch off `main`.
2. Make your modifications following the guidelines above.
3. Ensure automated tests pass:

   ```bash
   ./tests/run_tests.sh
   ```

4. Verify that packaging builds without errors:

   ```bash
   ./build.sh
   # Or to test the Flatpak build:
   ./packaging/flatpak/build-flatpak.sh --bundle
   ```

5. Open a Pull Request against `main`. Provide a clear description of the problem solved, the implementation details, and any test results.
