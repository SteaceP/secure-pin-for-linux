---
name: Issue Report
about: Report a bug, request a feature, or report a TPM/PAM integration issue
title: ''
labels: ''
assignees: ''
---

<!--
Thank you for reporting an issue or suggestion for Secure PIN for Linux!
Please complete the relevant sections below.

SECURITY NOTE:
Do NOT post plain passwords, PINs, unencrypted private keys, or confidential secrets.
-->

## Issue Type

- [ ] Bug Report
- [ ] Feature Request / Enhancement
- [ ] TPM 2.0 / Hardware Compatibility Issue
- [ ] PAM / Desktop Keyring Integration Issue
- [ ] Documentation / Packaging Issue

---

### Description

<!-- Provide a clear and concise summary of the issue or feature request. -->

---

### Environment Information

<!-- Please fill in the details of your system environment: -->

- **Linux Distribution & Version**: (e.g., Ubuntu 24.04 LTS, Fedora 41, Arch Linux)
- **Kernel Version** (`uname -r`):
- **Secure PIN Version** (`tpm-pin-ctl --version` or package version):
- **TPM Device & Hardware**: (e.g., discrete TPM 2.0, fTPM/Intel PTT, AMD fTPM, swtpm emulator)
- **TPM Status Output** (`tpm-pin-ctl status`):

  ```text
  (paste output here)
  ```

- **Desktop Environment & Display Manager**: (e.g., GNOME 46 / GDM, KDE Plasma 6 / SDDM)
- **Installation Method**: (e.g., `.deb`, `.rpm`, Arch AUR / `PKGBUILD`, compiled from source)

---

### Steps to Reproduce

<!-- If reporting a bug, list the exact steps required to reproduce the behavior: -->

1.
2.
3.

---

### Expected Behavior

<!-- What did you expect to happen? -->

---

### Actual Behavior

<!-- What actually happened? Include error messages or unexpected behavior. -->

---

### Relevant Logs / Diagnostics

<!--
Include relevant terminal output or journal logs where applicable:
- Journal logs: journalctl -b -t pam_tpm_pin
- System auth log: /var/log/auth.log or journalctl -u systemd-logind
-->

<details>
<summary>Click to view logs</summary>

```text
(paste sanitized logs here)
```

</details>

---

### Additional Context

<!-- Add any other context, hardware specifications, or screenshots about the problem here. -->
