#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include "tpm_pin.h"

#define KEYRING_BLOCK_BEGIN "# BEGIN tpm-pin-keyring"
#define KEYRING_BLOCK_END   "# END tpm-pin-keyring"

static linux_distro_t match_distro_token(const char *val) {
    if (!val || val[0] == '\0') return DISTRO_UNKNOWN;
    if (strstr(val, "arch") || strstr(val, "cachyos") || strstr(val, "manjaro") ||
        strstr(val, "endeavouros") || strstr(val, "garuda") || strstr(val, "artix") ||
        strstr(val, "arcolinux")) {
        return DISTRO_ARCH;
    }
    if (strstr(val, "ubuntu") || strstr(val, "debian") || strstr(val, "pop") ||
        strstr(val, "mint") || strstr(val, "kali")) {
        return DISTRO_DEBIAN_UBUNTU;
    }
    if (strstr(val, "fedora") || strstr(val, "rhel") || strstr(val, "centos") ||
        strstr(val, "almalinux") || strstr(val, "rocky") || strstr(val, "nobara")) {
        return DISTRO_FEDORA_RHEL;
    }
    if (strstr(val, "opensuse") || strstr(val, "suse")) {
        return DISTRO_OPENSUSE;
    }
    return DISTRO_UNKNOWN;
}

linux_distro_t pam_manager_detect_distro_from_file(const char *os_release_path) {
    const char *path = os_release_path ? os_release_path : "/etc/os-release";
    FILE *f = fopen(path, "r");
    if (!f) return DISTRO_GENERIC;

    char line[256];
    char id_buf[256] = {0};
    char id_like_buf[256] = {0};

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "ID=", 3) == 0) {
            snprintf(id_buf, sizeof(id_buf), "%s", line + 3);
        } else if (strncmp(line, "ID_LIKE=", 8) == 0) {
            snprintf(id_like_buf, sizeof(id_like_buf), "%s", line + 8);
        }
    }
    fclose(f);

    for (size_t i = 0; id_buf[i]; i++) id_buf[i] = (char)tolower((unsigned char)id_buf[i]);
    for (size_t i = 0; id_like_buf[i]; i++) id_like_buf[i] = (char)tolower((unsigned char)id_like_buf[i]);

    linux_distro_t d = match_distro_token(id_buf);
    if (d != DISTRO_UNKNOWN) return d;

    d = match_distro_token(id_like_buf);
    if (d != DISTRO_UNKNOWN) return d;

    return DISTRO_GENERIC;
}

linux_distro_t pam_manager_detect_distro(void) {
    return pam_manager_detect_distro_from_file("/etc/os-release");
}

const char *pam_manager_distro_name(linux_distro_t distro) {
    switch (distro) {
        case DISTRO_DEBIAN_UBUNTU: return "Debian/Ubuntu";
        case DISTRO_FEDORA_RHEL:   return "Fedora/RHEL";
        case DISTRO_ARCH:          return "Arch Linux";
        case DISTRO_OPENSUSE:      return "openSUSE";
        default:                   return "Generic Linux";
    }
}

static bool is_pam_type_line(const char *line, const char *type_name) {
    if (!line || !type_name) return false;
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '-') p++;
    size_t tlen = strlen(type_name);
    if (strncmp(p, type_name, tlen) == 0 && (p[tlen] == ' ' || p[tlen] == '\t')) {
        return true;
    }
    return false;
}

static bool is_auth_rule_line(const char *line) {
    return is_pam_type_line(line, "auth");
}

static bool file_contains_auth_module(const char *filepath, const char *module_name) {
    FILE *f = fopen(filepath, "r");
    if (!f) return false;
    char line[1024];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (is_auth_rule_line(line) && strstr(line, module_name)) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

bool pam_manager_is_enabled(void) {
    if (file_contains_auth_module("/etc/pam.d/common-auth", "pam_tpm_pin.so")) return true;
    if (file_contains_auth_module("/etc/pam.d/system-auth", "pam_tpm_pin.so")) return true;
    if (file_contains_auth_module("/etc/pam.d/password-auth", "pam_tpm_pin.so")) return true;
    return false;
}

static bool create_backup(const char *filepath, char *backup_out, size_t backup_len) {
    if (geteuid() != 0) return false;

    time_t now = time(NULL);
    char dir[256];
    snprintf(dir, sizeof(dir), "/etc/tpm-pin/pam-backups/%ld", (long)now);
    mkdir("/etc/tpm-pin", 0755);
    mkdir("/etc/tpm-pin/pam-backups", 0755);
    mkdir(dir, 0755);

    const char *basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;

    snprintf(backup_out, backup_len, "%s/%s", dir, basename);

    FILE *src = fopen(filepath, "r");
    if (!src) return false;
    FILE *dst = fopen(backup_out, "w");
    if (!dst) { fclose(src); return false; }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) {
            fclose(src);
            fclose(dst);
            return false;
        }
    }
    fclose(src);
    fclose(dst);
    return true;
}

static bool insert_pam_rule(const char *filepath, const char *rule, const char *before_needle) {
    char backup[512];
    create_backup(filepath, backup, sizeof(backup));

    FILE *in = fopen(filepath, "r");
    if (!in) return false;

    char tmp_file[512];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tpm_tmp.%d", filepath, (int)getpid());
    int fd = open(tmp_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) {
        fclose(in);
        return false;
    }
    FILE *out = fdopen(fd, "w");
    if (!out) {
        close(fd);
        unlink(tmp_file);
        fclose(in);
        return false;
    }

    char line[1024];
    bool inserted = false;
    bool needle_exists = before_needle ? file_contains_auth_module(filepath, before_needle) : false;

    if (!needle_exists) {
        /* Prepend at the beginning of the auth stack if before_needle isn't found */
        fprintf(out, "%s\n", rule);
        inserted = true;
    }

    while (fgets(line, sizeof(line), in)) {
        if (!inserted && before_needle &&
            is_auth_rule_line(line) &&
            strstr(line, before_needle) &&
            !strstr(line, "pam_tpm_pin.so")) {
            const char *succ = strstr(line, "success=");
            if (succ) {
                int jump_val = atoi(succ + 8);
                if (jump_val > 0) {
                    fprintf(out, "auth\t[success=%d authinfo_unavail=ignore open_err=ignore default=ignore]\tpam_tpm_pin.so\n", jump_val + 1);
                } else {
                    fprintf(out, "%s\n", rule);
                }
            } else {
                fprintf(out, "%s\n", rule);
            }
            inserted = true;
        }
        if (!(is_auth_rule_line(line) && strstr(line, "pam_tpm_pin.so"))) {
            fputs(line, out);
        }
    }

    fclose(in);
    if (ferror(out) || fflush(out) != 0 || fsync(fd) != 0) {
        fclose(out);
        unlink(tmp_file);
        return false;
    }
    if (fclose(out) != 0) {
        unlink(tmp_file);
        return false;
    }

    chmod(tmp_file, 0644);
    if (rename(tmp_file, filepath) != 0) {
        unlink(tmp_file);
        return false;
    }
    return true;
}

bool pam_manager_apply_auth_file(const char *filepath) {
    if (!filepath) return false;
    const char *rule = "auth [success=1 authinfo_unavail=ignore open_err=ignore default=ignore] pam_tpm_pin.so";
    /*
     * On Arch Linux (pambase), -auth [success=2 default=ignore] pam_systemd_home.so
     * immediately precedes pam_unix.so with a relative jump over pam_unix.so and pam_faillock.so.
     * Inserting before pam_systemd_home.so (with success=3) preserves pam_systemd_home.so's jump
     * while skipping pam_systemd_home.so, pam_unix.so, and pam_faillock.so authfail on PIN success.
     */
    const char *anchor = file_contains_auth_module(filepath, "pam_systemd_home.so")
                         ? "pam_systemd_home.so"
                         : "pam_unix.so";
    return insert_pam_rule(filepath, rule, anchor);
}

bool pam_manager_remove_from_file(const char *filepath) {
    if (!filepath) return false;
    if (!file_contains_auth_module(filepath, "pam_tpm_pin.so")) return true;

    char backup[512];
    create_backup(filepath, backup, sizeof(backup));

    FILE *in = fopen(filepath, "r");
    if (!in) return false;

    char tmp_file[512];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tpm_tmp.%d", filepath, (int)getpid());
    int fd = open(tmp_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) {
        fclose(in);
        return false;
    }
    FILE *out = fdopen(fd, "w");
    if (!out) {
        close(fd);
        unlink(tmp_file);
        fclose(in);
        return false;
    }

    char line[1024];
    while (fgets(line, sizeof(line), in)) {
        if (!(is_auth_rule_line(line) && strstr(line, "pam_tpm_pin.so"))) {
            fputs(line, out);
        }
    }

    fclose(in);
    if (ferror(out) || fflush(out) != 0 || fsync(fd) != 0) {
        fclose(out);
        unlink(tmp_file);
        return false;
    }
    if (fclose(out) != 0) {
        unlink(tmp_file);
        return false;
    }

    chmod(tmp_file, 0644);
    if (rename(tmp_file, filepath) != 0) {
        unlink(tmp_file);
        return false;
    }
    return true;
}

bool pam_manager_configure_arch_keyring_file(const char *filepath, bool enable) {
    if (!filepath) return false;
    if (access(filepath, R_OK | W_OK) != 0) return true;

    FILE *scan = fopen(filepath, "r");
    if (!scan) return false;

    bool in_block = false;
    bool had_block = false;
    bool has_unmanaged_gkr = false;
    bool has_unmanaged_kw = false;
    char line[1024];

    while (fgets(line, sizeof(line), scan)) {
        if (strncmp(line, KEYRING_BLOCK_BEGIN, strlen(KEYRING_BLOCK_BEGIN)) == 0) {
            in_block = true;
            had_block = true;
            continue;
        }
        if (strncmp(line, KEYRING_BLOCK_END, strlen(KEYRING_BLOCK_END)) == 0) {
            in_block = false;
            continue;
        }
        if (!in_block) {
            const char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p != '#') {
                if (strstr(p, "pam_gnome_keyring.so")) has_unmanaged_gkr = true;
                if (strstr(p, "pam_kwallet5.so")) has_unmanaged_kw = true;
            }
        }
    }
    fclose(scan);

    if (!enable && !had_block) {
        return true;
    }
    if (enable && has_unmanaged_gkr && has_unmanaged_kw && !had_block) {
        return true;
    }

    char backup[512];
    create_backup(filepath, backup, sizeof(backup));

    FILE *in = fopen(filepath, "r");
    if (!in) return false;

    char tmp_file[512];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tpm_kr_tmp.%d", filepath, (int)getpid());
    int fd = open(tmp_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) {
        fclose(in);
        return false;
    }
    FILE *out = fdopen(fd, "w");
    if (!out) {
        close(fd);
        unlink(tmp_file);
        fclose(in);
        return false;
    }

    in_block = false;
    bool inserted_auth = false;
    bool inserted_session = false;

    while (fgets(line, sizeof(line), in)) {
        if (strncmp(line, KEYRING_BLOCK_BEGIN, strlen(KEYRING_BLOCK_BEGIN)) == 0) {
            in_block = true;
            continue;
        }
        if (strncmp(line, KEYRING_BLOCK_END, strlen(KEYRING_BLOCK_END)) == 0) {
            in_block = false;
            continue;
        }
        if (in_block) {
            continue;
        }

        fputs(line, out);

        if (enable && (!has_unmanaged_gkr || !has_unmanaged_kw)) {
            if (!inserted_auth && is_pam_type_line(line, "auth") && strstr(line, "system-login")) {
                fprintf(out, "%s\n", KEYRING_BLOCK_BEGIN);
                if (!has_unmanaged_gkr) fprintf(out, "-auth      optional   pam_gnome_keyring.so\n");
                if (!has_unmanaged_kw)  fprintf(out, "-auth      optional   pam_kwallet5.so\n");
                fprintf(out, "%s\n", KEYRING_BLOCK_END);
                inserted_auth = true;
            } else if (!inserted_session && is_pam_type_line(line, "session") && strstr(line, "system-login")) {
                fprintf(out, "%s\n", KEYRING_BLOCK_BEGIN);
                if (!has_unmanaged_gkr) fprintf(out, "-session   optional   pam_gnome_keyring.so auto_start\n");
                if (!has_unmanaged_kw)  fprintf(out, "-session   optional   pam_kwallet5.so auto_start\n");
                fprintf(out, "%s\n", KEYRING_BLOCK_END);
                inserted_session = true;
            }
        }
    }

    fclose(in);
    if (ferror(out) || fflush(out) != 0 || fsync(fd) != 0) {
        fclose(out);
        unlink(tmp_file);
        return false;
    }
    if (fclose(out) != 0) {
        unlink(tmp_file);
        return false;
    }

    chmod(tmp_file, 0644);
    if (rename(tmp_file, filepath) != 0) {
        unlink(tmp_file);
        return false;
    }
    return true;
}

static bool configure_polkit_and_udev_overrides(bool enable) {
    const char *dropin_dir = "/etc/systemd/system/polkit-agent-helper@.service.d";
    const char *dropin_file = "/etc/systemd/system/polkit-agent-helper@.service.d/tpm-pin.conf";
    const char *etc_udev_rule = "/etc/udev/rules.d/70-tpm-pin.rules";

    if (enable) {
        mkdir("/etc/systemd", 0755);
        mkdir("/etc/systemd/system", 0755);
        if (mkdir(dropin_dir, 0755) != 0 && errno != EEXIST) {
            return false;
        }

        FILE *f = fopen(dropin_file, "w");
        if (!f) return false;

        fprintf(f, "[Service]\n"
                   "PrivateDevices=no\n"
                   "DeviceAllow=/dev/tpmrm0 rw\n"
                   "DeviceAllow=/dev/tpm0 rw\n"
                   "DeviceAllow=char-tpm rw\n"
                   "StandardError=journal\n");
        fclose(f);
        chmod(dropin_file, 0644);

        /* Ensure uaccess udev rule exists even when running from a source build */
        if (access("/usr/lib/udev/rules.d/70-tpm-pin.rules", R_OK) != 0 &&
            access("/lib/udev/rules.d/70-tpm-pin.rules", R_OK) != 0) {
            mkdir("/etc/udev", 0755);
            mkdir("/etc/udev/rules.d", 0755);
            FILE *uf = fopen(etc_udev_rule, "w");
            if (uf) {
                fprintf(uf, "# Managed by tpm-pin\n"
                            "KERNEL==\"tpmrm[0-9]*\", TAG+=\"uaccess\"\n");
                fclose(uf);
                chmod(etc_udev_rule, 0644);
            }
        }
    } else {
        unlink(dropin_file);
        rmdir(dropin_dir);
        unlink(etc_udev_rule);
    }

    if (access("/bin/systemctl", X_OK) == 0 || access("/usr/bin/systemctl", X_OK) == 0) {
        int ret = system("systemctl daemon-reload >/dev/null 2>&1");
        (void)ret;
    }

    if (access("/bin/udevadm", X_OK) == 0 || access("/usr/bin/udevadm", X_OK) == 0) {
        int ret = system("udevadm control --reload >/dev/null 2>&1 && "
                         "udevadm trigger --action=change --subsystem-match=tpmrm >/dev/null 2>&1");
        (void)ret;
    }
    return true;
}

bool pam_manager_enable(const tpm_pin_config_t *cfg, char *err_buf, size_t err_len) {
    linux_distro_t distro = pam_manager_detect_distro();
    bool enabled = false;

    if (distro == DISTRO_DEBIAN_UBUNTU) {
        /* If pam-auth-update profile exists, apply it non-interactively */
        if (access("/usr/share/pam-configs/tpm-pin", R_OK) == 0 && access("/usr/sbin/pam-auth-update", X_OK) == 0) {
            int ret = system("/usr/sbin/pam-auth-update --package --force >/dev/null 2>&1");
            if (ret == 0 && pam_manager_is_enabled()) {
                enabled = true;
            }
        }
        /* Fallback: direct safe insertion in /etc/pam.d/common-auth */
        if (!enabled && faccessat(AT_FDCWD, "/etc/pam.d/common-auth", W_OK, AT_EACCESS) == 0) {
            enabled = pam_manager_apply_auth_file("/etc/pam.d/common-auth");
        }
    } else if (distro == DISTRO_FEDORA_RHEL) {
        bool ok = true;
        if (faccessat(AT_FDCWD, "/etc/pam.d/system-auth", W_OK, AT_EACCESS) == 0) {
            ok = pam_manager_apply_auth_file("/etc/pam.d/system-auth");
        }
        if (faccessat(AT_FDCWD, "/etc/pam.d/password-auth", W_OK, AT_EACCESS) == 0) {
            ok = ok && pam_manager_apply_auth_file("/etc/pam.d/password-auth");
        }
        enabled = ok;
    } else if (distro == DISTRO_OPENSUSE) {
        if (faccessat(AT_FDCWD, "/etc/pam.d/common-auth", W_OK, AT_EACCESS) == 0) {
            enabled = pam_manager_apply_auth_file("/etc/pam.d/common-auth");
        }
    } else {
        /* Arch Linux or Generic */
        if (faccessat(AT_FDCWD, "/etc/pam.d/system-auth", W_OK, AT_EACCESS) == 0) {
            enabled = pam_manager_apply_auth_file("/etc/pam.d/system-auth");
        }
        if (enabled && distro == DISTRO_ARCH) {
            bool want_keyring = cfg ? cfg->enable_keyring_unlock : true;
            pam_manager_configure_arch_keyring_file("/etc/pam.d/system-local-login", want_keyring);
        }
    }

    if (enabled) {
        configure_polkit_and_udev_overrides(true);
        return true;
    }

    if (err_buf && err_len > 0) {
        snprintf(err_buf, err_len, "Unable to write to PAM configuration files (permission denied or unsupported layout). Run with sudo/pkexec.");
    }
    return false;
}

bool pam_manager_disable(char *err_buf, size_t err_len) {
    linux_distro_t distro = pam_manager_detect_distro();

    if (distro == DISTRO_DEBIAN_UBUNTU) {
        if (access("/usr/share/pam-configs/tpm-pin", R_OK) == 0 && access("/usr/sbin/pam-auth-update", X_OK) == 0) {
            int ret = system("/usr/sbin/pam-auth-update --package --remove tpm-pin >/dev/null 2>&1");
            (void)ret;
        }
        if (faccessat(AT_FDCWD, "/etc/pam.d/common-auth", W_OK, AT_EACCESS) == 0) {
            pam_manager_remove_from_file("/etc/pam.d/common-auth");
        }
    }

    if (faccessat(AT_FDCWD, "/etc/pam.d/system-auth", W_OK, AT_EACCESS) == 0) {
        pam_manager_remove_from_file("/etc/pam.d/system-auth");
    }
    if (faccessat(AT_FDCWD, "/etc/pam.d/password-auth", W_OK, AT_EACCESS) == 0) {
        pam_manager_remove_from_file("/etc/pam.d/password-auth");
    }
    if (faccessat(AT_FDCWD, "/etc/pam.d/system-local-login", W_OK, AT_EACCESS) == 0) {
        pam_manager_configure_arch_keyring_file("/etc/pam.d/system-local-login", false);
    }

    configure_polkit_and_udev_overrides(false);

    (void)err_buf;
    (void)err_len;
    return true;
}
