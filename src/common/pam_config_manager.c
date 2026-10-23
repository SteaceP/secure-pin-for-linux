#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include "tpm_pin.h"

linux_distro_t pam_manager_detect_distro(void) {
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) return DISTRO_GENERIC;

    char line[256];
    linux_distro_t distro = DISTRO_GENERIC;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "ID=", 3) == 0 || strncmp(line, "ID_LIKE=", 8) == 0) {
            char *val = line + (line[2] == '=' ? 3 : 8);
            if (*val == '"' || *val == '\'') val++;
            if (strstr(val, "ubuntu") || strstr(val, "debian") || strstr(val, "pop") || strstr(val, "mint")) {
                distro = DISTRO_DEBIAN_UBUNTU;
                break;
            } else if (strstr(val, "fedora") || strstr(val, "rhel") || strstr(val, "centos") || strstr(val, "almalinux") || strstr(val, "rocky")) {
                distro = DISTRO_FEDORA_RHEL;
                break;
            } else if (strstr(val, "arch") || strstr(val, "manjaro") || strstr(val, "endeavouros")) {
                distro = DISTRO_ARCH;
                break;
            } else if (strstr(val, "opensuse") || strstr(val, "suse")) {
                distro = DISTRO_OPENSUSE;
                break;
            }
        }
    }
    fclose(f);
    return distro;
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

static bool file_contains(const char *filepath, const char *needle) {
    FILE *f = fopen(filepath, "r");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

bool pam_manager_is_enabled(void) {
    if (file_contains("/etc/pam.d/common-auth", "pam_tpm_pin.so")) return true;
    if (file_contains("/etc/pam.d/system-auth", "pam_tpm_pin.so")) return true;
    if (file_contains("/etc/pam.d/password-auth", "pam_tpm_pin.so")) return true;
    return false;
}

static bool create_backup(const char *filepath, char *backup_out, size_t backup_len) {
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
        fwrite(buf, 1, n, dst);
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
    bool needle_exists = before_needle ? file_contains(filepath, before_needle) : false;

    if (!needle_exists) {
        /* Prepend at the beginning of the auth stack if before_needle isn't found */
        fprintf(out, "%s\n", rule);
        inserted = true;
    }

    while (fgets(line, sizeof(line), in)) {
        if (!inserted && before_needle && strstr(line, before_needle) && !strstr(line, "pam_tpm_pin.so")) {
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
        if (strstr(line, "pam_tpm_pin.so") == NULL) {
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

static bool remove_pam_rule(const char *filepath) {
    if (!file_contains(filepath, "pam_tpm_pin.so")) return true;

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
        if (!strstr(line, "pam_tpm_pin.so")) {
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

bool pam_manager_enable(const tpm_pin_config_t *cfg, char *err_buf, size_t err_len) {
    (void)cfg;
    linux_distro_t distro = pam_manager_detect_distro();

    const char *rule = "auth [success=1 authinfo_unavail=ignore open_err=ignore default=ignore] pam_tpm_pin.so";

    if (distro == DISTRO_DEBIAN_UBUNTU) {
        /* If pam-auth-update profile exists, apply it non-interactively */
        if (access("/usr/share/pam-configs/tpm-pin", R_OK) == 0 && access("/usr/sbin/pam-auth-update", X_OK) == 0) {
            int ret = system("/usr/sbin/pam-auth-update --package --force >/dev/null 2>&1");
            if (ret == 0 && pam_manager_is_enabled()) return true;
        }
        /* Fallback: direct safe insertion in /etc/pam.d/common-auth before pam_unix.so */
        if (access("/etc/pam.d/common-auth", W_OK) == 0) {
            return insert_pam_rule("/etc/pam.d/common-auth", rule, "pam_unix.so");
        }
    } else if (distro == DISTRO_FEDORA_RHEL) {
        bool ok = true;
        if (access("/etc/pam.d/system-auth", W_OK) == 0) {
            ok = insert_pam_rule("/etc/pam.d/system-auth", rule, "pam_unix.so");
        }
        if (access("/etc/pam.d/password-auth", W_OK) == 0) {
            ok = ok && insert_pam_rule("/etc/pam.d/password-auth", rule, "pam_unix.so");
        }
        return ok;
    } else if (distro == DISTRO_OPENSUSE) {
        if (access("/etc/pam.d/common-auth", W_OK) == 0) {
            return insert_pam_rule("/etc/pam.d/common-auth", rule, "pam_unix.so");
        }
    } else {
        /* Arch or Generic */
        if (access("/etc/pam.d/system-auth", W_OK) == 0) {
            return insert_pam_rule("/etc/pam.d/system-auth", rule, "pam_unix.so");
        }
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
        if (access("/etc/pam.d/common-auth", W_OK) == 0) {
            remove_pam_rule("/etc/pam.d/common-auth");
        }
    }

    if (access("/etc/pam.d/system-auth", W_OK) == 0) {
        remove_pam_rule("/etc/pam.d/system-auth");
    }
    if (access("/etc/pam.d/password-auth", W_OK) == 0) {
        remove_pam_rule("/etc/pam.d/password-auth");
    }

    (void)err_buf;
    (void)err_len;
    return true;
}
