#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ftw.h>
#include <time.h>
#include <errno.h>
#include "tpm_pin.h"

#define KEYRING_BLOCK_BEGIN "# BEGIN tpm-pin-keyring"
#define KEYRING_BLOCK_END   "# END tpm-pin-keyring"

#define PAM_FILE_MAX_LINES  1024

#define AUTHSELECT_BIN              "/usr/bin/authselect"
#define AUTHSELECT_CONF             "/etc/authselect/authselect.conf"
#define TPM_AUTHSELECT_NAME         "tpm-pin"
#define TPM_AUTHSELECT_PROFILE      "custom/" TPM_AUTHSELECT_NAME
#define TPM_AUTHSELECT_DIR          "/etc/authselect/" TPM_AUTHSELECT_PROFILE
#define TPM_AUTHSELECT_BASE_FILE    TPM_AUTHSELECT_DIR "/.base-profile"
#define TPM_AUTHSELECT_ADDED_FILE   TPM_AUTHSELECT_DIR "/.added-features"
#define AUTHSELECT_KEYRING_FEATURE  "with-pam-gnome-keyring"

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
        strstr(val, "almalinux") || strstr(val, "rocky") || strstr(val, "nobara") ||
        strstr(val, "bazzite") || strstr(val, "bluefin") || strstr(val, "aurora") ||
        strstr(val, "silverblue") || strstr(val, "kinoite")) {
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

/*
 * Runs argv[0] (absolute path) with the given arguments, without a shell, with
 * stdin/stdout/stderr redirected to /dev/null. Returns the exit status, or -1.
 */
static int run_argv(const char *const argv[]) {
    if (!argv || !argv[0]) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) {
                close(devnull);
            }
        }
        char *const envp[] = {
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL=C",
            "DEBIAN_FRONTEND=noninteractive",
            NULL
        };
        execve(argv[0], (char *const *)argv, envp);
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void run_restorecon(const char *path) {
    if (!path || geteuid() != 0) return;
    /* selinuxfs is only mounted when SELinux is enabled */
    if (access("/sys/fs/selinux/enforce", F_OK) != 0) return;
    const char *bin = (access("/usr/sbin/restorecon", X_OK) == 0) ? "/usr/sbin/restorecon"
                    : (access("/sbin/restorecon", X_OK) == 0) ? "/sbin/restorecon"
                    : (access("/usr/bin/restorecon", X_OK) == 0) ? "/usr/bin/restorecon" : NULL;
    if (bin) {
        const char *argv[] = { bin, "-R", path, NULL };
        (void)run_argv(argv);
    }
}

static int remove_tree_entry(const char *path, const struct stat *sb, int flag, struct FTW *ftwbuf) {
    (void)sb;
    (void)flag;
    (void)ftwbuf;
    return (remove(path) == 0 || errno == ENOENT) ? 0 : -1;
}

static void remove_tree(const char *path) {
    /* FTW_PHYS: never follow symlinks (profile meta files may be symlinks to the base profile) */
    (void)nftw(path, remove_tree_entry, 16, FTW_DEPTH | FTW_PHYS);
}

static bool authselect_is_active(void) {
    return (access(AUTHSELECT_BIN, X_OK) == 0 &&
            access(AUTHSELECT_CONF, R_OK) == 0);
}

static bool is_tpm_pin_profile(const char *profile) {
    return profile && strcmp(profile, TPM_AUTHSELECT_PROFILE) == 0;
}

/* Profile IDs and feature names are passed as argv; reject anything that could be parsed as an option. */
static bool is_safe_authselect_token(const char *s) {
    if (!s || s[0] == '\0' || s[0] == '-') return false;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.' || c == '/')) return false;
    }
    return true;
}

static bool feature_list_contains(const char *features, const char *feature) {
    if (!features || !feature) return false;
    size_t flen = strlen(feature);
    const char *p = features;
    while ((p = strstr(p, feature)) != NULL) {
        bool start_ok = (p == features || p[-1] == ' ' || p[-1] == '\t');
        bool end_ok = (p[flen] == '\0' || p[flen] == ' ' || p[flen] == '\t');
        if (start_ok && end_ok) return true;
        p += flen;
    }
    return false;
}

static void feature_list_append(char *features, size_t feat_sz, const char *feature) {
    size_t len = strlen(features);
    snprintf(features + len, feat_sz - len, "%s%s", len > 0 ? " " : "", feature);
}

static bool authselect_get_current_state(char *profile_out, size_t prof_sz, char *features_out, size_t feat_sz) {
    FILE *f = fopen(AUTHSELECT_CONF, "re");
    if (!f) return false;

    char line[256];
    bool first = true;
    if (profile_out && prof_sz > 0) profile_out[0] = '\0';
    if (features_out && feat_sz > 0) features_out[0] = '\0';

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        size_t len = strlen(p);
        while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == '\r' || p[len - 1] == ' ' || p[len - 1] == '\t')) {
            p[--len] = '\0';
        }
        if (len == 0 || p[0] == '#') continue;

        if (first) {
            if (profile_out) snprintf(profile_out, prof_sz, "%s", p);
            first = false;
        } else {
            if (features_out) {
                if (features_out[0] != '\0') strncat(features_out, " ", feat_sz - strlen(features_out) - 1);
                strncat(features_out, p, feat_sz - strlen(features_out) - 1);
            }
        }
    }
    fclose(f);
    return !first;
}

bool pam_manager_is_enabled(void) {
    char current_prof[128];
    if (authselect_is_active() && authselect_get_current_state(current_prof, sizeof(current_prof), NULL, 0)) {
        if (is_tpm_pin_profile(current_prof)) return true;
    }
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
    chmod("/etc/tpm-pin", 0755);
    mkdir("/etc/tpm-pin/pam-backups", 0700);
    chmod("/etc/tpm-pin/pam-backups", 0700);
    mkdir(dir, 0700);
    chmod(dir, 0700);

    const char *basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;

    snprintf(backup_out, backup_len, "%s/%s", dir, basename);

    struct stat st;
    mode_t orig_mode = 0600;
    if (stat(filepath, &st) == 0) {
        orig_mode = st.st_mode & 07777;
    }

    FILE *src = fopen(filepath, "re");
    if (!src) return false;

    unlink(backup_out);
    int dst_fd = open(backup_out, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, orig_mode);
    if (dst_fd < 0) {
        fclose(src);
        return false;
    }
    FILE *dst = fdopen(dst_fd, "we");
    if (!dst) {
        close(dst_fd);
        unlink(backup_out);
        fclose(src);
        return false;
    }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        if (fwrite(buf, 1, n, dst) != n) {
            fclose(src);
            fclose(dst);
            unlink(backup_out);
            return false;
        }
    }
    fclose(src);
    if (fchmod(dst_fd, orig_mode) != 0 || fflush(dst) != 0 || fsync(dst_fd) != 0 || fclose(dst) != 0) {
        unlink(backup_out);
        return false;
    }
    return true;
}

/* Returns a pointer to the control field of a PAM rule line (the token after the type), or NULL. */
static const char *pam_control_field(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '-') p++;
    while (*p && *p != ' ' && *p != '\t') p++;
    while (*p == ' ' || *p == '\t') p++;
    return (*p && *p != '\n') ? p : NULL;
}

/*
 * Parses a bracketed PAM control field ("[value=action ...]") and returns the numeric
 * jump for `key` (e.g. "success"), or the largest numeric jump of any key when key is NULL.
 * Returns 0 when the control has no numeric jump (required, sufficient, done, ignore, ...).
 */
static int pam_control_jump(const char *line, const char *key) {
    const char *ctl = line ? pam_control_field(line) : NULL;
    if (!ctl || *ctl != '[') return 0;
    const char *end = strchr(ctl, ']');
    if (!end) return 0;

    int best = 0;
    const char *p = ctl + 1;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t')) p++;
        const char *tok = p;
        while (p < end && *p != ' ' && *p != '\t') p++;
        const char *eq = memchr(tok, '=', (size_t)(p - tok));
        if (!eq || eq + 1 >= p || !isdigit((unsigned char)eq[1])) continue;
        size_t klen = (size_t)(eq - tok);
        if (key && (strlen(key) != klen || strncmp(tok, key, klen) != 0)) continue;
        long n = strtol(eq + 1, NULL, 10);
        if (n > best && n < 1000) best = (int)n;
    }
    return best;
}

static void free_lines(char **lines, size_t count) {
    for (size_t i = 0; i < count; i++) free(lines[i]);
}

static bool insert_pam_rule(const char *filepath, const char *rule, const char *before_needle) {
    if (!filepath || !rule) return false;

    char resolved[4096];
    const char *target = filepath;
    if (realpath(filepath, resolved)) {
        target = resolved;
    }

    char backup[4160];
    create_backup(target, backup, sizeof(backup));

    struct stat orig_st;
    mode_t orig_mode = 0644;
    if (stat(target, &orig_st) == 0) {
        orig_mode = orig_st.st_mode & 07777;
    }

    FILE *in = fopen(target, "re");
    if (!in) return false;

    /* Load the file, dropping any stale pam_tpm_pin.so auth rules (idempotent re-apply) */
    char *lines[PAM_FILE_MAX_LINES];
    size_t count = 0;
    char line[1024];
    bool load_ok = true;
    while (fgets(line, sizeof(line), in)) {
        if (is_auth_rule_line(line) && strstr(line, "pam_tpm_pin.so")) continue;
        if (count >= PAM_FILE_MAX_LINES || !(lines[count] = strdup(line))) {
            load_ok = false;
            break;
        }
        count++;
    }
    fclose(in);
    if (!load_ok) {
        free_lines(lines, count);
        return false;
    }

    /* Anchor: first auth rule mentioning before_needle, else the first auth rule, else append */
    size_t anchor = count;
    if (before_needle) {
        for (size_t i = 0; i < count; i++) {
            if (is_auth_rule_line(lines[i]) && strstr(lines[i], before_needle)) {
                anchor = i;
                break;
            }
        }
    }
    if (anchor == count) {
        for (size_t i = 0; i < count; i++) {
            if (is_auth_rule_line(lines[i])) {
                anchor = i;
                break;
            }
        }
    }

    /*
     * PAM jumps ([default=N], [success=N], ...) count auth rules. If an earlier rule jumps
     * across the insertion point, inserting there would shift its target by one. Move the
     * insertion point above any such rule so that every existing jump keeps its meaning.
     */
    size_t insert_at = anchor;
    size_t between = 0;
    for (size_t j = insert_at; j-- > 0;) {
        if (!is_auth_rule_line(lines[j])) continue;
        int jump = pam_control_jump(lines[j], NULL);
        if (jump > 0 && (size_t)jump > between) {
            insert_at = j;
            between = 0;
            continue;
        }
        between++;
    }

    /*
     * Our rule must land where the anchor's success path lands (anchor uses success=N),
     * or skip through the anchor (rule uses success=N). Both are relative to the auth
     * rules between the insertion point and the anchor.
     */
    char rule_buf[256];
    const char *rule_out = rule;
    if (anchor < count) {
        size_t gap = 0;
        for (size_t i = insert_at; i < anchor; i++) {
            if (is_auth_rule_line(lines[i])) gap++;
        }
        int anchor_jump = pam_control_jump(lines[anchor], "success");
        int rule_jump = pam_control_jump(rule, "success");
        int jump = 0;
        if (anchor_jump > 0) {
            jump = anchor_jump + 1 + (int)gap;
        } else if (rule_jump > 0 && gap > 0) {
            jump = rule_jump + (int)gap;
        }
        if (jump > 0) {
            snprintf(rule_buf, sizeof(rule_buf),
                     "auth\t[success=%d authinfo_unavail=ignore open_err=ignore default=ignore]\tpam_tpm_pin.so",
                     jump);
            rule_out = rule_buf;
        }
    }

    char tmp_file[4160];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tpm_tmp.%d", target, (int)getpid());
    unlink(tmp_file);
    int fd = open(tmp_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, orig_mode);
    if (fd < 0) {
        free_lines(lines, count);
        return false;
    }
    FILE *out = fdopen(fd, "we");
    if (!out) {
        close(fd);
        unlink(tmp_file);
        free_lines(lines, count);
        return false;
    }

    for (size_t i = 0; i < count; i++) {
        if (i == insert_at) fprintf(out, "%s\n", rule_out);
        fputs(lines[i], out);
    }
    if (insert_at >= count) {
        if (count > 0 && lines[count - 1][strlen(lines[count - 1]) - 1] != '\n') fputc('\n', out);
        fprintf(out, "%s\n", rule_out);
    }
    free_lines(lines, count);

    if (ferror(out) || fchmod(fd, orig_mode) != 0 || fflush(out) != 0 || fsync(fd) != 0) {
        fclose(out);
        unlink(tmp_file);
        return false;
    }
    if (fclose(out) != 0) {
        unlink(tmp_file);
        return false;
    }

    if (rename(tmp_file, target) != 0) {
        unlink(tmp_file);
        return false;
    }
    run_restorecon(target);
    return true;
}

/* Returns the first module from `candidates` that appears in an auth rule of filepath, in file order. */
static const char *first_auth_module_of(const char *filepath, const char *const candidates[]) {
    FILE *f = fopen(filepath, "re");
    if (!f) return NULL;
    char line[1024];
    const char *found = NULL;
    while (!found && fgets(line, sizeof(line), f)) {
        if (!is_auth_rule_line(line) || strstr(line, "pam_tpm_pin.so")) continue;
        for (size_t i = 0; candidates[i]; i++) {
            if (strstr(line, candidates[i])) {
                found = candidates[i];
                break;
            }
        }
    }
    fclose(f);
    return found;
}

bool pam_manager_apply_fedora_file(const char *filepath) {
    if (!filepath) return false;
    const char *rule = "auth\t[success=done authinfo_unavail=ignore open_err=ignore default=ignore]\tpam_tpm_pin.so";
    /*
     * authselect profiles (local, sssd, winbind, nis) order the interactive methods as
     * pam_fprintd.so -> pam_u2f.so -> pam_unix.so, with pam_systemd_home.so placed AFTER
     * pam_unix.so. Insert before whichever comes first so the PIN is offered alongside
     * fingerprint/security keys and before the password prompt. password-auth has no
     * pam_fprintd.so line, so pam_systemd_home.so must never be used as the anchor here.
     */
    static const char *const candidates[] = { "pam_fprintd.so", "pam_u2f.so", "pam_unix.so", NULL };
    return insert_pam_rule(filepath, rule, first_auth_module_of(filepath, candidates));
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

    char resolved[4096];
    const char *target = filepath;
    if (realpath(filepath, resolved)) {
        target = resolved;
    }

    char backup[4160];
    create_backup(target, backup, sizeof(backup));

    struct stat orig_st;
    mode_t orig_mode = 0644;
    if (stat(target, &orig_st) == 0) {
        orig_mode = orig_st.st_mode & 07777;
    }

    FILE *in = fopen(target, "re");
    if (!in) return false;

    char tmp_file[4160];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tpm_tmp.%d", target, (int)getpid());
    unlink(tmp_file);
    int fd = open(tmp_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, orig_mode);
    if (fd < 0) {
        fclose(in);
        return false;
    }
    FILE *out = fdopen(fd, "we");
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
    if (ferror(out) || fchmod(fd, orig_mode) != 0 || fflush(out) != 0 || fsync(fd) != 0) {
        fclose(out);
        unlink(tmp_file);
        return false;
    }
    if (fclose(out) != 0) {
        unlink(tmp_file);
        return false;
    }

    if (rename(tmp_file, target) != 0) {
        unlink(tmp_file);
        return false;
    }
    run_restorecon(target);
    return true;
}

bool pam_manager_configure_arch_keyring_file(const char *filepath, bool enable) {
    if (!filepath) return false;
    if (access(filepath, R_OK | W_OK) != 0) return true;

    FILE *scan = fopen(filepath, "re");
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

    char resolved[4096];
    const char *target = filepath;
    if (realpath(filepath, resolved)) {
        target = resolved;
    }

    char backup[4160];
    create_backup(target, backup, sizeof(backup));

    struct stat orig_st;
    mode_t orig_mode = 0644;
    if (stat(target, &orig_st) == 0) {
        orig_mode = orig_st.st_mode & 07777;
    }

    FILE *in = fopen(target, "re");
    if (!in) return false;

    char tmp_file[4160];
    snprintf(tmp_file, sizeof(tmp_file), "%s.tpm_kr_tmp.%d", target, (int)getpid());
    unlink(tmp_file);
    int fd = open(tmp_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, orig_mode);
    if (fd < 0) {
        fclose(in);
        return false;
    }
    FILE *out = fdopen(fd, "we");
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
    if (ferror(out) || fchmod(fd, orig_mode) != 0 || fflush(out) != 0 || fsync(fd) != 0) {
        fclose(out);
        unlink(tmp_file);
        return false;
    }
    if (fclose(out) != 0) {
        unlink(tmp_file);
        return false;
    }

    if (rename(tmp_file, target) != 0) {
        unlink(tmp_file);
        return false;
    }
    run_restorecon(target);
    return true;
}

static bool configure_polkit_and_udev_overrides(bool enable) {
    const char *dropin_dir = "/etc/systemd/system/polkit-agent-helper@.service.d";
    const char *dropin_file = "/etc/systemd/system/polkit-agent-helper@.service.d/tpm-pin.conf";
    const char *mask_dropin_file = "/etc/systemd/system/polkit-agent-helper@.service.d/50-tpm-pin.conf";
    const char *etc_udev_rule = "/etc/udev/rules.d/70-tpm-pin.rules";
    bool pkg_dropin_exists = (access("/usr/lib/systemd/system/polkit-agent-helper@.service.d/50-tpm-pin.conf", F_OK) == 0 ||
                              access("/lib/systemd/system/polkit-agent-helper@.service.d/50-tpm-pin.conf", F_OK) == 0);
    bool pkg_udev_exists = (access("/usr/lib/udev/rules.d/70-tpm-pin.rules", F_OK) == 0 ||
                            access("/lib/udev/rules.d/70-tpm-pin.rules", F_OK) == 0);

    if (enable) {
        mkdir("/etc/systemd", 0755);
        chmod("/etc/systemd", 0755);
        mkdir("/etc/systemd/system", 0755);
        chmod("/etc/systemd/system", 0755);
        if (mkdir(dropin_dir, 0755) != 0 && errno != EEXIST) {
            return false;
        }
        chmod(dropin_dir, 0755);

        /* Clear any prior /dev/null masks created on disable */
        unlink(mask_dropin_file);
        unlink(dropin_file);
        unlink(etc_udev_rule);

        int dfd = open(dropin_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
        if (dfd < 0) return false;
        FILE *f = fdopen(dfd, "we");
        if (!f) {
            close(dfd);
            unlink(dropin_file);
            return false;
        }

        fprintf(f, "[Service]\n"
                   "PrivateDevices=no\n"
                   "DeviceAllow=/dev/tpmrm0 rw\n"
                   "DeviceAllow=/dev/tpm0 rw\n"
                   "DeviceAllow=char-tpm rw\n"
                   "StandardError=journal\n");
        if (fchmod(dfd, 0644) != 0 || fflush(f) != 0 || fsync(dfd) != 0 || fclose(f) != 0) {
            unlink(dropin_file);
            return false;
        }

        /* Ensure uaccess udev rule exists even when running from a source build */
        if (!pkg_udev_exists) {
            mkdir("/etc/udev", 0755);
            chmod("/etc/udev", 0755);
            mkdir("/etc/udev/rules.d", 0755);
            chmod("/etc/udev/rules.d", 0755);
            int ufd = open(etc_udev_rule, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
            if (ufd >= 0) {
                FILE *uf = fdopen(ufd, "we");
                if (uf) {
                    fprintf(uf, "# Managed by tpm-pin\n"
                                "KERNEL==\"tpmrm[0-9]*\", TAG+=\"uaccess\"\n");
                    if (fchmod(ufd, 0644) != 0 || fflush(uf) != 0 || fsync(ufd) != 0 || fclose(uf) != 0) {
                        unlink(etc_udev_rule);
                    }
                } else {
                    close(ufd);
                    unlink(etc_udev_rule);
                }
            }
        }
        run_restorecon(etc_udev_rule);
        run_restorecon(dropin_file);
    } else {
        unlink(dropin_file);
        unlink(mask_dropin_file);
        if (pkg_dropin_exists) {
            /* Package-installed drop-in in /usr/lib must be masked via /etc symlink to /dev/null */
            mkdir("/etc/systemd", 0755);
            chmod("/etc/systemd", 0755);
            mkdir("/etc/systemd/system", 0755);
            chmod("/etc/systemd/system", 0755);
            if (mkdir(dropin_dir, 0755) == 0 || errno == EEXIST) {
                chmod(dropin_dir, 0755);
                if (symlink("/dev/null", mask_dropin_file) == 0) {
                    run_restorecon(mask_dropin_file);
                }
            }
        } else {
            rmdir(dropin_dir);
        }

        unlink(etc_udev_rule);
        if (pkg_udev_exists) {
            /* Package-installed udev rule in /usr/lib must be masked via /etc symlink to /dev/null */
            mkdir("/etc/udev", 0755);
            chmod("/etc/udev", 0755);
            mkdir("/etc/udev/rules.d", 0755);
            chmod("/etc/udev/rules.d", 0755);
            if (symlink("/dev/null", etc_udev_rule) == 0) {
                run_restorecon(etc_udev_rule);
            }
        }
    }

    const char *systemctl_bin = (access("/usr/bin/systemctl", X_OK) == 0) ? "/usr/bin/systemctl"
                              : (access("/bin/systemctl", X_OK) == 0) ? "/bin/systemctl" : NULL;
    if (systemctl_bin) {
        const char *argv[] = { systemctl_bin, "daemon-reload", NULL };
        (void)run_argv(argv);
    }

    const char *udevadm_bin = (access("/usr/bin/udevadm", X_OK) == 0) ? "/usr/bin/udevadm"
                            : (access("/bin/udevadm", X_OK) == 0) ? "/bin/udevadm" : NULL;
    if (udevadm_bin) {
        const char *reload_argv[] = { udevadm_bin, "control", "--reload", NULL };
        if (run_argv(reload_argv) == 0) {
            const char *trig_argv[] = { udevadm_bin, "trigger", "--action=change", "--subsystem-match=tpmrm", NULL };
            (void)run_argv(trig_argv);
        }
    }
    return true;
}

/* Reads a single validated token from a small state file in our authselect profile. */
static bool read_profile_state_file(const char *path, char *out, size_t out_sz) {
    if (!out || out_sz == 0) return false;
    out[0] = '\0';
    FILE *f = fopen(path, "re");
    if (!f) return false;
    char line[1024];
    size_t len = 0;
    while (fgets(line, sizeof(line), f)) {
        char *save = NULL;
        for (char *tok = strtok_r(line, " \t\r\n", &save); tok; tok = strtok_r(NULL, " \t\r\n", &save)) {
            if (!is_safe_authselect_token(tok)) continue;
            int w = snprintf(out + len, out_sz - len, "%s%s", len > 0 ? " " : "", tok);
            if (w < 0 || (size_t)w >= out_sz - len) {
                out[len] = '\0';
                break;
            }
            len += (size_t)w;
        }
    }
    fclose(f);
    return len > 0;
}

static bool write_profile_state_file(const char *path, const char *content) {
    unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    FILE *f = fdopen(fd, "we");
    if (!f) {
        close(fd);
        unlink(path);
        return false;
    }
    fprintf(f, "%s\n", content);
    if (fchmod(fd, 0644) != 0 || fflush(f) != 0 || fsync(fd) != 0 || fclose(f) != 0) {
        unlink(path);
        return false;
    }
    return true;
}

/* True if any PAM template of the profile references `feature` (i.e. the profile supports it). */
static bool authselect_profile_has_feature(const char *profile_dir, const char *feature) {
    static const char *const files[] = { "system-auth", "password-auth", "postlogin", NULL };
    for (size_t i = 0; files[i]; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", profile_dir, files[i]);
        FILE *f = fopen(path, "re");
        if (!f) continue;
        char line[1024];
        bool found = false;
        while (!found && fgets(line, sizeof(line), f)) {
            if (strstr(line, feature)) found = true;
        }
        fclose(f);
        if (found) return true;
    }
    return false;
}

/* Runs `authselect select <profile> <features...> --force`. */
static bool authselect_select(const char *profile, const char *features) {
    if (!is_safe_authselect_token(profile)) return false;

    char feat_copy[1024];
    snprintf(feat_copy, sizeof(feat_copy), "%s", features ? features : "");

    const char *argv[64];
    size_t argc = 0;
    argv[argc++] = AUTHSELECT_BIN;
    argv[argc++] = "select";
    argv[argc++] = profile;
    char *save = NULL;
    for (char *tok = strtok_r(feat_copy, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
        if (!is_safe_authselect_token(tok)) continue;
        if (argc >= (sizeof(argv) / sizeof(argv[0])) - 2) return false;
        argv[argc++] = tok;
    }
    argv[argc++] = "--force";
    argv[argc] = NULL;
    return run_argv(argv) == 0;
}

static void authselect_restore_labels(void) {
    run_restorecon("/etc/pam.d");
    run_restorecon("/etc/authselect");
}

static bool authselect_enable(bool want_keyring) {
    char current_profile[128] = {0};
    char features[1024] = {0};
    if (!authselect_get_current_state(current_profile, sizeof(current_profile), features, sizeof(features))) {
        return false;
    }

    if (is_tpm_pin_profile(current_profile) && access(TPM_AUTHSELECT_DIR "/system-auth", R_OK) == 0) {
        /* Already selected: refresh the PIN rule in our profile templates and regenerate */
        bool ok = pam_manager_apply_fedora_file(TPM_AUTHSELECT_DIR "/system-auth");
        ok = pam_manager_apply_fedora_file(TPM_AUTHSELECT_DIR "/password-auth") && ok;
        if (ok) {
            const char *argv[] = { AUTHSELECT_BIN, "apply-changes", NULL };
            ok = (run_argv(argv) == 0);
        }
        authselect_restore_labels();
        return ok;
    }

    char base_profile[128] = {0};
    if (is_tpm_pin_profile(current_profile)) {
        /* Our profile is selected but broken: recreate it on top of the recorded base */
        if (!read_profile_state_file(TPM_AUTHSELECT_BASE_FILE, base_profile, sizeof(base_profile))) {
            snprintf(base_profile, sizeof(base_profile), "local");
        }
    } else {
        snprintf(base_profile, sizeof(base_profile), "%s", current_profile);
    }
    if (!is_safe_authselect_token(base_profile)) return false;

    remove_tree(TPM_AUTHSELECT_DIR);

    const char *create_argv[] = {
        AUTHSELECT_BIN, "create-profile", TPM_AUTHSELECT_NAME, "-b", base_profile,
        "--symlink-meta", "--symlink-nsswitch", "--symlink-dconf", NULL
    };
    if (run_argv(create_argv) != 0) {
        remove_tree(TPM_AUTHSELECT_DIR);
        return false;
    }

    char added[256] = {0};
    if (want_keyring && !feature_list_contains(features, AUTHSELECT_KEYRING_FEATURE) &&
        authselect_profile_has_feature(TPM_AUTHSELECT_DIR, AUTHSELECT_KEYRING_FEATURE)) {
        feature_list_append(features, sizeof(features), AUTHSELECT_KEYRING_FEATURE);
        snprintf(added, sizeof(added), "%s", AUTHSELECT_KEYRING_FEATURE);
    }

    bool ok = write_profile_state_file(TPM_AUTHSELECT_BASE_FILE, base_profile) &&
              (added[0] == '\0' || write_profile_state_file(TPM_AUTHSELECT_ADDED_FILE, added)) &&
              pam_manager_apply_fedora_file(TPM_AUTHSELECT_DIR "/system-auth") &&
              pam_manager_apply_fedora_file(TPM_AUTHSELECT_DIR "/password-auth") &&
              authselect_select(TPM_AUTHSELECT_PROFILE, features);

    if (!ok && !is_tpm_pin_profile(current_profile)) {
        /* Selection did not happen; the previous profile is still active */
        remove_tree(TPM_AUTHSELECT_DIR);
    }
    authselect_restore_labels();
    return ok;
}

static bool authselect_disable(void) {
    char current_profile[128] = {0};
    char features[1024] = {0};
    if (!authselect_get_current_state(current_profile, sizeof(current_profile), features, sizeof(features))) {
        return false;
    }

    if (!is_tpm_pin_profile(current_profile)) {
        return true;
    }

    char base_profile[128];
    if (!read_profile_state_file(TPM_AUTHSELECT_BASE_FILE, base_profile, sizeof(base_profile))) {
        snprintf(base_profile, sizeof(base_profile), "local");
    }

    /* Drop features we enabled ourselves so the original configuration is restored */
    char added[256];
    char restored[1024] = {0};
    bool have_added = read_profile_state_file(TPM_AUTHSELECT_ADDED_FILE, added, sizeof(added));
    char *save = NULL;
    for (char *tok = strtok_r(features, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
        if (have_added && feature_list_contains(added, tok)) continue;
        feature_list_append(restored, sizeof(restored), tok);
    }

    bool ok = authselect_select(base_profile, restored);
    if (ok) {
        /* Only delete our profile once it is no longer selected */
        remove_tree(TPM_AUTHSELECT_DIR);
    }
    authselect_restore_labels();
    return ok;
}

bool pam_manager_enable(const tpm_pin_config_t *cfg, char *err_buf, size_t err_len) {
    linux_distro_t distro = pam_manager_detect_distro();
    bool enabled = false;

    if (distro == DISTRO_DEBIAN_UBUNTU) {
        /* If pam-auth-update profile exists, apply it non-interactively */
        if (access("/usr/share/pam-configs/tpm-pin", R_OK) == 0 && access("/usr/sbin/pam-auth-update", X_OK) == 0) {
            const char *argv[] = { "/usr/sbin/pam-auth-update", "--package", "--force", NULL };
            int ret = run_argv(argv);
            if (ret == 0 && pam_manager_is_enabled()) {
                enabled = true;
            }
        }
        /* Fallback: direct safe insertion in /etc/pam.d/common-auth */
        if (!enabled && faccessat(AT_FDCWD, "/etc/pam.d/common-auth", W_OK, AT_EACCESS) == 0) {
            enabled = pam_manager_apply_auth_file("/etc/pam.d/common-auth");
        }
    } else if (distro == DISTRO_FEDORA_RHEL) {
        bool want_keyring = cfg ? cfg->enable_keyring_unlock : true;
        if (authselect_is_active()) {
            enabled = authselect_enable(want_keyring);
        }
        if (!enabled) {
            bool ok = true;
            if (faccessat(AT_FDCWD, "/etc/pam.d/system-auth", W_OK, AT_EACCESS) == 0) {
                ok = pam_manager_apply_fedora_file("/etc/pam.d/system-auth");
            }
            if (faccessat(AT_FDCWD, "/etc/pam.d/password-auth", W_OK, AT_EACCESS) == 0) {
                ok = ok && pam_manager_apply_fedora_file("/etc/pam.d/password-auth");
            }
            enabled = ok;
        }
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
            const char *argv[] = { "/usr/sbin/pam-auth-update", "--package", "--remove", "tpm-pin", NULL };
            (void)run_argv(argv);
        }
        if (faccessat(AT_FDCWD, "/etc/pam.d/common-auth", W_OK, AT_EACCESS) == 0) {
            pam_manager_remove_from_file("/etc/pam.d/common-auth");
        }
    }

    if (distro == DISTRO_FEDORA_RHEL && authselect_is_active()) {
        authselect_disable();
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
