#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include "tpm_pin.h"

void tpm_pin_config_defaults(tpm_pin_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->digits_only = true;
    cfg->min_length = 4;
    cfg->max_length = 32;
    cfg->disallow_simple_pins = true;
    cfg->enable_login = true;
    cfg->enable_lockscreen = true;
    cfg->enable_sudo = true;
    cfg->enable_polkit = true;
    cfg->enable_keyring_unlock = true;
    cfg->bind_pcr7 = false;
    cfg->da_max_tries = 5;
    cfg->da_recovery_time = 600;       /* 10 minutes */
    cfg->da_lockout_recovery = 86400;   /* 24 hours */
    cfg->tcti_name[0] = '\0';
    snprintf(cfg->data_dir, sizeof(cfg->data_dir), "%s", TPM_PIN_DEFAULT_DATA_DIR);
}

static char *trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static bool parse_bool(const char *val) {
    if (!val) return false;
    return (strcasecmp(val, "true") == 0 ||
            strcasecmp(val, "yes") == 0 ||
            strcasecmp(val, "1") == 0 ||
            strcasecmp(val, "on") == 0);
}

static void strip_inline_comment(char *val) {
    if (!val) return;
    for (size_t i = 0; val[i] != '\0'; i++) {
        if ((val[i] == '#' || val[i] == ';') && i > 0 && isspace((unsigned char)val[i - 1])) {
            val[i] = '\0';
            break;
        }
    }
}

static bool parse_u32_strict(const char *val, uint32_t *out) {
    if (!val || !out || !isdigit((unsigned char)val[0])) return false;
    errno = 0;
    char *endptr = NULL;
    unsigned long parsed = strtoul(val, &endptr, 10);
    if (errno == ERANGE || !endptr || *endptr != '\0' || parsed > (unsigned long)UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)parsed;
    return true;
}

bool tpm_pin_config_load(const char *path, tpm_pin_config_t *cfg) {
    if (!cfg) return false;
    tpm_pin_config_defaults(cfg);

    const char *cfg_path = path ? path : TPM_PIN_DEFAULT_CONFIG_PATH;
    FILE *f = fopen(cfg_path, "re");
    if (!f) {
        /* If config does not exist, defaults remain in effect */
        return true;
    }

    bool saw_enable_polkit = false;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        size_t line_len = strlen(line);
        if (line_len > 0 && line[line_len - 1] != '\n' && !feof(f)) {
            int ch;
            while ((ch = fgetc(f)) != '\n' && ch != EOF) {
                /* Discard overlong line remainder */
            }
        }
        char *p = trim(line);
        if (*p == '#' || *p == ';' || *p == '\0') continue;

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);
        strip_inline_comment(val);
        val = trim(val);

        uint32_t uval = 0;
        if (strcasecmp(key, "digits_only") == 0) {
            cfg->digits_only = parse_bool(val);
        } else if (strcasecmp(key, "min_length") == 0) {
            if (parse_u32_strict(val, &uval)) {
                if (uval < 4) uval = 4;
                if (uval > TPM_PIN_MAX_PIN_LEN) uval = TPM_PIN_MAX_PIN_LEN;
                cfg->min_length = uval;
            }
        } else if (strcasecmp(key, "max_length") == 0) {
            if (parse_u32_strict(val, &uval)) {
                if (uval < 4) uval = 4;
                if (uval > TPM_PIN_MAX_PIN_LEN) uval = TPM_PIN_MAX_PIN_LEN;
                cfg->max_length = uval;
            }
        } else if (strcasecmp(key, "disallow_simple_pins") == 0) {
            cfg->disallow_simple_pins = parse_bool(val);
        } else if (strcasecmp(key, "enable_login") == 0) {
            cfg->enable_login = parse_bool(val);
        } else if (strcasecmp(key, "enable_lockscreen") == 0) {
            cfg->enable_lockscreen = parse_bool(val);
        } else if (strcasecmp(key, "enable_sudo") == 0) {
            cfg->enable_sudo = parse_bool(val);
        } else if (strcasecmp(key, "enable_polkit") == 0) {
            cfg->enable_polkit = parse_bool(val);
            saw_enable_polkit = true;
        } else if (strcasecmp(key, "enable_keyring_unlock") == 0) {
            cfg->enable_keyring_unlock = parse_bool(val);
        } else if (strcasecmp(key, "bind_pcr7") == 0) {
            cfg->bind_pcr7 = parse_bool(val);
        } else if (strcasecmp(key, "da_max_tries") == 0) {
            if (parse_u32_strict(val, &uval)) {
                if (uval < 1) uval = 1;
                if (uval > 1000) uval = 1000;
                cfg->da_max_tries = uval;
            }
        } else if (strcasecmp(key, "da_recovery_time") == 0) {
            if (parse_u32_strict(val, &uval)) {
                if (uval < 1) uval = 1;
                if (uval > 2592000U) uval = 2592000U;
                cfg->da_recovery_time = uval;
            }
        } else if (strcasecmp(key, "da_lockout_recovery") == 0) {
            if (parse_u32_strict(val, &uval)) {
                if (uval < 1) uval = 1;
                if (uval > 2592000U) uval = 2592000U;
                cfg->da_lockout_recovery = uval;
            }
        } else if (strcasecmp(key, "tcti_name") == 0) {
            if (strpbrk(val, "\r\n") == NULL) {
                snprintf(cfg->tcti_name, sizeof(cfg->tcti_name), "%s", val);
            }
        } else if (strcasecmp(key, "data_dir") == 0) {
            if (val[0] == '/' && strstr(val, "..") == NULL && strpbrk(val, "\r\n") == NULL) {
                snprintf(cfg->data_dir, sizeof(cfg->data_dir), "%s", val);
            }
        }
    }

    if (!saw_enable_polkit) {
        cfg->enable_polkit = cfg->enable_sudo;
    }

    if (cfg->min_length < 4) cfg->min_length = 4;
    if (cfg->min_length > TPM_PIN_MAX_PIN_LEN) cfg->min_length = TPM_PIN_MAX_PIN_LEN;
    if (cfg->max_length > TPM_PIN_MAX_PIN_LEN) cfg->max_length = TPM_PIN_MAX_PIN_LEN;
    if (cfg->max_length < cfg->min_length) cfg->max_length = cfg->min_length;
    if (cfg->da_max_tries < 1) cfg->da_max_tries = 1;
    if (cfg->da_max_tries > 1000) cfg->da_max_tries = 1000;
    if (cfg->da_recovery_time < 1) cfg->da_recovery_time = 1;
    if (cfg->da_recovery_time > 2592000U) cfg->da_recovery_time = 2592000U;
    if (cfg->da_lockout_recovery < 1) cfg->da_lockout_recovery = 1;
    if (cfg->da_lockout_recovery > 2592000U) cfg->da_lockout_recovery = 2592000U;
    if (cfg->data_dir[0] != '/' || strstr(cfg->data_dir, "..") != NULL) {
        snprintf(cfg->data_dir, sizeof(cfg->data_dir), "%s", TPM_PIN_DEFAULT_DATA_DIR);
    }

    fclose(f);
    return true;
}

bool tpm_pin_config_save(const char *path, const tpm_pin_config_t *cfg) {
    if (!cfg) return false;
    const char *cfg_path = path ? path : TPM_PIN_DEFAULT_CONFIG_PATH;

    if (cfg->tcti_name[0] && strpbrk(cfg->tcti_name, "\r\n") != NULL) {
        return false;
    }

    char tmp_path[512];
    int tn = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", cfg_path, (int)getpid());
    if (tn < 0 || (size_t)tn >= sizeof(tmp_path)) return false;

    /* Ensure directory exists */
    char dir_path[512];
    int dn = snprintf(dir_path, sizeof(dir_path), "%s", cfg_path);
    if (dn < 0 || (size_t)dn >= sizeof(dir_path)) return false;
    char *slash = strrchr(dir_path, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir_path, 0755);
    }

    unlink(tmp_path);
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) return false;

    FILE *f = fdopen(fd, "we");
    if (!f) {
        close(fd);
        unlink(tmp_path);
        return false;
    }

    uint32_t min_len = cfg->min_length < 4 ? 4 : cfg->min_length;
    if (min_len > TPM_PIN_MAX_PIN_LEN) min_len = TPM_PIN_MAX_PIN_LEN;
    uint32_t max_len = cfg->max_length > TPM_PIN_MAX_PIN_LEN ? TPM_PIN_MAX_PIN_LEN : cfg->max_length;
    if (max_len < min_len) max_len = min_len;

    uint32_t da_max = cfg->da_max_tries ? cfg->da_max_tries : 5;
    if (da_max > 1000) da_max = 1000;
    uint32_t da_rec = cfg->da_recovery_time ? cfg->da_recovery_time : 600;
    if (da_rec > 2592000U) da_rec = 2592000U;
    uint32_t da_lock = cfg->da_lockout_recovery ? cfg->da_lockout_recovery : 86400;
    if (da_lock > 2592000U) da_lock = 2592000U;

    const char *safe_data_dir = (cfg->data_dir[0] == '/' &&
                                strstr(cfg->data_dir, "..") == NULL &&
                                strpbrk(cfg->data_dir, "\r\n") == NULL)
                                ? cfg->data_dir : TPM_PIN_DEFAULT_DATA_DIR;

    fprintf(f, "# Secure PIN for Linux Configuration\n");
    fprintf(f, "# Managed automatically by tpm-pin-settings and tpm-pin-ctl\n\n");
    fprintf(f, "[Policy]\n");
    fprintf(f, "digits_only = %s\n", cfg->digits_only ? "true" : "false");
    fprintf(f, "min_length = %u\n", min_len);
    fprintf(f, "max_length = %u\n", max_len);
    fprintf(f, "disallow_simple_pins = %s\n\n", cfg->disallow_simple_pins ? "true" : "false");
    fprintf(f, "[Scopes]\n");
    fprintf(f, "enable_login = %s\n", cfg->enable_login ? "true" : "false");
    fprintf(f, "enable_lockscreen = %s\n", cfg->enable_lockscreen ? "true" : "false");
    fprintf(f, "enable_sudo = %s\n", cfg->enable_sudo ? "true" : "false");
    fprintf(f, "enable_polkit = %s\n", cfg->enable_polkit ? "true" : "false");
    fprintf(f, "enable_keyring_unlock = %s\n\n", cfg->enable_keyring_unlock ? "true" : "false");
    fprintf(f, "[Security]\n");
    fprintf(f, "bind_pcr7 = %s\n", cfg->bind_pcr7 ? "true" : "false");
    fprintf(f, "da_max_tries = %u\n", da_max);
    fprintf(f, "da_recovery_time = %u\n", da_rec);
    fprintf(f, "da_lockout_recovery = %u\n\n", da_lock);
    fprintf(f, "[System]\n");
    if (cfg->tcti_name[0]) {
        fprintf(f, "tcti_name = %s\n", cfg->tcti_name);
    }
    fprintf(f, "data_dir = %s\n", safe_data_dir);

    bool write_ok = (!ferror(f) && fchmod(fd, 0644) == 0 && fflush(f) == 0 && fsync(fd) == 0);
    if (fclose(f) != 0) write_ok = false;
    if (!write_ok) {
        unlink(tmp_path);
        return false;
    }

    if (rename(tmp_path, cfg_path) != 0) {
        unlink(tmp_path);
        return false;
    }
    return true;
}
