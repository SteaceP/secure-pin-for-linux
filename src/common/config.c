#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include "tpm_pin.h"

void tpm_pin_config_defaults(tpm_pin_config_t *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->digits_only = true;
    cfg->min_length = 4;
    cfg->max_length = 32;
    cfg->enable_login = true;
    cfg->enable_lockscreen = true;
    cfg->enable_sudo = true;
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

bool tpm_pin_config_load(const char *path, tpm_pin_config_t *cfg) {
    if (!cfg) return false;
    tpm_pin_config_defaults(cfg);

    const char *cfg_path = path ? path : TPM_PIN_DEFAULT_CONFIG_PATH;
    FILE *f = fopen(cfg_path, "r");
    if (!f) {
        /* If config does not exist, defaults remain in effect */
        return true;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == '#' || *p == ';' || *p == '\0') continue;

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);

        if (strcasecmp(key, "digits_only") == 0) {
            cfg->digits_only = parse_bool(val);
        } else if (strcasecmp(key, "min_length") == 0) {
            cfg->min_length = (uint32_t)strtoul(val, NULL, 10);
            if (cfg->min_length < 4) cfg->min_length = 4;
        } else if (strcasecmp(key, "max_length") == 0) {
            cfg->max_length = (uint32_t)strtoul(val, NULL, 10);
            if (cfg->max_length > TPM_PIN_MAX_PIN_LEN) cfg->max_length = TPM_PIN_MAX_PIN_LEN;
        } else if (strcasecmp(key, "enable_login") == 0) {
            cfg->enable_login = parse_bool(val);
        } else if (strcasecmp(key, "enable_lockscreen") == 0) {
            cfg->enable_lockscreen = parse_bool(val);
        } else if (strcasecmp(key, "enable_sudo") == 0) {
            cfg->enable_sudo = parse_bool(val);
        } else if (strcasecmp(key, "enable_keyring_unlock") == 0) {
            cfg->enable_keyring_unlock = parse_bool(val);
        } else if (strcasecmp(key, "bind_pcr7") == 0) {
            cfg->bind_pcr7 = parse_bool(val);
        } else if (strcasecmp(key, "da_max_tries") == 0) {
            cfg->da_max_tries = (uint32_t)strtoul(val, NULL, 10);
            if (cfg->da_max_tries == 0) cfg->da_max_tries = 5;
        } else if (strcasecmp(key, "da_recovery_time") == 0) {
            cfg->da_recovery_time = (uint32_t)strtoul(val, NULL, 10);
        } else if (strcasecmp(key, "da_lockout_recovery") == 0) {
            cfg->da_lockout_recovery = (uint32_t)strtoul(val, NULL, 10);
        } else if (strcasecmp(key, "tcti_name") == 0) {
            snprintf(cfg->tcti_name, sizeof(cfg->tcti_name), "%s", val);
        } else if (strcasecmp(key, "data_dir") == 0) {
            snprintf(cfg->data_dir, sizeof(cfg->data_dir), "%s", val);
        }
    }

    fclose(f);
    return true;
}

bool tpm_pin_config_save(const char *path, const tpm_pin_config_t *cfg) {
    if (!cfg) return false;
    const char *cfg_path = path ? path : TPM_PIN_DEFAULT_CONFIG_PATH;

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", cfg_path, (int)getpid());

    /* Ensure directory exists */
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s", cfg_path);
    char *slash = strrchr(dir_path, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir_path, 0755);
    }

    FILE *f = fopen(tmp_path, "w");
    if (!f) return false;

    fprintf(f, "# Secure PIN for Linux Configuration\n");
    fprintf(f, "# Managed automatically by tpm-pin-settings and tpm-pin-ctl\n\n");
    fprintf(f, "[Policy]\n");
    fprintf(f, "digits_only = %s\n", cfg->digits_only ? "true" : "false");
    fprintf(f, "min_length = %u\n", cfg->min_length);
    fprintf(f, "max_length = %u\n\n", cfg->max_length);
    fprintf(f, "[Scopes]\n");
    fprintf(f, "enable_login = %s\n", cfg->enable_login ? "true" : "false");
    fprintf(f, "enable_lockscreen = %s\n", cfg->enable_lockscreen ? "true" : "false");
    fprintf(f, "enable_sudo = %s\n", cfg->enable_sudo ? "true" : "false");
    fprintf(f, "enable_keyring_unlock = %s\n\n", cfg->enable_keyring_unlock ? "true" : "false");
    fprintf(f, "[Security]\n");
    fprintf(f, "bind_pcr7 = %s\n", cfg->bind_pcr7 ? "true" : "false");
    fprintf(f, "da_max_tries = %u\n", cfg->da_max_tries);
    fprintf(f, "da_recovery_time = %u\n", cfg->da_recovery_time);
    fprintf(f, "da_lockout_recovery = %u\n\n", cfg->da_lockout_recovery);
    fprintf(f, "[System]\n");
    if (cfg->tcti_name[0]) {
        fprintf(f, "tcti_name = %s\n", cfg->tcti_name);
    }
    fprintf(f, "data_dir = %s\n", cfg->data_dir);

    fclose(f);

    chmod(tmp_path, 0644);
    if (rename(tmp_path, cfg_path) != 0) {
        unlink(tmp_path);
        return false;
    }
    return true;
}
