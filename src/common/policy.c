#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "tpm_pin.h"

bool tpm_pin_validate_pin(const char *pin, const tpm_pin_config_t *cfg, char *err_buf, size_t err_size) {
    if (!pin) {
        if (err_buf && err_size > 0) snprintf(err_buf, err_size, "PIN cannot be empty.");
        return false;
    }

    size_t len = strlen(pin);
    uint32_t min_len = cfg ? cfg->min_length : 4;
    uint32_t max_len = cfg ? cfg->max_length : 32;

    if (len < min_len) {
        if (err_buf && err_size > 0)
            snprintf(err_buf, err_size, "PIN is too short (minimum %u characters required).", min_len);
        return false;
    }

    if (len > max_len) {
        if (err_buf && err_size > 0)
            snprintf(err_buf, err_size, "PIN is too long (maximum %u characters allowed).", max_len);
        return false;
    }

    if (cfg && cfg->digits_only) {
        for (size_t i = 0; i < len; i++) {
            if (!isdigit((unsigned char)pin[i])) {
                if (err_buf && err_size > 0)
                    snprintf(err_buf, err_size, "PIN must contain numbers only.");
                return false;
            }
        }
    }

    /* Reject trivial all-identical PINs (e.g. "0000", "1111") */
    bool all_same = true;
    for (size_t i = 1; i < len; i++) {
        if (pin[i] != pin[0]) {
            all_same = false;
            break;
        }
    }
    if (all_same && len >= 4) {
        if (err_buf && err_size > 0)
            snprintf(err_buf, err_size, "PIN cannot consist of all identical characters.");
        return false;
    }

    return true;
}

bool tpm_pin_is_likely_pin(const char *input, const tpm_pin_config_t *cfg) {
    if (!input) return false;
    size_t len = strlen(input);
    uint32_t min_len = cfg ? cfg->min_length : 4;
    uint32_t max_len = cfg ? cfg->max_length : 32;

    if (len < min_len || len > max_len) {
        return false;
    }

    if (cfg && cfg->digits_only) {
        for (size_t i = 0; i < len; i++) {
            if (!isdigit((unsigned char)input[i])) {
                return false;
            }
        }
    }

    return true;
}

bool tpm_pin_is_service_enabled(const char *service, bool unprivileged_caller, const tpm_pin_config_t *cfg) {
    if (!service || service[0] == '\0' || !cfg) return false;

    /* Explicitly deny remote and non-interactive services before substring checks (e.g. "rlogin", "system-remote-login") */
    if (strcmp(service, "sshd") == 0 ||
        strcmp(service, "dropbear") == 0 ||
        strcmp(service, "rlogin") == 0 ||
        strcmp(service, "rsh") == 0 ||
        strcmp(service, "telnet") == 0 ||
        strcmp(service, "cockpit") == 0 ||
        strcmp(service, "cron") == 0 ||
        strcmp(service, "crond") == 0 ||
        strstr(service, "remote") != NULL ||
        strstr(service, "xrdp") != NULL ||
        strstr(service, "vnc") != NULL) {
        return false;
    }

    if (strcmp(service, "sudo") == 0 ||
        strcmp(service, "sudo-i") == 0 ||
        strcmp(service, "su") == 0 ||
        strcmp(service, "su-l") == 0 ||
        strcmp(service, "doas") == 0) {
        return cfg->enable_sudo;
    }

    if (strcmp(service, "gdm-password") == 0) {
        return cfg->enable_login || cfg->enable_lockscreen;
    }

    /* Unprivileged user-session screen lockers (e.g. COSMIC cosmic-greeter, swaylock fallback) invoke "login" */
    if (strcmp(service, "login") == 0 && unprivileged_caller) {
        return cfg->enable_lockscreen;
    }

    if (strcmp(service, "kde") == 0 ||
        strncmp(service, "kde-", 4) == 0 ||
        strcmp(service, "cosmic-greeter") == 0 ||
        strstr(service, "screenlocker") != NULL ||
        strstr(service, "screensaver") != NULL ||
        strstr(service, "lock") != NULL ||
        strstr(service, "polkit") != NULL ||
        strstr(service, "policykit") != NULL) {
        return cfg->enable_lockscreen;
    }

    if (strcmp(service, "greetd") == 0 ||
        strcmp(service, "ly") == 0 ||
        strcmp(service, "lxdm") == 0 ||
        strcmp(service, "lemurs") == 0 ||
        strcmp(service, "slim") == 0 ||
        strstr(service, "login") != NULL ||
        strstr(service, "gdm") != NULL ||
        strstr(service, "sddm") != NULL ||
        strstr(service, "lightdm") != NULL ||
        strstr(service, "greeter") != NULL) {
        return cfg->enable_login;
    }

    /* Unknown services must NOT allow PIN by default */
    return false;
}
