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

    for (size_t i = 0; i < len; i++) {
        if (iscntrl((unsigned char)pin[i])) {
            if (err_buf && err_size > 0)
                snprintf(err_buf, err_size, "PIN cannot contain control characters.");
            return false;
        }
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

    for (size_t i = 0; i < len; i++) {
        if (iscntrl((unsigned char)input[i])) {
            return false;
        }
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

static bool has_suffix(const char *s, const char *suffix) {
    size_t slen = strlen(s);
    size_t suflen = strlen(suffix);
    if (slen < suflen) return false;
    return strcmp(s + (slen - suflen), suffix) == 0;
}

bool tpm_pin_is_service_enabled(const char *service, bool unprivileged_caller, const tpm_pin_config_t *cfg) {
    if (!service || service[0] == '\0' || !cfg) return false;

    /* Explicitly deny remote, network, and non-interactive services before allowlist checks */
    if (strcmp(service, "sshd") == 0 ||
        strcmp(service, "dropbear") == 0 ||
        strcmp(service, "rlogin") == 0 ||
        strcmp(service, "rsh") == 0 ||
        strcmp(service, "klogin") == 0 ||
        strcmp(service, "eklogin") == 0 ||
        strcmp(service, "krlogin") == 0 ||
        strcmp(service, "rexec") == 0 ||
        strcmp(service, "telnet") == 0 ||
        strcmp(service, "cockpit") == 0 ||
        strcmp(service, "cron") == 0 ||
        strcmp(service, "crond") == 0 ||
        strcmp(service, "atd") == 0 ||
        strcmp(service, "systemd-user") == 0 ||
        strcmp(service, "ftp") == 0 ||
        strcmp(service, "vsftpd") == 0 ||
        strcmp(service, "proftpd") == 0 ||
        strcmp(service, "pure-ftpd") == 0 ||
        strcmp(service, "dovecot") == 0 ||
        strcmp(service, "samba") == 0 ||
        strcmp(service, "smbd") == 0 ||
        strcmp(service, "x2go") == 0 ||
        strcmp(service, "wayvnc") == 0 ||
        strstr(service, "remote") != NULL ||
        strstr(service, "autologin") != NULL ||
        strstr(service, "xrdp") != NULL ||
        strstr(service, "vnc") != NULL) {
        return false;
    }

    /* Privilege elevation (CLI and graphical Polkit) requires root caller & enable_sudo */
    if (strcmp(service, "sudo") == 0 ||
        strcmp(service, "sudo-i") == 0 ||
        strcmp(service, "su") == 0 ||
        strcmp(service, "su-l") == 0 ||
        strcmp(service, "doas") == 0 ||
        strcmp(service, "polkit") == 0 ||
        strcmp(service, "polkit-1") == 0 ||
        strcmp(service, "policykit") == 0 ||
        strcmp(service, "pkexec") == 0 ||
        strncmp(service, "polkit-", 7) == 0) {
        if (unprivileged_caller) return false;
        return cfg->enable_sudo;
    }

    if (strcmp(service, "gdm-password") == 0) {
        if (unprivileged_caller) return cfg->enable_lockscreen;
        return cfg->enable_login || cfg->enable_lockscreen;
    }

    /* Unprivileged user-session screen lockers (e.g. COSMIC cosmic-greeter, swaylock fallback) invoke "login" or "cosmic-greeter" */
    if (strcmp(service, "login") == 0 || strcmp(service, "cosmic-greeter") == 0) {
        return unprivileged_caller ? cfg->enable_lockscreen : cfg->enable_login;
    }

    /* Lock screens and screensavers */
    if (strcmp(service, "kde") == 0 ||
        strncmp(service, "kde-", 4) == 0 ||
        strcmp(service, "kscreensaver") == 0 ||
        strcmp(service, "kscreenlocker") == 0 ||
        strcmp(service, "gnome-screensaver") == 0 ||
        strcmp(service, "cinnamon-screensaver") == 0 ||
        strcmp(service, "mate-screensaver") == 0 ||
        strcmp(service, "xfce4-screensaver") == 0 ||
        strcmp(service, "xscreensaver") == 0 ||
        strcmp(service, "light-locker") == 0 ||
        strcmp(service, "swaylock") == 0 ||
        strcmp(service, "hyprlock") == 0 ||
        strcmp(service, "gtklock") == 0 ||
        strcmp(service, "waylock") == 0 ||
        strcmp(service, "i3lock") == 0 ||
        strcmp(service, "xlock") == 0 ||
        strcmp(service, "slock") == 0 ||
        strcmp(service, "vlock") == 0 ||
        strcmp(service, "physlock") == 0 ||
        strcmp(service, "xsecurelock") == 0 ||
        strcmp(service, "deepin-screensaver") == 0 ||
        strcmp(service, "ukui-screensaver") == 0 ||
        strcmp(service, "budgie-screensaver") == 0 ||
        strcmp(service, "pantheon-screensaver") == 0 ||
        has_suffix(service, "-screensaver") ||
        has_suffix(service, "-screenlocker")) {
        return cfg->enable_lockscreen;
    }

    /* Local display managers & console login (must run as root) */
    if (strcmp(service, "greetd") == 0 ||
        strcmp(service, "ly") == 0 ||
        strcmp(service, "lxdm") == 0 ||
        strcmp(service, "lemurs") == 0 ||
        strcmp(service, "slim") == 0 ||
        strcmp(service, "sddm") == 0 ||
        strcmp(service, "sddm-greeter") == 0 ||
        strcmp(service, "lightdm") == 0 ||
        strcmp(service, "lightdm-greeter") == 0 ||
        strcmp(service, "gdm") == 0 ||
        strcmp(service, "gdm-launch-environment") == 0 ||
        strcmp(service, "mdm") == 0 ||
        strcmp(service, "xdm") == 0 ||
        strcmp(service, "emptty") == 0 ||
        strcmp(service, "tuigreet") == 0 ||
        strcmp(service, "system-local-login") == 0 ||
        strcmp(service, "local-login") == 0 ||
        strncmp(service, "gdm-", 4) == 0 ||
        strncmp(service, "sddm-", 5) == 0 ||
        strncmp(service, "lightdm-", 8) == 0) {
        if (unprivileged_caller) return false;
        return cfg->enable_login;
    }

    /* Unknown services must NOT allow PIN by default */
    return false;
}
