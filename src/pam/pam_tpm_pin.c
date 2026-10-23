#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "tpm_pin.h"

static bool is_service_enabled(const char *service, const tpm_pin_config_t *cfg) {
    if (!service || !cfg) return false;

    if (strcmp(service, "sudo") == 0 || strcmp(service, "sudo-i") == 0 || strcmp(service, "su") == 0) {
        return cfg->enable_sudo;
    }
    if (strstr(service, "screenlocker") || strstr(service, "lock") || strstr(service, "polkit") || strstr(service, "policykit")) {
        return cfg->enable_lockscreen;
    }
    if (strcmp(service, "gdm-password") == 0) {
        return cfg->enable_login || cfg->enable_lockscreen;
    }
    if (strstr(service, "login") || strstr(service, "gdm") || strstr(service, "sddm") || strstr(service, "lightdm")) {
        return cfg->enable_login;
    }
    /* Unknown or remote services (e.g. sshd, cockpit, cron) must NOT allow PIN by default */
    return false;
}

static void pam_cleanup_secret(pam_handle_t *pamh, void *data, int error_status) {
    (void)pamh;
    (void)error_status;
    if (data) {
        char *str = (char *)data;
        tpm_pin_zero(str, strlen(str));
        free(str);
    }
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)argc;
    (void)argv;

    /* Prevent TSS2 error strings from leaking into Polkit helper socket streams */
    setenv("TSS2_LOG", "NONE", 1);
    setenv("TSS2_LOGFILE", "/dev/null", 1);

    const char *service = NULL;
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);

    tpm_pin_config_t cfg;
    tpm_pin_config_load(NULL, &cfg);

    if (!is_service_enabled(service, &cfg)) {
        return PAM_IGNORE;
    }

    const char *username = NULL;
    int rc = pam_get_user(pamh, &username, NULL);
    if (rc != PAM_SUCCESS || !username) {
        return PAM_USER_UNKNOWN;
    }

    struct passwd pwd_buf;
    struct passwd *pwd = NULL;
    char pbuf[1024];
    if (getpwnam_r(username, &pwd_buf, pbuf, sizeof(pbuf), &pwd) != 0 || !pwd) {
        return PAM_USER_UNKNOWN;
    }

    /* If user has not enrolled a PIN, pass through cleanly */
    if (!tpm_pin_user_is_enrolled(pwd->pw_uid, &cfg)) {
        return PAM_IGNORE;
    }

    char *input = NULL;
    const void *authtok = NULL;
    pam_get_item(pamh, PAM_AUTHTOK, &authtok);

    if (authtok && strlen((const char *)authtok) > 0) {
        input = strdup((const char *)authtok);
    } else {
        char *resp = NULL;
        rc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "PIN or Password: ");
        if (rc != PAM_SUCCESS || !resp) {
            return PAM_AUTHINFO_UNAVAIL;
        }
        input = resp;
    }

    if (!input || strlen(input) == 0) {
        if (input) {
            tpm_pin_zero(input, strlen(input));
            free(input);
        }
        return PAM_AUTHINFO_UNAVAIL;
    }

    char unsealed_pwd[TPM_PIN_MAX_PASSWORD_LEN] = {0};
    int tpm_rc = 0;

    bool pin_success = false;
    if (tpm_pin_is_likely_pin(input, &cfg)) {
        pin_success = tpm_pin_verify_user(
            pwd->pw_uid,
            input,
            &cfg,
            unsealed_pwd,
            sizeof(unsealed_pwd),
            &tpm_rc
        );
    }

    if (pin_success) {
        /* Successfully authenticated with hardware TPM PIN */
        if (strlen(unsealed_pwd) > 0) {
            /* Pass unsealed system password to PAM_AUTHTOK so GNOME Keyring unlocks automatically */
            pam_set_item(pamh, PAM_AUTHTOK, unsealed_pwd);

            /* Stash unsealed password in PAM data so pam_gnome_keyring session can auto-unlock */
            char *gkr_pwd = strdup(unsealed_pwd);
            if (gkr_pwd) {
                pam_set_data(pamh, "gkr_system_authtok", gkr_pwd, pam_cleanup_secret);
            }
        } else {
            pam_set_item(pamh, PAM_AUTHTOK, input);
        }
        tpm_pin_zero(unsealed_pwd, sizeof(unsealed_pwd));
        tpm_pin_zero(input, strlen(input));
        free(input);
        return PAM_SUCCESS;
    }

    /*
     * PIN verification was not successful, or input was not in PIN format.
     * Store the entered input as PAM_AUTHTOK so downstream pam_unix try_first_pass
     * can test it as a regular user password without prompting the user a second time!
     */
    pam_set_item(pamh, PAM_AUTHTOK, input);

    if (((tpm_rc & 0xFFF) == (TPM2_RC_LOCKOUT & 0xFFF)) && !(flags & PAM_SILENT)) {
        pam_info(pamh, "TPM Dictionary Attack Lockout active. Falling back to system password.");
    }

    tpm_pin_zero(unsealed_pwd, sizeof(unsealed_pwd));
    tpm_pin_zero(input, strlen(input));
    free(input);

    return PAM_AUTHINFO_UNAVAIL;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags;
    (void)argc;
    (void)argv;

    /* When user changes password, optionally re-seal */
    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
        return PAM_SUCCESS;
    }

    struct passwd pwd_buf;
    struct passwd *pwd = NULL;
    char pbuf[1024];
    if (getpwnam_r(username, &pwd_buf, pbuf, sizeof(pbuf), &pwd) != 0 || !pwd) {
        return PAM_SUCCESS;
    }

    tpm_pin_config_t cfg;
    tpm_pin_config_load(NULL, &cfg);

    if (!tpm_pin_user_is_enrolled(pwd->pw_uid, &cfg) || !cfg.enable_keyring_unlock) {
        return PAM_SUCCESS;
    }

    return PAM_SUCCESS;
}
