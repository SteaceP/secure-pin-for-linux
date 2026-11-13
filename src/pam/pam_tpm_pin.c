#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "tpm_pin.h"

static void pam_cleanup_secret(pam_handle_t *pamh, void *data, int error_status) {
    (void)pamh;
    (void)error_status;
    if (data) {
        char *str = (char *)data;
        tpm_pin_zero(str, strlen(str));
        free(str);
    }
}

static const char *find_verify_helper(void) {
    static const char *const candidates[] = {
#ifdef TPM_PIN_VERIFY_PATH
        TPM_PIN_VERIFY_PATH,
#endif
        "/usr/lib/tpm-pin/tpm-pin-verify",
        "/usr/libexec/tpm-pin-verify",
    };

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0 &&
            S_ISREG(st.st_mode) &&
            st.st_uid == 0 &&
            (st.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
            (st.st_mode & S_ISUID) != 0 &&
            (st.st_mode & S_IXOTH) != 0) {
            return candidates[i];
        }
    }
    return NULL;
}

static bool verify_via_setuid_helper(const char *username, const char *pin, int *tpm_rc) {
    const char *helper = find_verify_helper();
    if (!helper || !username || !pin) return false;

    size_t pin_len = strlen(pin);
    if (pin_len == 0 || pin_len > TPM_PIN_MAX_PIN_LEN) return false;

    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC) != 0) {
        return false;
    }

    /* Write small PIN payload before fork while pfd[0] is open: cannot block or raise SIGPIPE */
    char msg[TPM_PIN_MAX_PIN_LEN + 2];
    memcpy(msg, pin, pin_len);
    msg[pin_len] = '\n';
    ssize_t written = write(pfd[1], msg, pin_len + 1);
    tpm_pin_zero(msg, sizeof(msg));
    close(pfd[1]);

    if (written != (ssize_t)(pin_len + 1)) {
        close(pfd[0]);
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        return false;
    }

    if (pid == 0) {
        if (dup2(pfd[0], STDIN_FILENO) < 0) {
            _exit(127);
        }
        if (pfd[0] != STDIN_FILENO) {
            close(pfd[0]);
        }
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        char *const args[] = { (char *)helper, (char *)username, NULL };
        char *const envp[] = { "PATH=/usr/bin:/bin", "TSS2_LOG=all+NONE", "TSS2_LOGFILE=/dev/null", NULL };
        execve(helper, args, envp);
        _exit(127);
    }

    close(pfd[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return false;
        }
    }

    if (!WIFEXITED(status)) {
        return false;
    }

    int code = WEXITSTATUS(status);
    if (code == 0) {
        if (tpm_rc) *tpm_rc = 0;
        return true;
    }
    if (code == 2 && tpm_rc) {
        *tpm_rc = TPM2_RC_LOCKOUT;
    } else if (code == 3 && tpm_rc) {
        *tpm_rc = TPM2_RC_POLICY_FAIL;
    }
    return false;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)argc;
    (void)argv;

    /* Prevent TSS2 error strings from leaking into Polkit helper socket streams */
    if (getenv("TSS2_LOG") == NULL) {
        setenv("TSS2_LOG", "all+NONE", 1);
    }
    if (getenv("TSS2_LOGFILE") == NULL) {
        setenv("TSS2_LOGFILE", "/dev/null", 1);
    }

    const char *service = NULL;
    pam_get_item(pamh, PAM_SERVICE, (const void **)&service);

    tpm_pin_config_t cfg;
    tpm_pin_config_load(NULL, &cfg);

    if (!tpm_pin_is_service_enabled(service, geteuid() != 0, &cfg)) {
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

    bool is_unpriv = (geteuid() != 0);
    if (is_unpriv && pwd->pw_uid != getuid()) {
        tpm_pin_zero(input, strlen(input));
        free(input);
        return PAM_AUTHINFO_UNAVAIL;
    }

    bool likely_pin = tpm_pin_is_likely_pin(input, &cfg);
    bool pin_success = false;
    if (likely_pin) {
        bool use_helper = (is_unpriv &&
                           pwd->pw_uid == getuid() &&
                           find_verify_helper() != NULL &&
                           cfg.tcti_name[0] == '\0' &&
                           secure_getenv("TCTI") == NULL);

        if (use_helper) {
            pin_success = verify_via_setuid_helper(username, input, &tpm_rc);
        } else {
            /* Never unseal keyring password into an unprivileged caller's address space */
            char *pwd_out = is_unpriv ? NULL : unsealed_pwd;
            size_t pwd_sz = is_unpriv ? 0 : sizeof(unsealed_pwd);
            pin_success = tpm_pin_verify_user(
                pwd->pw_uid,
                input,
                &cfg,
                pwd_out,
                pwd_sz,
                &tpm_rc
            );
        }
    }

    if (pin_success) {
        /* Successfully authenticated with hardware TPM PIN */
        if (strlen(unsealed_pwd) > 0) {
            /* Pass unsealed system password to PAM_AUTHTOK so GNOME Keyring / KWallet unlock automatically */
            pam_set_item(pamh, PAM_AUTHTOK, unsealed_pwd);

            /* Stash unsealed password in PAM data so pam_gnome_keyring sessions auto-unlock */
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
     * Store the entered input as PAM_AUTHTOK only if it wasn't a digits-only PIN
     * (so downstream pam_unix.so prompts for the Unix password instead of burning
     * pam_faillock tries on a failed PIN), or if alphanumeric PIN mode is active.
     */
    if (!likely_pin || !cfg.digits_only) {
        pam_set_item(pamh, PAM_AUTHTOK, input);
    }

    if (!(flags & PAM_SILENT)) {
        if ((tpm_rc & 0xFFF) == (TPM2_RC_LOCKOUT & 0xFFF)) {
            pam_info(pamh, "TPM Dictionary Attack Lockout active. Falling back to system password.");
        } else if ((tpm_rc & 0xFFF) == (TPM2_RC_POLICY_FAIL & 0xFFF) || (tpm_rc & 0xBF) == 0x84) {
            pam_info(pamh, "Secure Boot (PCR 7) state changed. Falling back to system password.");
        }
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
    return PAM_IGNORE;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
