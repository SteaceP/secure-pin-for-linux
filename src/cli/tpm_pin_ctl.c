#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>
#include <termios.h>
#include <getopt.h>
#include "tpm_pin.h"

static volatile sig_atomic_t echo_disabled_flag = 0;
static struct termios saved_orig_termios;

static void secret_signal_handler(int sig) {
    if (echo_disabled_flag) {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_orig_termios);
        echo_disabled_flag = 0;
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static bool disable_echo(struct termios *orig) {
    if (tcgetattr(STDIN_FILENO, orig) != 0) return false;
    struct termios t = *orig;
    t.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    return (tcsetattr(STDIN_FILENO, TCSANOW, &t) == 0);
}

static void restore_echo(const struct termios *orig) {
    tcsetattr(STDIN_FILENO, TCSANOW, orig);
}

static char *read_secret(const char *prompt) {
    struct termios orig;
    struct sigaction sa, old_int, old_term;
    bool has_int = false;
    bool has_term = false;
    bool echo_changed = false;

    printf("%s", prompt);
    fflush(stdout);

    bool is_tty = isatty(STDIN_FILENO);
    if (is_tty && disable_echo(&orig)) {
        saved_orig_termios = orig;
        echo_disabled_flag = 1;
        echo_changed = true;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = secret_signal_handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGINT, &sa, &old_int) == 0) has_int = true;
        if (sigaction(SIGTERM, &sa, &old_term) == 0) has_term = true;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read_bytes = getline(&line, &len, stdin);

    if (is_tty) {
        if (echo_changed) {
            echo_disabled_flag = 0;
            if (has_int) sigaction(SIGINT, &old_int, NULL);
            if (has_term) sigaction(SIGTERM, &old_term, NULL);
            restore_echo(&orig);
        }
        printf("\n");
    }

    if (read_bytes <= 0 || !line) {
        if (line) {
            tpm_pin_zero(line, len);
            free(line);
        }
        return NULL;
    }

    while (read_bytes > 0 && (line[read_bytes - 1] == '\n' || line[read_bytes - 1] == '\r')) {
        line[--read_bytes] = '\0';
    }
    return line;
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

static bool parse_bool_strict(const char *val, bool *out) {
    if (!val || !out) return false;
    if (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0 ||
        strcasecmp(val, "yes") == 0 || strcasecmp(val, "on") == 0) {
        *out = true;
        return true;
    }
    if (strcasecmp(val, "false") == 0 || strcmp(val, "0") == 0 ||
        strcasecmp(val, "no") == 0 || strcasecmp(val, "off") == 0) {
        *out = false;
        return true;
    }
    return false;
}

static bool lookup_user_by_name(const char *username, uid_t *uid_out, char *name_out, size_t name_sz) {
    if (!username || !uid_out) return false;
    long init_sz = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t buf_sz = (init_sz > 0) ? (size_t)init_sz : 1024;
    if (buf_sz < 1024) buf_sz = 1024;

    while (buf_sz <= 65536) {
        char *pbuf = (char *)malloc(buf_sz);
        if (!pbuf) return false;
        struct passwd pwd_s;
        struct passwd *pw = NULL;
        int rc = getpwnam_r(username, &pwd_s, pbuf, buf_sz, &pw);
        if (rc == 0 && pw) {
            *uid_out = pw->pw_uid;
            if (name_out && name_sz > 0) snprintf(name_out, name_sz, "%s", pw->pw_name);
            free(pbuf);
            return true;
        }
        free(pbuf);
        if (rc != ERANGE) return false;
        buf_sz *= 2;
    }
    return false;
}

static bool lookup_user_by_uid(uid_t uid, char *name_out, size_t name_sz) {
    long init_sz = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t buf_sz = (init_sz > 0) ? (size_t)init_sz : 1024;
    if (buf_sz < 1024) buf_sz = 1024;

    while (buf_sz <= 65536) {
        char *pbuf = (char *)malloc(buf_sz);
        if (!pbuf) return false;
        struct passwd pwd_s;
        struct passwd *pw = NULL;
        int rc = getpwuid_r(uid, &pwd_s, pbuf, buf_sz, &pw);
        if (rc == 0 && pw) {
            if (name_out && name_sz > 0) snprintf(name_out, name_sz, "%s", pw->pw_name);
            free(pbuf);
            return true;
        }
        free(pbuf);
        if (rc != ERANGE) return false;
        buf_sz *= 2;
    }
    return false;
}

static void print_json_escaped(const char *s) {
    putchar('"');
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            unsigned char c = *p;
            if (c == '"' || c == '\\') {
                putchar('\\');
                putchar(c);
            } else if (c == '\n') {
                fputs("\\n", stdout);
            } else if (c == '\r') {
                fputs("\\r", stdout);
            } else if (c == '\t') {
                fputs("\\t", stdout);
            } else if (c < 0x20) {
                printf("\\u%04x", (unsigned int)c);
            } else {
                putchar(c);
            }
        }
    }
    putchar('"');
}

static void print_usage(const char *prog) {
    printf("Secure PIN for Linux (TPM 2.0 Windows Hello–Style PIN)\n\n");
    printf("Usage:\n");
    printf("  %s status [--json] [--user <username>]\n", prog);
    printf("  %s enroll [--user <username>]\n", prog);
    printf("  %s verify [--user <username>]\n", prog);
    printf("  %s remove [--user <username>]\n", prog);
    printf("  %s pam <enable|disable [--uninstall]|status>\n", prog);
    printf("  %s da-reset\n", prog);
    printf("  %s da-config --max-tries <n> --recovery-sec <s> [--lockout-recovery <s>]\n", prog);
    printf("  %s config get <key>\n", prog);
    printf("  %s config set <key> <value>\n", prog);
}

int main(int argc, char **argv) {
    if (getenv("TSS2_LOG") == NULL) {
        setenv("TSS2_LOG", "all+NONE", 0);
    }

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];
    const char *username = NULL;
    char *opt_pin_buf = NULL;
    char *opt_pwd_buf = NULL;
    bool json_output = false;
    bool opt_uninstall = false;
    const char *arg_max_tries = NULL;
    const char *arg_recovery_sec = NULL;
    const char *arg_lockout_recovery = NULL;

    int exit_code = 1;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            json_output = true;
        } else if (strcmp(argv[i], "--uninstall") == 0) {
            opt_uninstall = true;
        } else if (strcmp(argv[i], "--user") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --user requires a username argument.\n");
                goto cleanup;
            }
            username = argv[++i];
        } else if (strcmp(argv[i], "--pin") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --pin requires a PIN argument.\n");
                goto cleanup;
            }
            i++;
            fprintf(stderr, "Warning: Passing --pin on the command line exposes secrets in process listings; prefer interactive/stdin input.\n");
            if (opt_pin_buf) {
                tpm_pin_zero(opt_pin_buf, strlen(opt_pin_buf));
                free(opt_pin_buf);
            }
            opt_pin_buf = strdup(argv[i]);
            tpm_pin_zero(argv[i], strlen(argv[i]));
        } else if (strcmp(argv[i], "--password") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --password requires a password argument.\n");
                goto cleanup;
            }
            i++;
            fprintf(stderr, "Warning: Passing --password on the command line exposes secrets in process listings; prefer interactive/stdin input.\n");
            if (opt_pwd_buf) {
                tpm_pin_zero(opt_pwd_buf, strlen(opt_pwd_buf));
                free(opt_pwd_buf);
            }
            opt_pwd_buf = strdup(argv[i]);
            tpm_pin_zero(argv[i], strlen(argv[i]));
        } else if (strcmp(argv[i], "--max-tries") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --max-tries requires a numeric argument.\n");
                goto cleanup;
            }
            arg_max_tries = argv[++i];
        } else if (strcmp(argv[i], "--recovery-sec") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --recovery-sec requires a numeric argument.\n");
                goto cleanup;
            }
            arg_recovery_sec = argv[++i];
        } else if (strcmp(argv[i], "--lockout-recovery") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --lockout-recovery requires a numeric argument.\n");
                goto cleanup;
            }
            arg_lockout_recovery = argv[++i];
        }
    }

    uid_t caller_uid = getuid();
    uid_t uid = caller_uid;
    char user_buf[128] = {0};

    if (username) {
        uid_t target_uid = 0;
        if (!lookup_user_by_name(username, &target_uid, user_buf, sizeof(user_buf))) {
            fprintf(stderr, "Error: Unknown user '%s'\n", username);
            goto cleanup;
        }
        if (caller_uid != 0 && target_uid != caller_uid) {
            fprintf(stderr, "Error: Permission denied (only root can target another user).\n");
            goto cleanup;
        }
        uid = target_uid;
        username = user_buf;
    } else {
        if (caller_uid == 0) {
            const char *pkexec_uid = secure_getenv("PKEXEC_UID");
            const char *sudo_uid = secure_getenv("SUDO_UID");
            const char *orig_uid_str = pkexec_uid ? pkexec_uid : sudo_uid;
            if (orig_uid_str && orig_uid_str[0] != '\0') {
                uint32_t parsed_uid = 0;
                if (parse_u32_strict(orig_uid_str, &parsed_uid) && parsed_uid > 0) {
                    if (lookup_user_by_uid((uid_t)parsed_uid, user_buf, sizeof(user_buf))) {
                        uid = (uid_t)parsed_uid;
                        username = user_buf;
                    }
                }
            }
        }
        if (!username && lookup_user_by_uid(uid, user_buf, sizeof(user_buf))) {
            username = user_buf;
        }
    }

    tpm_pin_config_t cfg;
    tpm_pin_config_load(NULL, &cfg);

    if (strcmp(action, "status") == 0) {
        tpm_pin_status_t status;
        tpm_pin_get_user_status(uid, &cfg, &status);
        bool pam_active = pam_manager_is_enabled();
        linux_distro_t distro = pam_manager_detect_distro();

        if (json_output) {
            printf("{\n");
            printf("  \"tpm_present\": %s,\n", status.tpm_present ? "true" : "false");
            printf("  \"tpm_accessible\": %s,\n", status.tpm_accessible ? "true" : "false");
            printf("  \"tpm_manufacturer\": ");
            print_json_escaped(status.manufacturer[0] ? status.manufacturer : "TPM 2.0");
            printf(",\n");
            printf("  \"hardware_type\": ");
            print_json_escaped(status.hardware_type[0] ? status.hardware_type : "TPM 2.0");
            printf(",\n");
            printf("  \"bus_encryption\": ");
            print_json_escaped(status.bus_encryption[0] ? status.bus_encryption : "Active");
            printf(",\n");
            printf("  \"user\": ");
            print_json_escaped(username ? username : "unknown");
            printf(",\n");
            printf("  \"uid\": %u,\n", (unsigned int)uid);
            printf("  \"is_enrolled\": %s,\n", status.is_enrolled ? "true" : "false");
            printf("  \"pcr7_bound\": %s,\n", status.pcr7_bound ? "true" : "false");
            printf("  \"bind_pcr7\": %s,\n", cfg.bind_pcr7 ? "true" : "false");
            printf("  \"is_locked_out\": %s,\n", status.is_locked_out ? "true" : "false");
            printf("  \"failed_tries\": %u,\n", status.failed_tries);
            printf("  \"max_tries\": %u,\n", status.max_tries);
            printf("  \"keyring_pwd_saved\": %s,\n", status.keyring_pwd_saved ? "true" : "false");
            printf("  \"pam_enabled\": %s,\n", pam_active ? "true" : "false");
            printf("  \"distro\": ");
            print_json_escaped(pam_manager_distro_name(distro));
            printf(",\n");
            printf("  \"digits_only\": %s,\n", cfg.digits_only ? "true" : "false");
            printf("  \"min_length\": %u,\n", cfg.min_length);
            printf("  \"max_length\": %u,\n", cfg.max_length);
            printf("  \"da_max_tries\": %u,\n", cfg.da_max_tries);
            printf("  \"da_recovery_time\": %u,\n", cfg.da_recovery_time);
            printf("  \"enable_login\": %s,\n", cfg.enable_login ? "true" : "false");
            printf("  \"enable_lockscreen\": %s,\n", cfg.enable_lockscreen ? "true" : "false");
            printf("  \"enable_sudo\": %s,\n", cfg.enable_sudo ? "true" : "false");
            printf("  \"enable_keyring_unlock\": %s\n", cfg.enable_keyring_unlock ? "true" : "false");
            printf("}\n");
        } else {
            const char *tpm_state_str = "Not Found";
            if (status.tpm_present && status.tpm_accessible) {
                tpm_state_str = "Detected & Ready";
            } else if (status.tpm_present) {
                tpm_state_str = "Detected (Hardware protected — run with sudo or activate PAM)";
            }
            printf("=== Secure PIN for Linux Status ===\n");
            printf("TPM 2.0 Device:         %s\n", tpm_state_str);
            printf("Hardware Security:      %s\n", status.hardware_type[0] ? status.hardware_type : "TPM 2.0");
            printf("Bus Protection:         %s\n", status.bus_encryption[0] ? status.bus_encryption : "Active");
            printf("Target User:            %s (UID: %u)\n", username ? username : "unknown", (unsigned int)uid);
            printf("PIN Enrolled:           %s\n", status.is_enrolled ? "Yes" : "No");
            printf("Keyring Auto-Unlock:    %s\n", status.keyring_pwd_saved ? "Configured" : "None");
            printf("Secure Boot PCR 7:      %s\n", status.pcr7_bound ? "Bound" : "Not bound");
            printf("PAM Integration:        %s (Detected Distro: %s)\n",
                   pam_active ? "Active" : "Inactive (Run: sudo tpm-pin-ctl pam enable)",
                   pam_manager_distro_name(distro));
            printf("PIN Policy:             %s (Length: %u - %u)\n",
                   cfg.digits_only ? "Digits-only" : "Alphanumeric",
                   cfg.min_length, cfg.max_length);
            printf("TPM DA Lockout Max:     %u failed attempts (cooldown: %u sec)\n",
                   cfg.da_max_tries, cfg.da_recovery_time);
            if (status.tpm_present && status.tpm_accessible) {
                printf("TPM Hardware DA State:  %s (%u / %u failed tries)\n",
                       status.is_locked_out ? "LOCKED OUT" : "Ready",
                       status.failed_tries, status.max_tries);
            }
        }
        exit_code = 0;
        goto cleanup;
    }

    if (strcmp(action, "enroll") == 0) {
        if (geteuid() != 0) {
            fprintf(stderr, "Error: Root privileges required. Run with sudo or pkexec.\n");
            goto cleanup;
        }
        tpm_pin_status_t status;
        if (tpm_pin_get_user_status(uid, &cfg, &status)) {
            if (!status.tpm_present) {
                fprintf(stderr, "Error: TPM 2.0 device was not detected on this system.\n");
                fprintf(stderr, "Cannot enroll a hardware-backed PIN without a functional TPM 2.0.\n");
                goto cleanup;
            }
            if (!status.tpm_accessible) {
                fprintf(stderr, "Error: TPM 2.0 device is present, but permission was denied (/dev/tpmrm0).\n");
                fprintf(stderr, "Run with sudo/pkexec to access the TPM device.\n");
                goto cleanup;
            }
        }

        char *pin = NULL;
        char *pwd = NULL;

        if (opt_pwd_buf) {
            pwd = strdup(opt_pwd_buf);
        } else if (cfg.enable_keyring_unlock) {
            pwd = read_secret("Enter current login password (to seal for keyring auto-unlock): ");
            if (pwd && pwd[0] != '\0') {
                char *confirm_pwd = read_secret("Confirm current login password: ");
                if (!confirm_pwd || strcmp(pwd, confirm_pwd) != 0) {
                    fprintf(stderr, "Error: Login passwords do not match.\n");
                    tpm_pin_zero(pwd, strlen(pwd));
                    free(pwd);
                    pwd = NULL;
                    if (confirm_pwd) {
                        tpm_pin_zero(confirm_pwd, strlen(confirm_pwd));
                        free(confirm_pwd);
                    }
                    goto cleanup;
                }
                tpm_pin_zero(confirm_pwd, strlen(confirm_pwd));
                free(confirm_pwd);
            } else {
                fprintf(stderr, "Note: No login password provided; keyring auto-unlock will not be sealed.\n");
            }
        }

        if (opt_pin_buf) {
            pin = strdup(opt_pin_buf);
        } else {
            pin = read_secret("Enter new PIN: ");
            char *confirm = read_secret("Confirm new PIN: ");
            if (!confirm || !pin || strcmp(pin, confirm) != 0) {
                fprintf(stderr, "Error: PINs do not match.\n");
                if (pin) { tpm_pin_zero(pin, strlen(pin)); free(pin); }
                if (confirm) { tpm_pin_zero(confirm, strlen(confirm)); free(confirm); }
                if (pwd) { tpm_pin_zero(pwd, strlen(pwd)); free(pwd); }
                goto cleanup;
            }
            tpm_pin_zero(confirm, strlen(confirm));
            free(confirm);
        }

        char err[256];
        if (!tpm_pin_validate_pin(pin, &cfg, err, sizeof(err))) {
            fprintf(stderr, "Policy Error: %s\n", err);
            if (pin) { tpm_pin_zero(pin, strlen(pin)); free(pin); }
            if (pwd) {
                tpm_pin_zero(pwd, strlen(pwd));
                free(pwd);
            }
            goto cleanup;
        }

        printf("Sealing PIN into TPM 2.0...\n");
        bool ok = tpm_pin_enroll_user(uid, pin, pwd, &cfg);

        tpm_pin_zero(pin, strlen(pin));
        free(pin);
        if (pwd) {
            tpm_pin_zero(pwd, strlen(pwd));
            free(pwd);
        }

        if (ok) {
            printf("Success: PIN successfully enrolled and bound to TPM 2.0!\n");
            exit_code = 0;
        } else {
            fprintf(stderr, "Error: Failed to enroll PIN into TPM 2.0.\n");
        }
        goto cleanup;
    }

    if (strcmp(action, "verify") == 0) {
        char *pin = opt_pin_buf ? strdup(opt_pin_buf) : read_secret("Enter PIN to verify: ");
        if (!pin) goto cleanup;

        char unsealed[TPM_PIN_MAX_PASSWORD_LEN] = {0};
        int tpm_rc = 0;
        bool ok = tpm_pin_verify_user(uid, pin, &cfg, unsealed, sizeof(unsealed), &tpm_rc);

        tpm_pin_zero(pin, strlen(pin));
        free(pin);

        bool has_unsealed = (strlen(unsealed) > 0);
        tpm_pin_zero(unsealed, sizeof(unsealed));

        if (ok) {
            printf("Verification SUCCESS: TPM hardware verified the PIN.\n");
            if (has_unsealed) {
                printf("Keyring password successfully unsealed from TPM.\n");
            }
            exit_code = 0;
        } else if (geteuid() != 0 && tpm_rc == 0) {
            fprintf(stderr, "Verification FAILED: Root privileges (sudo) are required to access sealed credential blobs.\n");
        } else {
            fprintf(stderr, "Verification FAILED: Invalid PIN (TPM code: 0x%x).\n", tpm_rc);
        }
        goto cleanup;
    }

    if (strcmp(action, "remove") == 0) {
        if (geteuid() != 0) {
            fprintf(stderr, "Error: Root privileges required. Run with sudo or pkexec.\n");
            goto cleanup;
        }
        if (tpm_pin_remove_user(uid, &cfg)) {
            printf("PIN enrollment removed for user %s.\n", username ? username : "");
            exit_code = 0;
        } else {
            fprintf(stderr, "No enrolled PIN found for user %s.\n", username ? username : "");
        }
        goto cleanup;
    }

    if (strcmp(action, "pam") == 0) {
        if (argc < 3) {
            printf("Usage: %s pam <enable|disable [--uninstall]|status>\n", argv[0]);
            goto cleanup;
        }
        const char *pam_cmd = argv[2];
        if (strcmp(pam_cmd, "status") == 0) {
            bool active = pam_manager_is_enabled();
            printf("PAM Integration: %s\n", active ? "Enabled" : "Disabled");
            exit_code = active ? 0 : 1;
            goto cleanup;
        } else if (strcmp(pam_cmd, "enable") == 0) {
            if (geteuid() != 0) {
                fprintf(stderr, "Error: Root privileges required. Run with sudo or pkexec.\n");
                goto cleanup;
            }
            char err[256] = {0};
            if (pam_manager_enable(&cfg, err, sizeof(err))) {
                printf("Success: PAM integration enabled for %s!\n",
                       pam_manager_distro_name(pam_manager_detect_distro()));
                exit_code = 0;
            } else {
                fprintf(stderr, "Failed to enable PAM: %s\n", err[0] ? err : "Unknown error");
            }
            goto cleanup;
        } else if (strcmp(pam_cmd, "disable") == 0) {
            if (geteuid() != 0) {
                fprintf(stderr, "Error: Root privileges required. Run with sudo or pkexec.\n");
                goto cleanup;
            }
            char err[256] = {0};
            if (pam_manager_disable_ex(opt_uninstall, err, sizeof(err))) {
                printf("Success: PAM integration disabled.\n");
                exit_code = 0;
            } else {
                fprintf(stderr, "Failed to disable PAM: %s\n", err[0] ? err : "Unknown error");
            }
            goto cleanup;
        }
    }

    if (strcmp(action, "da-reset") == 0) {
        if (geteuid() != 0) {
            fprintf(stderr, "Error: Root privileges required. Run with sudo or pkexec.\n");
            goto cleanup;
        }
        ESYS_CONTEXT *ctx = NULL;
        TSS2_RC rc = tpm_engine_init(cfg.tcti_name, &ctx);
        if (rc == TSS2_RC_SUCCESS && ctx) {
            rc = tpm_engine_reset_da_lockout(ctx);
            tpm_engine_destroy(&ctx);
            if (rc == TSS2_RC_SUCCESS) {
                printf("Success: TPM Dictionary Attack lockout counter reset.\n");
                exit_code = 0;
                goto cleanup;
            }
        }
        fprintf(stderr, "Failed to reset TPM lockout counter (RC: 0x%x). Requires root / lockout authorization.\n", rc);
        goto cleanup;
    }

    if (strcmp(action, "da-config") == 0) {
        if (geteuid() != 0) {
            fprintf(stderr, "Error: Root privileges required. Run with sudo or pkexec.\n");
            goto cleanup;
        }
        uint32_t max_tries = cfg.da_max_tries;
        uint32_t recovery_sec = cfg.da_recovery_time;
        uint32_t lockout_recovery = cfg.da_lockout_recovery;

        if (arg_max_tries) {
            if (!parse_u32_strict(arg_max_tries, &max_tries) || max_tries < 1 || max_tries > 1000) {
                fprintf(stderr, "Error: --max-tries must be an integer between 1 and 1000.\n");
                goto cleanup;
            }
        }
        if (arg_recovery_sec) {
            if (!parse_u32_strict(arg_recovery_sec, &recovery_sec) || recovery_sec < 1 || recovery_sec > 2592000U) {
                fprintf(stderr, "Error: --recovery-sec must be an integer between 1 and 2592000.\n");
                goto cleanup;
            }
        }
        if (arg_lockout_recovery) {
            if (!parse_u32_strict(arg_lockout_recovery, &lockout_recovery) || lockout_recovery < 1 || lockout_recovery > 2592000U) {
                fprintf(stderr, "Error: --lockout-recovery must be an integer between 1 and 2592000.\n");
                goto cleanup;
            }
        }

        ESYS_CONTEXT *ctx = NULL;
        TSS2_RC rc = tpm_engine_init(cfg.tcti_name, &ctx);
        if (rc == TSS2_RC_SUCCESS && ctx) {
            rc = tpm_engine_configure_da(ctx, max_tries, recovery_sec, lockout_recovery);
            tpm_engine_destroy(&ctx);
            if (rc == TSS2_RC_SUCCESS) {
                cfg.da_max_tries = max_tries;
                cfg.da_recovery_time = recovery_sec;
                cfg.da_lockout_recovery = lockout_recovery;
                if (!tpm_pin_config_save(NULL, &cfg)) {
                    fprintf(stderr, "Error: Hardware DA parameters updated, but failed to save config file.\n");
                    goto cleanup;
                }
                printf("Success: TPM Dictionary Attack parameters configured (max_tries=%u, recovery=%u, lockout_recovery=%u).\n",
                       max_tries, recovery_sec, lockout_recovery);
                exit_code = 0;
                goto cleanup;
            }
        }
        fprintf(stderr, "Failed to configure TPM DA protection (RC: 0x%x). Requires root / lockout authorization.\n", rc);
        goto cleanup;
    }

    if (strcmp(action, "config") == 0) {
        if (argc < 4) {
            printf("Usage: %s config get <key> | config set <key> <value>\n", argv[0]);
            goto cleanup;
        }
        const char *sub = argv[2];
        const char *key = argv[3];

        if (strcmp(sub, "get") == 0) {
            if (strcasecmp(key, "digits_only") == 0) printf("%s\n", cfg.digits_only ? "true" : "false");
            else if (strcasecmp(key, "min_length") == 0) printf("%u\n", cfg.min_length);
            else if (strcasecmp(key, "max_length") == 0) printf("%u\n", cfg.max_length);
            else if (strcasecmp(key, "enable_login") == 0) printf("%s\n", cfg.enable_login ? "true" : "false");
            else if (strcasecmp(key, "enable_lockscreen") == 0) printf("%s\n", cfg.enable_lockscreen ? "true" : "false");
            else if (strcasecmp(key, "enable_sudo") == 0) printf("%s\n", cfg.enable_sudo ? "true" : "false");
            else if (strcasecmp(key, "enable_keyring_unlock") == 0) printf("%s\n", cfg.enable_keyring_unlock ? "true" : "false");
            else if (strcasecmp(key, "bind_pcr7") == 0) printf("%s\n", cfg.bind_pcr7 ? "true" : "false");
            else if (strcasecmp(key, "da_max_tries") == 0) printf("%u\n", cfg.da_max_tries);
            else if (strcasecmp(key, "da_recovery_time") == 0) printf("%u\n", cfg.da_recovery_time);
            else if (strcasecmp(key, "da_lockout_recovery") == 0) printf("%u\n", cfg.da_lockout_recovery);
            else {
                fprintf(stderr, "Error: Unknown config key '%s'\n", key);
                goto cleanup;
            }
            exit_code = 0;
            goto cleanup;
        } else if (strcmp(sub, "set") == 0 && argc >= 5) {
            if (geteuid() != 0) {
                fprintf(stderr, "Error: Root privileges required. Run with sudo or pkexec.\n");
                goto cleanup;
            }
            const char *val = argv[4];
            bool bval = false;
            uint32_t uval = 0;
            bool da_changed = false;

            if (strcasecmp(key, "digits_only") == 0) {
                if (!parse_bool_strict(val, &bval)) {
                    fprintf(stderr, "Error: digits_only requires a boolean value (true/false).\n");
                    goto cleanup;
                }
                cfg.digits_only = bval;
            } else if (strcasecmp(key, "min_length") == 0) {
                if (!parse_u32_strict(val, &uval) || uval < 4 || uval > TPM_PIN_MAX_PIN_LEN) {
                    fprintf(stderr, "Error: min_length must be between 4 and %d\n", TPM_PIN_MAX_PIN_LEN);
                    goto cleanup;
                }
                cfg.min_length = uval;
                if (cfg.max_length < cfg.min_length) cfg.max_length = cfg.min_length;
            } else if (strcasecmp(key, "max_length") == 0) {
                if (!parse_u32_strict(val, &uval) || uval < 4 || uval > TPM_PIN_MAX_PIN_LEN) {
                    fprintf(stderr, "Error: max_length must be between 4 and %d\n", TPM_PIN_MAX_PIN_LEN);
                    goto cleanup;
                }
                cfg.max_length = uval;
                if (cfg.min_length > cfg.max_length) cfg.min_length = cfg.max_length;
            } else if (strcasecmp(key, "enable_login") == 0) {
                if (!parse_bool_strict(val, &bval)) {
                    fprintf(stderr, "Error: enable_login requires a boolean value (true/false).\n");
                    goto cleanup;
                }
                cfg.enable_login = bval;
            } else if (strcasecmp(key, "enable_lockscreen") == 0) {
                if (!parse_bool_strict(val, &bval)) {
                    fprintf(stderr, "Error: enable_lockscreen requires a boolean value (true/false).\n");
                    goto cleanup;
                }
                cfg.enable_lockscreen = bval;
            } else if (strcasecmp(key, "enable_sudo") == 0) {
                if (!parse_bool_strict(val, &bval)) {
                    fprintf(stderr, "Error: enable_sudo requires a boolean value (true/false).\n");
                    goto cleanup;
                }
                cfg.enable_sudo = bval;
            } else if (strcasecmp(key, "enable_keyring_unlock") == 0) {
                if (!parse_bool_strict(val, &bval)) {
                    fprintf(stderr, "Error: enable_keyring_unlock requires a boolean value (true/false).\n");
                    goto cleanup;
                }
                cfg.enable_keyring_unlock = bval;
            } else if (strcasecmp(key, "bind_pcr7") == 0) {
                if (!parse_bool_strict(val, &bval)) {
                    fprintf(stderr, "Error: bind_pcr7 requires a boolean value (true/false).\n");
                    goto cleanup;
                }
                cfg.bind_pcr7 = bval;
            } else if (strcasecmp(key, "da_max_tries") == 0) {
                if (!parse_u32_strict(val, &uval) || uval < 1 || uval > 1000) {
                    fprintf(stderr, "Error: da_max_tries must be between 1 and 1000\n");
                    goto cleanup;
                }
                cfg.da_max_tries = uval;
                da_changed = true;
            } else if (strcasecmp(key, "da_recovery_time") == 0) {
                if (!parse_u32_strict(val, &uval) || uval < 1 || uval > 2592000U) {
                    fprintf(stderr, "Error: da_recovery_time must be between 1 and 2592000\n");
                    goto cleanup;
                }
                cfg.da_recovery_time = uval;
                da_changed = true;
            } else if (strcasecmp(key, "da_lockout_recovery") == 0) {
                if (!parse_u32_strict(val, &uval) || uval < 1 || uval > 2592000U) {
                    fprintf(stderr, "Error: da_lockout_recovery must be between 1 and 2592000\n");
                    goto cleanup;
                }
                cfg.da_lockout_recovery = uval;
                da_changed = true;
            } else {
                fprintf(stderr, "Error: Unknown config key '%s'\n", key);
                goto cleanup;
            }

            if (tpm_pin_config_save(NULL, &cfg)) {
                if (strcasecmp(key, "enable_keyring_unlock") == 0 && pam_manager_is_enabled()) {
                    linux_distro_t d = pam_manager_detect_distro();
                    if (d == DISTRO_ARCH) {
                        pam_manager_configure_arch_keyring_file("/etc/pam.d/system-local-login", cfg.enable_keyring_unlock);
                    }
                }
                if (da_changed) {
                    ESYS_CONTEXT *ctx = NULL;
                    if (tpm_engine_init(cfg.tcti_name, &ctx) == TSS2_RC_SUCCESS && ctx) {
                        (void)tpm_engine_configure_da(ctx, cfg.da_max_tries, cfg.da_recovery_time, cfg.da_lockout_recovery);
                        tpm_engine_destroy(&ctx);
                    }
                }
                printf("Updated config: %s = %s\n", key, val);
                exit_code = 0;
                goto cleanup;
            } else {
                fprintf(stderr, "Failed to save configuration. Run with sudo/pkexec.\n");
                goto cleanup;
            }
        }
    }

    print_usage(argv[0]);

cleanup:
    if (opt_pin_buf) {
        tpm_pin_zero(opt_pin_buf, strlen(opt_pin_buf));
        free(opt_pin_buf);
    }
    if (opt_pwd_buf) {
        tpm_pin_zero(opt_pwd_buf, strlen(opt_pwd_buf));
        free(opt_pwd_buf);
    }
    return exit_code;
}
