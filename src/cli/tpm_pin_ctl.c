#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <termios.h>
#include <getopt.h>
#include "tpm_pin.h"

static void disable_echo(struct termios *orig) {
    struct termios t;
    tcgetattr(STDIN_FILENO, orig);
    t = *orig;
    t.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

static void restore_echo(const struct termios *orig) {
    tcsetattr(STDIN_FILENO, TCSANOW, orig);
}

static char *read_secret(const char *prompt) {
    struct termios orig;
    printf("%s", prompt);
    fflush(stdout);

    bool is_tty = isatty(STDIN_FILENO);
    if (is_tty) disable_echo(&orig);

    char *line = NULL;
    size_t len = 0;
    ssize_t read_bytes = getline(&line, &len, stdin);

    if (is_tty) {
        restore_echo(&orig);
        printf("\n");
    }

    if (read_bytes <= 0 || !line) {
        if (line) free(line);
        return NULL;
    }

    if (line[read_bytes - 1] == '\n') {
        line[read_bytes - 1] = '\0';
    }
    return line;
}

static void print_usage(const char *prog) {
    printf("Secure PIN for Linux (TPM 2.0 Windows Hello–Style PIN)\n\n");
    printf("Usage:\n");
    printf("  %s status [--json] [--user <username>]\n", prog);
    printf("  %s enroll [--user <username>] [--pin <pin>] [--password <pwd>]\n", prog);
    printf("  %s verify [--user <username>] [--pin <pin>]\n", prog);
    printf("  %s remove [--user <username>]\n", prog);
    printf("  %s pam <enable|disable|status>\n", prog);
    printf("  %s da-reset\n", prog);
    printf("  %s da-config --max-tries <n> --recovery-sec <s>\n", prog);
    printf("  %s config get <key>\n", prog);
    printf("  %s config set <key> <value>\n", prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *action = argv[1];
    const char *username = NULL;
    const char *opt_pin = NULL;
    const char *opt_pwd = NULL;
    bool json_output = false;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            json_output = true;
        } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            username = argv[++i];
        } else if (strcmp(argv[i], "--pin") == 0 && i + 1 < argc) {
            opt_pin = argv[++i];
        } else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            opt_pwd = argv[++i];
        }
    }

    uid_t caller_uid = getuid();
    uid_t uid = caller_uid;
    char user_buf[128] = {0};

    if (username) {
        struct passwd pwd_s;
        struct passwd *pw = NULL;
        char pbuf[1024];
        if (getpwnam_r(username, &pwd_s, pbuf, sizeof(pbuf), &pw) != 0 || !pw) {
            fprintf(stderr, "Error: Unknown user '%s'\n", username);
            return 1;
        }
        if (caller_uid != 0 && pw->pw_uid != caller_uid) {
            fprintf(stderr, "Error: Permission denied (only root can target another user).\n");
            return 1;
        }
        uid = pw->pw_uid;
        snprintf(user_buf, sizeof(user_buf), "%s", pw->pw_name);
        username = user_buf;
    } else {
        if (caller_uid == 0) {
            const char *pkexec_uid = getenv("PKEXEC_UID");
            const char *sudo_uid = getenv("SUDO_UID");
            const char *orig_uid_str = pkexec_uid ? pkexec_uid : sudo_uid;
            if (orig_uid_str && orig_uid_str[0] != '\0') {
                char *endptr = NULL;
                unsigned long parsed = strtoul(orig_uid_str, &endptr, 10);
                if (endptr && *endptr == '\0' && parsed > 0) {
                    uid = (uid_t)parsed;
                }
            }
        }
        struct passwd pwd_s;
        struct passwd *pw = NULL;
        char pbuf[1024];
        if (getpwuid_r(uid, &pwd_s, pbuf, sizeof(pbuf), &pw) == 0 && pw) {
            snprintf(user_buf, sizeof(user_buf), "%s", pw->pw_name);
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
            printf("  \"tpm_manufacturer\": \"%s\",\n", status.manufacturer[0] ? status.manufacturer : "TPM 2.0");
            printf("  \"hardware_type\": \"%s\",\n", status.hardware_type[0] ? status.hardware_type : "TPM 2.0");
            printf("  \"bus_encryption\": \"%s\",\n", status.bus_encryption[0] ? status.bus_encryption : "Active");
            printf("  \"user\": \"%s\",\n", username ? username : "unknown");
            printf("  \"uid\": %u,\n", (unsigned int)uid);
            printf("  \"is_enrolled\": %s,\n", status.is_enrolled ? "true" : "false");
            printf("  \"pcr7_bound\": %s,\n", status.pcr7_bound ? "true" : "false");
            printf("  \"bind_pcr7\": %s,\n", cfg.bind_pcr7 ? "true" : "false");
            printf("  \"is_locked_out\": %s,\n", status.is_locked_out ? "true" : "false");
            printf("  \"failed_tries\": %u,\n", status.failed_tries);
            printf("  \"max_tries\": %u,\n", status.max_tries);
            printf("  \"keyring_pwd_saved\": %s,\n", status.keyring_pwd_saved ? "true" : "false");
            printf("  \"pam_enabled\": %s,\n", pam_active ? "true" : "false");
            printf("  \"distro\": \"%s\",\n", pam_manager_distro_name(distro));
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
            printf("=== Secure PIN for Linux Status ===\n");
            printf("TPM 2.0 Device:         %s\n", status.tpm_present ? "Detected & Ready" : "Not Found");
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
            if (status.tpm_present) {
                printf("TPM Hardware DA State:  %s (%u / %u failed tries)\n",
                       status.is_locked_out ? "LOCKED OUT" : "Ready",
                       status.failed_tries, status.max_tries);
            }
        }
        return 0;
    }

    if (strcmp(action, "enroll") == 0) {
        char *pin = NULL;
        char *pwd = NULL;

        if (opt_pwd) {
            pwd = strdup(opt_pwd);
        } else if (cfg.enable_keyring_unlock) {
            pwd = read_secret("Enter current login password (to seal for keyring auto-unlock): ");
        }

        if (opt_pin) {
            pin = strdup(opt_pin);
        } else {
            pin = read_secret("Enter new PIN: ");
            char *confirm = read_secret("Confirm new PIN: ");
            if (!confirm || !pin || strcmp(pin, confirm) != 0) {
                fprintf(stderr, "Error: PINs do not match.\n");
                if (pin) { tpm_pin_zero(pin, strlen(pin)); free(pin); }
                if (confirm) { tpm_pin_zero(confirm, strlen(confirm)); free(confirm); }
                if (pwd) { tpm_pin_zero(pwd, strlen(pwd)); free(pwd); }
                return 1;
            }
            tpm_pin_zero(confirm, strlen(confirm));
            free(confirm);
        }

        char err[256];
        if (!tpm_pin_validate_pin(pin, &cfg, err, sizeof(err))) {
            fprintf(stderr, "Policy Error: %s\n", err);
            tpm_pin_zero(pin, strlen(pin));
            free(pin);
            if (pwd) {
                tpm_pin_zero(pwd, strlen(pwd));
                free(pwd);
            }
            return 1;
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
            return 0;
        } else {
            fprintf(stderr, "Error: Failed to enroll PIN into TPM 2.0.\n");
            return 1;
        }
    }

    if (strcmp(action, "verify") == 0) {
        char *pin = opt_pin ? strdup(opt_pin) : read_secret("Enter PIN to verify: ");
        if (!pin) return 1;

        char unsealed[TPM_PIN_MAX_PASSWORD_LEN] = {0};
        int tpm_rc = 0;
        bool ok = tpm_pin_verify_user(uid, pin, &cfg, unsealed, sizeof(unsealed), &tpm_rc);

        tpm_pin_zero(pin, strlen(pin));
        free(pin);

        if (ok) {
            printf("Verification SUCCESS: TPM hardware verified the PIN.\n");
            if (strlen(unsealed) > 0) {
                printf("Keyring password successfully unsealed from TPM.\n");
            }
            tpm_pin_zero(unsealed, sizeof(unsealed));
            return 0;
        } else {
            fprintf(stderr, "Verification FAILED: Invalid PIN (TPM code: 0x%x).\n", tpm_rc);
            return 1;
        }
    }

    if (strcmp(action, "remove") == 0) {
        if (tpm_pin_remove_user(uid, &cfg)) {
            printf("PIN enrollment removed for user %s.\n", username ? username : "");
            return 0;
        } else {
            fprintf(stderr, "No enrolled PIN found for user %s.\n", username ? username : "");
            return 1;
        }
    }

    if (strcmp(action, "pam") == 0) {
        if (argc < 3) {
            printf("Usage: %s pam <enable|disable|status>\n", argv[0]);
            return 1;
        }
        const char *pam_cmd = argv[2];
        if (strcmp(pam_cmd, "status") == 0) {
            bool active = pam_manager_is_enabled();
            printf("PAM Integration: %s\n", active ? "Enabled" : "Disabled");
            return active ? 0 : 1;
        } else if (strcmp(pam_cmd, "enable") == 0) {
            char err[256] = {0};
            if (pam_manager_enable(&cfg, err, sizeof(err))) {
                printf("Success: PAM integration enabled for %s!\n",
                       pam_manager_distro_name(pam_manager_detect_distro()));
                return 0;
            } else {
                fprintf(stderr, "Failed to enable PAM: %s\n", err[0] ? err : "Unknown error");
                return 1;
            }
        } else if (strcmp(pam_cmd, "disable") == 0) {
            char err[256] = {0};
            if (pam_manager_disable(err, sizeof(err))) {
                printf("Success: PAM integration disabled.\n");
                return 0;
            } else {
                fprintf(stderr, "Failed to disable PAM: %s\n", err[0] ? err : "Unknown error");
                return 1;
            }
        }
    }

    if (strcmp(action, "da-reset") == 0) {
        ESYS_CONTEXT *ctx = NULL;
        TSS2_RC rc = tpm_engine_init(cfg.tcti_name, &ctx);
        if (rc == TSS2_RC_SUCCESS && ctx) {
            rc = tpm_engine_reset_da_lockout(ctx);
            tpm_engine_destroy(&ctx);
            if (rc == TSS2_RC_SUCCESS) {
                printf("Success: TPM Dictionary Attack lockout counter reset.\n");
                return 0;
            }
        }
        fprintf(stderr, "Failed to reset TPM lockout counter (RC: 0x%x). Requires root / lockout authorization.\n", rc);
        return 1;
    }

    if (strcmp(action, "da-config") == 0) {
        uint32_t max_tries = cfg.da_max_tries;
        uint32_t recovery_sec = cfg.da_recovery_time;
        uint32_t lockout_recovery = cfg.da_lockout_recovery;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--max-tries") == 0 && i + 1 < argc) {
                max_tries = (uint32_t)strtoul(argv[++i], NULL, 10);
            } else if (strcmp(argv[i], "--recovery-sec") == 0 && i + 1 < argc) {
                recovery_sec = (uint32_t)strtoul(argv[++i], NULL, 10);
            } else if (strcmp(argv[i], "--lockout-recovery") == 0 && i + 1 < argc) {
                lockout_recovery = (uint32_t)strtoul(argv[++i], NULL, 10);
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
                tpm_pin_config_save(NULL, &cfg);
                printf("Success: TPM Dictionary Attack parameters configured (max_tries=%u, recovery=%u, lockout_recovery=%u).\n",
                       max_tries, recovery_sec, lockout_recovery);
                return 0;
            }
        }
        fprintf(stderr, "Failed to configure TPM DA protection (RC: 0x%x). Requires root / lockout authorization.\n", rc);
        return 1;
    }

    if (strcmp(action, "config") == 0) {
        if (argc < 4) {
            printf("Usage: %s config get <key> | config set <key> <value>\n", argv[0]);
            return 1;
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
                return 1;
            }
            return 0;
        } else if (strcmp(sub, "set") == 0 && argc >= 5) {
            const char *val = argv[4];
            bool bval = (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0 || strcasecmp(val, "yes") == 0);

            if (strcasecmp(key, "digits_only") == 0) cfg.digits_only = bval;
            else if (strcasecmp(key, "min_length") == 0) {
                long val_num = strtol(val, NULL, 10);
                if (val_num < 4 || val_num > TPM_PIN_MAX_PIN_LEN) {
                    fprintf(stderr, "Error: min_length must be between 4 and %d\n", TPM_PIN_MAX_PIN_LEN);
                    return 1;
                }
                cfg.min_length = (uint32_t)val_num;
                if (cfg.max_length < cfg.min_length) cfg.max_length = cfg.min_length;
            } else if (strcasecmp(key, "max_length") == 0) {
                long val_num = strtol(val, NULL, 10);
                if (val_num < 4 || val_num > TPM_PIN_MAX_PIN_LEN) {
                    fprintf(stderr, "Error: max_length must be between 4 and %d\n", TPM_PIN_MAX_PIN_LEN);
                    return 1;
                }
                cfg.max_length = (uint32_t)val_num;
                if (cfg.min_length > cfg.max_length) cfg.min_length = cfg.max_length;
            } else if (strcasecmp(key, "enable_login") == 0) cfg.enable_login = bval;
            else if (strcasecmp(key, "enable_lockscreen") == 0) cfg.enable_lockscreen = bval;
            else if (strcasecmp(key, "enable_sudo") == 0) cfg.enable_sudo = bval;
            else if (strcasecmp(key, "enable_keyring_unlock") == 0) cfg.enable_keyring_unlock = bval;
            else if (strcasecmp(key, "bind_pcr7") == 0) cfg.bind_pcr7 = bval;
            else if (strcasecmp(key, "da_max_tries") == 0) {
                long val_num = strtol(val, NULL, 10);
                if (val_num < 1 || val_num > 1000) {
                    fprintf(stderr, "Error: da_max_tries must be at least 1\n");
                    return 1;
                }
                cfg.da_max_tries = (uint32_t)val_num;
            } else if (strcasecmp(key, "da_recovery_time") == 0) {
                cfg.da_recovery_time = (uint32_t)strtoul(val, NULL, 10);
            } else if (strcasecmp(key, "da_lockout_recovery") == 0) {
                cfg.da_lockout_recovery = (uint32_t)strtoul(val, NULL, 10);
            } else {
                fprintf(stderr, "Error: Unknown config key '%s'\n", key);
                return 1;
            }

            if (tpm_pin_config_save(NULL, &cfg)) {
                printf("Updated config: %s = %s\n", key, val);
                return 0;
            } else {
                fprintf(stderr, "Failed to save configuration. Run with sudo/pkexec.\n");
                return 1;
            }
        }
    }

    print_usage(argv[0]);
    return 1;
}
