#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include "tpm_pin.h"

int main(int argc, char **argv) {
    uid_t uid = getuid();
    if (argc >= 2) {
        struct passwd *pw = getpwnam(argv[1]);
        if (pw) uid = pw->pw_uid;
    }

    tpm_pin_config_t cfg;
    tpm_pin_config_load(NULL, &cfg);

    char pin_buf[TPM_PIN_MAX_PIN_LEN + 2] = {0};
    if (!fgets(pin_buf, sizeof(pin_buf), stdin)) {
        return 1;
    }

    size_t len = strlen(pin_buf);
    if (len > 0 && pin_buf[len - 1] == '\n') {
        pin_buf[len - 1] = '\0';
    }

    int tpm_rc = 0;
    char unsealed[TPM_PIN_MAX_PASSWORD_LEN] = {0};
    bool ok = tpm_pin_verify_user(uid, pin_buf, &cfg, unsealed, sizeof(unsealed), &tpm_rc);

    tpm_pin_zero(pin_buf, sizeof(pin_buf));

    if (ok) {
        /* Print unsealed keyring password if available, then zero */
        if (strlen(unsealed) > 0) {
            printf("%s\n", unsealed);
        }
        tpm_pin_zero(unsealed, sizeof(unsealed));
        return 0;
    }

    tpm_pin_zero(unsealed, sizeof(unsealed));
    return 1;
}
