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
        struct passwd pwd_s;
        struct passwd *pw = NULL;
        char pbuf[1024];
        if (getpwnam_r(argv[1], &pwd_s, pbuf, sizeof(pbuf), &pw) != 0 || !pw) {
            return 1;
        }
        /* Only root can verify PIN on behalf of a different user */
        if (uid != 0 && uid != pw->pw_uid) {
            fprintf(stderr, "Permission denied.\n");
            return 1;
        }
        uid = pw->pw_uid;
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
    bool ok = tpm_pin_verify_user(uid, pin_buf, &cfg, NULL, 0, &tpm_rc);

    tpm_pin_zero(pin_buf, sizeof(pin_buf));

    return ok ? 0 : 1;
}
