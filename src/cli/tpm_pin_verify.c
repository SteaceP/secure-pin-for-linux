#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <pwd.h>
#include "tpm_pin.h"

static void sanitize_std_fds(void) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
        if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
            int nullfd = open("/dev/null", (fd == STDIN_FILENO) ? O_RDONLY : O_WRONLY);
            if (nullfd < 0) _exit(127);
            if (nullfd != fd) {
                if (dup2(nullfd, fd) < 0) _exit(127);
                close(nullfd);
            }
        }
    }
}

static bool lookup_uid_by_name(const char *username, uid_t *uid_out) {
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
            free(pbuf);
            return true;
        }
        free(pbuf);
        if (rc != ERANGE) return false;
        buf_sz *= 2;
    }
    return false;
}

int main(int argc, char **argv) {
    sanitize_std_fds();
    clearenv();
    setenv("TSS2_LOG", "all+NONE", 1);
    setenv("TSS2_LOGFILE", "/dev/null", 1);

    uid_t caller_uid = getuid();
    uid_t uid = caller_uid;
    if (argc >= 2) {
        uid_t target_uid = 0;
        if (!lookup_uid_by_name(argv[1], &target_uid)) {
            return 1;
        }
        /* Only root can verify PIN on behalf of a different user */
        if (caller_uid != 0 && caller_uid != target_uid) {
            fprintf(stderr, "Permission denied.\n");
            return 1;
        }
        uid = target_uid;
    }

    tpm_pin_config_t cfg;
    tpm_pin_config_load(NULL, &cfg);

    if (caller_uid != 0 && !cfg.enable_lockscreen) {
        return 1;
    }

    char pin_buf[TPM_PIN_MAX_PIN_LEN + 2] = {0};
    if (!fgets(pin_buf, sizeof(pin_buf), stdin)) {
        return 1;
    }

    size_t len = strlen(pin_buf);
    if (len > 0 && (pin_buf[len - 1] == '\n' || pin_buf[len - 1] == '\r')) {
        pin_buf[--len] = '\0';
    }
    if (len > 0 && pin_buf[len - 1] == '\r') {
        pin_buf[--len] = '\0';
    }

    int tpm_rc = 0;
    bool ok = tpm_pin_verify_user(uid, pin_buf, &cfg, NULL, 0, &tpm_rc);

    tpm_pin_zero(pin_buf, sizeof(pin_buf));

    if (ok) {
        return 0;
    }

    openlog("tpm-pin-verify", LOG_PID, LOG_AUTHPRIV);
    if (tpm_pin_rc_is_lockout((uint32_t)tpm_rc)) {
        syslog(LOG_AUTHPRIV | LOG_WARNING, "TPM DA lockout active during PIN verification for uid=%u", (unsigned int)uid);
    } else if (tpm_pin_rc_is_policy_fail((uint32_t)tpm_rc)) {
        syslog(LOG_AUTHPRIV | LOG_NOTICE, "TPM PCR7 policy mismatch during PIN verification for uid=%u", (unsigned int)uid);
    } else {
        syslog(LOG_AUTHPRIV | LOG_NOTICE, "Failed PIN verification attempt for uid=%u (tpm_rc=0x%x)", (unsigned int)uid, (unsigned int)tpm_rc);
    }
    closelog();

    if (caller_uid != 0) {
        struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
        while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
    }

    if (tpm_pin_rc_is_lockout((uint32_t)tpm_rc)) {
        return 2;
    }
    if (tpm_pin_rc_is_policy_fail((uint32_t)tpm_rc)) {
        return 3;
    }
    return 1;
}
