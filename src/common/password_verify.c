#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <shadow.h>
#include <openssl/crypto.h>
#ifdef HAVE_LIBCRYPT
#include <crypt.h>
#endif
#include "tpm_pin.h"

int tpm_pin_verify_shadow_hash(const char *password, const char *shadow_hash) {
    if (!password || !shadow_hash || shadow_hash[0] == '\0') {
        return -1;
    }

    /* Locked accounts, non-shadow placeholders, or truncated hashes cannot be verified locally */
    size_t hash_len = strlen(shadow_hash);
    if (shadow_hash[0] == '!' || shadow_hash[0] == '*' ||
        strcmp(shadow_hash, "x") == 0 || hash_len < 13) {
        return -1;
    }

#ifdef HAVE_LIBCRYPT
    struct crypt_data *cdata = (struct crypt_data *)calloc(1, sizeof(struct crypt_data));
    if (!cdata) {
        return -1;
    }

    const char *computed = crypt_r(password, shadow_hash, cdata);
    int res = -1;
    if (computed && computed[0] != '*') {
        size_t comp_len = strlen(computed);
        res = (comp_len == hash_len && CRYPTO_memcmp(computed, shadow_hash, hash_len) == 0) ? 1 : 0;
    }

    tpm_pin_zero(cdata, sizeof(*cdata));
    free(cdata);
    return res;
#else
    (void)password;
    return -1;
#endif
}

int tpm_pin_verify_system_password(const char *username, const char *password) {
    if (!username || username[0] == '\0' || !password) {
        return -1;
    }
    if (geteuid() != 0) {
        return -1;
    }

    long init_sz = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t buf_sz = (init_sz > 0) ? (size_t)init_sz : 1024;
    if (buf_sz < 1024) buf_sz = 1024;

    while (buf_sz <= 65536) {
        char *buf = (char *)malloc(buf_sz);
        if (!buf) {
            return -1;
        }
        struct spwd sp_s;
        struct spwd *sp = NULL;
        int rc = getspnam_r(username, &sp_s, buf, buf_sz, &sp);
        if (rc == 0 && sp && sp->sp_pwdp) {
            int verified = tpm_pin_verify_shadow_hash(password, sp->sp_pwdp);
            tpm_pin_zero(buf, buf_sz);
            free(buf);
            return verified;
        }
        tpm_pin_zero(buf, buf_sz);
        free(buf);
        if (rc != ERANGE) {
            return -1;
        }
        buf_sz *= 2;
    }

    return -1;
}
