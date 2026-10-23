#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "tpm_pin.h"

void tpm_pin_zero(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
#if defined(HAVE_EXPLICIT_BZERO) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
    explicit_bzero(ptr, size);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (size--) *p++ = 0;
#endif
}

bool tpm_pin_random_bytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return false;
    if (RAND_bytes(buf, (int)len) == 1) {
        return true;
    }
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            close(fd);
            return false;
        }
        total += (size_t)n;
    }
    close(fd);
    return true;
}

bool tpm_pin_derive_auth(const char *pin, const uint8_t *salt, size_t salt_len, uint8_t *out_auth, size_t auth_len) {
    if (!pin || !salt || !out_auth) return false;
    int ret = PKCS5_PBKDF2_HMAC(
        pin, (int)strlen(pin),
        salt, (int)salt_len,
        100000,
        EVP_sha256(),
        (int)auth_len,
        out_auth
    );
    return (ret == 1);
}

bool tpm_pin_encrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *plaintext, size_t pt_len,
                     uint8_t *ciphertext, uint8_t *tag) {
    if (!key || !iv || !plaintext || !ciphertext || !tag) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    int len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TPM_PIN_IV_LEN, NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto cleanup;

    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)pt_len) != 1) goto cleanup;
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TPM_PIN_TAG_LEN, tag) != 1) goto cleanup;

    ok = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool tpm_pin_decrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *ciphertext, size_t ct_len,
                     const uint8_t *tag, uint8_t *plaintext) {
    if (!key || !iv || !ciphertext || !tag || !plaintext) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    int len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, TPM_PIN_IV_LEN, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto cleanup;

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ct_len) != 1) goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TPM_PIN_TAG_LEN, (void *)tag) != 1) goto cleanup;

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len) != 1) {
        /* Authentication tag failed or corrupted data */
        goto cleanup;
    }

    ok = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
