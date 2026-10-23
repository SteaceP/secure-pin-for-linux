#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "tpm_pin.h"

static const char *get_safe_base_dir(const tpm_pin_config_t *cfg) {
    if (cfg && cfg->data_dir[0] == '/' && strstr(cfg->data_dir, "..") == NULL) {
        return cfg->data_dir;
    }
    return TPM_PIN_DEFAULT_DATA_DIR;
}

static void get_user_blob_path(uid_t uid, const tpm_pin_config_t *cfg, char *out_path, size_t out_len) {
    const char *base_dir = get_safe_base_dir(cfg);
    snprintf(out_path, out_len, "%s/%u/sealed.blob", base_dir, (unsigned int)uid);
}

static void get_user_dir_path(uid_t uid, const tpm_pin_config_t *cfg, char *out_path, size_t out_len) {
    const char *base_dir = get_safe_base_dir(cfg);
    snprintf(out_path, out_len, "%s/%u", base_dir, (unsigned int)uid);
}

static FILE *open_regular_file_ro(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return NULL;
    }
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return NULL;
    }
    return f;
}

bool tpm_pin_user_is_enrolled(uid_t uid, const tpm_pin_config_t *cfg) {
    char path[512];
    get_user_blob_path(uid, cfg, path, sizeof(path));
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return false;
    }
    return (access(path, R_OK) == 0);
}

bool tpm_pin_remove_user(uid_t uid, const tpm_pin_config_t *cfg) {
    char path[512];
    get_user_blob_path(uid, cfg, path, sizeof(path));
    if (unlink(path) == 0) {
        char dir[512];
        get_user_dir_path(uid, cfg, dir, sizeof(dir));
        rmdir(dir);
        return true;
    }
    return false;
}

bool tpm_pin_enroll_user(uid_t uid, const char *pin, const char *password, const tpm_pin_config_t *cfg) {
    if (!pin) return false;

    tpm_pin_config_t local_cfg;
    if (!cfg) {
        tpm_pin_config_load(NULL, &local_cfg);
        cfg = &local_cfg;
    }

    char err_buf[256];
    if (!tpm_pin_validate_pin(pin, cfg, err_buf, sizeof(err_buf))) {
        return false;
    }

    uint8_t salt[TPM_PIN_SALT_LEN];
    if (!tpm_pin_random_bytes(salt, sizeof(salt))) return false;

    uint8_t auth[32];
    if (!tpm_pin_derive_auth(pin, salt, sizeof(salt), auth, sizeof(auth))) {
        tpm_pin_zero(salt, sizeof(salt));
        return false;
    }

    uint8_t master_key[TPM_PIN_KEY_LEN];
    if (!tpm_pin_random_bytes(master_key, sizeof(master_key))) {
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(auth, sizeof(auth));
        return false;
    }

    ESYS_CONTEXT *esys = NULL;
    TSS2_RC rc = tpm_engine_init(cfg->tcti_name, &esys);
    if (rc != TSS2_RC_SUCCESS || !esys) {
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(auth, sizeof(auth));
        tpm_pin_zero(master_key, sizeof(master_key));
        return false;
    }

    TPM2B_PRIVATE priv;
    TPM2B_PUBLIC  pub;
    memset(&priv, 0, sizeof(priv));
    memset(&pub, 0, sizeof(pub));

    rc = tpm_engine_seal_key(
        esys,
        auth, sizeof(auth),
        cfg->bind_pcr7,
        master_key, sizeof(master_key),
        &priv, &pub
    );

    tpm_pin_zero(auth, sizeof(auth));
    tpm_engine_destroy(&esys);

    if (rc != TSS2_RC_SUCCESS) {
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(master_key, sizeof(master_key));
        tpm_pin_zero(&priv, sizeof(priv));
        return false;
    }

    /* Prepare plaintext payload: Magic + User Password */
    size_t pwd_len = (password && cfg->enable_keyring_unlock) ? strlen(password) : 0;
    if (pwd_len >= TPM_PIN_MAX_PASSWORD_LEN) {
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(master_key, sizeof(master_key));
        tpm_pin_zero(&priv, sizeof(priv));
        return false;
    }
    size_t magic_len = strlen(TPM_PIN_VERIFY_TOKEN_MAGIC) + 1;
    size_t pt_len = magic_len + pwd_len + 1;

    uint8_t *plaintext = (uint8_t *)calloc(1, pt_len);
    if (!plaintext) {
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(master_key, sizeof(master_key));
        tpm_pin_zero(&priv, sizeof(priv));
        return false;
    }

    memcpy(plaintext, TPM_PIN_VERIFY_TOKEN_MAGIC, magic_len);
    if (pwd_len > 0) {
        memcpy(plaintext + magic_len, password, pwd_len + 1);
    }

    uint8_t iv[TPM_PIN_IV_LEN];
    uint8_t tag[TPM_PIN_TAG_LEN];
    if (!tpm_pin_random_bytes(iv, sizeof(iv))) {
        tpm_pin_zero(plaintext, pt_len);
        free(plaintext);
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(master_key, sizeof(master_key));
        tpm_pin_zero(&priv, sizeof(priv));
        return false;
    }

    uint8_t *ciphertext = (uint8_t *)calloc(1, pt_len);
    bool enc_ok = ciphertext && tpm_pin_encrypt(master_key, iv, plaintext, pt_len, ciphertext, tag);

    tpm_pin_zero(plaintext, pt_len);
    free(plaintext);
    tpm_pin_zero(master_key, sizeof(master_key));

    if (!enc_ok) {
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(&priv, sizeof(priv));
        if (ciphertext) free(ciphertext);
        return false;
    }

    /* Write out sealed blob */
    const char *base_dir = get_safe_base_dir(cfg);
    char dir_path[512];
    get_user_dir_path(uid, cfg, dir_path, sizeof(dir_path));
    mkdir(base_dir, 0755);
    mkdir(dir_path, 0700);

    char blob_path[512];
    get_user_blob_path(uid, cfg, blob_path, sizeof(blob_path));

    char tmp_path[1024];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%d", blob_path, (int)getpid());

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(&priv, sizeof(priv));
        free(ciphertext);
        return false;
    }

    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        unlink(tmp_path);
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(&priv, sizeof(priv));
        free(ciphertext);
        return false;
    }

    tpm_sealed_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = TPM_PIN_MAGIC;
    hdr.version = TPM_PIN_VERSION;
    hdr.flags = (cfg->bind_pcr7 ? FLAG_PCR7_BOUND : 0) |
                ((pwd_len > 0) ? FLAG_KEYRING_PWD_STORED : 0);
    memcpy(hdr.salt, salt, sizeof(salt));
    tpm_pin_zero(salt, sizeof(salt));
    hdr.tpm_priv_size = (uint16_t)sizeof(priv);
    hdr.tpm_pub_size  = (uint16_t)sizeof(pub);
    hdr.enc_payload_size = (uint16_t)pt_len;
    memcpy(hdr.iv, iv, sizeof(iv));
    memcpy(hdr.tag, tag, sizeof(tag));

    if (fwrite(&hdr, sizeof(hdr), 1, f) != 1 ||
        fwrite(&priv, sizeof(priv), 1, f) != 1 ||
        fwrite(&pub, sizeof(pub), 1, f) != 1 ||
        fwrite(ciphertext, 1, pt_len, f) != pt_len ||
        fflush(f) != 0 ||
        fsync(fd) != 0) {
        tpm_pin_zero(&priv, sizeof(priv));
        fclose(f);
        unlink(tmp_path);
        free(ciphertext);
        return false;
    }
    tpm_pin_zero(&priv, sizeof(priv));
    if (fclose(f) != 0) {
        unlink(tmp_path);
        free(ciphertext);
        return false;
    }

    free(ciphertext);

    chmod(tmp_path, 0600);
    if (getuid() == 0 && uid != 0) {
        if (chown(dir_path, uid, (gid_t)-1) != 0 || chown(tmp_path, uid, (gid_t)-1) != 0) {
            unlink(tmp_path);
            return false;
        }
    }
    if (rename(tmp_path, blob_path) != 0) {
        unlink(tmp_path);
        return false;
    }
    if (getuid() == 0 && uid != 0) {
        if (chown(blob_path, uid, (gid_t)-1) != 0) {
            unlink(blob_path);
            return false;
        }
    }

    return true;
}

bool tpm_pin_verify_user(uid_t uid, const char *pin, const tpm_pin_config_t *cfg,
                         char *unsealed_password, size_t pwd_buf_size,
                         int *tpm_status_code) {
    if (!pin) return false;
    if (tpm_status_code) *tpm_status_code = 0;

    tpm_pin_config_t local_cfg;
    if (!cfg) {
        tpm_pin_config_load(NULL, &local_cfg);
        cfg = &local_cfg;
    }

    /* Filter out passwords to avoid wasting TPM DA attempts */
    if (!tpm_pin_is_likely_pin(pin, cfg)) {
        return false;
    }

    char blob_path[512];
    get_user_blob_path(uid, cfg, blob_path, sizeof(blob_path));

    FILE *f = open_regular_file_ro(blob_path);
    if (!f) return false;

    tpm_sealed_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1 ||
        hdr.magic != TPM_PIN_MAGIC ||
        hdr.version != TPM_PIN_VERSION) {
        fclose(f);
        return false;
    }

    size_t magic_len = strlen(TPM_PIN_VERIFY_TOKEN_MAGIC) + 1;
    if (hdr.enc_payload_size < magic_len || hdr.enc_payload_size > 4096 ||
        hdr.tpm_priv_size == 0 || hdr.tpm_priv_size > sizeof(TPM2B_PRIVATE) ||
        hdr.tpm_pub_size == 0 || hdr.tpm_pub_size > sizeof(TPM2B_PUBLIC)) {
        fclose(f);
        return false;
    }

    TPM2B_PRIVATE priv;
    TPM2B_PUBLIC  pub;
    memset(&priv, 0, sizeof(priv));
    memset(&pub, 0, sizeof(pub));
    if (fread(&priv, hdr.tpm_priv_size, 1, f) != 1 ||
        fread(&pub, hdr.tpm_pub_size, 1, f) != 1) {
        tpm_pin_zero(&priv, sizeof(priv));
        fclose(f);
        return false;
    }

    uint8_t *ciphertext = (uint8_t *)malloc(hdr.enc_payload_size);
    if (!ciphertext || fread(ciphertext, 1, hdr.enc_payload_size, f) != hdr.enc_payload_size) {
        tpm_pin_zero(&priv, sizeof(priv));
        if (ciphertext) free(ciphertext);
        fclose(f);
        return false;
    }
    fclose(f);

    uint8_t auth[32];
    if (!tpm_pin_derive_auth(pin, hdr.salt, sizeof(hdr.salt), auth, sizeof(auth))) {
        tpm_pin_zero(&priv, sizeof(priv));
        free(ciphertext);
        return false;
    }

    ESYS_CONTEXT *esys = NULL;
    TSS2_RC rc = tpm_engine_init(cfg->tcti_name, &esys);
    if (rc != TSS2_RC_SUCCESS || !esys) {
        tpm_pin_zero(&priv, sizeof(priv));
        tpm_pin_zero(auth, sizeof(auth));
        free(ciphertext);
        return false;
    }

    uint8_t master_key[TPM_PIN_KEY_LEN];
    size_t key_len = sizeof(master_key);

    bool pcr_bound = (hdr.flags & FLAG_PCR7_BOUND) != 0;
    rc = tpm_engine_unseal_key(
        esys,
        auth, sizeof(auth),
        pcr_bound,
        &priv, &pub,
        master_key, &key_len
    );

    tpm_pin_zero(&priv, sizeof(priv));
    tpm_pin_zero(auth, sizeof(auth));
    tpm_engine_destroy(&esys);

    if (tpm_status_code) {
        *tpm_status_code = (int)rc;
    }

    if (rc != TSS2_RC_SUCCESS) {
        free(ciphertext);
        return false;
    }

    uint8_t *plaintext = (uint8_t *)calloc(1, hdr.enc_payload_size + 1);
    if (!plaintext) {
        tpm_pin_zero(master_key, sizeof(master_key));
        free(ciphertext);
        return false;
    }

    bool dec_ok = tpm_pin_decrypt(master_key, hdr.iv, ciphertext, hdr.enc_payload_size, hdr.tag, plaintext);
    tpm_pin_zero(master_key, sizeof(master_key));
    free(ciphertext);

    if (!dec_ok) {
        tpm_pin_zero(plaintext, hdr.enc_payload_size + 1);
        free(plaintext);
        return false;
    }

    if (hdr.enc_payload_size < magic_len ||
        memcmp(plaintext, TPM_PIN_VERIFY_TOKEN_MAGIC, magic_len) != 0) {
        tpm_pin_zero(plaintext, hdr.enc_payload_size + 1);
        free(plaintext);
        return false;
    }

    if (unsealed_password && pwd_buf_size > 0 && (hdr.flags & FLAG_KEYRING_PWD_STORED)) {
        const char *pwd = (const char *)(plaintext + magic_len);
        snprintf(unsealed_password, pwd_buf_size, "%.*s", (int)(hdr.enc_payload_size - magic_len), pwd);
    }

    tpm_pin_zero(plaintext, hdr.enc_payload_size + 1);
    free(plaintext);
    return true;
}

bool tpm_pin_get_user_status(uid_t uid, const tpm_pin_config_t *cfg, tpm_pin_status_t *status) {
    if (!status) return false;
    memset(status, 0, sizeof(*status));

    tpm_pin_config_t local_cfg;
    if (!cfg) {
        tpm_pin_config_load(NULL, &local_cfg);
        cfg = &local_cfg;
    }

    status->is_enrolled = tpm_pin_user_is_enrolled(uid, cfg);

    if (status->is_enrolled) {
        char blob_path[512];
        get_user_blob_path(uid, cfg, blob_path, sizeof(blob_path));
        FILE *f = open_regular_file_ro(blob_path);
        if (f) {
            tpm_sealed_header_t hdr;
            if (fread(&hdr, sizeof(hdr), 1, f) == 1 && hdr.magic == TPM_PIN_MAGIC) {
                status->pcr7_bound = (hdr.flags & FLAG_PCR7_BOUND) != 0;
                status->keyring_pwd_saved = (hdr.flags & FLAG_KEYRING_PWD_STORED) != 0;
            }
            fclose(f);
        }
    }

    ESYS_CONTEXT *esys = NULL;
    TSS2_RC rc = tpm_engine_init(cfg->tcti_name, &esys);
    if (rc == TSS2_RC_SUCCESS && esys) {
        tpm_engine_get_status(esys, status);
        tpm_engine_destroy(&esys);
    }

    return true;
}
