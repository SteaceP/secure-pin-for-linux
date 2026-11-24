#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <tss2/tss2_mu.h>
#include "tpm_pin.h"

static const char *get_safe_base_dir(const tpm_pin_config_t *cfg) {
    if (cfg && cfg->data_dir[0] == '/' && strstr(cfg->data_dir, "..") == NULL) {
        return cfg->data_dir;
    }
    return TPM_PIN_DEFAULT_DATA_DIR;
}

static bool is_system_data_dir(const tpm_pin_config_t *cfg) {
    return strcmp(get_safe_base_dir(cfg), TPM_PIN_DEFAULT_DATA_DIR) == 0;
}

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
} tpm_sealed_meta_t;

#define TPM_PIN_AAD_LEN 54

static void get_user_blob_path(uid_t uid, const tpm_pin_config_t *cfg, char *out_path, size_t out_len) {
    const char *base_dir = get_safe_base_dir(cfg);
    snprintf(out_path, out_len, "%s/%u/sealed.blob", base_dir, (unsigned int)uid);
}

static void get_user_meta_path(uid_t uid, const tpm_pin_config_t *cfg, char *out_path, size_t out_len) {
    const char *base_dir = get_safe_base_dir(cfg);
    snprintf(out_path, out_len, "%s/%u/sealed.meta", base_dir, (unsigned int)uid);
}

static void get_user_dir_path(uid_t uid, const tpm_pin_config_t *cfg, char *out_path, size_t out_len) {
    const char *base_dir = get_safe_base_dir(cfg);
    snprintf(out_path, out_len, "%s/%u", base_dir, (unsigned int)uid);
}

static void build_header_aad(uid_t uid, const tpm_sealed_header_t *hdr, uint8_t *aad_out, size_t aad_len) {
    if (!hdr || !aad_out || aad_len < TPM_PIN_AAD_LEN) return;
    uint32_t uid32 = (uint32_t)uid;
    size_t off = 0;
    memcpy(aad_out + off, &hdr->magic, sizeof(hdr->magic)); off += sizeof(hdr->magic);
    memcpy(aad_out + off, &hdr->version, sizeof(hdr->version)); off += sizeof(hdr->version);
    memcpy(aad_out + off, &hdr->flags, sizeof(hdr->flags)); off += sizeof(hdr->flags);
    memcpy(aad_out + off, hdr->salt, sizeof(hdr->salt)); off += sizeof(hdr->salt);
    memcpy(aad_out + off, &hdr->tpm_priv_size, sizeof(hdr->tpm_priv_size)); off += sizeof(hdr->tpm_priv_size);
    memcpy(aad_out + off, &hdr->tpm_pub_size, sizeof(hdr->tpm_pub_size)); off += sizeof(hdr->tpm_pub_size);
    memcpy(aad_out + off, &hdr->enc_payload_size, sizeof(hdr->enc_payload_size)); off += sizeof(hdr->enc_payload_size);
    memcpy(aad_out + off, &uid32, sizeof(uid32));
}

static FILE *open_regular_file_ro(const char *path, bool system_dir) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        close(fd);
        return NULL;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(fd);
        return NULL;
    }
    if (geteuid() == 0 || system_dir) {
        if (st.st_uid != 0) {
            close(fd);
            return NULL;
        }
    } else {
        if (st.st_uid != 0 && st.st_uid != geteuid()) {
            close(fd);
            return NULL;
        }
    }
    /* Ensure sane file size */
    if (st.st_size < (off_t)sizeof(tpm_sealed_header_t) || st.st_size > 65536) {
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

static bool read_meta_flags(const char *meta_path, bool system_dir, uint32_t *flags_out) {
    int mfd = open(meta_path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (mfd < 0) return false;
    struct stat mst;
    bool ok = false;
    if (fstat(mfd, &mst) == 0 && S_ISREG(mst.st_mode) && mst.st_nlink == 1 &&
        (mst.st_mode & (S_IWGRP | S_IWOTH)) == 0) {
        bool owner_ok = (geteuid() == 0 || system_dir)
                        ? (mst.st_uid == 0)
                        : (mst.st_uid == 0 || mst.st_uid == geteuid());
        if (owner_ok) {
            tpm_sealed_meta_t meta;
            if (read(mfd, &meta, sizeof(meta)) == (ssize_t)sizeof(meta) &&
                meta.magic == TPM_PIN_MAGIC &&
                meta.version == TPM_PIN_VERSION) {
                if (flags_out) *flags_out = meta.flags;
                ok = true;
            }
        }
    }
    close(mfd);
    return ok;
}

static int ensure_owned_dir(const char *path, mode_t mode) {
    if (mkdir(path, mode) != 0 && errno != EEXIST) {
        return -1;
    }
    int dfd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) return -1;
    struct stat st;
    if (fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode)) {
        close(dfd);
        return -1;
    }
    if (geteuid() == 0 && fchown(dfd, 0, 0) != 0) {
        close(dfd);
        return -1;
    }
    if (fchmod(dfd, mode) != 0) {
        close(dfd);
        return -1;
    }
    return dfd;
}

bool tpm_pin_user_is_enrolled(uid_t uid, const tpm_pin_config_t *cfg) {
    bool sys_dir = is_system_data_dir(cfg);
    char path[512];
    get_user_blob_path(uid, cfg, path, sizeof(path));
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        return false;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        st.st_size < (off_t)sizeof(tpm_sealed_header_t) ||
        st.st_size > 65536) {
        return false;
    }
    if (geteuid() == 0 || sys_dir) {
        if (st.st_uid != 0) return false;
    } else {
        if (st.st_uid != 0 && st.st_uid != geteuid()) return false;
    }

    FILE *f = open_regular_file_ro(path, sys_dir);
    if (f) {
        tpm_sealed_header_t hdr;
        bool valid = (fread(&hdr, sizeof(hdr), 1, f) == 1 &&
                      hdr.magic == TPM_PIN_MAGIC &&
                      hdr.version == TPM_PIN_VERSION);
        fclose(f);
        return valid;
    }

    char meta_path[512];
    get_user_meta_path(uid, cfg, meta_path, sizeof(meta_path));
    return read_meta_flags(meta_path, sys_dir, NULL);
}

bool tpm_pin_remove_user(uid_t uid, const tpm_pin_config_t *cfg) {
    bool sys_dir = is_system_data_dir(cfg);
    char dir_path[512];
    get_user_dir_path(uid, cfg, dir_path, sizeof(dir_path));

    int dfd = open(dir_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) return false;

    struct stat dst;
    if (fstat(dfd, &dst) != 0 || !S_ISDIR(dst.st_mode) ||
        (geteuid() != 0 && (sys_dir || dst.st_uid != geteuid()))) {
        close(dfd);
        return false;
    }

    /* Securely overwrite blob contents with zeroes before unlinking */
    int fd = openat(dfd, "sealed.blob", O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
            (st.st_uid == 0 || (geteuid() != 0 && !sys_dir && st.st_uid == geteuid())) &&
            st.st_size > 0 && st.st_size <= 65536) {
            uint8_t zero_buf[512] = {0};
            off_t remaining = st.st_size;
            while (remaining > 0) {
                size_t to_write = (remaining > (off_t)sizeof(zero_buf)) ? sizeof(zero_buf) : (size_t)remaining;
                ssize_t w = write(fd, zero_buf, to_write);
                if (w <= 0) {
                    if (w < 0 && errno == EINTR) continue;
                    break;
                }
                remaining -= (off_t)w;
            }
            if (fsync(fd) != 0) {
                /* fsync attempted */
            }
        }
        close(fd);
    }

    unlinkat(dfd, "sealed.meta", 0);
    bool removed = (unlinkat(dfd, "sealed.blob", 0) == 0);
    close(dfd);

    if (removed) {
        rmdir(dir_path);
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

    (void)tpm_engine_configure_da(
        esys,
        cfg->da_max_tries ? cfg->da_max_tries : 5,
        cfg->da_recovery_time,
        cfg->da_lockout_recovery
    );

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
        tpm_pin_zero(&pub, sizeof(pub));
        return false;
    }

    uint8_t priv_buf[sizeof(TPM2B_PRIVATE) + 64];
    uint8_t pub_buf[sizeof(TPM2B_PUBLIC) + 64];
    size_t priv_off = 0;
    size_t pub_off = 0;
    TSS2_RC mu_rc1 = Tss2_MU_TPM2B_PRIVATE_Marshal(&priv, priv_buf, sizeof(priv_buf), &priv_off);
    TSS2_RC mu_rc2 = Tss2_MU_TPM2B_PUBLIC_Marshal(&pub, pub_buf, sizeof(pub_buf), &pub_off);
    tpm_pin_zero(&priv, sizeof(priv));
    tpm_pin_zero(&pub, sizeof(pub));
    if (mu_rc1 != TSS2_RC_SUCCESS || mu_rc2 != TSS2_RC_SUCCESS ||
        priv_off == 0 || priv_off > UINT16_MAX ||
        pub_off == 0 || pub_off > UINT16_MAX) {
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(master_key, sizeof(master_key));
        return false;
    }

    /* Prepare plaintext payload: Magic + User Password */
    size_t pwd_len = (password && cfg->enable_keyring_unlock) ? strlen(password) : 0;
    if (pwd_len >= TPM_PIN_MAX_PASSWORD_LEN) {
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(master_key, sizeof(master_key));
        return false;
    }
    size_t magic_len = strlen(TPM_PIN_VERIFY_TOKEN_MAGIC) + 1;
    size_t pt_len = magic_len + pwd_len + 1;

    uint8_t *plaintext = (uint8_t *)calloc(1, pt_len);
    if (!plaintext) {
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(master_key, sizeof(master_key));
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
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        tpm_pin_zero(salt, sizeof(salt));
        tpm_pin_zero(master_key, sizeof(master_key));
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
    hdr.tpm_priv_size = (uint16_t)priv_off;
    hdr.tpm_pub_size  = (uint16_t)pub_off;
    hdr.enc_payload_size = (uint16_t)pt_len;
    memcpy(hdr.iv, iv, sizeof(iv));

    uint8_t aad[TPM_PIN_AAD_LEN];
    build_header_aad(uid, &hdr, aad, sizeof(aad));

    uint8_t *ciphertext = (uint8_t *)calloc(1, pt_len);
    bool enc_ok = ciphertext && tpm_pin_encrypt_aad(master_key, iv, aad, sizeof(aad), plaintext, pt_len, ciphertext, tag);

    tpm_pin_zero(plaintext, pt_len);
    free(plaintext);
    tpm_pin_zero(master_key, sizeof(master_key));

    if (!enc_ok) {
        tpm_pin_zero(tag, sizeof(tag));
        tpm_pin_zero(&hdr, sizeof(hdr));
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        if (ciphertext) free(ciphertext);
        return false;
    }
    memcpy(hdr.tag, tag, sizeof(tag));
    tpm_pin_zero(tag, sizeof(tag));

    /* Write out sealed blob (owned by root:root so unprivileged processes cannot forge blobs) */
    const char *base_dir = get_safe_base_dir(cfg);
    char dir_path[512];
    get_user_dir_path(uid, cfg, dir_path, sizeof(dir_path));

    int base_dfd = ensure_owned_dir(base_dir, 0755);
    if (base_dfd < 0) {
        tpm_pin_zero(&hdr, sizeof(hdr));
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        free(ciphertext);
        return false;
    }
    close(base_dfd);

    int dir_dfd = ensure_owned_dir(dir_path, 0755);
    if (dir_dfd < 0) {
        tpm_pin_zero(&hdr, sizeof(hdr));
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        free(ciphertext);
        return false;
    }

    char tmp_name[128];
    snprintf(tmp_name, sizeof(tmp_name), "sealed.blob.tmp.%d", (int)getpid());
    unlinkat(dir_dfd, tmp_name, 0);

    int fd = openat(dir_dfd, tmp_name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        close(dir_dfd);
        tpm_pin_zero(&hdr, sizeof(hdr));
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        free(ciphertext);
        return false;
    }

    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        unlinkat(dir_dfd, tmp_name, 0);
        close(dir_dfd);
        tpm_pin_zero(&hdr, sizeof(hdr));
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        free(ciphertext);
        return false;
    }

    bool write_ok = (fwrite(&hdr, sizeof(hdr), 1, f) == 1 &&
                     fwrite(priv_buf, 1, priv_off, f) == priv_off &&
                     fwrite(pub_buf, 1, pub_off, f) == pub_off &&
                     fwrite(ciphertext, 1, pt_len, f) == pt_len &&
                     !ferror(f) &&
                     fchmod(fd, 0600) == 0 &&
                     fflush(f) == 0 &&
                     fsync(fd) == 0);
    tpm_pin_zero(priv_buf, sizeof(priv_buf));
    tpm_pin_zero(pub_buf, sizeof(pub_buf));
    free(ciphertext);

    if (fclose(f) != 0) write_ok = false;
    if (!write_ok) {
        unlinkat(dir_dfd, tmp_name, 0);
        close(dir_dfd);
        tpm_pin_zero(&hdr, sizeof(hdr));
        return false;
    }

    if (renameat(dir_dfd, tmp_name, dir_dfd, "sealed.blob") != 0) {
        unlinkat(dir_dfd, tmp_name, 0);
        close(dir_dfd);
        tpm_pin_zero(&hdr, sizeof(hdr));
        return false;
    }

    /* Write non-sensitive status metadata atomically so unprivileged status queries can read flags */
    char meta_tmp_name[128];
    snprintf(meta_tmp_name, sizeof(meta_tmp_name), "sealed.meta.tmp.%d", (int)getpid());
    unlinkat(dir_dfd, meta_tmp_name, 0);
    int mfd = openat(dir_dfd, meta_tmp_name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (mfd >= 0) {
        tpm_sealed_meta_t meta;
        meta.magic = hdr.magic;
        meta.version = hdr.version;
        meta.flags = hdr.flags;
        ssize_t mw = write(mfd, &meta, sizeof(meta));
        if (mw == (ssize_t)sizeof(meta) && fchmod(mfd, 0644) == 0 && fsync(mfd) == 0) {
            close(mfd);
            if (renameat(dir_dfd, meta_tmp_name, dir_dfd, "sealed.meta") != 0) {
                unlinkat(dir_dfd, meta_tmp_name, 0);
            }
        } else {
            close(mfd);
            unlinkat(dir_dfd, meta_tmp_name, 0);
        }
    }
    (void)fsync(dir_dfd);
    close(dir_dfd);
    tpm_pin_zero(&hdr, sizeof(hdr));

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

    bool sys_dir = is_system_data_dir(cfg);
    char blob_path[512];
    get_user_blob_path(uid, cfg, blob_path, sizeof(blob_path));

    FILE *f = open_regular_file_ro(blob_path, sys_dir);
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
        hdr.tpm_priv_size == 0 || hdr.tpm_priv_size > sizeof(TPM2B_PRIVATE) + 64 ||
        hdr.tpm_pub_size == 0 || hdr.tpm_pub_size > sizeof(TPM2B_PUBLIC) + 64) {
        fclose(f);
        return false;
    }

    uint8_t priv_buf[sizeof(TPM2B_PRIVATE) + 64];
    uint8_t pub_buf[sizeof(TPM2B_PUBLIC) + 64];
    if (fread(priv_buf, 1, hdr.tpm_priv_size, f) != hdr.tpm_priv_size ||
        fread(pub_buf, 1, hdr.tpm_pub_size, f) != hdr.tpm_pub_size) {
        tpm_pin_zero(priv_buf, sizeof(priv_buf));
        tpm_pin_zero(pub_buf, sizeof(pub_buf));
        fclose(f);
        return false;
    }

    TPM2B_PRIVATE priv;
    TPM2B_PUBLIC  pub;
    memset(&priv, 0, sizeof(priv));
    memset(&pub, 0, sizeof(pub));
    size_t priv_off = 0;
    size_t pub_off = 0;
    TSS2_RC mu_rc1 = Tss2_MU_TPM2B_PRIVATE_Unmarshal(priv_buf, hdr.tpm_priv_size, &priv_off, &priv);
    TSS2_RC mu_rc2 = Tss2_MU_TPM2B_PUBLIC_Unmarshal(pub_buf, hdr.tpm_pub_size, &pub_off, &pub);
    tpm_pin_zero(priv_buf, sizeof(priv_buf));
    tpm_pin_zero(pub_buf, sizeof(pub_buf));
    if (mu_rc1 != TSS2_RC_SUCCESS || priv_off != hdr.tpm_priv_size ||
        mu_rc2 != TSS2_RC_SUCCESS || pub_off != hdr.tpm_pub_size) {
        tpm_pin_zero(&priv, sizeof(priv));
        tpm_pin_zero(&pub, sizeof(pub));
        fclose(f);
        return false;
    }

    uint8_t *ciphertext = (uint8_t *)malloc(hdr.enc_payload_size);
    if (!ciphertext || fread(ciphertext, 1, hdr.enc_payload_size, f) != hdr.enc_payload_size) {
        tpm_pin_zero(&priv, sizeof(priv));
        tpm_pin_zero(&pub, sizeof(pub));
        if (ciphertext) free(ciphertext);
        fclose(f);
        return false;
    }
    fclose(f);

    uint8_t auth[32];
    if (!tpm_pin_derive_auth(pin, hdr.salt, sizeof(hdr.salt), auth, sizeof(auth))) {
        tpm_pin_zero(&priv, sizeof(priv));
        tpm_pin_zero(&pub, sizeof(pub));
        free(ciphertext);
        return false;
    }

    ESYS_CONTEXT *esys = NULL;
    TSS2_RC rc = tpm_engine_init(cfg->tcti_name, &esys);
    if (rc != TSS2_RC_SUCCESS || !esys) {
        tpm_pin_zero(&priv, sizeof(priv));
        tpm_pin_zero(&pub, sizeof(pub));
        tpm_pin_zero(auth, sizeof(auth));
        free(ciphertext);
        return false;
    }

    uint8_t master_key[TPM_PIN_KEY_LEN] = {0};
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
    tpm_pin_zero(&pub, sizeof(pub));
    tpm_pin_zero(auth, sizeof(auth));
    tpm_engine_destroy(&esys);

    if (tpm_status_code) {
        *tpm_status_code = (int)rc;
    }

    if (rc != TSS2_RC_SUCCESS || key_len != TPM_PIN_KEY_LEN) {
        tpm_pin_zero(master_key, sizeof(master_key));
        free(ciphertext);
        return false;
    }

    uint8_t *plaintext = (uint8_t *)calloc(1, hdr.enc_payload_size + 1);
    if (!plaintext) {
        tpm_pin_zero(master_key, sizeof(master_key));
        free(ciphertext);
        return false;
    }

    uint8_t aad[TPM_PIN_AAD_LEN];
    build_header_aad(uid, &hdr, aad, sizeof(aad));

    bool dec_ok = tpm_pin_decrypt_aad(master_key, hdr.iv, aad, sizeof(aad),
                                      ciphertext, hdr.enc_payload_size, hdr.tag, plaintext);
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

    if (unsealed_password && pwd_buf_size > 0) {
        unsealed_password[0] = '\0';
        if (hdr.flags & FLAG_KEYRING_PWD_STORED) {
            const char *pwd = (const char *)(plaintext + magic_len);
            snprintf(unsealed_password, pwd_buf_size, "%.*s", (int)(hdr.enc_payload_size - magic_len), pwd);
        }
    }

    tpm_pin_zero(plaintext, hdr.enc_payload_size + 1);
    free(plaintext);
    return true;
}

static int cmp_uid_asc(const void *a, const void *b) {
    uid_t ua = *(const uid_t *)a;
    uid_t ub = *(const uid_t *)b;
    return (ua < ub) ? -1 : ((ua > ub) ? 1 : 0);
}

static bool parse_uid_dir_name(const char *name, uid_t *uid_out) {
    if (!name || !name[0] || !uid_out) return false;
    for (size_t i = 0; name[i] != '\0'; i++) {
        if (!isdigit((unsigned char)name[i])) return false;
    }
    errno = 0;
    char *endptr = NULL;
    unsigned long val = strtoul(name, &endptr, 10);
    if (errno == ERANGE || !endptr || *endptr != '\0' || val > (unsigned long)UINT32_MAX) {
        return false;
    }
    *uid_out = (uid_t)val;
    return true;
}

bool tpm_pin_get_user_enrollment_flags(uid_t uid, const tpm_pin_config_t *cfg,
                                       bool *pcr7_bound, bool *keyring_pwd_saved) {
    if (pcr7_bound) *pcr7_bound = false;
    if (keyring_pwd_saved) *keyring_pwd_saved = false;

    tpm_pin_config_t local_cfg;
    if (!cfg) {
        tpm_pin_config_load(NULL, &local_cfg);
        cfg = &local_cfg;
    }

    if (!tpm_pin_user_is_enrolled(uid, cfg)) {
        return false;
    }

    bool sys_dir = is_system_data_dir(cfg);
    char blob_path[512];
    get_user_blob_path(uid, cfg, blob_path, sizeof(blob_path));
    FILE *f = open_regular_file_ro(blob_path, sys_dir);
    if (f) {
        tpm_sealed_header_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, f) == 1 &&
            hdr.magic == TPM_PIN_MAGIC &&
            hdr.version == TPM_PIN_VERSION) {
            if (pcr7_bound) *pcr7_bound = (hdr.flags & FLAG_PCR7_BOUND) != 0;
            if (keyring_pwd_saved) *keyring_pwd_saved = (hdr.flags & FLAG_KEYRING_PWD_STORED) != 0;
        }
        fclose(f);
        return true;
    }

    char meta_path[512];
    get_user_meta_path(uid, cfg, meta_path, sizeof(meta_path));
    uint32_t meta_flags = 0;
    if (read_meta_flags(meta_path, sys_dir, &meta_flags)) {
        if (pcr7_bound) *pcr7_bound = (meta_flags & FLAG_PCR7_BOUND) != 0;
        if (keyring_pwd_saved) *keyring_pwd_saved = (meta_flags & FLAG_KEYRING_PWD_STORED) != 0;
    }
    return true;
}

size_t tpm_pin_list_enrolled_users(const tpm_pin_config_t *cfg, uid_t *uids_out, size_t max_uids) {
    tpm_pin_config_t local_cfg;
    if (!cfg) {
        tpm_pin_config_load(NULL, &local_cfg);
        cfg = &local_cfg;
    }

    const char *base_dir = get_safe_base_dir(cfg);
    bool sys_dir = is_system_data_dir(cfg);

    int dfd = open(base_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) return 0;

    struct stat st;
    if (fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (sys_dir && st.st_uid != 0)) {
        close(dfd);
        return 0;
    }

    DIR *dir = fdopendir(dfd);
    if (!dir) {
        close(dfd);
        return 0;
    }

    size_t cap = 64;
    size_t total = 0;
    uid_t *found = (uid_t *)malloc(cap * sizeof(uid_t));
    if (!found) {
        closedir(dir);
        return 0;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        uid_t uid = 0;
        if (!parse_uid_dir_name(ent->d_name, &uid)) {
            continue;
        }
        if (!tpm_pin_user_is_enrolled(uid, cfg)) {
            continue;
        }
        if (total == cap) {
            if (cap >= 65536) break;
            size_t new_cap = cap * 2;
            uid_t *tmp = (uid_t *)realloc(found, new_cap * sizeof(uid_t));
            if (!tmp) break;
            found = tmp;
            cap = new_cap;
        }
        found[total++] = uid;
    }

    closedir(dir);

    if (total > 1) {
        qsort(found, total, sizeof(uid_t), cmp_uid_asc);
    }

    if (!uids_out || max_uids == 0) {
        free(found);
        return total;
    }

    size_t written = (total < max_uids) ? total : max_uids;
    memcpy(uids_out, found, written * sizeof(uid_t));
    free(found);
    return written;
}

bool tpm_pin_change_pin(uid_t uid, const char *old_pin, const char *new_pin,
                        const char *override_password, const tpm_pin_config_t *cfg,
                        int *tpm_status_code) {
    if (tpm_status_code) *tpm_status_code = 0;
    if (!old_pin || old_pin[0] == '\0' || !new_pin) return false;

    size_t old_len = strlen(old_pin);
    if (old_len > TPM_PIN_MAX_PIN_LEN) return false;
    for (size_t i = 0; i < old_len; i++) {
        if (iscntrl((unsigned char)old_pin[i])) return false;
    }

    tpm_pin_config_t local_cfg;
    if (!cfg) {
        tpm_pin_config_load(NULL, &local_cfg);
        cfg = &local_cfg;
    }

    char err_buf[256];
    if (!tpm_pin_validate_pin(new_pin, cfg, err_buf, sizeof(err_buf))) {
        return false;
    }

    /*
     * Allow verifying old_pin even if policy constraints (min_length, max_length, digits_only)
     * were tightened after enrollment, while still validating new_pin against the active policy.
     */
    tpm_pin_config_t verify_cfg = *cfg;
    verify_cfg.digits_only = false;
    verify_cfg.min_length = 1;
    verify_cfg.max_length = TPM_PIN_MAX_PIN_LEN;

    char unsealed_pwd[TPM_PIN_MAX_PASSWORD_LEN] = {0};
    int tpm_rc = 0;
    if (!tpm_pin_verify_user(uid, old_pin, &verify_cfg, unsealed_pwd, sizeof(unsealed_pwd), &tpm_rc)) {
        if (tpm_status_code) *tpm_status_code = tpm_rc;
        tpm_pin_zero(unsealed_pwd, sizeof(unsealed_pwd));
        return false;
    }

    const char *pwd_to_seal = NULL;
    if (cfg->enable_keyring_unlock) {
        if (override_password && override_password[0] != '\0') {
            pwd_to_seal = override_password;
        } else if (unsealed_pwd[0] != '\0') {
            pwd_to_seal = unsealed_pwd;
        }
    }

    bool ok = tpm_pin_enroll_user(uid, new_pin, pwd_to_seal, cfg);
    tpm_pin_zero(unsealed_pwd, sizeof(unsealed_pwd));
    return ok;
}

bool tpm_pin_get_user_status(uid_t uid, const tpm_pin_config_t *cfg, tpm_pin_status_t *status) {
    if (!status) return false;
    memset(status, 0, sizeof(*status));

    tpm_pin_config_t local_cfg;
    if (!cfg) {
        tpm_pin_config_load(NULL, &local_cfg);
        cfg = &local_cfg;
    }

    status->is_enrolled = tpm_pin_get_user_enrollment_flags(
        uid, cfg, &status->pcr7_bound, &status->keyring_pwd_saved);

    ESYS_CONTEXT *esys = NULL;
    TSS2_RC rc = tpm_engine_init(cfg->tcti_name, &esys);
    if (rc == TSS2_RC_SUCCESS && esys) {
        tpm_engine_get_status(esys, status);
        tpm_engine_destroy(&esys);
    } else if (cfg->tcti_name[0] == '\0' && secure_getenv("TCTI") == NULL && tpm_engine_sysfs_present()) {
        status->tpm_present = true;
        status->tpm_accessible = false;
        snprintf(status->manufacturer, sizeof(status->manufacturer), "TPM 2.0");
        tpm_engine_detect_sysfs_hardware("", "", status);
        snprintf(status->bus_encryption, sizeof(status->bus_encryption),
                 "Active (AES-128-CFB parameter transit encryption)");
    }

    return true;
}
