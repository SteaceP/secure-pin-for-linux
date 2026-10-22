#ifndef TPM_PIN_H
#define TPM_PIN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include <tss2/tss2_types.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TPM_PIN_DEFAULT_CONFIG_PATH "/etc/tpm-pin/config.conf"
#define TPM_PIN_DEFAULT_DATA_DIR    "/var/lib/tpm-pin"
#define TPM_PIN_MAGIC               0x54504D50  /* "TPMP" */
#define TPM_PIN_VERSION             1

#define TPM_PIN_SALT_LEN            32
#define TPM_PIN_IV_LEN              12
#define TPM_PIN_TAG_LEN             16
#define TPM_PIN_KEY_LEN             32
#define TPM_PIN_MAX_PIN_LEN         64
#define TPM_PIN_MAX_PASSWORD_LEN    256
#define TPM_PIN_VERIFY_TOKEN_MAGIC  "TPM_PIN_V1_OK"

#define FLAG_PCR7_BOUND             (1 << 0)
#define FLAG_KEYRING_PWD_STORED     (1 << 1)

typedef struct {
    bool     digits_only;
    uint32_t min_length;
    uint32_t max_length;
    bool     enable_login;
    bool     enable_lockscreen;
    bool     enable_sudo;
    bool     enable_keyring_unlock;
    bool     bind_pcr7;
    uint32_t da_max_tries;
    uint32_t da_recovery_time;
    uint32_t da_lockout_recovery;
    char     tcti_name[128];
    char     data_dir[256];
} tpm_pin_config_t;

typedef struct {
    bool     tpm_present;
    char     manufacturer[64];
    char     hardware_type[128];
    char     bus_encryption[64];
    bool     is_enrolled;
    bool     is_locked_out;
    uint32_t failed_tries;
    uint32_t max_tries;
    bool     pcr7_bound;
    bool     keyring_pwd_saved;
} tpm_pin_status_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    uint8_t  salt[TPM_PIN_SALT_LEN];
    uint16_t tpm_priv_size;
    uint16_t tpm_pub_size;
    uint16_t enc_payload_size;
    uint8_t  iv[TPM_PIN_IV_LEN];
    uint8_t  tag[TPM_PIN_TAG_LEN];
} tpm_sealed_header_t;

typedef enum {
    DISTRO_UNKNOWN = 0,
    DISTRO_DEBIAN_UBUNTU,
    DISTRO_FEDORA_RHEL,
    DISTRO_ARCH,
    DISTRO_OPENSUSE,
    DISTRO_GENERIC
} linux_distro_t;

/* Policy Functions */
bool tpm_pin_validate_pin(const char *pin, const tpm_pin_config_t *cfg, char *err_buf, size_t err_size);
bool tpm_pin_is_likely_pin(const char *input, const tpm_pin_config_t *cfg);

/* Crypto Functions */
void tpm_pin_zero(void *ptr, size_t size);
bool tpm_pin_derive_auth(const char *pin, const uint8_t *salt, size_t salt_len, uint8_t *out_auth, size_t auth_len);
bool tpm_pin_random_bytes(uint8_t *buf, size_t len);
bool tpm_pin_encrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *plaintext, size_t pt_len,
                     uint8_t *ciphertext, uint8_t *tag);
bool tpm_pin_decrypt(const uint8_t *key, const uint8_t *iv,
                     const uint8_t *ciphertext, size_t ct_len,
                     const uint8_t *tag, uint8_t *plaintext);

/* Config Functions */
void tpm_pin_config_defaults(tpm_pin_config_t *cfg);
bool tpm_pin_config_load(const char *path, tpm_pin_config_t *cfg);
bool tpm_pin_config_save(const char *path, const tpm_pin_config_t *cfg);

/* TPM 2.0 Engine Functions */
TSS2_RC tpm_engine_init(const char *tcti_conf, ESYS_CONTEXT **esys_ctx);
void    tpm_engine_destroy(ESYS_CONTEXT **esys_ctx);
TSS2_RC tpm_engine_get_status(ESYS_CONTEXT *ctx, tpm_pin_status_t *status);
TSS2_RC tpm_engine_seal_key(ESYS_CONTEXT *ctx,
                           const uint8_t *auth, size_t auth_len,
                           bool bind_pcr7,
                           const uint8_t *master_key, size_t key_len,
                           TPM2B_PRIVATE *out_priv, TPM2B_PUBLIC *out_pub);
TSS2_RC tpm_engine_unseal_key(ESYS_CONTEXT *ctx,
                             const uint8_t *auth, size_t auth_len,
                             bool bind_pcr7,
                             const TPM2B_PRIVATE *in_priv, const TPM2B_PUBLIC *in_pub,
                             uint8_t *out_key, size_t *out_key_len);
TSS2_RC tpm_engine_configure_da(ESYS_CONTEXT *ctx,
                               uint32_t max_tries, uint32_t recovery_time, uint32_t lockout_recovery);
TSS2_RC tpm_engine_reset_da_lockout(ESYS_CONTEXT *ctx);

/* High-level User Actions */
bool tpm_pin_enroll_user(uid_t uid, const char *pin, const char *password, const tpm_pin_config_t *cfg);
bool tpm_pin_verify_user(uid_t uid, const char *pin, const tpm_pin_config_t *cfg,
                         char *unsealed_password, size_t pwd_buf_size,
                         int *tpm_status_code);
bool tpm_pin_remove_user(uid_t uid, const tpm_pin_config_t *cfg);
bool tpm_pin_user_is_enrolled(uid_t uid, const tpm_pin_config_t *cfg);
bool tpm_pin_get_user_status(uid_t uid, const tpm_pin_config_t *cfg, tpm_pin_status_t *status);

/* Distro PAM Configuration Manager */
linux_distro_t pam_manager_detect_distro(void);
const char    *pam_manager_distro_name(linux_distro_t distro);
bool           pam_manager_enable(const tpm_pin_config_t *cfg, char *err_buf, size_t err_len);
bool           pam_manager_disable(char *err_buf, size_t err_len);
bool           pam_manager_is_enabled(void);

#ifdef __cplusplus
}
#endif

#endif /* TPM_PIN_H */
