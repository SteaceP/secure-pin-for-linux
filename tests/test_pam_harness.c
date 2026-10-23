#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <dlfcn.h>
#include "tpm_pin.h"

static int test_count = 0;
static int pass_count = 0;

#define RUN_TEST(name, func) do { \
    printf("Running test: %s ... ", name); \
    test_count++; \
    if (func()) { \
        printf("PASSED\n"); \
        pass_count++; \
    } else { \
        printf("FAILED\n"); \
    } \
} while (0)

static bool test_policy_validation(void) {
    tpm_pin_config_t cfg;
    tpm_pin_config_defaults(&cfg);
    cfg.digits_only = true;
    cfg.min_length = 4;
    cfg.max_length = 8;

    char err[256];
    /* Valid 6-digit PIN */
    if (!tpm_pin_validate_pin("123456", &cfg, err, sizeof(err))) return false;

    /* Too short */
    if (tpm_pin_validate_pin("123", &cfg, err, sizeof(err))) return false;

    /* Too long */
    if (tpm_pin_validate_pin("123456789", &cfg, err, sizeof(err))) return false;

    /* Contains non-digit */
    if (tpm_pin_validate_pin("123a56", &cfg, err, sizeof(err))) return false;

    /* All identical */
    if (tpm_pin_validate_pin("777777", &cfg, err, sizeof(err))) return false;

    /* Alphanumeric mode */
    cfg.digits_only = false;
    if (!tpm_pin_validate_pin("p1n_C0de", &cfg, err, sizeof(err))) return false;

    return true;
}

static bool test_crypto_roundtrip(void) {
    uint8_t salt[TPM_PIN_SALT_LEN];
    if (!tpm_pin_random_bytes(salt, sizeof(salt))) return false;

    uint8_t auth[32];
    if (!tpm_pin_derive_auth("849201", salt, sizeof(salt), auth, sizeof(auth))) return false;

    uint8_t key[TPM_PIN_KEY_LEN];
    if (!tpm_pin_random_bytes(key, sizeof(key))) return false;

    uint8_t iv[TPM_PIN_IV_LEN];
    if (!tpm_pin_random_bytes(iv, sizeof(iv))) return false;

    const char *plaintext = "SuperSecretPassword123!_UnlockKeyring";
    size_t pt_len = strlen(plaintext) + 1;

    uint8_t ciphertext[128] = {0};
    uint8_t tag[TPM_PIN_TAG_LEN] = {0};

    if (!tpm_pin_encrypt(key, iv, (const uint8_t *)plaintext, pt_len, ciphertext, tag)) return false;

    uint8_t decrypted[128] = {0};
    if (!tpm_pin_decrypt(key, iv, ciphertext, pt_len, tag, decrypted)) return false;

    if (strcmp((char *)decrypted, plaintext) != 0) return false;

    /* Tampering with ciphertext should fail decryption */
    ciphertext[0] ^= 0xFF;
    if (tpm_pin_decrypt(key, iv, ciphertext, pt_len, tag, decrypted)) return false;

    return true;
}

static bool test_config_serialization(void) {
    tpm_pin_config_t cfg;
    tpm_pin_config_defaults(&cfg);
    cfg.digits_only = false;
    cfg.min_length = 6;
    cfg.max_length = 16;
    cfg.enable_sudo = false;
    cfg.bind_pcr7 = true;

    const char *tmp_conf = "/tmp/test_tpm_pin_config.conf";
    if (!tpm_pin_config_save(tmp_conf, &cfg)) return false;

    tpm_pin_config_t loaded;
    if (!tpm_pin_config_load(tmp_conf, &loaded)) {
        unlink(tmp_conf);
        return false;
    }
    unlink(tmp_conf);

    if (loaded.digits_only != false) return false;
    if (loaded.min_length != 6) return false;
    if (loaded.max_length != 16) return false;
    if (loaded.enable_sudo != false) return false;
    if (loaded.bind_pcr7 != true) return false;

    return true;
}

static bool test_tpm_enroll_and_verify(void) {
    tpm_pin_config_t cfg;
    tpm_pin_config_defaults(&cfg);

    const char *tcti_env = getenv("TCTI");
    if (tcti_env) {
        snprintf(cfg.tcti_name, sizeof(cfg.tcti_name), "%s", tcti_env);
    }
    snprintf(cfg.data_dir, sizeof(cfg.data_dir), "/tmp/test_tpm_data_%d", (int)getpid());

    uid_t test_uid = 9999;
    const char *test_pin = "958214";
    const char *test_password = "UserSystemPassword!";

    /* Clean old state if any */
    tpm_pin_remove_user(test_uid, &cfg);

    /* Enroll */
    bool enrolled = tpm_pin_enroll_user(test_uid, test_pin, test_password, &cfg);
    if (!enrolled) {
        if (tcti_env || access("/dev/tpmrm0", R_OK | W_OK) == 0) {
            return false;
        }
        printf("[Notice: TPM not accessible or supported in this test environment] ");
        return true; /* Skip gracefully only if no TPM is running */
    }

    if (!tpm_pin_user_is_enrolled(test_uid, &cfg)) return false;

    /* Verify with correct PIN */
    char unsealed[TPM_PIN_MAX_PASSWORD_LEN] = {0};
    int tpm_rc = 0;
    if (!tpm_pin_verify_user(test_uid, test_pin, &cfg, unsealed, sizeof(unsealed), &tpm_rc)) {
        return false;
    }

    /* Check that saved password for keyring unsealed properly */
    if (strcmp(unsealed, test_password) != 0) return false;

    /* Verify with wrong PIN */
    if (tpm_pin_verify_user(test_uid, "112233", &cfg, unsealed, sizeof(unsealed), &tpm_rc)) {
        return false;
    }

    /* Verify that regular non-PIN password is rejected by policy filter without hitting TPM */
    if (tpm_pin_is_likely_pin("AlphaPassword123!", &cfg)) {
        return false;
    }

    /* Cleanup */
    tpm_pin_remove_user(test_uid, &cfg);
    return true;
}

static bool test_tpm_enroll_and_verify_pcr7(void) {
    tpm_pin_config_t cfg;
    tpm_pin_config_defaults(&cfg);
    cfg.bind_pcr7 = true;

    const char *tcti_env = getenv("TCTI");
    if (tcti_env) {
        snprintf(cfg.tcti_name, sizeof(cfg.tcti_name), "%s", tcti_env);
    }
    snprintf(cfg.data_dir, sizeof(cfg.data_dir), "/tmp/test_tpm_data_%d", (int)getpid());

    uid_t test_uid = 9998;
    const char *test_pin = "834192";
    const char *test_password = "PCR7BoundPassword!";

    tpm_pin_remove_user(test_uid, &cfg);

    bool enrolled = tpm_pin_enroll_user(test_uid, test_pin, test_password, &cfg);
    if (!enrolled) {
        if (tcti_env || access("/dev/tpmrm0", R_OK | W_OK) == 0) {
            return false;
        }
        return true; /* Skip gracefully only if no TPM is accessible */
    }

    if (!tpm_pin_user_is_enrolled(test_uid, &cfg)) return false;

    /* Verify status reflects PCR 7 binding and saved keyring password */
    tpm_pin_status_t st;
    if (!tpm_pin_get_user_status(test_uid, &cfg, &st) || !st.is_enrolled || !st.pcr7_bound || !st.keyring_pwd_saved) {
        tpm_pin_remove_user(test_uid, &cfg);
        return false;
    }

    /* Verify with correct PIN */
    char unsealed[TPM_PIN_MAX_PASSWORD_LEN] = {0};
    int tpm_rc = 0;
    if (!tpm_pin_verify_user(test_uid, test_pin, &cfg, unsealed, sizeof(unsealed), &tpm_rc)) {
        tpm_pin_remove_user(test_uid, &cfg);
        return false;
    }

    if (strcmp(unsealed, test_password) != 0) {
        tpm_pin_remove_user(test_uid, &cfg);
        return false;
    }

    /* Verify that wrong PIN FAILS even with PCR7 binding */
    if (tpm_pin_verify_user(test_uid, "123456", &cfg, unsealed, sizeof(unsealed), &tpm_rc)) {
        tpm_pin_remove_user(test_uid, &cfg);
        return false;
    }

    /*
     * Simulate an attacker tampering with the on-disk blob header to strip FLAG_PCR7_BOUND
     * in an attempt to bypass PCR 7 policy using direct HMAC authorization.
     * Because TPMA_OBJECT_USERWITHAUTH is cleared in the TPM-signed public area, the TPM
     * must reject the unseal even when the attacker supplies the valid PIN.
     */
    char blob_path[512];
    snprintf(blob_path, sizeof(blob_path), "%s/%u/sealed.blob", cfg.data_dir, (unsigned int)test_uid);
    FILE *bf = fopen(blob_path, "r+b");
    if (bf) {
        tpm_sealed_header_t hdr;
        if (fread(&hdr, sizeof(hdr), 1, bf) == 1) {
            hdr.flags &= ~FLAG_PCR7_BOUND;
            fseek(bf, 0, SEEK_SET);
            fwrite(&hdr, sizeof(hdr), 1, bf);
        }
        fclose(bf);
        if (tpm_pin_verify_user(test_uid, test_pin, &cfg, unsealed, sizeof(unsealed), &tpm_rc)) {
            tpm_pin_remove_user(test_uid, &cfg);
            return false;
        }
    }

    /* Reset DA lockout counter after negative tests and verify failed_tries returns to 0 if reset was permitted */
    ESYS_CONTEXT *esys = NULL;
    bool da_reset_ok = false;
    if (tpm_engine_init(cfg.tcti_name, &esys) == TSS2_RC_SUCCESS && esys) {
        da_reset_ok = (tpm_engine_reset_da_lockout(esys) == TSS2_RC_SUCCESS);
        tpm_engine_destroy(&esys);
    }

    if (!tpm_pin_get_user_status(test_uid, &cfg, &st) || (da_reset_ok && st.failed_tries != 0)) {
        tpm_pin_remove_user(test_uid, &cfg);
        return false;
    }

    tpm_pin_remove_user(test_uid, &cfg);
    return true;
}

static bool test_pam_module_dlopen(void) {
    const char *paths[] = {
        "./pam_tpm_pin.so",
        "./build/pam_tpm_pin.so",
        "../build/pam_tpm_pin.so",
        "/usr/lib/x86_64-linux-gnu/security/pam_tpm_pin.so"
    };
    void *handle = NULL;
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
        handle = dlopen(paths[i], RTLD_NOW);
        if (handle) break;
    }
    if (!handle) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return false;
    }
    const char *syms[] = {
        "pam_sm_authenticate",
        "pam_sm_setcred",
        "pam_sm_acct_mgmt",
        "pam_sm_open_session",
        "pam_sm_close_session",
        "pam_sm_chauthtok"
    };
    for (size_t i = 0; i < sizeof(syms)/sizeof(syms[0]); i++) {
        if (!dlsym(handle, syms[i])) {
            fprintf(stderr, "Missing symbol: %s\n", syms[i]);
            dlclose(handle);
            return false;
        }
    }
    dlclose(handle);
    return true;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    printf("=== Secure PIN for Linux — PAM & TPM Test Suite ===\n");

    RUN_TEST("PAM Module Dynamic Linking (dlopen)", test_pam_module_dlopen);
    RUN_TEST("PIN Policy Validation", test_policy_validation);
    RUN_TEST("AES-256-GCM + PBKDF2 Crypto Roundtrip", test_crypto_roundtrip);
    RUN_TEST("Configuration Serialization", test_config_serialization);
    RUN_TEST("TPM 2.0 User Enrollment & Unsealing", test_tpm_enroll_and_verify);
    RUN_TEST("TPM 2.0 PCR 7 Binding & Authentication", test_tpm_enroll_and_verify_pcr7);

    printf("\nTest Summary: %d / %d tests passed.\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
