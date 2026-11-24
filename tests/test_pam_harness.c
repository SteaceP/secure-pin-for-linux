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
#ifdef HAVE_LIBCRYPT
#include <crypt.h>
#endif
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
    /* Valid non-trivial 6-digit PIN */
    if (!tpm_pin_validate_pin("849201", &cfg, err, sizeof(err))) return false;

    /* Too short */
    if (tpm_pin_validate_pin("123", &cfg, err, sizeof(err))) return false;

    /* Too long */
    if (tpm_pin_validate_pin("849201739", &cfg, err, sizeof(err))) return false;

    /* Contains non-digit */
    if (tpm_pin_validate_pin("849a01", &cfg, err, sizeof(err))) return false;

    /* All identical */
    if (tpm_pin_validate_pin("777777", &cfg, err, sizeof(err))) return false;

    /* Sequential and repeating PINs rejected when disallow_simple_pins is true */
    if (tpm_pin_validate_pin("123456", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_validate_pin("0123", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_validate_pin("654321", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_validate_pin("1212", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_validate_pin("123123", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_validate_pin("12121", &cfg, err, sizeof(err))) return false;

    /* PAM candidate classifier MUST still accept sequential/repeating PINs for legacy users */
    if (!tpm_pin_is_likely_pin("123456", &cfg)) return false;
    if (!tpm_pin_is_likely_pin("1212", &cfg)) return false;

    /* Sequential/repeating allowed only when disallow_simple_pins is false */
    cfg.disallow_simple_pins = false;
    if (!tpm_pin_validate_pin("123456", &cfg, err, sizeof(err))) return false;
    if (!tpm_pin_validate_pin("1212", &cfg, err, sizeof(err))) return false;
    /* All-identical remains blocked even when disallow_simple_pins is false */
    if (tpm_pin_validate_pin("7777", &cfg, err, sizeof(err))) return false;

    /* Alphanumeric mode */
    cfg.disallow_simple_pins = true;
    cfg.digits_only = false;
    if (!tpm_pin_validate_pin("p1n_C0de", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_validate_pin("abcd", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_validate_pin("ababab", &cfg, err, sizeof(err))) return false;

    /* Control characters must be rejected even in alphanumeric mode */
    if (tpm_pin_validate_pin("p1n\n123", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_validate_pin("p1n\r123", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_validate_pin("p1n\x07" "123", &cfg, err, sizeof(err))) return false;
    if (tpm_pin_is_likely_pin("p1n\n123", &cfg)) return false;

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

    /* Tampering with ciphertext should fail decryption and zero output buffer */
    ciphertext[0] ^= 0xFF;
    if (tpm_pin_decrypt(key, iv, ciphertext, pt_len, tag, decrypted)) return false;
    for (size_t i = 0; i < pt_len; i++) {
        if (decrypted[i] != 0) return false;
    }

    return true;
}

static bool test_config_serialization(void) {
    tpm_pin_config_t cfg;
    tpm_pin_config_defaults(&cfg);
    cfg.digits_only = false;
    cfg.min_length = 6;
    cfg.max_length = 16;
    cfg.disallow_simple_pins = false;
    cfg.enable_sudo = false;
    cfg.enable_polkit = true;
    cfg.bind_pcr7 = true;
    cfg.da_lockout_recovery = 43200;

    char tmp_conf[256];
    snprintf(tmp_conf, sizeof(tmp_conf), "/tmp/test_tpm_pin_config_%d.conf", (int)getpid());
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
    if (loaded.disallow_simple_pins != false) return false;
    if (loaded.enable_sudo != false) return false;
    if (loaded.enable_polkit != true) return false;
    if (loaded.bind_pcr7 != true) return false;
    if (loaded.da_lockout_recovery != 43200) return false;

    /* Legacy config without enable_polkit must inherit enable_sudo */
    FILE *cf = fopen(tmp_conf, "w");
    if (!cf) return false;
    fprintf(cf, "enable_sudo = false\n");
    fclose(cf);

    bool ok_legacy = tpm_pin_config_load(tmp_conf, &loaded);
    unlink(tmp_conf);
    if (!ok_legacy || loaded.enable_sudo != false || loaded.enable_polkit != false) return false;

    /* Test inline comments and min_length upper clamping */
    cf = fopen(tmp_conf, "w");
    if (!cf) return false;
    fprintf(cf, "digits_only = true # inline comment\nmin_length = 100\nmax_length = 12\n");
    fclose(cf);

    bool ok_edge = tpm_pin_config_load(tmp_conf, &loaded);
    unlink(tmp_conf);
    if (!ok_edge) return false;
    if (loaded.digits_only != true) return false;
    if (loaded.min_length != TPM_PIN_MAX_PIN_LEN) return false;
    if (loaded.max_length != TPM_PIN_MAX_PIN_LEN) return false;

    /* Invalid negative/non-numeric DA config values must not wrap or zero out timers */
    cf = fopen(tmp_conf, "w");
    if (!cf) return false;
    fprintf(cf, "da_max_tries = -1\nda_recovery_time = abc\nda_lockout_recovery = -5\n");
    fclose(cf);

    bool ok_invalid = tpm_pin_config_load(tmp_conf, &loaded);
    unlink(tmp_conf);
    if (!ok_invalid) return false;
    if (loaded.da_max_tries != 5) return false;
    if (loaded.da_recovery_time != 600) return false;
    if (loaded.da_lockout_recovery != 86400) return false;

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
        tpm_pin_remove_user(test_uid, &cfg);
        return false;
    }

    /* Verify that copying sealed.blob to another UID fails due to UID AAD binding */
    uid_t other_uid = test_uid + 1;
    char src_blob[512], dst_dir[512], dst_blob[544];
    snprintf(src_blob, sizeof(src_blob), "%s/%u/sealed.blob", cfg.data_dir, (unsigned int)test_uid);
    snprintf(dst_dir, sizeof(dst_dir), "%s/%u", cfg.data_dir, (unsigned int)other_uid);
    snprintf(dst_blob, sizeof(dst_blob), "%s/sealed.blob", dst_dir);
    mkdir(dst_dir, 0755);
    FILE *sf = fopen(src_blob, "rb");
    FILE *df = fopen(dst_blob, "wb");
    if (sf && df) {
        uint8_t buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), sf)) > 0) {
            fwrite(buf, 1, n, df);
        }
    }
    if (sf) fclose(sf);
    if (df) fclose(df);
    chmod(dst_blob, 0600);

    bool cross_uid_ok = tpm_pin_verify_user(other_uid, test_pin, &cfg, unsealed, sizeof(unsealed), &tpm_rc);
    tpm_pin_remove_user(other_uid, &cfg);
    if (cross_uid_ok) {
        tpm_pin_remove_user(test_uid, &cfg);
        return false;
    }

    /* Cleanup */
    tpm_pin_remove_user(test_uid, &cfg);
    rmdir(cfg.data_dir);
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
        tpm_sealed_header_t orig_hdr;
        bool have_hdr = (fread(&orig_hdr, sizeof(orig_hdr), 1, bf) == 1);
        if (have_hdr) {
            tpm_sealed_header_t hdr = orig_hdr;
            hdr.flags &= ~FLAG_PCR7_BOUND;
            fseek(bf, 0, SEEK_SET);
            fwrite(&hdr, sizeof(hdr), 1, bf);
        }
        fclose(bf);
        if (tpm_pin_verify_user(test_uid, test_pin, &cfg, unsealed, sizeof(unsealed), &tpm_rc)) {
            tpm_pin_remove_user(test_uid, &cfg);
            return false;
        }
        if (have_hdr) {
            bf = fopen(blob_path, "r+b");
            if (bf) {
                fwrite(&orig_hdr, sizeof(orig_hdr), 1, bf);
                fclose(bf);
            }
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

    /* Verify RC helper behavior across Format-1 / Format-0 return codes */
    if (!tpm_pin_rc_is_lockout(0x921) || !tpm_pin_rc_is_policy_fail(0x99d) || !tpm_pin_rc_is_policy_fail(0x9d)) {
        tpm_pin_remove_user(test_uid, &cfg);
        return false;
    }

#if defined(__has_include) && __has_include(<tss2/tss2_common.h>)
    /* When running against swtpm/mssim, extend PCR 7 and verify policy fail RC detection */
    if (tcti_env && (strncmp(tcti_env, "swtpm", 5) == 0 || strncmp(tcti_env, "mssim", 5) == 0)) {
        ESYS_CONTEXT *pcr_ctx = NULL;
        if (tpm_engine_init(cfg.tcti_name, &pcr_ctx) != TSS2_RC_SUCCESS || !pcr_ctx) {
            tpm_pin_remove_user(test_uid, &cfg);
            return false;
        }
        TPML_DIGEST_VALUES pcr_vals;
        memset(&pcr_vals, 0, sizeof(pcr_vals));
        pcr_vals.count = 1;
        pcr_vals.digests[0].hashAlg = TPM2_ALG_SHA256;
        pcr_vals.digests[0].digest.sha256[0] = 0xAA;
        TSS2_RC ext_rc = Esys_PCR_Extend(pcr_ctx, 7, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &pcr_vals);
        tpm_engine_destroy(&pcr_ctx);
        if (ext_rc != TSS2_RC_SUCCESS) {
            tpm_pin_remove_user(test_uid, &cfg);
            return false;
        }
        int pcr_rc = 0;
        if (tpm_pin_verify_user(test_uid, test_pin, &cfg, unsealed, sizeof(unsealed), &pcr_rc)) {
            tpm_pin_remove_user(test_uid, &cfg);
            return false;
        }
        if (!tpm_pin_rc_is_policy_fail((uint32_t)pcr_rc)) {
            tpm_pin_remove_user(test_uid, &cfg);
            return false;
        }
    }
#endif

    tpm_pin_remove_user(test_uid, &cfg);
    return true;
}

static bool test_pam_module_dlopen(void) {
    const char *paths[] = {
        "./pam_tpm_pin.so",
        "./build/pam_tpm_pin.so",
        "../build/pam_tpm_pin.so",
        "/usr/lib64/security/pam_tpm_pin.so",
        "/usr/lib/security/pam_tpm_pin.so",
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

static bool read_whole_file(const char *path, char *buf, size_t buf_sz) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(buf, 1, buf_sz - 1, f);
    buf[n] = '\0';
    fclose(f);
    return true;
}

static bool write_whole_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) return false;
    size_t len = strlen(content);
    bool ok = (fwrite(content, 1, len, f) == len);
    fclose(f);
    return ok;
}

static bool test_arch_distro_and_pam_stack(void) {
    char osrel_path[256];
    char sysauth_path[256];
    char local_login_path[256];
    int pid = (int)getpid();

    snprintf(osrel_path, sizeof(osrel_path), "/tmp/test_os_release_%d", pid);
    snprintf(sysauth_path, sizeof(sysauth_path), "/tmp/test_system_auth_%d", pid);
    snprintf(local_login_path, sizeof(local_login_path), "/tmp/test_system_local_login_%d", pid);

    const char *arch_osrel =
        "NAME=\"Arch Linux\"\n"
        "PRETTY_NAME=\"Arch Linux\"\n"
        "ID=customarch\n"
        "ID_LIKE=arch\n"
        "BUILD_ID=rolling\n";
    if (!write_whole_file(osrel_path, arch_osrel)) return false;

    linux_distro_t d = pam_manager_detect_distro_from_file(osrel_path);
    unlink(osrel_path);
    if (d != DISTRO_ARCH) return false;
    if (strcmp(pam_manager_distro_name(d), "Arch Linux") != 0) return false;

    /* Standard Arch pambase system-auth layout, plus a comment trap mentioning pam_unix.so */
    const char *arch_system_auth =
        "#%PAM-1.0\n"
        "# Note: fallback to pam_unix.so happens below\n"
        "\n"
        "auth       required                    pam_faillock.so      preauth\n"
        "-auth      [success=2 default=ignore]  pam_systemd_home.so\n"
        "auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok\n"
        "auth       [default=die]               pam_faillock.so      authfail\n"
        "auth       optional                    pam_permit.so\n"
        "auth       required                    pam_env.so\n"
        "auth        requisite                   pam_faillock.so      authsucc\n"
        "\n"
        "account    required                    pam_unix.so\n"
        "password   required                    pam_unix.so          try_first_pass nullok sha512 shadow\n"
        "session    required                    pam_unix.so\n";

    if (!write_whole_file(sysauth_path, arch_system_auth)) return false;

    if (!pam_manager_apply_auth_file(sysauth_path)) {
        unlink(sysauth_path);
        return false;
    }

    /* Idempotency check */
    if (!pam_manager_apply_auth_file(sysauth_path)) {
        unlink(sysauth_path);
        return false;
    }

    char updated[4096];
    if (!read_whole_file(sysauth_path, updated, sizeof(updated))) {
        unlink(sysauth_path);
        return false;
    }

    /* Must use success=3 and sit strictly BEFORE pam_systemd_home.so (so success=2 jump stays intact) */
    const char *pin_pos = strstr(updated, "auth\t[success=3 authinfo_unavail=ignore open_err=ignore default=ignore]\tpam_tpm_pin.so");
    const char *home_pos = strstr(updated, "-auth      [success=2 default=ignore]  pam_systemd_home.so");
    const char *comment_pos = strstr(updated, "# Note: fallback to pam_unix.so happens below");
    if (!pin_pos || !home_pos || !comment_pos || !(comment_pos < pin_pos && pin_pos < home_pos)) {
        unlink(sysauth_path);
        return false;
    }

    /* Clean removal must restore exact original content */
    if (!pam_manager_remove_from_file(sysauth_path)) {
        unlink(sysauth_path);
        return false;
    }
    if (!read_whole_file(sysauth_path, updated, sizeof(updated)) ||
        strcmp(updated, arch_system_auth) != 0) {
        unlink(sysauth_path);
        return false;
    }
    unlink(sysauth_path);

    /* Test Arch system-local-login keyring auto-unlock block (via symlink to verify symlink preservation) */
    const char *arch_local_login =
        "#%PAM-1.0\n"
        "\n"
        "auth      include   system-login\n"
        "account   include   system-login\n"
        "password  include   system-login\n"
        "session   include   system-login\n";

    char local_login_link[256];
    snprintf(local_login_link, sizeof(local_login_link), "/tmp/test_system_local_login_link_%d", pid);
    unlink(local_login_link);

    if (!write_whole_file(local_login_path, arch_local_login)) return false;
    if (symlink(local_login_path, local_login_link) != 0) {
        unlink(local_login_path);
        return false;
    }

    if (!pam_manager_configure_arch_keyring_file(local_login_link, true) ||
        !pam_manager_configure_arch_keyring_file(local_login_link, true)) {
        unlink(local_login_link);
        unlink(local_login_path);
        return false;
    }

    struct stat lkst;
    if (lstat(local_login_link, &lkst) != 0 || !S_ISLNK(lkst.st_mode)) {
        unlink(local_login_link);
        unlink(local_login_path);
        return false;
    }

    if (!read_whole_file(local_login_path, updated, sizeof(updated)) ||
        !strstr(updated, "-auth      optional   pam_gnome_keyring.so") ||
        !strstr(updated, "-session   optional   pam_gnome_keyring.so auto_start") ||
        !strstr(updated, "-session   optional   pam_kwallet5.so auto_start")) {
        unlink(local_login_link);
        unlink(local_login_path);
        return false;
    }

    if (!pam_manager_configure_arch_keyring_file(local_login_link, false) ||
        !read_whole_file(local_login_path, updated, sizeof(updated)) ||
        strcmp(updated, arch_local_login) != 0) {
        unlink(local_login_link);
        unlink(local_login_path);
        return false;
    }

    if (lstat(local_login_link, &lkst) != 0 || !S_ISLNK(lkst.st_mode)) {
        unlink(local_login_link);
        unlink(local_login_path);
        return false;
    }

    unlink(local_login_link);
    unlink(local_login_path);

    /* Verify sufficient pam_unix.so + required pam_deny.so emits success=done */
    const char *sufficient_unix_auth =
        "#%PAM-1.0\n"
        "auth       required     pam_env.so\n"
        "auth       sufficient   pam_unix.so\n"
        "auth       required     pam_deny.so\n";
    if (!write_whole_file(sysauth_path, sufficient_unix_auth)) return false;
    if (!pam_manager_apply_auth_file(sysauth_path) ||
        !read_whole_file(sysauth_path, updated, sizeof(updated)) ||
        !strstr(updated, "auth\t[success=done authinfo_unavail=ignore open_err=ignore default=ignore]\tpam_tpm_pin.so")) {
        unlink(sysauth_path);
        return false;
    }
    unlink(sysauth_path);

    return true;
}

static bool test_fedora_bazzite_distro_and_pam_stack(void) {
    char osrel_path[256];
    char sysauth_path[256];
    char link_path[256];
    int pid = (int)getpid();

    snprintf(osrel_path, sizeof(osrel_path), "/tmp/test_os_release_bazzite_%d", pid);
    snprintf(sysauth_path, sizeof(sysauth_path), "/tmp/test_system_auth_fedora_%d", pid);
    snprintf(link_path, sizeof(link_path), "/tmp/test_link_fedora_%d", pid);

    const char *bazzite_osrel =
        "NAME=\"Bazzite\"\n"
        "VERSION=\"44.20261012.0 (Silverblue)\"\n"
        "ID=bazzite\n"
        "ID_LIKE=\"fedora\"\n"
        "VARIANT=\"Silverblue\"\n"
        "VARIANT_ID=bazzite-gnome\n";
    if (!write_whole_file(osrel_path, bazzite_osrel)) return false;

    linux_distro_t d = pam_manager_detect_distro_from_file(osrel_path);
    unlink(osrel_path);
    if (d != DISTRO_FEDORA_RHEL) return false;
    if (strcmp(pam_manager_distro_name(d), "Fedora/RHEL") != 0) return false;

    const char *fedora_system_auth =
        "# Generated by authselect\n"
        "auth        required                                     pam_env.so\n"
        "auth        required                                     pam_faildelay.so delay=2000000\n"
        "auth        sufficient                                   pam_fprintd.so\n"
        "auth        sufficient                                   pam_unix.so nullok\n"
        "auth        required                                     pam_deny.so\n"
        "\n"
        "account     required                                     pam_unix.so\n"
        "password    required                                     pam_deny.so\n"
        "session     required                                     pam_unix.so\n";

    if (!write_whole_file(sysauth_path, fedora_system_auth)) return false;

    unlink(link_path);
    if (symlink(sysauth_path, link_path) != 0) {
        unlink(sysauth_path);
        return false;
    }

    /* Apply twice to verify idempotency */
    if (!pam_manager_apply_fedora_file(link_path) ||
        !pam_manager_apply_fedora_file(link_path)) {
        unlink(link_path);
        unlink(sysauth_path);
        return false;
    }

    struct stat st;
    if (lstat(link_path, &st) != 0 || !S_ISLNK(st.st_mode)) {
        unlink(link_path);
        unlink(sysauth_path);
        return false;
    }

    char updated[4096];
    if (!read_whole_file(sysauth_path, updated, sizeof(updated))) {
        unlink(link_path);
        unlink(sysauth_path);
        return false;
    }

    const char *pin_pos = strstr(updated, "auth\t[success=done authinfo_unavail=ignore open_err=ignore default=ignore]\tpam_tpm_pin.so");
    const char *fprint_pos = strstr(updated, "auth        sufficient                                   pam_fprintd.so");
    if (!pin_pos || !fprint_pos || !(pin_pos < fprint_pos)) {
        unlink(link_path);
        unlink(sysauth_path);
        return false;
    }

    /* Verify rule count is exactly 1 (idempotency check) */
    const char *first_module = strstr(updated, "pam_tpm_pin.so");
    if (!first_module) {
        unlink(link_path);
        unlink(sysauth_path);
        return false;
    }
    const char *second_pos = strstr(first_module + strlen("pam_tpm_pin.so"), "pam_tpm_pin.so");
    if (second_pos) {
        unlink(link_path);
        unlink(sysauth_path);
        return false;
    }

    if (!pam_manager_remove_from_file(link_path)) {
        unlink(link_path);
        unlink(sysauth_path);
        return false;
    }

    if (lstat(link_path, &st) != 0 || !S_ISLNK(st.st_mode)) {
        unlink(link_path);
        unlink(sysauth_path);
        return false;
    }

    if (!read_whole_file(sysauth_path, updated, sizeof(updated)) ||
        strcmp(updated, fedora_system_auth) != 0) {
        unlink(link_path);
        unlink(sysauth_path);
        return false;
    }

    unlink(link_path);
    unlink(sysauth_path);

    /* Test password-auth layout where pam_systemd_home.so is after pam_unix.so */
    const char *fedora_pw_auth =
        "# Generated by authselect\n"
        "auth        required                                     pam_env.so\n"
        "auth        required                                     pam_faildelay.so delay=2000000\n"
        "auth        sufficient                                   pam_u2f.so cue\n"
        "auth        sufficient                                   pam_unix.so nullok\n"
        "auth        sufficient                                   pam_systemd_home.so\n"
        "auth        required                                     pam_deny.so\n";

    if (!write_whole_file(sysauth_path, fedora_pw_auth)) return false;

    if (!pam_manager_apply_fedora_file(sysauth_path) ||
        !pam_manager_apply_fedora_file(sysauth_path)) {
        unlink(sysauth_path);
        return false;
    }

    if (!read_whole_file(sysauth_path, updated, sizeof(updated))) {
        unlink(sysauth_path);
        return false;
    }

    pin_pos = strstr(updated, "auth\t[success=done authinfo_unavail=ignore open_err=ignore default=ignore]\tpam_tpm_pin.so");
    const char *u2f_pos = strstr(updated, "auth        sufficient                                   pam_u2f.so cue");
    const char *unix_pos = strstr(updated, "auth        sufficient                                   pam_unix.so nullok");
    if (!pin_pos || !u2f_pos || !(pin_pos < u2f_pos && u2f_pos < unix_pos)) {
        unlink(sysauth_path);
        return false;
    }

    if (!pam_manager_remove_from_file(sysauth_path) ||
        !read_whole_file(sysauth_path, updated, sizeof(updated)) ||
        strcmp(updated, fedora_pw_auth) != 0) {
        unlink(sysauth_path);
        return false;
    }

    unlink(sysauth_path);
    return true;
}

static bool test_pam_service_allowlist(void) {
    tpm_pin_config_t cfg;
    tpm_pin_config_defaults(&cfg);

    /* Remote / background / autologin services must NEVER be allowed */
    if (tpm_pin_is_service_enabled("sshd", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("dropbear", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("rlogin", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("klogin", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("eklogin", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("krlogin", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("telnet", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("system-remote-login", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("sddm-autologin", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("gdm-autologin", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("cockpit", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("crond", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("xrdp-sesman", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("tightvnc", false, &cfg)) return false;

    /* Display managers (greetd, SDDM, GDM, ly) follow enable_login */
    cfg.enable_login = true;
    cfg.enable_lockscreen = false;
    if (!tpm_pin_is_service_enabled("greetd", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("sddm", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("lightdm", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("gdm-password", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("ly", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("login", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("cosmic-greeter", false, &cfg)) return false;

    /* Unprivileged cosmic-greeter lock screen uses PAM service "login" or "cosmic-greeter" with euid != 0 -> enable_lockscreen */
    if (tpm_pin_is_service_enabled("login", true, &cfg)) return false;
    if (tpm_pin_is_service_enabled("cosmic-greeter", true, &cfg)) return false;
    if (tpm_pin_is_service_enabled("kde", true, &cfg)) return false;
    if (tpm_pin_is_service_enabled("hyprlock", true, &cfg)) return false;
    if (tpm_pin_is_service_enabled("swaylock", true, &cfg)) return false;
    if (tpm_pin_is_service_enabled("xfce4-screensaver", true, &cfg)) return false;

    cfg.enable_login = false;
    cfg.enable_lockscreen = true;
    if (tpm_pin_is_service_enabled("greetd", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("login", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("cosmic-greeter", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("login", true, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("cosmic-greeter", true, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("kde", true, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("hyprlock", true, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("swaylock", true, &cfg)) return false;

    /* Sudo / doas / su-l follow enable_sudo; Polkit / pkexec follow enable_polkit */
    cfg.enable_sudo = true;
    cfg.enable_polkit = false;
    if (!tpm_pin_is_service_enabled("sudo", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("sudo", true, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("doas", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("su-l", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("polkit-1", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("polkit", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("pkexec", false, &cfg)) return false;

    cfg.enable_sudo = false;
    cfg.enable_polkit = true;
    if (tpm_pin_is_service_enabled("sudo", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("doas", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("polkit-1", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("polkit-1", true, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("polkit", false, &cfg)) return false;
    if (!tpm_pin_is_service_enabled("pkexec", false, &cfg)) return false;

    cfg.enable_polkit = false;
    if (tpm_pin_is_service_enabled("polkit-1", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("polkit", false, &cfg)) return false;
    if (tpm_pin_is_service_enabled("pkexec", false, &cfg)) return false;

    return true;
}

static bool test_shadow_password_verification(void) {
    /* Locked, disabled, placeholder, or invalid shadow hashes must return -1 */
    if (tpm_pin_verify_shadow_hash("pass", "!") != -1) return false;
    if (tpm_pin_verify_shadow_hash("pass", "!!") != -1) return false;
    if (tpm_pin_verify_shadow_hash("pass", "*") != -1) return false;
    if (tpm_pin_verify_shadow_hash("pass", "x") != -1) return false;
    if (tpm_pin_verify_shadow_hash("pass", "") != -1) return false;
    if (tpm_pin_verify_shadow_hash("pass", "short") != -1) return false;

#ifdef HAVE_LIBCRYPT
    struct crypt_data *cdata = (struct crypt_data *)calloc(1, sizeof(struct crypt_data));
    if (!cdata) return false;
    const char *computed = crypt_r("MySecretPass99!", "$6$testsalt1234567$", cdata);
    if (!computed || computed[0] == '*') {
        tpm_pin_zero(cdata, sizeof(*cdata));
        free(cdata);
        return false;
    }
    char hash_copy[256];
    snprintf(hash_copy, sizeof(hash_copy), "%s", computed);
    tpm_pin_zero(cdata, sizeof(*cdata));
    free(cdata);

    if (tpm_pin_verify_shadow_hash("MySecretPass99!", hash_copy) != 1) return false;
    if (tpm_pin_verify_shadow_hash("WrongPassword!", hash_copy) != 0) return false;
#endif
    return true;
}

static bool test_tpm_change_pin_and_list(void) {
    tpm_pin_config_t cfg;
    tpm_pin_config_defaults(&cfg);

    const char *tcti_env = getenv("TCTI");
    if (tcti_env) {
        snprintf(cfg.tcti_name, sizeof(cfg.tcti_name), "%s", tcti_env);
    }
    snprintf(cfg.data_dir, sizeof(cfg.data_dir), "/tmp/test_tpm_change_%d", (int)getpid());

    uid_t uid1 = 9991;
    uid_t uid2 = 9992;
    tpm_pin_remove_user(uid1, &cfg);
    tpm_pin_remove_user(uid2, &cfg);

    /* Enroll uid2 first (out of order) to also verify sorted listing */
    cfg.bind_pcr7 = true;
    bool ok2 = tpm_pin_enroll_user(uid2, "593714", NULL, &cfg);
    if (!ok2) {
        if (tcti_env || access("/dev/tpmrm0", R_OK | W_OK) == 0) {
            return false;
        }
        return true; /* Skip gracefully only if no TPM is accessible */
    }

    cfg.bind_pcr7 = false;
    if (!tpm_pin_enroll_user(uid1, "849201", "PwdOne!", &cfg)) {
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }

    uid_t listed[16] = {0};
    size_t n = tpm_pin_list_enrolled_users(&cfg, listed, 16);
    if (n != 2 || listed[0] != uid1 || listed[1] != uid2) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }

    bool pcr7 = true, keyring = false;
    if (!tpm_pin_get_user_enrollment_flags(uid1, &cfg, &pcr7, &keyring) || pcr7 || !keyring) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }
    if (!tpm_pin_get_user_enrollment_flags(uid2, &cfg, &pcr7, &keyring) || !pcr7 || keyring) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }

    /* Wrong old PIN must fail while leaving original PIN intact */
    int tpm_rc = 0;
    if (tpm_pin_change_pin(uid1, "000000", "472910", NULL, &cfg, &tpm_rc)) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }

    /* Weak new PIN must be rejected by policy before touching TPM */
    if (tpm_pin_change_pin(uid1, "849201", "123456", NULL, &cfg, &tpm_rc)) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }

    /* Rotate PIN with updated PCR 7 binding and carry over keyring password */
    cfg.bind_pcr7 = true;
    if (!tpm_pin_change_pin(uid1, "849201", "472910", NULL, &cfg, &tpm_rc)) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }

    char unsealed[TPM_PIN_MAX_PASSWORD_LEN] = {0};
    if (tpm_pin_verify_user(uid1, "849201", &cfg, unsealed, sizeof(unsealed), &tpm_rc)) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }
    if (!tpm_pin_verify_user(uid1, "472910", &cfg, unsealed, sizeof(unsealed), &tpm_rc) ||
        strcmp(unsealed, "PwdOne!") != 0) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }

    if (!tpm_pin_get_user_enrollment_flags(uid1, &cfg, &pcr7, &keyring) || !pcr7 || !keyring) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }

    /* Tighten policy after enrolling a 4-digit PIN and verify rotation to 6-digit PIN works */
    if (!tpm_pin_change_pin(uid1, "472910", "4829", NULL, &cfg, &tpm_rc)) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }
    cfg.min_length = 6;
    if (tpm_pin_change_pin(uid1, "4829", "5913", NULL, &cfg, &tpm_rc)) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }
    if (!tpm_pin_change_pin(uid1, "4829", "739150", NULL, &cfg, &tpm_rc)) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }
    if (!tpm_pin_verify_user(uid1, "739150", &cfg, unsealed, sizeof(unsealed), &tpm_rc) ||
        strcmp(unsealed, "PwdOne!") != 0) {
        tpm_pin_remove_user(uid1, &cfg);
        tpm_pin_remove_user(uid2, &cfg);
        rmdir(cfg.data_dir);
        return false;
    }

    ESYS_CONTEXT *esys = NULL;
    if (tpm_engine_init(cfg.tcti_name, &esys) == TSS2_RC_SUCCESS && esys) {
        (void)tpm_engine_reset_da_lockout(esys);
        tpm_engine_destroy(&esys);
    }

    tpm_pin_remove_user(uid1, &cfg);
    tpm_pin_remove_user(uid2, &cfg);
    rmdir(cfg.data_dir);
    return true;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    printf("=== Secure PIN for Linux — PAM & TPM Test Suite ===\n");

    RUN_TEST("PAM Module Dynamic Linking (dlopen)", test_pam_module_dlopen);
    RUN_TEST("PIN Policy Validation", test_policy_validation);
    RUN_TEST("Arch PAM Stack & Keyring Management", test_arch_distro_and_pam_stack);
    RUN_TEST("Fedora/Bazzite PAM Stack & Symlink Preservation", test_fedora_bazzite_distro_and_pam_stack);
    RUN_TEST("Desktop & PAM Service Allowlist", test_pam_service_allowlist);
    RUN_TEST("AES-256-GCM + PBKDF2 Crypto Roundtrip", test_crypto_roundtrip);
    RUN_TEST("Configuration Serialization", test_config_serialization);
    RUN_TEST("Shadow Password Hash Verification", test_shadow_password_verification);
    RUN_TEST("TPM 2.0 User Enrollment & Unsealing", test_tpm_enroll_and_verify);
    RUN_TEST("TPM 2.0 PIN Rotation & Enrolled User Listing", test_tpm_change_pin_and_list);
    RUN_TEST("TPM 2.0 PCR 7 Binding & Authentication", test_tpm_enroll_and_verify_pcr7);

    printf("\nTest Summary: %d / %d tests passed.\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
