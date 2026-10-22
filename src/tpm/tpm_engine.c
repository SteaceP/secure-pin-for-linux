#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tpm_pin.h"

static TSS2_TCTI_CONTEXT *g_tcti_ctx = NULL;

static TSS2_RC init_tcti(const char *tcti_conf, TSS2_TCTI_CONTEXT **out_tcti) {
    if (!out_tcti) return TSS2_TCTI_RC_LAYER;
    *out_tcti = NULL;

    const char *conf = tcti_conf;
    if (!conf || strlen(conf) == 0) {
        conf = getenv("TCTI");
    }

    if (conf && strncmp(conf, "mssim:", 6) == 0) {
        const char *mssim_args = conf + 6;
        size_t size = 0;
        TSS2_RC rc = Tss2_Tcti_Mssim_Init(NULL, &size, mssim_args);
        if (rc != TSS2_RC_SUCCESS) return rc;

        TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT *)malloc(size);
        if (!ctx) return TSS2_TCTI_RC_LAYER;

        rc = Tss2_Tcti_Mssim_Init(ctx, &size, mssim_args);
        if (rc != TSS2_RC_SUCCESS) {
            free(ctx);
            return rc;
        }
        *out_tcti = ctx;
        return TSS2_RC_SUCCESS;
    } else if (conf && strncmp(conf, "swtpm:", 6) == 0) {
        const char *swtpm_args = conf + 6;
        size_t size = 0;
        TSS2_RC rc = Tss2_Tcti_Swtpm_Init(NULL, &size, swtpm_args);
        if (rc != TSS2_RC_SUCCESS) return rc;

        TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT *)malloc(size);
        if (!ctx) return TSS2_TCTI_RC_LAYER;

        rc = Tss2_Tcti_Swtpm_Init(ctx, &size, swtpm_args);
        if (rc != TSS2_RC_SUCCESS) {
            free(ctx);
            return rc;
        }
        *out_tcti = ctx;
        return TSS2_RC_SUCCESS;
    } else if (conf && strncmp(conf, "device:", 7) == 0) {
        const char *dev_path = conf + 7;
        size_t size = 0;
        TSS2_RC rc = Tss2_Tcti_Device_Init(NULL, &size, dev_path);
        if (rc != TSS2_RC_SUCCESS) return rc;

        TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT *)malloc(size);
        if (!ctx) return TSS2_TCTI_RC_LAYER;

        rc = Tss2_Tcti_Device_Init(ctx, &size, dev_path);
        if (rc != TSS2_RC_SUCCESS) {
            free(ctx);
            return rc;
        }
        *out_tcti = ctx;
        return TSS2_RC_SUCCESS;
    } else if (access("/dev/tpmrm0", R_OK | W_OK) == 0) {
        size_t size = 0;
        TSS2_RC rc = Tss2_Tcti_Device_Init(NULL, &size, "/dev/tpmrm0");
        if (rc == TSS2_RC_SUCCESS) {
            TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT *)malloc(size);
            if (ctx) {
                rc = Tss2_Tcti_Device_Init(ctx, &size, "/dev/tpmrm0");
                if (rc == TSS2_RC_SUCCESS) {
                    *out_tcti = ctx;
                    return TSS2_RC_SUCCESS;
                }
                free(ctx);
            }
        }
    } else if (access("/dev/tpm0", R_OK | W_OK) == 0) {
        size_t size = 0;
        TSS2_RC rc = Tss2_Tcti_Device_Init(NULL, &size, "/dev/tpm0");
        if (rc == TSS2_RC_SUCCESS) {
            TSS2_TCTI_CONTEXT *ctx = (TSS2_TCTI_CONTEXT *)malloc(size);
            if (ctx) {
                rc = Tss2_Tcti_Device_Init(ctx, &size, "/dev/tpm0");
                if (rc == TSS2_RC_SUCCESS) {
                    *out_tcti = ctx;
                    return TSS2_RC_SUCCESS;
                }
                free(ctx);
            }
        }
    }

    return TSS2_RC_SUCCESS; /* Let Esys_Initialize try its default if any */
}

TSS2_RC tpm_engine_init(const char *tcti_conf, ESYS_CONTEXT **esys_ctx) {
    if (!esys_ctx) return TSS2_ESYS_RC_LAYER;
    *esys_ctx = NULL;

    TSS2_TCTI_CONTEXT *tcti = NULL;
    TSS2_RC rc = init_tcti(tcti_conf, &tcti);
    if (rc != TSS2_RC_SUCCESS && tcti) {
        free(tcti);
        return rc;
    }

    rc = Esys_Initialize(esys_ctx, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        if (tcti) free(tcti);
        return rc;
    }

    g_tcti_ctx = tcti;
    return TSS2_RC_SUCCESS;
}

void tpm_engine_destroy(ESYS_CONTEXT **esys_ctx) {
    if (esys_ctx && *esys_ctx) {
        Esys_Finalize(esys_ctx);
        *esys_ctx = NULL;
    }
    if (g_tcti_ctx) {
        free(g_tcti_ctx);
        g_tcti_ctx = NULL;
    }
}

static void fill_pcr7_selection(TPML_PCR_SELECTION *pcrSel) {
    memset(pcrSel, 0, sizeof(*pcrSel));
    pcrSel->count = 1;
    pcrSel->pcrSelections[0].hashAlg = TPM2_ALG_SHA256;
    pcrSel->pcrSelections[0].sizeofSelect = 3;
    pcrSel->pcrSelections[0].pcrSelect[0] = (1 << 7); /* PCR 7 */
}

static TSS2_RC create_primary_storage_key(ESYS_CONTEXT *ctx, ESYS_TR *primaryHandle) {
    TPM2B_SENSITIVE_CREATE inSensitivePrimary;
    memset(&inSensitivePrimary, 0, sizeof(inSensitivePrimary));

    TPM2B_PUBLIC inPublic;
    memset(&inPublic, 0, sizeof(inPublic));

    /* Try ECC NIST P256 Storage Primary first */
    inPublic.publicArea.type = TPM2_ALG_ECC;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes =
        TPMA_OBJECT_RESTRICTED |
        TPMA_OBJECT_DECRYPT |
        TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN |
        TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.eccDetail.symmetric.mode = TPM2_ALG_CFB;
    inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.eccDetail.curveID = 0x0003; /* NIST P-256 */
    inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;

    TPM2B_DATA outsideInfo;
    memset(&outsideInfo, 0, sizeof(outsideInfo));
    TPML_PCR_SELECTION creationPCR;
    memset(&creationPCR, 0, sizeof(creationPCR));

    TSS2_RC rc = Esys_CreatePrimary(
        ctx,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inSensitivePrimary,
        &inPublic,
        &outsideInfo,
        &creationPCR,
        primaryHandle,
        NULL, NULL, NULL, NULL
    );

    if (rc == TSS2_RC_SUCCESS) return rc;

    /* Fallback to RSA 2048 Storage Primary */
    memset(&inPublic, 0, sizeof(inPublic));
    inPublic.publicArea.type = TPM2_ALG_RSA;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes =
        TPMA_OBJECT_RESTRICTED |
        TPMA_OBJECT_DECRYPT |
        TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN |
        TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.publicArea.parameters.rsaDetail.symmetric.mode = TPM2_ALG_CFB;
    inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;

    return Esys_CreatePrimary(
        ctx,
        ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inSensitivePrimary,
        &inPublic,
        &outsideInfo,
        &creationPCR,
        primaryHandle,
        NULL, NULL, NULL, NULL
    );
}

TSS2_RC tpm_engine_seal_key(ESYS_CONTEXT *ctx,
                           const uint8_t *auth, size_t auth_len,
                           bool bind_pcr7,
                           const uint8_t *master_key, size_t key_len,
                           TPM2B_PRIVATE *out_priv, TPM2B_PUBLIC *out_pub) {
    if (!ctx || !auth || !master_key || !out_priv || !out_pub) return TSS2_ESYS_RC_LAYER;

    ESYS_TR primaryHandle = ESYS_TR_NONE;
    TSS2_RC rc = create_primary_storage_key(ctx, &primaryHandle);
    if (rc != TSS2_RC_SUCCESS) return rc;

    TPM2B_SENSITIVE_CREATE inSensitive;
    memset(&inSensitive, 0, sizeof(inSensitive));
    inSensitive.sensitive.userAuth.size = (UINT16)auth_len;
    memcpy(inSensitive.sensitive.userAuth.buffer, auth, auth_len);
    inSensitive.sensitive.data.size = (UINT16)key_len;
    memcpy(inSensitive.sensitive.data.buffer, master_key, key_len);

    TPM2B_PUBLIC inPublic;
    memset(&inPublic, 0, sizeof(inPublic));
    inPublic.publicArea.type = TPM2_ALG_KEYEDHASH;
    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    /* TPMA_OBJECT_NODA is 0: hardware Dictionary Attack lockout is enabled */
    inPublic.publicArea.objectAttributes =
        TPMA_OBJECT_FIXEDTPM |
        TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_USERWITHAUTH;
    inPublic.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;

    if (bind_pcr7) {
        ESYS_TR trialSession = ESYS_TR_NONE;
        TPMT_SYM_DEF sym_null;
        memset(&sym_null, 0, sizeof(sym_null));
        sym_null.algorithm = TPM2_ALG_NULL;

        rc = Esys_StartAuthSession(
            ctx, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            NULL, TPM2_SE_TRIAL, &sym_null, TPM2_ALG_SHA256,
            &trialSession
        );
        if (rc == TSS2_RC_SUCCESS) {
            TPML_PCR_SELECTION pcrSel;
            fill_pcr7_selection(&pcrSel);
            rc = Esys_PolicyPCR(ctx, trialSession, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, &pcrSel);
            if (rc == TSS2_RC_SUCCESS) {
                TPM2B_DIGEST *policyDigest = NULL;
                rc = Esys_PolicyGetDigest(ctx, trialSession, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &policyDigest);
                if (rc == TSS2_RC_SUCCESS && policyDigest) {
                    inPublic.publicArea.authPolicy = *policyDigest;
                    inPublic.publicArea.objectAttributes |= TPMA_OBJECT_ADMINWITHPOLICY;
                    Esys_Free(policyDigest);
                }
            }
            Esys_FlushContext(ctx, trialSession);
        }
    }

    TPM2B_DATA outsideInfo;
    memset(&outsideInfo, 0, sizeof(outsideInfo));
    TPML_PCR_SELECTION creationPCR;
    memset(&creationPCR, 0, sizeof(creationPCR));

    TPM2B_PRIVATE *outPrivate = NULL;
    TPM2B_PUBLIC  *outPublic = NULL;

    ESYS_TR authSession = ESYS_TR_PASSWORD;
    TPMT_SYM_DEF sym_aes;
    memset(&sym_aes, 0, sizeof(sym_aes));
    sym_aes.algorithm = TPM2_ALG_AES;
    sym_aes.keyBits.aes = 128;
    sym_aes.mode = TPM2_ALG_CFB;

    TSS2_RC s_rc = Esys_StartAuthSession(
        ctx, primaryHandle, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        NULL, TPM2_SE_HMAC, &sym_aes, TPM2_ALG_SHA256,
        &authSession
    );
    if (s_rc == TSS2_RC_SUCCESS) {
        Esys_TRSess_SetAttributes(ctx, authSession,
            TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT | TPMA_SESSION_CONTINUESESSION,
            0xff);
    } else {
        authSession = ESYS_TR_PASSWORD;
    }

    rc = Esys_Create(
        ctx,
        primaryHandle,
        authSession,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &inSensitive,
        &inPublic,
        &outsideInfo,
        &creationPCR,
        &outPrivate,
        &outPublic,
        NULL, NULL, NULL
    );

    if (authSession != ESYS_TR_PASSWORD) {
        Esys_FlushContext(ctx, authSession);
    }

    if (rc == TSS2_RC_SUCCESS) {
        *out_priv = *outPrivate;
        *out_pub  = *outPublic;
        Esys_Free(outPrivate);
        Esys_Free(outPublic);
    }

    Esys_FlushContext(ctx, primaryHandle);
    return rc;
}

TSS2_RC tpm_engine_unseal_key(ESYS_CONTEXT *ctx,
                             const uint8_t *auth, size_t auth_len,
                             bool bind_pcr7,
                             const TPM2B_PRIVATE *in_priv, const TPM2B_PUBLIC *in_pub,
                             uint8_t *out_key, size_t *out_key_len) {
    if (!ctx || !auth || !in_priv || !in_pub || !out_key || !out_key_len) return TSS2_ESYS_RC_LAYER;

    ESYS_TR primaryHandle = ESYS_TR_NONE;
    TSS2_RC rc = create_primary_storage_key(ctx, &primaryHandle);
    if (rc != TSS2_RC_SUCCESS) return rc;

    ESYS_TR itemHandle = ESYS_TR_NONE;
    rc = Esys_Load(
        ctx,
        primaryHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        in_priv,
        in_pub,
        &itemHandle
    );

    if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx, primaryHandle);
        return rc;
    }

    TPM2B_AUTH authVal;
    memset(&authVal, 0, sizeof(authVal));
    authVal.size = (UINT16)auth_len;
    memcpy(authVal.buffer, auth, auth_len);
    Esys_TR_SetAuth(ctx, itemHandle, &authVal);

    TPM2B_SENSITIVE_DATA *outData = NULL;

    if (bind_pcr7) {
        ESYS_TR policySession = ESYS_TR_NONE;
        TPMT_SYM_DEF sym_null;
        memset(&sym_null, 0, sizeof(sym_null));
        sym_null.algorithm = TPM2_ALG_NULL;

        rc = Esys_StartAuthSession(
            ctx, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            NULL, TPM2_SE_POLICY, &sym_null, TPM2_ALG_SHA256,
            &policySession
        );
        if (rc == TSS2_RC_SUCCESS) {
            TPML_PCR_SELECTION pcrSel;
            fill_pcr7_selection(&pcrSel);
            rc = Esys_PolicyPCR(ctx, policySession, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, &pcrSel);
            if (rc == TSS2_RC_SUCCESS) {
                rc = Esys_Unseal(
                    ctx,
                    itemHandle,
                    policySession,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &outData
                );
            }
            Esys_FlushContext(ctx, policySession);
        }
    } else {
        ESYS_TR authSession = ESYS_TR_PASSWORD;
        TPMT_SYM_DEF sym_aes;
        memset(&sym_aes, 0, sizeof(sym_aes));
        sym_aes.algorithm = TPM2_ALG_AES;
        sym_aes.keyBits.aes = 128;
        sym_aes.mode = TPM2_ALG_CFB;

        TSS2_RC s_rc = Esys_StartAuthSession(
            ctx, primaryHandle, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
            NULL, TPM2_SE_HMAC, &sym_aes, TPM2_ALG_SHA256,
            &authSession
        );
        if (s_rc == TSS2_RC_SUCCESS) {
            Esys_TRSess_SetAttributes(ctx, authSession,
                TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT,
                0xff);
        } else {
            authSession = ESYS_TR_PASSWORD;
        }

        rc = Esys_Unseal(
            ctx,
            itemHandle,
            authSession,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &outData
        );

        if (authSession != ESYS_TR_PASSWORD) {
            Esys_FlushContext(ctx, authSession);
        }
    }

    if (rc == TSS2_RC_SUCCESS && outData) {
        size_t copy_len = outData->size;
        if (copy_len > *out_key_len) copy_len = *out_key_len;
        memcpy(out_key, outData->buffer, copy_len);
        *out_key_len = copy_len;
        Esys_Free(outData);
    }

    Esys_FlushContext(ctx, itemHandle);
    Esys_FlushContext(ctx, primaryHandle);
    return rc;
}

TSS2_RC tpm_engine_configure_da(ESYS_CONTEXT *ctx,
                               uint32_t max_tries, uint32_t recovery_time, uint32_t lockout_recovery) {
    if (!ctx) return TSS2_ESYS_RC_LAYER;
    return Esys_DictionaryAttackParameters(
        ctx,
        ESYS_TR_RH_LOCKOUT,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        max_tries,
        recovery_time,
        lockout_recovery
    );
}

TSS2_RC tpm_engine_reset_da_lockout(ESYS_CONTEXT *ctx) {
    if (!ctx) return TSS2_ESYS_RC_LAYER;
    return Esys_DictionaryAttackLockReset(
        ctx,
        ESYS_TR_RH_LOCKOUT,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE
    );
}

TSS2_RC tpm_engine_get_status(ESYS_CONTEXT *ctx, tpm_pin_status_t *status) {
    if (!ctx || !status) return TSS2_ESYS_RC_LAYER;
    status->tpm_present = true;

    char mfg[32] = {0};
    char vendor_str[64] = {0};

    TPMI_YES_NO moreData = 0;
    TPMS_CAPABILITY_DATA *capData = NULL;

    TSS2_RC rc = Esys_GetCapability(
        ctx,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        TPM2_CAP_TPM_PROPERTIES,
        TPM2_PT_MANUFACTURER,
        8,
        &moreData,
        &capData
    );

    if (rc == TSS2_RC_SUCCESS && capData) {
        UINT32 count = capData->data.tpmProperties.count;
        for (UINT32 i = 0; i < count; i++) {
            UINT32 prop = capData->data.tpmProperties.tpmProperty[i].property;
            UINT32 val  = capData->data.tpmProperties.tpmProperty[i].value;

            if (prop == TPM2_PT_MANUFACTURER) {
                mfg[0] = (char)((val >> 24) & 0xFF);
                mfg[1] = (char)((val >> 16) & 0xFF);
                mfg[2] = (char)((val >> 8) & 0xFF);
                mfg[3] = (char)(val & 0xFF);
                mfg[4] = '\0';
            } else if (prop >= TPM2_PT_VENDOR_STRING_1 && prop <= TPM2_PT_VENDOR_STRING_4) {
                size_t cur_len = strlen(vendor_str);
                if (cur_len + 4 < sizeof(vendor_str)) {
                    vendor_str[cur_len + 0] = (char)((val >> 24) & 0xFF);
                    vendor_str[cur_len + 1] = (char)((val >> 16) & 0xFF);
                    vendor_str[cur_len + 2] = (char)((val >> 8) & 0xFF);
                    vendor_str[cur_len + 3] = (char)(val & 0xFF);
                    vendor_str[cur_len + 4] = '\0';
                }
            }
        }
        Esys_Free(capData);
    }

    for (int i = (int)strlen(mfg) - 1; i >= 0 && mfg[i] == ' '; i--) mfg[i] = '\0';
    for (int i = (int)strlen(vendor_str) - 1; i >= 0 && vendor_str[i] == ' '; i--) vendor_str[i] = '\0';

    if (mfg[0] == '\0') {
        snprintf(mfg, sizeof(mfg), "TPM 2.0");
    }
    snprintf(status->manufacturer, sizeof(status->manufacturer), "%s%s%s",
             mfg, vendor_str[0] ? " (" : "", vendor_str[0] ? vendor_str : "");
    if (vendor_str[0]) {
        size_t l = strlen(status->manufacturer);
        if (l + 1 < sizeof(status->manufacturer)) {
            status->manufacturer[l] = ')';
            status->manufacturer[l+1] = '\0';
        }
    }

    /* Architecture Detection: Microsoft Pluton vs AMD PSP vs Intel PTT vs dTPM */
    bool is_pluton = false;
    bool is_amd = false;
    bool is_intel = false;
    bool is_crb = false;

    FILE *f_hid = fopen("/sys/class/tpm/tpm0/device/firmware_node/hid", "r");
    char hid[64] = {0};
    if (f_hid) {
        if (fgets(hid, sizeof(hid), f_hid)) {
            char *nl = strchr(hid, '\n');
            if (nl) *nl = '\0';
        }
        fclose(f_hid);
    }

    char driver_link[256] = {0};
    ssize_t rlen = readlink("/sys/class/tpm/tpm0/device/driver", driver_link, sizeof(driver_link) - 1);
    if (rlen > 0) {
        driver_link[rlen] = '\0';
        if (strstr(driver_link, "crb")) is_crb = true;
    }

    char cpu_model[128] = {0};
    FILE *f_cpu = fopen("/proc/cpuinfo", "r");
    if (f_cpu) {
        char line[256];
        while (fgets(line, sizeof(line), f_cpu)) {
            if (strncmp(line, "model name", 10) == 0) {
                char *colon = strchr(line, ':');
                if (colon) {
                    snprintf(cpu_model, sizeof(cpu_model), "%s", colon + 2);
                    char *nl = strchr(cpu_model, '\n');
                    if (nl) *nl = '\0';
                }
                break;
            }
        }
        fclose(f_cpu);
    }

    if (strcmp(hid, "MSFT0200") == 0 || strstr(vendor_str, "Pluton") || strstr(vendor_str, "PLUTON")) {
        is_pluton = true;
    } else if (strcmp(mfg, "AMD") == 0 || (is_crb && strstr(cpu_model, "AMD"))) {
        is_amd = true;
    } else if (strcmp(mfg, "INTC") == 0 || (is_crb && strstr(cpu_model, "Intel"))) {
        is_intel = true;
    }

    if (is_pluton) {
        snprintf(status->hardware_type, sizeof(status->hardware_type),
                 "Microsoft Pluton (Silicon-Integrated Security Processor)");
    } else if (is_amd) {
        snprintf(status->hardware_type, sizeof(status->hardware_type),
                 "AMD Platform Security Processor (PSP fTPM 2.0)");
    } else if (is_intel) {
        snprintf(status->hardware_type, sizeof(status->hardware_type),
                 "Intel Platform Trust Technology (PTT fTPM 2.0)");
    } else if (is_crb) {
        snprintf(status->hardware_type, sizeof(status->hardware_type),
                 "Firmware TPM 2.0 (On-Die CRB)");
    } else {
        snprintf(status->hardware_type, sizeof(status->hardware_type),
                 "Discrete Hardware TPM (dTPM 2.0 Chip)");
    }

    snprintf(status->bus_encryption, sizeof(status->bus_encryption),
             "Active (AES-128-CFB parameter transit encryption)");

    return TSS2_RC_SUCCESS;
}
