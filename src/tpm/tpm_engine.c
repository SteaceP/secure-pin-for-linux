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

    rc = Esys_Create(
        ctx,
        primaryHandle,
        ESYS_TR_PASSWORD,
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
        rc = Esys_Unseal(
            ctx,
            itemHandle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &outData
        );
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
    snprintf(status->manufacturer, sizeof(status->manufacturer), "TPM 2.0 Device");
    return TSS2_RC_SUCCESS;
}
