#ifndef TSS2_ESYS_H
#define TSS2_ESYS_H

#include <tss2/tss2_types.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_tcti.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ESYS_CONTEXT ESYS_CONTEXT;
typedef uint32_t ESYS_TR;

#define ESYS_TR_NONE                    ((ESYS_TR)0xFFFU)
#define ESYS_TR_PASSWORD                ((ESYS_TR)0x0FFU)
#define ESYS_TR_RH_OWNER                ((ESYS_TR)0x101U)
#define ESYS_TR_RH_NULL                 ((ESYS_TR)0x107U)
#define ESYS_TR_RH_LOCKOUT              ((ESYS_TR)0x10AU)
#define ESYS_TR_RH_ENDORSEMENT          ((ESYS_TR)0x10BU)
#define ESYS_TR_RH_PLATFORM             ((ESYS_TR)0x10CU)

typedef struct {
    TPMI_ALG_SYM_OBJECT algorithm;
    union {
        UINT16 aes;
    } keyBits;
    TPMI_ALG_SYM_MODE mode;
} TPMT_SYM_DEF;

typedef struct {
    UINT16 size;
    struct {
        TPM2B_AUTH           userAuth;
        TPM2B_SENSITIVE_DATA data;
    } sensitive;
} TPM2B_SENSITIVE_CREATE;

typedef struct {
    uint32_t tssCreator;
    uint32_t tssFamily;
    uint32_t tssLevel;
    uint32_t tssVersion;
} TSS2_ABI_VERSION;

TSS2_RC Esys_Initialize(
    ESYS_CONTEXT **esys_context,
    TSS2_TCTI_CONTEXT *tcti,
    TSS2_ABI_VERSION *abiVersion);

void Esys_Finalize(
    ESYS_CONTEXT **esys_context);

TSS2_RC Esys_GetTctiContext(
    ESYS_CONTEXT *esys_context,
    TSS2_TCTI_CONTEXT **tcti);

TSS2_RC Esys_TR_Close(
    ESYS_CONTEXT *esys_context,
    ESYS_TR *rhandle);

TSS2_RC Esys_TR_SetAuth(
    ESYS_CONTEXT *esysContext,
    ESYS_TR handle,
    TPM2B_AUTH const *authValue);

TSS2_RC Esys_CreatePrimary(
    ESYS_CONTEXT *esysContext,
    ESYS_TR primaryHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_SENSITIVE_CREATE const *inSensitive,
    TPM2B_PUBLIC const *inPublic,
    TPM2B_DATA const *outsideInfo,
    TPML_PCR_SELECTION const *creationPCR,
    ESYS_TR *objectHandle,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPM2B_NAME **creationTicket);

TSS2_RC Esys_Create(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_SENSITIVE_CREATE const *inSensitive,
    TPM2B_PUBLIC const *inPublic,
    TPM2B_DATA const *outsideInfo,
    TPML_PCR_SELECTION const *creationPCR,
    TPM2B_PRIVATE **outPrivate,
    TPM2B_PUBLIC **outPublic,
    TPM2B_CREATION_DATA **creationData,
    TPM2B_DIGEST **creationHash,
    TPM2B_NAME **creationTicket);

TSS2_RC Esys_Load(
    ESYS_CONTEXT *esysContext,
    ESYS_TR parentHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_PRIVATE const *inPrivate,
    TPM2B_PUBLIC const *inPublic,
    ESYS_TR *objectHandle);

TSS2_RC Esys_Unseal(
    ESYS_CONTEXT *esysContext,
    ESYS_TR itemHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_SENSITIVE_DATA **outData);

TSS2_RC Esys_DictionaryAttackParameters(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    UINT32 newMaxTries,
    UINT32 newRecoveryTime,
    UINT32 lockoutRecovery);

TSS2_RC Esys_DictionaryAttackLockReset(
    ESYS_CONTEXT *esysContext,
    ESYS_TR lockHandle,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3);

TSS2_RC Esys_StartAuthSession(
    ESYS_CONTEXT *esysContext,
    ESYS_TR tpmKey,
    ESYS_TR bind,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_NONCE const *nonceCaller,
    TPM2_SE sessionType,
    TPMT_SYM_DEF const *symmetric,
    TPMI_ALG_HASH authHash,
    ESYS_TR *sessionHandle);

TSS2_RC Esys_PolicyPCR(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_DIGEST const *pcrDigest,
    TPML_PCR_SELECTION const *pcrs);

TSS2_RC Esys_PolicyGetDigest(
    ESYS_CONTEXT *esysContext,
    ESYS_TR policySession,
    ESYS_TR shandle1,
    ESYS_TR shandle2,
    ESYS_TR shandle3,
    TPM2B_DIGEST **policyDigest);

TSS2_RC Esys_FlushContext(
    ESYS_CONTEXT *esysContext,
    ESYS_TR flushHandle);

void Esys_Free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* TSS2_ESYS_H */
