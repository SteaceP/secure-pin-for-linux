#ifndef TSS2_TPM2_TYPES_H
#define TSS2_TPM2_TYPES_H

#include <tss2/tss2_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t   BYTE;
typedef uint8_t   TPMI_YES_NO;
typedef uint16_t  UINT16;
typedef uint32_t  UINT32;
typedef int32_t   INT32;
typedef uint32_t  TPM2_HANDLE;
typedef TPM2_HANDLE TPMI_DH_OBJECT;
typedef TPM2_HANDLE TPMI_RH_PROVISION;
typedef TPM2_HANDLE TPMI_RH_LOCKOUT;
typedef uint16_t  TPM2_ALG_ID;
typedef TPM2_ALG_ID TPMI_ALG_HASH;
typedef TPM2_ALG_ID TPMI_ALG_PUBLIC;
typedef TPM2_ALG_ID TPMI_ALG_KEYEDHASH_SCHEME;
typedef TPM2_ALG_ID TPMI_ALG_SYM_OBJECT;
typedef TPM2_ALG_ID TPMI_ALG_SYM_MODE;
typedef TPM2_ALG_ID TPMI_ALG_KDF;
typedef TPM2_ALG_ID TPMI_ALG_SIG_SCHEME;
typedef TPM2_ALG_ID TPMI_ALG_RSA_SCHEME;
typedef TPM2_ALG_ID TPMI_ALG_RSA_DECRYPT;
typedef TPM2_ALG_ID TPMI_ECC_CURVE;
typedef uint32_t  TPMA_OBJECT;
typedef uint32_t  TPMA_SESSION;
typedef uint8_t   TPM2_SE;

#define TPM2_MAX_DIGEST_SIZE            64
#define TPM2_SHA256_DIGEST_SIZE         32
#define TPM2_MAX_SYM_KEY_BYTES          32
#define TPM2_MAX_SYM_BLOCK_SIZE         16
#define TPM2_MAX_CAP_DATA               1024
#define TPM2_NUM_PCR_BANKS              16
#define TPM2_PCR_SELECT_MIN             3
#define TPM2_PCR_SELECT_MAX             4

/* TPM2 Constants */
#define TPM2_RH_OWNER                   0x40000001
#define TPM2_RH_NULL                    0x40000007
#define TPM2_RH_LOCKOUT                 0x4000000A
#define TPM2_RH_ENDORSEMENT             0x4000000B
#define TPM2_RH_PLATFORM                0x4000000C

#define TPM2_RS_PW                      0x40000009

/* Algorithms */
#define TPM2_ALG_ERROR                  0x0000
#define TPM2_ALG_RSA                    0x0001
#define TPM2_ALG_SHA256                 0x000B
#define TPM2_ALG_SHA384                 0x000C
#define TPM2_ALG_SHA512                 0x000D
#define TPM2_ALG_NULL                   0x0010
#define TPM2_ALG_KEYEDHASH              0x0008
#define TPM2_ALG_AES                    0x0006
#define TPM2_ALG_CFB                    0x0043
#define TPM2_ALG_ECC                    0x0023
#define TPM2_ALG_XOR                    0x000A

/* Object attributes */
#define TPMA_OBJECT_FIXEDTPM            ((TPMA_OBJECT)1 << 1)
#define TPMA_OBJECT_STCLEAR             ((TPMA_OBJECT)1 << 2)
#define TPMA_OBJECT_FIXEDPARENT         ((TPMA_OBJECT)1 << 4)
#define TPMA_OBJECT_SENSITIVEDATAORIGIN ((TPMA_OBJECT)1 << 5)
#define TPMA_OBJECT_USERWITHAUTH        ((TPMA_OBJECT)1 << 6)
#define TPMA_OBJECT_ADMINWITHPOLICY     ((TPMA_OBJECT)1 << 7)
#define TPMA_OBJECT_NODA                ((TPMA_OBJECT)1 << 10)
#define TPMA_OBJECT_RESTRICTED          ((TPMA_OBJECT)1 << 16)
#define TPMA_OBJECT_DECRYPT             ((TPMA_OBJECT)1 << 17)
#define TPMA_OBJECT_SIGN_ENCRYPT        ((TPMA_OBJECT)1 << 18)

/* Session types */
#define TPM2_SE_HMAC                    0x00
#define TPM2_SE_POLICY                  0x01
#define TPM2_SE_TRIAL                   0x02

/* Session attributes */
#define TPMA_SESSION_CONTINUESESSION    ((TPMA_SESSION)1 << 0)
#define TPMA_SESSION_AUDITEXCLUSIVE     ((TPMA_SESSION)1 << 1)
#define TPMA_SESSION_AUDITRESET         ((TPMA_SESSION)1 << 2)
#define TPMA_SESSION_DECRYPT            ((TPMA_SESSION)1 << 5)
#define TPMA_SESSION_ENCRYPT            ((TPMA_SESSION)1 << 6)
#define TPMA_SESSION_AUDIT              ((TPMA_SESSION)1 << 7)

/* Capabilities */
#define TPM2_CAP_TPM_PROPERTIES         ((UINT32)0x00000006)
#define TPM2_PT_MANUFACTURER            ((UINT32)0x00000105)
#define TPM2_PT_VENDOR_STRING_1         ((UINT32)0x00000106)
#define TPM2_PT_VENDOR_STRING_2         ((UINT32)0x00000107)
#define TPM2_PT_VENDOR_STRING_3         ((UINT32)0x00000108)
#define TPM2_PT_VENDOR_STRING_4         ((UINT32)0x00000109)
#define TPM2_PT_FIRMWARE_VERSION_1      ((UINT32)0x0000010B)
#define TPM2_PT_FIRMWARE_VERSION_2      ((UINT32)0x0000010C)

typedef struct {
    UINT32 property;
    UINT32 value;
} TPMS_TAGGED_PROPERTY;

typedef struct {
    UINT32 count;
    TPMS_TAGGED_PROPERTY tpmProperty[128];
} TPML_TAGGED_TPM_PROPERTY;

typedef struct {
    UINT32 capability;
    union {
        TPML_TAGGED_TPM_PROPERTY tpmProperties;
    } data;
} TPMS_CAPABILITY_DATA;

/* Return codes */
#define TPM2_RC_SUCCESS                 0x000
#define TPM2_RC_LOCKOUT                 0x921
#define TPM2_RC_AUTH_FAIL               0x98E
#define TPM2_RC_BAD_AUTH                0x922
#define TPM2_RC_POLICY_FAIL             0x99D

/* Generic buffer types */
typedef struct {
    UINT16 size;
    BYTE   buffer[TPM2_MAX_DIGEST_SIZE];
} TPM2B_DIGEST;

typedef struct {
    UINT16 size;
    BYTE   buffer[1024];
} TPM2B_DATA;

typedef TPM2B_DIGEST TPM2B_NONCE;
typedef TPM2B_DIGEST TPM2B_AUTH;

typedef struct {
    UINT16 size;
    BYTE   buffer[256];
} TPM2B_SENSITIVE_DATA;

typedef struct {
    UINT16 size;
    BYTE   buffer[2048];
} TPM2B_PRIVATE;

typedef struct {
    TPMI_ALG_HASH hashAlg;
    BYTE          sizeofSelect;
    BYTE          pcrSelect[TPM2_PCR_SELECT_MAX];
} TPMS_PCR_SELECTION;

typedef struct {
    UINT32             count;
    TPMS_PCR_SELECTION pcrSelections[TPM2_NUM_PCR_BANKS];
} TPML_PCR_SELECTION;

typedef struct {
    TPMI_ALG_KEYEDHASH_SCHEME scheme;
    union {
        struct {
            TPMI_ALG_HASH hashAlg;
        } hmac;
    } details;
} TPMT_KEYEDHASH_SCHEME;

typedef struct {
    TPMT_KEYEDHASH_SCHEME scheme;
} TPMS_KEYEDHASH_PARMS;

typedef struct {
    TPMI_ALG_SYM_OBJECT algorithm;
    union {
        UINT16 aes;
    } keyBits;
    TPMI_ALG_SYM_MODE mode;
} TPMT_SYM_DEF_OBJECT;

typedef struct {
    TPMI_ALG_RSA_SCHEME scheme;
    uint8_t             details[4];
} TPMT_RSA_SCHEME;

typedef struct {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_RSA_SCHEME     scheme;
    UINT16              keyBits;
    UINT32              exponent;
} TPMS_RSA_PARMS;

typedef struct {
    TPMI_ALG_SIG_SCHEME scheme;
    uint8_t             details[4];
} TPMT_ECC_SCHEME;

typedef struct {
    TPMI_ALG_KDF        scheme;
    uint8_t             details[4];
} TPMT_KDF_SCHEME;

typedef struct {
    TPMT_SYM_DEF_OBJECT symmetric;
    TPMT_ECC_SCHEME     scheme;
    TPMI_ECC_CURVE      curveID;
    TPMT_KDF_SCHEME     kdf;
} TPMS_ECC_PARMS;

typedef union {
    TPMS_KEYEDHASH_PARMS keyedHashDetail;
    TPMS_RSA_PARMS       rsaDetail;
    TPMS_ECC_PARMS       eccDetail;
    BYTE                 _pad[20];
} TPMU_PUBLIC_PARMS;

typedef struct {
    UINT16 size;
    BYTE   buffer[256];
} TPM2B_PUBLIC_KEY_RSA;

typedef struct {
    TPM2B_DIGEST x;
    TPM2B_DIGEST y;
} TPMS_ECC_POINT;

typedef union {
    TPM2B_DIGEST         keyedHash;
    TPM2B_PUBLIC_KEY_RSA rsa;
    TPMS_ECC_POINT       ecc;
} TPMU_PUBLIC_ID;

typedef struct {
    TPMI_ALG_PUBLIC   type;
    TPMI_ALG_HASH     nameAlg;
    TPMA_OBJECT       objectAttributes;
    TPM2B_DIGEST      authPolicy;
    TPMU_PUBLIC_PARMS parameters;
    TPMU_PUBLIC_ID    unique;
} TPMT_PUBLIC;

typedef struct {
    UINT16      size;
    TPMT_PUBLIC publicArea;
} TPM2B_PUBLIC;

typedef struct {
    TPM2B_AUTH           userAuth;
    TPM2B_SENSITIVE_DATA data;
} TPMT_SENSITIVE;

typedef struct {
    UINT16         size;
    TPMT_SENSITIVE sensitiveArea;
} TPM2B_SENSITIVE;

typedef struct {
    UINT16 size;
    BYTE   name[TPM2_MAX_DIGEST_SIZE + 2];
} TPM2B_NAME;

typedef struct {
    UINT16 size;
    BYTE   creationData[1024];
} TPM2B_CREATION_DATA;

typedef struct {
    UINT16 size;
    BYTE   buffer[1024];
} TPM2B_MAX_BUFFER;

#ifdef __cplusplus
}
#endif

#endif /* TSS2_TPM2_TYPES_H */
