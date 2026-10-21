#ifndef TSS2_TYPES_H
#define TSS2_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t TSS2_RC;

#define TSS2_RC_SUCCESS                  ((TSS2_RC)0)
#define TSS2_BASE_RC_AUTH_FAIL          ((TSS2_RC)0x000E)
#define TSS2_BASE_RC_LOCKOUT            ((TSS2_RC)0x0021)

#define TSS2_RC_LEVEL_SHIFT             16
#define TSS2_RC_LAYER_MASK              (0xFF << TSS2_RC_LEVEL_SHIFT)

#define TSS2_TPM_RC_LAYER               (0 << TSS2_RC_LEVEL_SHIFT)
#define TSS2_ESYS_RC_LAYER              (7 << TSS2_RC_LEVEL_SHIFT)
#define TSS2_TCTI_RC_LAYER              (10 << TSS2_RC_LEVEL_SHIFT)

#ifdef __cplusplus
}
#endif

#endif /* TSS2_TYPES_H */
