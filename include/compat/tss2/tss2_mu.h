#ifndef TSS2_MU_H
#define TSS2_MU_H

#include <stddef.h>
#include <stdint.h>
#include <tss2/tss2_types.h>
#include <tss2/tss2_tpm2_types.h>

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC Tss2_MU_TPM2B_PRIVATE_Marshal(
    TPM2B_PRIVATE const *src,
    uint8_t              buffer[],
    size_t               buffer_size,
    size_t              *offset);

TSS2_RC Tss2_MU_TPM2B_PRIVATE_Unmarshal(
    uint8_t const  buffer[],
    size_t         buffer_size,
    size_t        *offset,
    TPM2B_PRIVATE *dest);

TSS2_RC Tss2_MU_TPM2B_PUBLIC_Marshal(
    TPM2B_PUBLIC const *src,
    uint8_t             buffer[],
    size_t              buffer_size,
    size_t             *offset);

TSS2_RC Tss2_MU_TPM2B_PUBLIC_Unmarshal(
    uint8_t const buffer[],
    size_t        buffer_size,
    size_t       *offset,
    TPM2B_PUBLIC *dest);

#ifdef __cplusplus
}
#endif

#endif /* TSS2_MU_H */
