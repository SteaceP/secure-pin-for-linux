#ifndef TSS2_TCTI_H
#define TSS2_TCTI_H

#include <tss2/tss2_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TSS2_TCTI_CONTEXT_COMMON_V1 TSS2_TCTI_CONTEXT_COMMON_V1;

typedef TSS2_RC (*TSS2_TCTI_TRANSMIT_FCN)(
    TSS2_TCTI_CONTEXT_COMMON_V1 *tctiContext,
    size_t size,
    const uint8_t *command_buffer);

typedef TSS2_RC (*TSS2_TCTI_RECEIVE_FCN)(
    TSS2_TCTI_CONTEXT_COMMON_V1 *tctiContext,
    size_t *size,
    uint8_t *response_buffer,
    int32_t timeout);

typedef void (*TSS2_TCTI_FINALIZE_FCN)(
    TSS2_TCTI_CONTEXT_COMMON_V1 *tctiContext);

typedef TSS2_RC (*TSS2_TCTI_CANCEL_FCN)(
    TSS2_TCTI_CONTEXT_COMMON_V1 *tctiContext);

typedef TSS2_RC (*TSS2_TCTI_GET_POLL_HANDLES_FCN)(
    TSS2_TCTI_CONTEXT_COMMON_V1 *tctiContext,
    void *handles,
    size_t *num_handles);

typedef TSS2_RC (*TSS2_TCTI_SET_LOCALITY_FCN)(
    TSS2_TCTI_CONTEXT_COMMON_V1 *tctiContext,
    uint8_t locality);

struct TSS2_TCTI_CONTEXT_COMMON_V1 {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_TCTI_FINALIZE_FCN finalize;
    TSS2_TCTI_CANCEL_FCN cancel;
    TSS2_TCTI_GET_POLL_HANDLES_FCN getPollHandles;
    TSS2_TCTI_SET_LOCALITY_FCN setLocality;
};

typedef TSS2_TCTI_CONTEXT_COMMON_V1 TSS2_TCTI_CONTEXT;

TSS2_RC Tss2_Tcti_Device_Init(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf);

TSS2_RC Tss2_Tcti_Swtpm_Init(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf);

TSS2_RC Tss2_Tcti_Mssim_Init(
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf);

#ifdef __cplusplus
}
#endif

#endif /* TSS2_TCTI_H */
