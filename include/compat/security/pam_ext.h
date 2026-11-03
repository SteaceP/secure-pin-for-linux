#ifndef _SECURITY_PAM_EXT_H
#define _SECURITY_PAM_EXT_H

#if defined(__has_include)
#  if __has_include(<security/pam_appl.h>)
#    include <security/pam_appl.h>
#  else
#    include "pam_appl.h"
#  endif
#else
#  include <security/pam_appl.h>
#endif
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

int pam_prompt(pam_handle_t *pamh, int style, char **response, const char *fmt, ...);
int pam_vprompt(pam_handle_t *pamh, int style, char **response, const char *fmt, va_list args);
#ifndef pam_info
#define pam_info(pamh, ...) pam_prompt(pamh, PAM_TEXT_INFO, NULL, __VA_ARGS__)
#endif
#ifndef pam_vinfo
#define pam_vinfo(pamh, fmt, args) pam_vprompt(pamh, PAM_TEXT_INFO, NULL, fmt, args)
#endif
#ifndef pam_error
#define pam_error(pamh, ...) pam_prompt(pamh, PAM_ERROR_MSG, NULL, __VA_ARGS__)
#endif
#ifndef pam_verror
#define pam_verror(pamh, fmt, args) pam_vprompt(pamh, PAM_ERROR_MSG, NULL, fmt, args)
#endif
void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...);
void pam_vsyslog(const pam_handle_t *pamh, int priority, const char *fmt, va_list args);

#ifdef __cplusplus
}
#endif

#endif /* _SECURITY_PAM_EXT_H */
