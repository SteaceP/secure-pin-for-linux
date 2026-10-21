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
int pam_info(pam_handle_t *pamh, const char *fmt, ...);
int pam_error(pam_handle_t *pamh, const char *fmt, ...);
void pam_syslog(const pam_handle_t *pamh, int priority, const char *fmt, ...);
void pam_vsyslog(const pam_handle_t *pamh, int priority, const char *fmt, va_list args);

#ifdef __cplusplus
}
#endif

#endif /* _SECURITY_PAM_EXT_H */
