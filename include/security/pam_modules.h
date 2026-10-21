#ifndef _SECURITY_PAM_MODULES_H
#define _SECURITY_PAM_MODULES_H

#if defined(__has_include)
#  if __has_include(<security/pam_appl.h>)
#    include <security/pam_appl.h>
#  else
#    include "pam_appl.h"
#  endif
#else
#  include <security/pam_appl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PAM_DATA_SILENT                 0x40000000

int pam_set_data(pam_handle_t *pamh, const char *module_data_name,
                 void *data,
                 void (*cleanup)(pam_handle_t *pamh, void *data, int pam_end_status));

int pam_get_data(const pam_handle_t *pamh, const char *module_data_name,
                 const void **data);

int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt);

/* Module SPI prototypes */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif /* _SECURITY_PAM_MODULES_H */
