#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "tpm_pin.h"

bool tpm_pin_validate_pin(const char *pin, const tpm_pin_config_t *cfg, char *err_buf, size_t err_size) {
    if (!pin) {
        if (err_buf && err_size > 0) snprintf(err_buf, err_size, "PIN cannot be empty.");
        return false;
    }

    size_t len = strlen(pin);
    uint32_t min_len = cfg ? cfg->min_length : 4;
    uint32_t max_len = cfg ? cfg->max_length : 32;

    if (len < min_len) {
        if (err_buf && err_size > 0)
            snprintf(err_buf, err_size, "PIN is too short (minimum %u characters required).", min_len);
        return false;
    }

    if (len > max_len) {
        if (err_buf && err_size > 0)
            snprintf(err_buf, err_size, "PIN is too long (maximum %u characters allowed).", max_len);
        return false;
    }

    if (cfg && cfg->digits_only) {
        for (size_t i = 0; i < len; i++) {
            if (!isdigit((unsigned char)pin[i])) {
                if (err_buf && err_size > 0)
                    snprintf(err_buf, err_size, "PIN must contain numbers only.");
                return false;
            }
        }
    }

    /* Reject trivial all-identical PINs (e.g. "0000", "1111") */
    bool all_same = true;
    for (size_t i = 1; i < len; i++) {
        if (pin[i] != pin[0]) {
            all_same = false;
            break;
        }
    }
    if (all_same && len >= 4) {
        if (err_buf && err_size > 0)
            snprintf(err_buf, err_size, "PIN cannot consist of all identical characters.");
        return false;
    }

    return true;
}

bool tpm_pin_is_likely_pin(const char *input, const tpm_pin_config_t *cfg) {
    if (!input) return false;
    size_t len = strlen(input);
    uint32_t min_len = cfg ? cfg->min_length : 4;
    uint32_t max_len = cfg ? cfg->max_length : 32;

    if (len < min_len || len > max_len) {
        return false;
    }

    if (cfg && cfg->digits_only) {
        for (size_t i = 0; i < len; i++) {
            if (!isdigit((unsigned char)input[i])) {
                return false;
            }
        }
    }

    return true;
}
