CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Wformat=2 -Wformat-security -fstack-protector-strong
CFLAGS += -Iinclude -Iinclude/compat -fPIC

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
ifeq ($(shell [ -d /usr/lib64 ] && echo 1),1)
LIBDIR ?= $(PREFIX)/lib64
else
LIBDIR ?= $(PREFIX)/lib
endif
LIBEXECDIR ?= $(PREFIX)/libexec
DATADIR ?= $(PREFIX)/share
SYSCONFDIR ?= /etc

BUILD_DIR ?= build

# Libraries detection
LDLIBS_CRYPTO := -lcrypto

ifeq ($(shell $(CC) -lpam -shared -o /dev/null 2>/dev/null && echo ok),ok)
LDLIBS_PAM := -lpam
else ifneq ($(wildcard /usr/lib64/libpam.so.0),)
LDLIBS_PAM := /usr/lib64/libpam.so.0
else ifneq ($(wildcard /usr/lib/*/libpam.so.0),)
LDLIBS_PAM := $(firstword $(wildcard /usr/lib/*/libpam.so.0))
else
LDLIBS_PAM := -lpam
endif

ifeq ($(shell $(CC) -ltss2-esys -shared -o /dev/null 2>/dev/null && echo ok),ok)
LDLIBS_TSS2 := -ltss2-esys
ifeq ($(shell $(CC) -ltss2-tcti-device -shared -o /dev/null 2>/dev/null && echo ok),ok)
LDLIBS_TSS2 += -ltss2-tcti-device
endif
ifeq ($(shell $(CC) -ltss2-tcti-swtpm -shared -o /dev/null 2>/dev/null && echo ok),ok)
LDLIBS_TSS2 += -ltss2-tcti-swtpm
CFLAGS += -DHAVE_TCTI_SWTPM=1
endif
ifeq ($(shell $(CC) -ltss2-tcti-mssim -shared -o /dev/null 2>/dev/null && echo ok),ok)
LDLIBS_TSS2 += -ltss2-tcti-mssim
CFLAGS += -DHAVE_TCTI_MSSIM=1
endif
else ifneq ($(wildcard /usr/lib64/libtss2-esys.so.0),)
LDLIBS_TSS2 := /usr/lib64/libtss2-esys.so.0
ifneq ($(wildcard /usr/lib64/libtss2-tcti-device.so.0),)
LDLIBS_TSS2 += /usr/lib64/libtss2-tcti-device.so.0
endif
ifneq ($(wildcard /usr/lib64/libtss2-tcti-swtpm.so.0),)
LDLIBS_TSS2 += /usr/lib64/libtss2-tcti-swtpm.so.0
CFLAGS += -DHAVE_TCTI_SWTPM=1
endif
ifneq ($(wildcard /usr/lib64/libtss2-tcti-mssim.so.0),)
LDLIBS_TSS2 += /usr/lib64/libtss2-tcti-mssim.so.0
CFLAGS += -DHAVE_TCTI_MSSIM=1
endif
else ifneq ($(wildcard /usr/lib/*/libtss2-esys.so.0),)
LDLIBS_TSS2 := $(firstword $(wildcard /usr/lib/*/libtss2-esys.so.0))
else
LDLIBS_TSS2 := -ltss2-esys
endif

COMMON_SRCS := src/common/crypto.c \
               src/common/policy.c \
               src/common/config.c \
               src/common/pam_config_manager.c \
               src/common/user_manager.c \
               src/tpm/tpm_engine.c

COMMON_OBJS := $(patsubst src/%.c,$(BUILD_DIR)/%.o,$(COMMON_SRCS))

TARGETS := $(BUILD_DIR)/pam_tpm_pin.so \
           $(BUILD_DIR)/tpm-pin-ctl \
           $(BUILD_DIR)/tpm-pin-verify \
           $(BUILD_DIR)/test_pam_harness

.PHONY: all clean install

all: $(TARGETS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/common $(BUILD_DIR)/tpm $(BUILD_DIR)/pam $(BUILD_DIR)/cli $(BUILD_DIR)/tests

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pam_tpm_pin.so: src/pam/pam_tpm_pin.c $(COMMON_OBJS) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -shared -Wl,--no-undefined -DTPM_PIN_VERIFY_PATH=\"$(LIBEXECDIR)/tpm-pin-verify\" \
		src/pam/pam_tpm_pin.c $(COMMON_OBJS) -o $@ $(LDLIBS_CRYPTO) $(LDLIBS_PAM) $(LDLIBS_TSS2)

$(BUILD_DIR)/tpm-pin-ctl: src/cli/tpm_pin_ctl.c $(COMMON_OBJS) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) src/cli/tpm_pin_ctl.c $(COMMON_OBJS) -o $@ $(LDLIBS_CRYPTO) $(LDLIBS_PAM) $(LDLIBS_TSS2)

$(BUILD_DIR)/tpm-pin-verify: src/cli/tpm_pin_verify.c $(COMMON_OBJS) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) src/cli/tpm_pin_verify.c $(COMMON_OBJS) -o $@ $(LDLIBS_CRYPTO) $(LDLIBS_TSS2)

$(BUILD_DIR)/test_pam_harness: tests/test_pam_harness.c $(COMMON_OBJS) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) tests/test_pam_harness.c $(COMMON_OBJS) -o $@ $(LDLIBS_CRYPTO) $(LDLIBS_PAM) $(LDLIBS_TSS2)

clean:
	rm -rf $(BUILD_DIR)

install: all
	install -d $(DESTDIR)$(LIBDIR)/security
	install -m 0755 $(BUILD_DIR)/pam_tpm_pin.so $(DESTDIR)$(LIBDIR)/security/pam_tpm_pin.so
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BUILD_DIR)/tpm-pin-ctl $(DESTDIR)$(BINDIR)/tpm-pin-ctl
	install -m 0755 gui/tpm-pin-settings $(DESTDIR)$(BINDIR)/tpm-pin-settings
	install -d $(DESTDIR)$(LIBEXECDIR)
	install -m 4755 $(BUILD_DIR)/tpm-pin-verify $(DESTDIR)$(LIBEXECDIR)/tpm-pin-verify
	install -d $(DESTDIR)$(DATADIR)/polkit-1/actions
	install -m 0644 gui/io.github.securepin.policy $(DESTDIR)$(DATADIR)/polkit-1/actions/io.github.securepin.policy
	install -d $(DESTDIR)$(PREFIX)/lib/udev/rules.d
	install -m 0644 packaging/udev/70-tpm-pin.rules $(DESTDIR)$(PREFIX)/lib/udev/rules.d/70-tpm-pin.rules
	install -d $(DESTDIR)$(PREFIX)/lib/systemd/system/polkit-agent-helper@.service.d
	install -m 0644 packaging/systemd/polkit-agent-helper-tpm-pin.conf $(DESTDIR)$(PREFIX)/lib/systemd/system/polkit-agent-helper@.service.d/50-tpm-pin.conf
	install -d $(DESTDIR)$(PREFIX)/lib/tmpfiles.d
	install -m 0644 packaging/systemd/tpm-pin-tmpfiles.conf $(DESTDIR)$(PREFIX)/lib/tmpfiles.d/tpm-pin.conf
	install -d $(DESTDIR)$(DATADIR)/applications
	install -m 0644 gui/io.github.securepin.Settings.desktop $(DESTDIR)$(DATADIR)/applications/io.github.securepin.Settings.desktop
	install -d $(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps
	install -m 0644 gui/icons/hicolor/scalable/apps/io.github.securepin.Settings.svg $(DESTDIR)$(DATADIR)/icons/hicolor/scalable/apps/
	install -d $(DESTDIR)$(DATADIR)/icons/hicolor/symbolic/apps
	install -m 0644 gui/icons/hicolor/symbolic/apps/io.github.securepin.Settings-symbolic.svg $(DESTDIR)$(DATADIR)/icons/hicolor/symbolic/apps/
	install -d $(DESTDIR)$(DATADIR)/metainfo
	install -m 0644 gui/io.github.securepin.Settings.metainfo.xml $(DESTDIR)$(DATADIR)/metainfo/
