cmake_minimum_required(VERSION 3.16)
project(tpm-pin VERSION 1.0.4 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(GNUInstallDirs)

option(BUILD_GUI_ONLY "Build only the GUI application and desktop integration assets (e.g. for Flatpak)" OFF)

if(NOT BUILD_GUI_ONLY)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    find_package(OpenSSL REQUIRED)

    find_library(PAM_LIB NAMES pam libpam.so.0 pam.so.0
        PATHS /usr/lib/${CMAKE_LIBRARY_ARCHITECTURE} /usr/lib64 /usr/lib /usr/local/lib
    )
    if(NOT PAM_LIB)
        message(FATAL_ERROR "Could not find PAM library (libpam.so or libpam.so.0)")
    endif()

    find_library(TSS2_ESYS_LIB NAMES tss2-esys libtss2-esys.so.0 tss2-esys.so.0
        PATHS /usr/lib/${CMAKE_LIBRARY_ARCHITECTURE} /usr/lib64 /usr/lib /usr/local/lib
    )
    if(NOT TSS2_ESYS_LIB)
        message(FATAL_ERROR "Could not find TSS2 ESYS library (libtss2-esys.so or libtss2-esys.so.0)")
    endif()

    find_library(TSS2_TCTI_DEV_LIB NAMES tss2-tcti-device libtss2-tcti-device.so.0
        PATHS /usr/lib/${CMAKE_LIBRARY_ARCHITECTURE} /usr/lib64 /usr/lib /usr/local/lib
    )

    find_library(TSS2_TCTI_SWTPM_LIB NAMES tss2-tcti-swtpm libtss2-tcti-swtpm.so.0
        PATHS /usr/lib/${CMAKE_LIBRARY_ARCHITECTURE} /usr/lib64 /usr/lib /usr/local/lib
    )

    find_library(TSS2_TCTI_MSSIM_LIB NAMES tss2-tcti-mssim libtss2-tcti-mssim.so.0
        PATHS /usr/lib/${CMAKE_LIBRARY_ARCHITECTURE} /usr/lib64 /usr/lib /usr/local/lib
    )

    set(TSS2_LIBS ${TSS2_ESYS_LIB})
    if(TSS2_TCTI_DEV_LIB)
        list(APPEND TSS2_LIBS ${TSS2_TCTI_DEV_LIB})
    endif()
    if(TSS2_TCTI_SWTPM_LIB)
        list(APPEND TSS2_LIBS ${TSS2_TCTI_SWTPM_LIB})
        add_compile_definitions(HAVE_TCTI_SWTPM=1)
    endif()
    if(TSS2_TCTI_MSSIM_LIB)
        list(APPEND TSS2_LIBS ${TSS2_TCTI_MSSIM_LIB})
        add_compile_definitions(HAVE_TCTI_MSSIM=1)
    endif()

    set(COMMON_SOURCES
        src/common/crypto.c
        src/common/policy.c
        src/common/config.c
        src/common/pam_config_manager.c
        src/common/user_manager.c
        src/tpm/tpm_engine.c
    )

    add_library(tpmpin_common STATIC ${COMMON_SOURCES})
    target_link_libraries(tpmpin_common PUBLIC
        OpenSSL::Crypto
        ${TSS2_LIBS}
    )

    add_library(pam_tpm_pin MODULE src/pam/pam_tpm_pin.c)
    set_target_properties(pam_tpm_pin PROPERTIES
        PREFIX ""
        OUTPUT_NAME "pam_tpm_pin"
    )
    target_link_libraries(pam_tpm_pin PRIVATE
        tpmpin_common
        ${PAM_LIB}
    )
    target_link_options(pam_tpm_pin PRIVATE "-Wl,--no-undefined")

    add_executable(tpm-pin-ctl src/cli/tpm_pin_ctl.c)
    target_link_libraries(tpm-pin-ctl PRIVATE
        tpmpin_common
        ${PAM_LIB}
    )

    add_executable(tpm-pin-verify src/cli/tpm_pin_verify.c)
    target_link_libraries(tpm-pin-verify PRIVATE
        tpmpin_common
    )

    add_executable(test_pam_harness tests/test_pam_harness.c)
    target_link_libraries(test_pam_harness PRIVATE
        tpmpin_common
        ${PAM_LIB}
    )

    install(TARGETS pam_tpm_pin
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/security
    )

    install(TARGETS tpm-pin-ctl
        DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    install(TARGETS tpm-pin-verify
        DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}
        PERMISSIONS
            OWNER_READ OWNER_WRITE OWNER_EXECUTE
            GROUP_READ GROUP_EXECUTE
            WORLD_READ WORLD_EXECUTE
            SETUID
    )

    install(FILES gui/io.github.securepin.policy
        DESTINATION ${CMAKE_INSTALL_DATADIR}/polkit-1/actions
    )

    install(FILES packaging/pam-configs/tpm-pin
        DESTINATION ${CMAKE_INSTALL_DATADIR}/pam-configs
    )

    set(UDEV_RULES_DIR "lib/udev/rules.d" CACHE PATH "Directory for udev rules")
    install(FILES packaging/udev/70-tpm-pin.rules
        DESTINATION ${UDEV_RULES_DIR}
    )

    set(SYSTEMD_UNIT_DIR "lib/systemd/system" CACHE PATH "Directory for systemd units")
    install(FILES packaging/systemd/polkit-agent-helper-tpm-pin.conf
        DESTINATION ${SYSTEMD_UNIT_DIR}/polkit-agent-helper@.service.d
        RENAME 50-tpm-pin.conf
    )
endif()

install(PROGRAMS gui/tpm-pin-settings
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES gui/io.github.securepin.Settings.desktop
    DESTINATION ${CMAKE_INSTALL_DATADIR}/applications
)

install(FILES gui/icons/hicolor/scalable/apps/io.github.securepin.Settings.svg
    DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps
)

install(FILES gui/icons/hicolor/symbolic/apps/io.github.securepin.Settings-symbolic.svg
    DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/symbolic/apps
)

install(FILES gui/io.github.securepin.Settings.metainfo.xml
    DESTINATION ${CMAKE_INSTALL_DATADIR}/metainfo
)

if(NOT BUILD_GUI_ONLY)
    set(CPACK_PACKAGE_NAME "tpm-pin")
    set(CPACK_PACKAGE_VENDOR "Secure PIN Team")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "TPM 2.0 Windows Hello-style PIN authentication for Linux")
    set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/steacep/secure-pin-for-linux")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
    set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
    set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
    set(CPACK_GENERATOR "TGZ;DEB;RPM")

    set(CPACK_PACKAGE_DESCRIPTION "Hardware-backed PIN authentication using TPM 2.0. Integrates with PAM for login screen (GDM/SDDM), lock screen, sudo, and desktop keyring auto-unlock. Includes a native GTK4/Libadwaita settings application.")
    set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Secure PIN Team <steace@coderage.pro>")
    set(CPACK_DEBIAN_PACKAGE_SECTION "admin")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpam0g, python3, python3-gi, gir1.2-adw-1, gir1.2-gtk-4.0")
    set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
        "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/postinst;${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/prerm;${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/postrm"
    )
    set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")

    set(CPACK_RPM_PACKAGE_LICENSE "GPLv3+")
    set(CPACK_RPM_PACKAGE_GROUP "System Environment/Base")
    set(CPACK_RPM_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
    set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/rpm/changelog")
    set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/rpm/postinst")
    set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/rpm/preun")
    set(CPACK_RPM_PACKAGE_REQUIRES "pam, tpm2-tss, python3, python3-gobject, libadwaita")
    set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
        /usr/libexec
        /usr/lib/udev
        /usr/lib/udev/rules.d
        /usr/lib/systemd
        /usr/lib/systemd/system
        /usr/lib/systemd/system/polkit-agent-helper@.service.d
        /usr/lib/x86_64-linux-gnu
        /usr/lib/x86_64-linux-gnu/security
        /usr/share/applications
        /usr/share/icons
        /usr/share/icons/hicolor
        /usr/share/icons/hicolor/scalable
        /usr/share/icons/hicolor/scalable/apps
        /usr/share/icons/hicolor/symbolic
        /usr/share/icons/hicolor/symbolic/apps
        /usr/share/metainfo
        /usr/share/pam-configs
        /usr/share/polkit-1
        /usr/share/polkit-1/actions
    )
    set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")

    include(CPack)
endif()
