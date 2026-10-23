#!/usr/bin/env bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
MANIFEST="$SCRIPT_DIR/io.github.securepin.Settings.yml"
BUILD_DIR="$ROOT_DIR/build-flatpak"
REPO_DIR="$ROOT_DIR/flatpak-repo"
DIST_DIR="$ROOT_DIR/dist"

RUNTIME_VERSION="50"
APP_ID="io.github.securepin.Settings"

DO_INSTALL=false
DO_BUNDLE=false
DO_RUN=false
DO_CLEAN=false
INSTALL_DEPS=false

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Builds the Secure PIN Settings Flatpak application.

Options:
  -i, --install       Install application to user space upon successful build
  -b, --bundle        Export single-file .flatpak bundle to dist/
  -r, --run           Launch the Flatpak application after build/install
  -c, --clean         Clean previous Flatpak build directories before building
  --install-deps      Install required GNOME runtime and SDK from Flathub
  -h, --help          Show this help message
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--install)
            DO_INSTALL=true
            shift
            ;;
        -b|--bundle)
            DO_BUNDLE=true
            shift
            ;;
        -r|--run)
            DO_RUN=true
            shift
            ;;
        -c|--clean)
            DO_CLEAN=true
            shift
            ;;
        --install-deps)
            INSTALL_DEPS=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            ;;
    esac
done

if ! command -v flatpak >/dev/null 2>&1; then
    echo "Error: flatpak is not installed on this system." >&2
    exit 1
fi

if ! command -v flatpak-builder >/dev/null 2>&1; then
    echo "Error: flatpak-builder is not installed." >&2
    echo "Install it using your system package manager:" >&2
    echo "  Debian/Ubuntu: sudo apt install flatpak-builder" >&2
    echo "  Fedora/RHEL:   sudo dnf install flatpak-builder" >&2
    echo "  Arch Linux:    sudo pacman -S flatpak-builder" >&2
    exit 1
fi

if [ "$INSTALL_DEPS" = true ]; then
    echo "Installing required Flatpak SDK and Runtime from Flathub..."
    flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
    flatpak install --user -y flathub "org.gnome.Platform//${RUNTIME_VERSION}" "org.gnome.Sdk//${RUNTIME_VERSION}"
fi

# Verify required runtime and SDK exist
if ! flatpak info "org.gnome.Platform//${RUNTIME_VERSION}" >/dev/null 2>&1 || \
   ! flatpak info "org.gnome.Sdk//${RUNTIME_VERSION}" >/dev/null 2>&1; then
    echo "Notice: Required GNOME runtime or SDK (${RUNTIME_VERSION}) not found."
    echo "Run '$0 --install-deps' or manually install them:"
    echo "  flatpak install --user flathub org.gnome.Platform//${RUNTIME_VERSION} org.gnome.Sdk//${RUNTIME_VERSION}"
    exit 1
fi

if [ "$DO_CLEAN" = true ]; then
    echo "Cleaning Flatpak build and cache directories..."
    rm -rf "$BUILD_DIR" "$REPO_DIR" "$ROOT_DIR/.flatpak-builder"
fi

mkdir -p "$REPO_DIR" "$DIST_DIR"

BUILDER_ARGS=("--force-clean" "--repo=$REPO_DIR")
if [ "$DO_INSTALL" = true ]; then
    BUILDER_ARGS+=("--user" "--install")
fi

echo "Building Flatpak application from manifest: $MANIFEST"
flatpak-builder "${BUILDER_ARGS[@]}" "$BUILD_DIR" "$MANIFEST"

VERSION=$(sed -n 's/.*project(tpm-pin VERSION \([0-9.]*\).*/\1/p' "$ROOT_DIR/CMakeLists.txt")
[ -z "$VERSION" ] && VERSION="1.0.3"

if [ "$DO_BUNDLE" = true ]; then
    BUNDLE_NAME="${APP_ID}-${VERSION}.flatpak"
    BUNDLE_PATH="$DIST_DIR/$BUNDLE_NAME"
    echo "Creating Flatpak bundle: $BUNDLE_PATH"
    flatpak build-bundle "$REPO_DIR" "$BUNDLE_PATH" "$APP_ID"
    (cd "$DIST_DIR" && sha256sum "$BUNDLE_NAME" > "${BUNDLE_NAME}.sha256")
    echo "Bundle generated: $BUNDLE_PATH"
fi

if [ "$DO_RUN" = true ]; then
    echo "Launching $APP_ID..."
    flatpak run "$APP_ID"
fi

echo "Flatpak build completed successfully."
