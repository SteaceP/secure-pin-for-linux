#!/usr/bin/env bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR"
BUILD_DIR="$ROOT_DIR/build"
DIST_DIR="$ROOT_DIR/dist"

BUILD_TYPE="Release"
DO_PACKAGE=true
DO_CLEAN=false
CLEAN_ONLY=false
DO_TEST=false
BUILD_ARCH=false
BUILD_FLATPAK=false
JOBS="$(nproc 2>/dev/null || echo 2)"
PREFIX="/usr"

usage() {
    cat << 'EOF'
Usage: ./build.sh [OPTIONS]

Builds Secure PIN for Linux and packages release distributions into ./dist/

Options:
  -c, --clean         Clean build and dist directories before building
  --clean-only        Clean build and dist directories and exit immediately
  -p, --package       Build and generate distribution packages (default: enabled)
  --no-package        Build binaries only, skip packaging
  -t, --test          Run automated test suite before packaging
  -d, --debug         Build with Debug configuration (default: Release)
  --arch              Build Arch Linux package (pkg.tar.zst) via Docker
  --flatpak           Build Flatpak package (.flatpak) via flatpak-builder
  -j, --jobs <N>      Number of parallel compile jobs (default: nproc)
  --prefix <path>     Installation prefix for CMake (default: /usr)
  -h, --help          Show this help message
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--clean)
            DO_CLEAN=true
            shift
            ;;
        --clean-only)
            CLEAN_ONLY=true
            shift
            ;;
        -p|--package)
            DO_PACKAGE=true
            shift
            ;;
        --no-package)
            DO_PACKAGE=false
            shift
            ;;
        -t|--test)
            DO_TEST=true
            shift
            ;;
        -d|--debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        --arch)
            BUILD_ARCH=true
            shift
            ;;
        --flatpak)
            BUILD_FLATPAK=true
            shift
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        --prefix)
            PREFIX="$2"
            shift 2
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

cd "$ROOT_DIR"

if [ "$DO_CLEAN" = true ] || [ "$CLEAN_ONLY" = true ]; then
    echo "Cleaning build artifacts and release outputs..."
    rm -rf "$BUILD_DIR" "$ROOT_DIR/build-release" "$DIST_DIR" "$ROOT_DIR/release-assets" \
           "$ROOT_DIR/build-flatpak" "$ROOT_DIR/flatpak-repo" "$ROOT_DIR/.flatpak-builder"
    rm -f -- "$ROOT_DIR/-.o"
    if [ "$CLEAN_ONLY" = true ]; then
        echo "Clean complete."
        exit 0
    fi
fi

if [ "$DO_TEST" = true ]; then
    echo "Running test suite before packaging..."
    "$ROOT_DIR/tests/run_tests.sh"
fi

echo "Configuring CMake (${BUILD_TYPE})..."
cmake -B "$BUILD_DIR" -S "$ROOT_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

echo "Building project (${JOBS} jobs)..."
cmake --build "$BUILD_DIR" -j"$JOBS"

if [ "$DO_PACKAGE" = true ]; then
    echo "Generating release packages..."
    mkdir -p "$DIST_DIR"

    pushd "$BUILD_DIR" >/dev/null

    echo "Building Debian package (.deb)..."
    cpack -G DEB

    if command -v rpmbuild >/dev/null 2>&1; then
        echo "Building RedHat package (.rpm)..."
        cpack -G RPM
    else
        echo "rpmbuild not found, skipping RPM package generation."
    fi

    echo "Building universal tarball (.tar.gz)..."
    cpack -G TGZ

    popd >/dev/null

    rm -rf "$BUILD_DIR/_CPack_Packages"

    shopt -s nullglob
    PACKAGES=("$BUILD_DIR"/*.deb "$BUILD_DIR"/*.rpm "$BUILD_DIR"/*.tar.gz)
    if [ ${#PACKAGES[@]} -gt 0 ]; then
        mv "${PACKAGES[@]}" "$DIST_DIR/"
    fi

    if [ "$BUILD_ARCH" = true ]; then
        if command -v docker >/dev/null 2>&1; then
            echo "Building Arch Linux package via Docker..."
            VERSION=$(sed -n 's/.*project(tpm-pin VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
            [ -z "$VERSION" ] && VERSION="1.0.2"
            docker run --rm \
                -v "$ROOT_DIR:/src:ro" \
                -v "$DIST_DIR:/out" \
                archlinux:latest bash -c "
                  pacman -Sy --noconfirm base-devel cmake git openssl pam tpm2-tss python python-gobject libadwaita >/dev/null 2>&1
                  useradd -m builder
                  echo 'builder ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
                  git config --global --add safe.directory '*'
                  mkdir -p /home/builder/pkg
                  git clone /src /home/builder/repo >/dev/null 2>&1
                  cd /home/builder/repo
                  git archive --format=tar.gz --prefix=tpm-pin-${VERSION}/ HEAD > /home/builder/pkg/tpm-pin-${VERSION}.tar.gz
                  cp packaging/arch/PKGBUILD /home/builder/pkg/
                  sed -i \"s/^pkgver=.*/pkgver=${VERSION}/\" /home/builder/pkg/PKGBUILD
                  chown -R builder:builder /home/builder
                  su builder -c 'cd /home/builder/pkg && makepkg -f --noconfirm' >/dev/null 2>&1
                  cp /home/builder/pkg/*.pkg.tar.zst /out/
                "
        else
            echo "Docker not found, skipping Arch Linux package."
        fi
    fi

    if [ "$BUILD_FLATPAK" = true ]; then
        if command -v flatpak-builder >/dev/null 2>&1; then
            echo "Building Flatpak package via flatpak-builder..."
            VERSION=$(sed -n 's/.*project(tpm-pin VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
            [ -z "$VERSION" ] && VERSION="1.0.2"
            mkdir -p "$ROOT_DIR/build-flatpak" "$ROOT_DIR/flatpak-repo"
            flatpak-builder --force-clean --repo="$ROOT_DIR/flatpak-repo" "$ROOT_DIR/build-flatpak" packaging/flatpak/io.github.securepin.Settings.yml
            flatpak build-bundle "$ROOT_DIR/flatpak-repo" "$DIST_DIR/io.github.securepin.Settings-${VERSION}.flatpak" io.github.securepin.Settings
            rm -rf "$ROOT_DIR/build-flatpak" "$ROOT_DIR/flatpak-repo"
        else
            echo "flatpak-builder not found, skipping Flatpak package generation."
        fi
    fi

    pushd "$DIST_DIR" >/dev/null
    shopt -s nullglob
    DIST_FILES=(*.deb *.rpm *.tar.gz *.pkg.tar.zst *.flatpak)
    if [ ${#DIST_FILES[@]} -gt 0 ]; then
        sha256sum "${DIST_FILES[@]}" > SHA256SUMS.txt
    fi
    popd >/dev/null

    echo ""
    echo "============================================================"
    echo "Release packages generated in: dist/"
    echo "============================================================"
    printf "%-34s %-10s %-20s\n" "Filename" "Size" "Target Format"
    printf "%-34s %-10s %-20s\n" "----------------------------------" "----------" "--------------------"
    for f in "$DIST_DIR"/*; do
        [ -f "$f" ] || continue
        fname=$(basename "$f")
        fsize=$(ls -lh "$f" | awk '{print $5}')
        case "$fname" in
            *.deb) target="Debian / Ubuntu" ;;
            *.rpm) target="Fedora / RHEL" ;;
            *.tar.gz) target="Universal Archive" ;;
            *.pkg.tar.zst) target="Arch Linux" ;;
            *.flatpak) target="Flatpak Bundle" ;;
            SHA256SUMS.txt) target="SHA-256 Checksums" ;;
            *) target="Release File" ;;
        esac
        printf "%-34s %-10s %-20s\n" "$fname" "$fsize" "$target"
    done
    echo "============================================================"
fi
