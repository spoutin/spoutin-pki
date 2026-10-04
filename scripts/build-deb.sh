#!/usr/bin/env bash
set -euo pipefail

# Script to assemble wifi-enrollment Debian (.deb) package
VERSION="${1:-0.1.0}"
ARCH="${2:-amd64}"
CADDY_BIN="${3:-}"

# Strip leading 'v' from version if present
VERSION="${VERSION#v}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
STAGING_DIR="${REPO_ROOT}/build/deb-staging"

echo "=== Building wifi-enrollment package v${VERSION} (${ARCH}) ==="

# Clean staging directory
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/DEBIAN"
mkdir -p "${STAGING_DIR}/opt/wifi-enrollment/bin"
mkdir -p "${STAGING_DIR}/opt/wifi-enrollment/caddy"
mkdir -p "${STAGING_DIR}/opt/wifi-enrollment/systemd"
mkdir -p "${STAGING_DIR}/lib/systemd/system"
mkdir -p "${STAGING_DIR}/etc/systemd/system/caddy.service.d"
mkdir -p "${DIST_DIR}"

# 1. Prepare DEBIAN control and maintainer scripts
cp -r "${REPO_ROOT}/packaging/deb/DEBIAN/"* "${STAGING_DIR}/DEBIAN/"
sed -i.bak "s/^Version:.*/Version: ${VERSION}/" "${STAGING_DIR}/DEBIAN/control"
sed -i.bak "s/^Architecture:.*/Architecture: ${ARCH}/" "${STAGING_DIR}/DEBIAN/control"
rm -f "${STAGING_DIR}/DEBIAN/"*.bak
chmod 755 "${STAGING_DIR}/DEBIAN/postinst" "${STAGING_DIR}/DEBIAN/prerm"

# 2. Add Caddy binary (staged in /opt/wifi-enrollment/bin to prevent dpkg unpack conflicts with package caddy)
if [ -n "${CADDY_BIN}" ] && [ -f "${CADDY_BIN}" ]; then
    echo "Using provided Caddy binary: ${CADDY_BIN}"
    cp "${CADDY_BIN}" "${STAGING_DIR}/opt/wifi-enrollment/bin/caddy"
else
    echo "Downloading pre-compiled Caddy binary with Cloudflare DNS plugin..."
    curl -fsSL -o "${STAGING_DIR}/opt/wifi-enrollment/bin/caddy" \
        "https://caddyserver.com/api/download?os=linux&arch=${ARCH}&p=github.com%2Fcaddy-dns%2Fcloudflare"
fi
chmod 755 "${STAGING_DIR}/opt/wifi-enrollment/bin/caddy"

# 3. Add wifi-enrollment source and dependencies manifest
echo "Staging wifi-enrollment application files..."
cp -r "${REPO_ROOT}/services" "${STAGING_DIR}/opt/wifi-enrollment/"
cp "${REPO_ROOT}/pyproject.toml" "${STAGING_DIR}/opt/wifi-enrollment/"
cp "${REPO_ROOT}/uv.lock" "${STAGING_DIR}/opt/wifi-enrollment/"
cp "${REPO_ROOT}/README.md" "${STAGING_DIR}/opt/wifi-enrollment/"
cp "${REPO_ROOT}/.env.example" "${STAGING_DIR}/opt/wifi-enrollment/"

# 4. Add systemd units & configuration
cp "${REPO_ROOT}/packaging/systemd/wifi-enrollment.service" "${STAGING_DIR}/lib/systemd/system/"
cp "${REPO_ROOT}/packaging/systemd/spoutin-pki.target" "${STAGING_DIR}/lib/systemd/system/"
cp "${REPO_ROOT}/packaging/systemd/caddy.service" "${STAGING_DIR}/opt/wifi-enrollment/systemd/"
cp "${REPO_ROOT}/packaging/systemd/caddy-override.conf.example" "${STAGING_DIR}/opt/wifi-enrollment/systemd/override.conf.example"
cp "${REPO_ROOT}/packaging/systemd/caddy-override.conf.example" "${STAGING_DIR}/etc/systemd/system/caddy.service.d/override.conf.example"
cp "${REPO_ROOT}/infra/caddy/Caddyfile" "${STAGING_DIR}/opt/wifi-enrollment/caddy/Caddyfile"

# 5. Build .deb package
OUTPUT_DEB="${DIST_DIR}/wifi-enrollment_${VERSION}_${ARCH}.deb"

if command -v dpkg-deb >/dev/null 2>&1; then
    echo "Building Debian package with dpkg-deb..."
    dpkg-deb --build --root-owner-group "${STAGING_DIR}" "${OUTPUT_DEB}"
else
    echo "dpkg-deb not found locally; staging directory created at ${STAGING_DIR}"
    echo "In CI/CD, dpkg-deb will assemble the package into ${OUTPUT_DEB}"
    exit 0
fi

echo "Successfully built: ${OUTPUT_DEB}"
