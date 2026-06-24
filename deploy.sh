#!/usr/bin/env bash
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────
REMOTE_HOST="${DNS_DEPLOY_HOST:-akurai-mail}"  # SSH alias for EC2
REMOTE_USER="${DNS_DEPLOY_USER:-root}"
BINARY_NAME="akurai-dns"
REMOTE_BIN="/usr/local/bin/${BINARY_NAME}"
REMOTE_ZONE_DIR="/etc/akurai-dns/zones"
REMOTE_SERVICE="akurai-dns"
MUSL_TARGET="x86_64-unknown-linux-musl"
VERSION_FILE="VERSION"
CHANGELOG_FILE="CHANGELOG.md"

# ── Helpers ───────────────────────────────────────────────────────────
info()  { echo "==> $*"; }
die()   { echo "FATAL: $*" >&2; exit 1; }

# ── Read & bump version ──────────────────────────────────────────────
[ -f "$VERSION_FILE" ] || die "No $VERSION_FILE found"
CURRENT_VERSION=$(cat "$VERSION_FILE" | tr -d '[:space:]')

# Bump patch: 0.1.0 → 0.1.1
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"
PATCH=$((PATCH + 1))
NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"

info "Version: ${CURRENT_VERSION} → ${NEW_VERSION}"

# ── Build ─────────────────────────────────────────────────────────────
info "Building for ${MUSL_TARGET}"

# Check musl toolchain
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    info "Adding musl target"
    rustup target add "$MUSL_TARGET"
fi

CC_x86_64_unknown_linux_musl="${CC_MUSL:-musl-gcc}" \
    cargo build --release --target "$MUSL_TARGET"

BINARY="target/${MUSL_TARGET}/release/${BINARY_NAME}"
[ -f "$BINARY" ] || die "Binary not found at $BINARY"

BINARY_SIZE=$(du -h "$BINARY" | cut -f1)
info "Binary built: ${BINARY} (${BINARY_SIZE})"

# ── Upload ────────────────────────────────────────────────────────────
info "Uploading binary to ${REMOTE_HOST}"
scp -q "$BINARY" "${REMOTE_HOST}:/tmp/akurai-dns-bin"

info "Uploading zone files"
scp -q zones/*.toml "${REMOTE_HOST}:/tmp/"

# ── Install ───────────────────────────────────────────────────────────
info "Installing binary and systemd service"

ssh "$REMOTE_HOST" "sudo bash -s" << 'INSTALL'
set -euo pipefail

# Install binary
install -m 755 /tmp/akurai-dns-bin /usr/local/bin/akurai-dns
rm -f /tmp/akurai-dns-bin

# Setup zone directory + backup
mkdir -p /etc/akurai-dns/zones
if ls /etc/akurai-dns/zones/*.toml &>/dev/null; then
    BACKUP_DIR=/etc/akurai-dns/backups/$(date +%Y%m%d-%H%M%S)
    mkdir -p "$BACKUP_DIR"
    cp /etc/akurai-dns/zones/*.toml "$BACKUP_DIR/"
    echo "  Zones backed up to $BACKUP_DIR"
fi

# Install zone files
mv /tmp/*.toml /etc/akurai-dns/zones/ 2>/dev/null || true

# Check if systemd-resolved is hogging port 53
if ss -tlnp | grep -q ':53 ' 2>/dev/null; then
    echo "  Stopping systemd-resolved to free port 53"
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
    # Ensure /etc/resolv.conf points somewhere useful
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
fi

# Install systemd unit
cat > /etc/systemd/system/akurai-dns.service << 'UNIT'
[Unit]
Description=AkurAI Authoritative DNS Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/akurai-dns
Environment=DNS_ZONE_DIR=/etc/akurai-dns/zones
Environment=DNS_LISTEN=0.0.0.0
Environment=DNS_PORT=53
Environment=RUST_LOG=info
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/etc/akurai-dns
ProtectHome=true
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable akurai-dns
systemctl restart akurai-dns
echo "  Service restarted"
INSTALL

# ── Healthcheck ───────────────────────────────────────────────────────
info "Running healthcheck (waiting 2s for startup)"
sleep 2

# Run dig from the remote host against localhost
HEALTH=$(ssh "$REMOTE_HOST" "dig @127.0.0.1 golfsetridak.is A +short 2>/dev/null" || true)

if [ "$HEALTH" = "3.94.46.219" ]; then
    info "Healthcheck PASSED: golfsetridak.is → ${HEALTH}"
else
    echo "WARNING: Healthcheck returned unexpected result: '${HEALTH}'"
    echo "Check logs: ssh ${REMOTE_HOST} journalctl -u ${REMOTE_SERVICE} -n 50"
fi

# Also check health endpoint
HEALTH_TXT=$(ssh "$REMOTE_HOST" "dig @127.0.0.1 health.akurai-dns. TXT +short 2>/dev/null" || true)
if echo "$HEALTH_TXT" | grep -q "ok"; then
    info "Health endpoint: OK"
else
    echo "WARNING: Health endpoint returned: '${HEALTH_TXT}'"
fi

# ── Update version + changelog ────────────────────────────────────────
echo "$NEW_VERSION" > "$VERSION_FILE"

# Prepend to changelog
ENTRY="## ${NEW_VERSION} ($(date +%Y-%m-%d))\n\n- Deployed to ${REMOTE_HOST}\n"
TMPFILE=$(mktemp)
echo -e "# Changelog\n\n${ENTRY}" > "$TMPFILE"
tail -n +3 "$CHANGELOG_FILE" >> "$TMPFILE"
mv "$TMPFILE" "$CHANGELOG_FILE"

info "Deploy complete: v${NEW_VERSION}"
echo ""
echo "REMINDER: Ensure AWS security group allows inbound UDP+TCP port 53"
echo "  from 0.0.0.0/0 (or your registrar's NS check IPs)."
