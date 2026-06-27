#!/usr/bin/env bash
# scripts/validate.sh — Post-deploy validation for AkurAI-DNS
set -euo pipefail

PORT=53
RED='\033[0;31m'; GRN='\033[0;32m'; NC='\033[0m'
pass=0; fail=0
pass_() { printf "  ${GRN}PASS${NC} %s\n" "$*"; ((pass++)); }
fail_() { printf "  ${RED}FAIL${NC} %s\n" "$*"; ((fail++)); }

echo "=== Post-deploy validation: AkurAI-DNS ==="

# 1. Systemd
systemctl is-active --quiet akurai-dns.service 2>/dev/null && pass_ "systemd active" || fail_ "systemd not active"

# 2. UDP port 53 listening
if ss -uln | grep -q ":53 "; then
  pass_ "UDP port 53 bound"
else
  fail_ "UDP port 53 not listening"
fi

# 3. DNS query (SOA for olibuijr.com)
if dig +short @127.0.0.1 olibuijr.com SOA > /dev/null 2>&1; then
  pass_ "SOA query olibuijr.com resolved"
else
  fail_ "SOA query failed"
fi

# 4. DNS query (A record)
A=$(dig +short @127.0.0.1 mail.olibuijr.com A 2>/dev/null)
if [ "$A" = "3.94.46.219" ]; then
  pass_ "A record mail.olibuijr.com → $A"
else
  fail_ "A record mail.olibuijr.com → ${A:-none}"
fi

# 5. Zone file present
if [ -f "/etc/akurai-dns/zones/olibuijr.com.zone" ]; then
  pass_ "zone file present"
else
  fail_ "zone file missing"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GRN}Pass: $pass${NC}  ${RED}Fail: $fail${NC}"
[ "$fail" -eq 0 ] || exit 1
