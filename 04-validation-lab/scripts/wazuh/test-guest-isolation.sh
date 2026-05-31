#!/usr/bin/env bash
#
# test-guest-isolation.sh
# [Run inside CSL-Wazuh (Ubuntu, 10.10.10.10)] Linux mirror of Test-GuestIsolation.ps1.
# Proves: can ping a peer on the same subnet, but [absolutely] cannot reach the
# internet, cannot touch the host's real LAN, has no DNS, and no default gateway.
#
# Expected results (any item that "should fail but succeeds" = isolation breach; the script exits non-zero):
#   - Another VM inside the isolated network -> reachable      (PASS)
#   - Public IP 1.1.1.1 / 8.8.8.8            -> unreachable     (PASS = no egress)
#   - Public domain DNS resolution           -> fails           (PASS)
#   - Common home/enterprise subnet gateways -> unreachable     (PASS = cannot touch real LAN)
#   - Default gateway (default route)        -> does not exist   (PASS)
#   - curl/TCP443 to the internet            -> fails           (PASS = no egress at the app layer either)
#
# Usage:
#   chmod +x test-guest-isolation.sh
#   ./test-guest-isolation.sh                 # peer defaults to 10.10.10.20 (CSL-Server)
#   ./test-guest-isolation.sh 10.10.10.31     # specify a different peer on the same subnet
#
# Design: purely defensive, read-only probing, changes no configuration. LF line endings, set -u, only portable tools (ping -c / timeout / ip).
# Note: intentionally not using 'set -e' -- probe command failures are expected; each item must be judged individually rather than exiting midway.

set -u

# ---- peer: another VM inside the isolated network (this host is 10.10.10.10, so the default points to .20) ----
PEER_IP="${1:-10.10.10.20}"

PASS=0
FAIL=0
GREEN=''; RED=''; CYAN=''; RESET=''
if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
fi

# run_quiet <command...>  -> returns the command's exit code, discards all output
run_quiet() { "$@" >/dev/null 2>&1; }

# check <desc> <expect: ok|fail> <command...>
#   expect=ok   the command should succeed (exit 0)
#   expect=fail the command should fail (non-zero) -- in the isolation scenario "failing is correct"
check() {
    desc="$1"; expect="$2"; shift 2
    if run_quiet "$@"; then rc=0; else rc=$?; fi
    if { [ "$expect" = "ok" ] && [ "$rc" -eq 0 ]; } || \
       { [ "$expect" = "fail" ] && [ "$rc" -ne 0 ]; }; then
        printf '%s[PASS]%s %s\n' "$GREEN" "$RESET" "$desc"
        PASS=$((PASS + 1))
    else
        printf '%s[FAIL]%s %s  (expect=%s rc=%s)\n' "$RED" "$RESET" "$desc" "$expect" "$rc"
        FAIL=$((FAIL + 1))
    fi
}

# Portable ping with timeout: -c sets the count, -W the per-packet timeout (seconds), wrapped in an outer timeout as a fallback
ping_host() {
    timeout 6 ping -c 2 -W 2 "$1"
}

# DNS resolution probe: prefer getent (no extra package needed), fall back to host/nslookup
resolve_host() {
    name="$1"
    if command -v getent >/dev/null 2>&1; then
        timeout 5 getent ahosts "$name"
    elif command -v host >/dev/null 2>&1; then
        timeout 5 host "$name"
    elif command -v nslookup >/dev/null 2>&1; then
        timeout 5 nslookup "$name"
    else
        # No resolution tool at all = resolution is bound to fail = matches the isolation expectation
        return 1
    fi
}

# This host's isolated-network IP (for display only)
SELF_IP="$(ip -o -4 addr show 2>/dev/null | awk '/10\.10\.10\./ {print $4}' | cut -d/ -f1 | head -n1)"
[ -z "$SELF_IP" ] && SELF_IP='(no 10.10.10.x address obtained)'

printf '\n%s=== Guest isolation verification (this host: %s, peer: %s) ===%s\n\n' "$CYAN" "$SELF_IP" "$PEER_IP" "$RESET"

# 1) Positive: can ping the peer on the same subnet (otherwise agent->manager log collection breaks)
check "Can ping the peer inside the isolated network ($PEER_IP)" ok ping_host "$PEER_IP"

# 2) Negative: public IPs must be unreachable (including IPv6, so we don't miss an IPv6 path by only testing IPv4)
check "Public 1.1.1.1 unreachable (no internet egress)" fail ping_host '1.1.1.1'
check "Public 8.8.8.8 unreachable (no internet egress)" fail ping_host '8.8.8.8'
check "Public IPv6 2606:4700:4700::1111 unreachable" fail ping_host '2606:4700:4700::1111'

# 3) Public domain DNS resolution must fail (the isolated network has no DNS and no egress)
check "Public domain DNS resolution fails (www.microsoft.com)" fail resolve_host 'www.microsoft.com'

# 4) Common real home/enterprise LAN gateways unreachable (confirm we cannot touch the host's real network)
for gw in 192.168.1.1 192.168.0.1 192.168.31.1 10.0.0.1; do
    check "Real LAN gateway $gw unreachable" fail ping_host "$gw"
done

# 5) This host should have no default gateway (default route).
#    Note: `ip route show default` is a query command and returns 0 whether or not a default route exists;
#    feeding it directly to check (expect=fail) would falsely report FAIL when isolation is [correct].
#    Use an "existence" check instead: the helper returns 0 only when a default route truly exists.
has_default_route()  { ip    route show default 2>/dev/null | grep -q .; }
has_default_route6() { ip -6 route show default 2>/dev/null | grep -q .; }
check "This host has no default gateway (no IPv4 default route)" fail has_default_route
check "This host has no default gateway (no IPv6 default route)" fail has_default_route6

# 6) Application layer: curl to the internet must fail (short timeout, no retries)
if command -v curl >/dev/null 2>&1; then
    check "curl to the internet fails (http://1.1.1.1)" fail \
        timeout 8 curl -sS --max-time 5 --connect-timeout 4 -o /dev/null 'http://1.1.1.1'
else
    printf '%s[PASS]%s curl to the internet fails (curl not installed, treated as no egress)\n' "$GREEN" "$RESET"
    PASS=$((PASS + 1))
fi

# 7) Application layer: TCP 443 to the internet must fail (uses bash /dev/tcp, no extra tools needed)
check "TCP 443 -> internet fails (1.1.1.1:443)" fail \
    timeout 6 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'

printf '\n%s=== Result: PASS=%s  FAIL=%s ===%s\n' "$CYAN" "$PASS" "$FAIL" "$RESET"
if [ "$FAIL" -eq 0 ]; then
    printf '%sIsolation is in effect: this host can reach a VM on the same subnet, but has no internet egress, cannot touch the real LAN, has no DNS, and no default gateway. Compliant.%s\n' "$GREEN" "$RESET"
else
    printf '%sIsolation has a breach! Stop all research activity immediately and investigate the NIC/switch configuration (most likely some VM is still attached to the External/NAT switch).%s\n' "$RED" "$RESET"
fi

exit "$FAIL"
