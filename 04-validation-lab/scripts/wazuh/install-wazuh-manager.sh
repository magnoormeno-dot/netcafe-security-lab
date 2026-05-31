#!/usr/bin/env bash
#
# install-wazuh-manager.sh
# [Run on CSL-Wazuh (Ubuntu Server, 10.10.10.10)]
# Installs the single-node Wazuh stack (manager + indexer + dashboard) -- an open-source SIEM. Purely defensive.
#
# === Important: two-phase setup ===
# The isolated network has no internet access. Choose one of two approaches:
#   (A) Temporary online phase: connect the host's NIC to a temporary External/NAT switch first, install Wazuh and system updates,
#       then switch back to the isolated Private switch and run the host/guest isolation verification scripts. This script performs an online install.
#   (B) Fully offline: download the wazuh-install offline bundle and dependencies ahead of time, inject them via ISO/Copy, and switch to an offline install.
# (A) is recommended: simple and reliable; once offline, 04-Verify-Isolation.ps1 + Test-GuestIsolation.ps1 prove compliance.
#
# --- Static IP (netplan) reference; configure this before going offline ---
#   sudo tee /etc/netplan/99-cafesec.yaml >/dev/null <<'YAML'
#   network:
#     version: 2
#     ethernets:
#       eth0:                      # Use `ip link` to confirm the actual NIC name
#         dhcp4: no
#         addresses: [10.10.10.10/24]
#         # Deliberately no gateway4 / nameservers -- the isolated network has no egress
#   YAML
#   sudo netplan apply
#
set -euo pipefail

WAZUH_BRANCH="4.9"

echo "=== CafeSec: installing the single-node Wazuh stack (branch ${WAZUH_BRANCH}) ==="
if [[ $EUID -ne 0 ]]; then echo "Please run with sudo"; exit 1; fi

# 1) Fetch the official all-in-one installer script (this step requires temporary internet access -- see the note at the top)
#    -f: HTTP errors (404 / proxy error pages) return non-zero -> caught by set -e; -S shows errors; -L follows redirects.
#    (curl -sO still exits 0 on a 404 and saves the error page to a file, which would later be executed as the installer -- -f must guard against this.)
curl -fsSL -o wazuh-install.sh "https://packages.wazuh.com/${WAZUH_BRANCH}/wazuh-install.sh"
# Integrity safeguard: only continue if the file is non-empty and starts with a shebang (blocks error pages / truncated content masquerading as the installer)
[[ -s wazuh-install.sh ]] && head -n1 wazuh-install.sh | grep -q '^#!' || {
    echo 'Failed to download wazuh-install.sh or its content is invalid (possibly a 404/proxy/truncation).' >&2; exit 1; }
# Note: config.yml is only used by the multi-node (-g/--generate-config-files) flow; this all-in-one install (-a) does not consume it, so there is no need to download it.

# 2) All-in-one install (manager + Wazuh indexer + dashboard all installed locally)
bash ./wazuh-install.sh -a -i

echo
echo "=== Installation complete ==="
echo "Dashboard:  https://10.10.10.10  (accessible only from a VM browser inside the isolated network)"
echo "Admin password:  sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt"
echo
echo "--- Enable agent auto-enrollment (authd) so Windows agents can register automatically ---"
echo "In /var/ossec/etc/ossec.conf, set <disabled>no</disabled> in the <auth> section, then:"
echo "  sudo systemctl restart wazuh-manager"
echo
echo "--- Verification ---"
echo "  sudo /var/ossec/bin/agent_control -l     # List connected agents"
echo "  sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard"
echo
echo ">>> Now switch this host's NIC back to the isolated Private switch and run the isolation verification scripts to confirm compliance. <<<"
