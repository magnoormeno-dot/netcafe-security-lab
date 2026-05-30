#!/usr/bin/env bash
#
# install-wazuh-manager.sh
# 【在 CSL-Wazuh (Ubuntu Server, 10.10.10.10) 上运行】
# 安装 Wazuh 单机版 (manager + indexer + dashboard) —— 开源 SIEM。纯防御。
#
# === 重要:两阶段搭建 ===
# 隔离网无法联网。两种做法二选一:
#   (A) 临时联网阶段:把本机网卡先接到临时 External/NAT 交换机,装完 Wazuh 与系统更新,
#       再切回隔离 Private 交换机并运行宿主/客户机隔离验证脚本。本脚本走在线安装。
#   (B) 全离线:提前下载 wazuh-install 离线包与依赖,放进 ISO/Copy 注入,改用离线安装。
# 推荐 (A):简单可靠,断网后由 04-Verify-Isolation.ps1 + Test-GuestIsolation.ps1 证明合规。
#
# --- 静态 IP (netplan) 参考,断网前先配好 ---
#   sudo tee /etc/netplan/99-cafesec.yaml >/dev/null <<'YAML'
#   network:
#     version: 2
#     ethernets:
#       eth0:                      # 用 `ip link` 确认实际网卡名
#         dhcp4: no
#         addresses: [10.10.10.10/24]
#         # 刻意不配 gateway4 / nameservers —— 隔离网无出口
#   YAML
#   sudo netplan apply
#
set -euo pipefail

WAZUH_BRANCH="4.9"

echo "=== CafeSec: 安装 Wazuh 单机版 (branch ${WAZUH_BRANCH}) ==="
if [[ $EUID -ne 0 ]]; then echo "请用 sudo 运行"; exit 1; fi

# 1) 取官方一体化安装脚本(此步骤需临时联网 —— 见顶部说明)
#    -f: HTTP 错误(404/代理错误页)返回非零 -> 被 set -e 捕获;-S 显示错误;-L 跟随跳转。
#    (curl -sO 在 404 时仍退出 0 并把错误页存成文件,会被后面当安装脚本执行 —— 必须用 -f 防住。)
curl -fsSL -o wazuh-install.sh "https://packages.wazuh.com/${WAZUH_BRANCH}/wazuh-install.sh"
# 完整性兜底:文件非空且以 shebang 开头才继续(挡住错误页/截断内容冒充安装脚本)
[[ -s wazuh-install.sh ]] && head -n1 wazuh-install.sh | grep -q '^#!' || {
    echo 'wazuh-install.sh 下载失败或内容异常(可能是 404/代理/截断)。' >&2; exit 1; }
# 注:config.yml 仅用于多节点 (-g/--generate-config-files) 流程,本一体化安装 (-a) 不消费它,无需下载。

# 2) 一体化安装(manager + Wazuh indexer + dashboard 全装本机)
bash ./wazuh-install.sh -a -i

echo
echo "=== 安装完成 ==="
echo "Dashboard:  https://10.10.10.10  (仅限隔离网内的 VM 浏览器访问)"
echo "管理员密码:  sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt"
echo
echo "--- 开启 agent 自动注册 (authd),便于 Windows agent 自动注册 ---"
echo "编辑 /var/ossec/etc/ossec.conf 的 <auth> 段把 <disabled>no</disabled>,然后:"
echo "  sudo systemctl restart wazuh-manager"
echo
echo "--- 验证 ---"
echo "  sudo /var/ossec/bin/agent_control -l     # 列出已连接 agent"
echo "  sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard"
echo
echo ">>> 现在把本机网卡切回隔离 Private 交换机,并运行隔离验证脚本确认合规。<<<"
