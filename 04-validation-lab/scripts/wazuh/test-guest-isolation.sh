#!/usr/bin/env bash
#
# test-guest-isolation.sh
# 【在 CSL-Wazuh (Ubuntu, 10.10.10.10) 内部运行】Test-GuestIsolation.ps1 的 Linux 镜像版。
# 证明:能 ping 通同网段 peer,但【绝对】出不了外网、碰不到宿主真实 LAN、无 DNS、无默认网关。
#
# 期望结果(任何一项"本应失败却成功"= 隔离破裂,脚本以非零退出):
#   - 同隔离网内的另一台 VM         -> 可达          (PASS)
#   - 公网 IP 1.1.1.1 / 8.8.8.8     -> 不可达         (PASS = 出不去)
#   - 公网域名 DNS 解析             -> 失败          (PASS)
#   - 常见家用/企业网段网关         -> 不可达         (PASS = 碰不到真实 LAN)
#   - 默认网关 (default route)      -> 不存在         (PASS)
#   - curl/TCP443 到公网            -> 失败          (PASS = 应用层也出不去)
#
# 用法:
#   chmod +x test-guest-isolation.sh
#   ./test-guest-isolation.sh                 # peer 默认 10.10.10.20 (CSL-Server)
#   ./test-guest-isolation.sh 10.10.10.31     # 指定其它同网段 peer
#
# 设计:纯防御,只读探测,不改任何配置。LF 行尾、set -u、仅用可移植工具(ping -c / timeout / ip)。
# 注:刻意不用 'set -e' —— 探测命令失败是预期内的,需逐项判定而非中途退出。

set -u

# ---- peer:同隔离网内另一台 VM(本机是 10.10.10.10,故默认指向 .20)----
PEER_IP="${1:-10.10.10.20}"

PASS=0
FAIL=0
GREEN=''; RED=''; CYAN=''; RESET=''
if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
fi

# run_quiet <command...>  -> 返回该命令退出码,丢弃所有输出
run_quiet() { "$@" >/dev/null 2>&1; }

# check <desc> <expect: ok|fail> <command...>
#   expect=ok   命令应成功(退出 0)
#   expect=fail 命令应失败(非 0)—— 隔离场景下"失败才是对的"
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

# 可移植的带超时 ping:-c 计数,-W 单包超时(秒),外层再裹 timeout 兜底
ping_host() {
    timeout 6 ping -c 2 -W 2 "$1"
}

# DNS 解析探测:优先 getent(无需额外包),退化到 host/nslookup
resolve_host() {
    name="$1"
    if command -v getent >/dev/null 2>&1; then
        timeout 5 getent ahosts "$name"
    elif command -v host >/dev/null 2>&1; then
        timeout 5 host "$name"
    elif command -v nslookup >/dev/null 2>&1; then
        timeout 5 nslookup "$name"
    else
        # 无任何解析工具 = 必然解析不了 = 符合隔离预期
        return 1
    fi
}

# 本机隔离网 IP(仅用于展示)
SELF_IP="$(ip -o -4 addr show 2>/dev/null | awk '/10\.10\.10\./ {print $4}' | cut -d/ -f1 | head -n1)"
[ -z "$SELF_IP" ] && SELF_IP='(未取得 10.10.10.x 地址)'

printf '\n%s=== 客户机隔离验证 (本机: %s, peer: %s) ===%s\n\n' "$CYAN" "$SELF_IP" "$PEER_IP" "$RESET"

# 1) 正向:能 ping 通同网段 peer(否则 agent->manager 日志收集会断)
check "可 ping 通隔离网内 peer ($PEER_IP)" ok ping_host "$PEER_IP"

# 2) 反向:公网 IP 必须不可达(含 IPv6,避免只测 IPv4 漏判 IPv6 通路)
check "公网 1.1.1.1 不可达(出不了外网)" fail ping_host '1.1.1.1'
check "公网 8.8.8.8 不可达(出不了外网)" fail ping_host '8.8.8.8'
check "公网 IPv6 2606:4700:4700::1111 不可达" fail ping_host '2606:4700:4700::1111'

# 3) 公网域名 DNS 解析必须失败(隔离网无 DNS、也无出口)
check "公网域名 DNS 解析失败 (www.microsoft.com)" fail resolve_host 'www.microsoft.com'

# 4) 常见真实家用/企业 LAN 网关不可达(确认碰不到宿主真实网络)
for gw in 192.168.1.1 192.168.0.1 192.168.31.1 10.0.0.1; do
    check "真实 LAN 网关 $gw 不可达" fail ping_host "$gw"
done

# 5) 本机不应存在默认网关(default route)。
#    注意:`ip route show default` 是查询命令,无论有无默认路由都返回 0,
#    若直接喂给 check(expect=fail)会在【正确隔离】时误报 FAIL。
#    改用"存在性"判定:仅当确有默认路由时 helper 才返回 0。
has_default_route()  { ip    route show default 2>/dev/null | grep -q .; }
has_default_route6() { ip -6 route show default 2>/dev/null | grep -q .; }
check "本机无默认网关 (IPv4 无 default route)" fail has_default_route
check "本机无默认网关 (IPv6 无 default route)" fail has_default_route6

# 6) 应用层:curl 到公网必须失败(短超时,无重试)
if command -v curl >/dev/null 2>&1; then
    check "curl 到公网失败 (http://1.1.1.1)" fail \
        timeout 8 curl -sS --max-time 5 --connect-timeout 4 -o /dev/null 'http://1.1.1.1'
else
    printf '%s[PASS]%s curl 到公网失败 (未安装 curl,视为不可出网)\n' "$GREEN" "$RESET"
    PASS=$((PASS + 1))
fi

# 7) 应用层:TCP 443 到公网必须失败(用 bash /dev/tcp,无需额外工具)
check "TCP 443 -> 公网失败 (1.1.1.1:443)" fail \
    timeout 6 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'

printf '\n%s=== 结果: PASS=%s  FAIL=%s ===%s\n' "$CYAN" "$PASS" "$FAIL" "$RESET"
if [ "$FAIL" -eq 0 ]; then
    printf '%s隔离已生效:此机连得到同网段 VM,但出不了外网、碰不到真实 LAN、无 DNS、无默认网关。合规。%s\n' "$GREEN" "$RESET"
else
    printf '%s隔离存在破口!立即停止任何研究活动并排查网卡/交换机配置(多半是某台 VM 还连着 External/NAT 交换机)。%s\n' "$RED" "$RESET"
fi

exit "$FAIL"
