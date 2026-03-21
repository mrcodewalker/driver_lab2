#!/usr/bin/env bash
# =============================================================
# restart.bash — Unload → Load lại driver (không cần cắm lại USB)
# Dùng khi: đã có driver chạy, muốn reload sau khi sửa code
#
# Khác với setup.bash:
#   restart.bash = reload module đơn giản
#   setup.bash   = full setup từ đầu (unbind + modeswitch + wait)
# =============================================================
set -euo pipefail

RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m';  BOLD='\033[1m'
DIM='\033[2m';     RESET='\033[0m'

DRIVER_NAME="usb"
MODULE_NAME="aicsemi_multimode"
IFACE="aic0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KO_FILE="${SCRIPT_DIR}/${DRIVER_NAME}.ko"

sep()      { echo -e "${DIM}${CYAN}  ────────────────────────────────────────────────────${RESET}"; }
sep_bold() { echo -e "${BOLD}${CYAN}  ════════════════════════════════════════════════════${RESET}"; }
log_info() { echo -e "  ${CYAN}[ℹ]${RESET}  $*"; }
log_ok()   { echo -e "  ${GREEN}[✓]${RESET}  $*"; }
log_warn() { echo -e "  ${YELLOW}[⚠]${RESET}  $*"; }
log_err()  { echo -e "  ${RED}[✗]${RESET}  $*"; }
log_step() { echo -e "\n${BOLD}${BLUE}  ┌─ $* ${RESET}"; }

[ "$EUID" -ne 0 ] && {
    echo -e "  ${RED}[✗]${RESET} Cần sudo: sudo ./restart.bash"; exit 1; }

echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║   AIC Semi USB WiFi — Driver Restart                 ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
sep
echo -e "  ${BOLD}Module${RESET}    : ${CYAN}${MODULE_NAME}${RESET}"
echo -e "  ${BOLD}File${RESET}      : ${CYAN}${KO_FILE}${RESET}"
echo -e "  ${BOLD}Kernel${RESET}    : ${CYAN}$(uname -r)${RESET}"
echo -e "  ${BOLD}Thời gian${RESET} : ${CYAN}$(date '+%Y-%m-%d %H:%M:%S')${RESET}"
sep

# =============================================================
log_step "BƯỚC 1 — Kiểm tra file .ko"
sep
# =============================================================

[ -f "$KO_FILE" ] || {
    log_err "Không thấy ${KO_FILE}"
    log_warn "Chạy ./compile.bash trước"
    exit 1
}
log_ok "usb.ko: $(du -h "$KO_FILE" | cut -f1)  ver=$(modinfo "$KO_FILE" 2>/dev/null | grep "^version" | awk '{print $2}')"
sep

# =============================================================
log_step "BƯỚC 2 — Dọn trạng thái cũ"
sep
# =============================================================

# Tắt interface
for iface in aic0 aic1 usb0; do
    ip link show "$iface" &>/dev/null 2>&1 || continue
    log_info "Tắt interface $iface..."
    ip addr flush dev "$iface" 2>/dev/null || true
    ip link set "$iface" down   2>/dev/null || true
    log_ok "Interface $iface đã tắt"
done

# Unload module
for mod in "$MODULE_NAME" "$DRIVER_NAME"; do
    lsmod | grep -q "^${mod}[[:space:]]" || continue
    log_info "Unload module: $mod"
    rmmod "$mod" 2>/dev/null && log_ok "Unload $mod OK" || \
        log_warn "Không unload được $mod"
    sleep 1
    break
done
sep

# =============================================================
log_step "BƯỚC 3 — Unbind usb-storage (nếu cần)"
sep
# =============================================================

# Tìm thiết bị AIC và unbind nếu usb-storage đang giữ
AIC_UNBOUND=0
for d in /sys/bus/usb/devices/*/; do
    [ -f "${d}idVendor" ] || continue
    vendor=$(cat "${d}idVendor" 2>/dev/null || true)
    [ "$vendor" = "a69c" ] || continue

    dev=$(basename "${d%/}")
    intf="${dev}:1.0"
    intf_path="/sys/bus/usb/devices/${intf}"

    [ -L "${intf_path}/driver" ] || continue
    drv=$(readlink "${intf_path}/driver" | xargs basename)

    if [ "$drv" = "usb-storage" ] || [ "$drv" = "usb_storage" ]; then
        log_warn "usb-storage bind vào ${intf} — đang unbind..."
        echo -n "${intf}" > "/sys/bus/usb/drivers/usb-storage/unbind" 2>/dev/null && {
            log_ok "Đã unbind usb-storage"
            AIC_UNBOUND=1
        } || log_warn "Unbind thất bại"
    fi
done

[ "$AIC_UNBOUND" -eq 0 ] && log_ok "usb-storage không chiếm thiết bị AIC"
sep

# =============================================================
log_step "BƯỚC 4 — Load module"
sep
# =============================================================

log_info "insmod ${KO_FILE}..."
insmod "$KO_FILE" 2>/tmp/insmod_err && log_ok "insmod thành công" || {
    log_err "insmod thất bại: $(cat /tmp/insmod_err)"
    exit 1
}
sleep 2   # chờ probe()
sep

# =============================================================
log_step "BƯỚC 5 — Thiết lập interface"
sep
# =============================================================

FOUND=""
sleep 1
for iface in aic0 aic1; do
    ip link show "$iface" &>/dev/null 2>&1 && FOUND="$iface" && break
done

if [ -n "$FOUND" ]; then
    MAC=$(ip link show "$FOUND" | grep -oP '(?<=link/ether )[\da-f:]+')
    log_ok "Interface $FOUND xuất hiện — MAC: $MAC"
    ip link set "$FOUND" up
    ip addr add 192.168.99.1/24 dev "$FOUND" 2>/dev/null || true
    IP=$(ip addr show "$FOUND" | grep "inet " | awk '{print $2}')
    log_ok "IP: $IP"
else
    log_warn "Interface aic0/aic1 chưa có"
    log_info "Thiết bị có thể ở Storage mode — thử sudo ./setup.bash"
fi
sep

# =============================================================
log_step "BƯỚC 6 — Dmesg và /proc"
sep
# =============================================================

log_info "dmesg driver (10 dòng cuối):"
echo ""
dmesg | grep -E "\[aicsemi\]" | tail -10 | while IFS= read -r line; do
    if echo "$line" | grep -qE "✓|thành công|WIFI|UP"; then
        echo -e "    ${GREEN}${line}${RESET}"
    elif echo "$line" | grep -qE "✗|thất bại|error"; then
        echo -e "    ${RED}${line}${RESET}"
    else
        echo -e "    ${DIM}${line}${RESET}"
    fi
done
echo ""

if [ -f "/proc/aicsemi_usbnet/monitor" ]; then
    log_ok "/proc/aicsemi_usbnet/monitor: OK"
else
    log_info "/proc chưa có (thiết bị chưa ở WiFi mode)"
fi
sep

# =============================================================
sep_bold
echo -e "  ${GREEN}${BOLD}  ✓  RESTART HOÀN THÀNH${RESET}"
sep_bold
echo ""
echo -e "  ${BOLD}Tiếp theo:${RESET}"
echo -e "  ${DIM}# Mở monitor trước (terminal riêng):${RESET}"
echo -e "  ${CYAN}  sudo ./monitor aic0${RESET}"
echo ""
echo -e "  ${DIM}# Rồi gửi packets:${RESET}"
echo -e "  ${CYAN}  sudo ./demo${RESET}"
echo ""
echo -e "  ${DIM}# Hoặc xem log thô:${RESET}"
echo -e "  ${CYAN}  sudo dmesg -w | grep --color aicsemi${RESET}"
echo ""
