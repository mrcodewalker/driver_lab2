#!/usr/bin/env bash
# =============================================================
# restart.bash — Unload → Load lại driver AIC Semi USB
# Đề tài: USB Multi-Mode Network Driver
#
# Flow:
#   1. Kiểm tra quyền root
#   2. Tắt + unload module cũ
#   3. Gỡ module cạnh tranh (usb_storage)
#   4. Load module mới
#   5. Bật interface aic0 + gán IP
#   6. Kiểm tra /proc, lsmod, dmesg
# =============================================================
set -euo pipefail

# ── Màu sắc ────────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m';   BLUE='\033[0;34m';  MAGENTA='\033[0;35m'
BOLD='\033[1m';      DIM='\033[2m';       RESET='\033[0m'

DRIVER_NAME="usb"
MODULE_NAME="aicsemi_multimode"   # tên trong MODULE_AUTHOR / lsmod
IFACE="aic0"
IFACE_IP="192.168.99.1/24"
PROC_DIR="/proc/aicsemi_usbnet"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KO_FILE="${SCRIPT_DIR}/${DRIVER_NAME}.ko"

# ── Helpers ────────────────────────────────────────────────────
sep()      { echo -e "${DIM}${CYAN}  ────────────────────────────────────────────────────${RESET}"; }
sep_bold() { echo -e "${BOLD}${CYAN}  ════════════════════════════════════════════════════${RESET}"; }
log_info() { echo -e "  ${CYAN}[ℹ]${RESET}  $*"; }
log_ok()   { echo -e "  ${GREEN}[✓]${RESET}  $*"; }
log_warn() { echo -e "  ${YELLOW}[⚠]${RESET}  $*"; }
log_err()  { echo -e "  ${RED}[✗]${RESET}  $*"; }
log_step() { echo -e "\n${BOLD}${BLUE}  ┌─ $* ${RESET}"; }
log_run()  { echo -e "  ${DIM}»${RESET}  ${DIM}$*${RESET}"; }

# ── Kiểm tra root ──────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo -e "  ${RED}${BOLD}[✗] Script này cần quyền root!${RESET}"
    echo -e "  Chạy lại: ${CYAN}sudo ./restart.bash${RESET}"
    echo ""
    exit 1
fi

# ── Banner ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║       AIC Semi USB WiFi — Driver Restart             ║"
echo "  ║       Đề tài: USB Multi-Mode Network Driver          ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
sep
echo -e "  ${BOLD}Module${RESET}  : ${CYAN}${MODULE_NAME}${RESET}"
echo -e "  ${BOLD}File${RESET}    : ${CYAN}${KO_FILE}${RESET}"
echo -e "  ${BOLD}Kernel${RESET}  : ${CYAN}$(uname -r)${RESET}"
echo -e "  ${BOLD}PID${RESET}     : ${CYAN}$$${RESET}"
echo -e "  ${BOLD}Thời gian${RESET}: ${CYAN}$(date '+%Y-%m-%d %H:%M:%S')${RESET}"
sep

# =============================================================
log_step "BƯỚC 1 — Kiểm tra file .ko"
sep
# =============================================================

if [ ! -f "$KO_FILE" ]; then
    log_err "Không tìm thấy ${KO_FILE}"
    log_warn "Cần build trước: ./compile.bash"
    exit 1
fi

KO_SIZE=$(du -h "$KO_FILE" | cut -f1)
KO_VER=$(modinfo "$KO_FILE" 2>/dev/null | grep "^version" | awk '{print $2}')
KO_TS=$(stat -c '%y' "$KO_FILE" | cut -d'.' -f1)

log_ok "Tìm thấy: ${KO_FILE}"
log_info "Kích thước : ${KO_SIZE}"
log_info "Phiên bản  : ${MAGENTA}${KO_VER}${RESET}"
log_info "Build lúc  : ${KO_TS}"
sep

# =============================================================
log_step "BƯỚC 2 — Dọn dẹp trạng thái cũ"
sep
# =============================================================

# 2a. Tắt interface nếu đang UP
log_info "Kiểm tra interface mạng cũ..."
for iface in aic0 usb0; do
    if ip link show "$iface" &>/dev/null 2>&1; then
        STATE=$(ip link show "$iface" | grep -oP '(?<=state )\w+')
        log_warn "Phát hiện interface '$iface' (state=$STATE) — đang tắt..."
        log_run "ip addr flush dev $iface"
        ip addr flush dev "$iface" 2>/dev/null || true
        log_run "ip link set $iface down"
        ip link set "$iface" down 2>/dev/null || true
        log_ok "Interface '$iface' đã tắt"
    fi
done

# 2b. Unload module hiện tại (thử cả tên ngắn và tên đầy đủ)
log_info "Kiểm tra module đang load..."
UNLOADED=0
for mod in "$MODULE_NAME" "$DRIVER_NAME"; do
    if lsmod | grep -q "^${mod}[[:space:]]"; then
        log_warn "Module '${mod}' đang chạy — đang unload..."
        log_run "rmmod ${mod}"
        if rmmod "$mod" 2>/dev/null; then
            log_ok "Đã unload module '${mod}'"
            UNLOADED=1
            sleep 1
        else
            log_warn "rmmod thất bại, thử force..."
            rmmod -f "$mod" 2>/dev/null || log_warn "Không thể force unload — tiếp tục"
        fi
        break
    fi
done
if [ "$UNLOADED" -eq 0 ]; then
    log_ok "Không có module cũ đang chạy"
fi
sep

# =============================================================
log_step "BƯỚC 3 — Xử lý module cạnh tranh (usb-storage)"
sep
# =============================================================

log_info "Lý do: usb-storage thường bind vào thiết bị 0x5721 trước driver ta"
log_info "Giải pháp: gỡ tạm để driver aicsemi có thể probe được"
echo ""

REMOVED_COMPETING=0
for mod in usb_storage uas; do
    if lsmod | grep -q "^${mod}[[:space:]]"; then
        # Kiểm tra xem module có đang dùng không
        USED=$(lsmod | grep "^${mod}[[:space:]]" | awk '{print $3}')
        if [ "$USED" -gt 0 ]; then
            log_warn "Module '${mod}' đang bị giữ bởi ${USED} thiết bị khác — bỏ qua"
            log_info "  Nếu cần, rút thiết bị USB storage khác trước"
        else
            log_info "Gỡ module cạnh tranh: ${mod}..."
            log_run  "rmmod ${mod}"
            if rmmod "$mod" 2>/dev/null; then
                log_ok "Đã gỡ: ${mod}"
                REMOVED_COMPETING=1
            else
                log_warn "Không gỡ được ${mod} — tiếp tục"
            fi
        fi
    else
        log_ok "${mod}: không đang load"
    fi
done

# Unbind usb-storage khỏi thiết bị AIC nếu vẫn còn bind
AIC_IFACE_PATH=$(find /sys/bus/usb/devices -name "idVendor" \
    -exec grep -l "a69c" {} \; 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true)

if [ -n "$AIC_IFACE_PATH" ]; then
    BOUND_DRIVER=$(readlink "${AIC_IFACE_PATH}/driver" 2>/dev/null | xargs basename 2>/dev/null || true)
    if [ "$BOUND_DRIVER" = "usb-storage" ] || [ "$BOUND_DRIVER" = "usb_storage" ]; then
        DEV_INTF="${AIC_IFACE_PATH##*/}"
        log_warn "usb-storage đang bind vào thiết bị AIC (${DEV_INTF})"
        log_run  "echo -n '${DEV_INTF}:1.0' > /sys/bus/usb/drivers/usb-storage/unbind"
        echo -n "${DEV_INTF}:1.0" > /sys/bus/usb/drivers/usb-storage/unbind 2>/dev/null || true
        log_ok "Đã unbind usb-storage khỏi thiết bị AIC"
    fi
fi

if [ "$REMOVED_COMPETING" -eq 0 ]; then
    log_info "Không cần gỡ module cạnh tranh"
fi
sep

# =============================================================
log_step "BƯỚC 4 — Load module mới"
sep
# =============================================================

log_info "Đang load ${KO_FILE}..."
log_run  "insmod ${KO_FILE}"

if ! insmod "$KO_FILE" 2>/tmp/insmod_err; then
    log_err "insmod THẤT BẠI!"
    ERR_MSG=$(cat /tmp/insmod_err)
    log_err "Lý do: ${ERR_MSG}"
    echo ""
    log_warn "Kiểm tra dmesg để biết thêm:"
    dmesg | tail -10 | while IFS= read -r line; do
        echo -e "    ${DIM}$line${RESET}"
    done
    exit 1
fi

# Đợi kernel chạy probe()
log_info "Đang chờ kernel gọi probe()..."
sleep 1

# Xác nhận module đã load
if lsmod | grep -qE "^(${MODULE_NAME}|${DRIVER_NAME})[[:space:]]"; then
    MODULE_INFO=$(lsmod | grep -E "^(${MODULE_NAME}|${DRIVER_NAME})[[:space:]]")
    MOD_SIZE=$(echo "$MODULE_INFO" | awk '{print $2}')
    log_ok "Module đã load thành công!"
    log_info "Thông tin lsmod:"
    log_info "  Tên      : $(echo "$MODULE_INFO" | awk '{print $1}')"
    log_info "  Kích thước: ${MOD_SIZE} bytes"
else
    log_warn "Module không xuất hiện trong lsmod — có thể đã probe xong và unload"
fi
sep

# =============================================================
log_step "BƯỚC 5 — Thiết lập network interface"
sep
# =============================================================

log_info "Kiểm tra interface ${IFACE}..."
sleep 1   # thêm thời gian cho probe() tạo interface

if ip link show "$IFACE" &>/dev/null 2>&1; then
    MAC=$(ip link show "$IFACE" | grep -oP '(?<=link/ether )[\da-f:]+')
    log_ok "Interface '${IFACE}' đã xuất hiện — MAC: ${MAC}"

    log_info "Bật interface..."
    log_run  "ip link set ${IFACE} up"
    ip link set "$IFACE" up

    log_info "Gán địa chỉ IP: ${IFACE_IP}..."
    log_run  "ip addr add ${IFACE_IP} dev ${IFACE}"
    ip addr add "$IFACE_IP" dev "$IFACE" 2>/dev/null || \
        log_warn "IP đã tồn tại — bỏ qua"

    # Xác nhận
    sleep 0.5
    IP_ASSIGNED=$(ip addr show "$IFACE" | grep "inet " | awk '{print $2}' || true)
    if [ -n "$IP_ASSIGNED" ]; then
        log_ok "IP đã gán: ${GREEN}${IP_ASSIGNED}${RESET}"
    fi

else
    log_warn "Interface '${IFACE}' chưa xuất hiện"
    log_info "Thiết bị có thể đang ở Storage mode (0x5721)"
    log_info "Driver đã gửi modeswitch command — thiết bị sẽ re-enumerate"
    log_info "Cắm lại thiết bị USB nếu interface vẫn chưa xuất hiện"
fi
sep

# =============================================================
log_step "BƯỚC 6 — Kiểm tra /proc interface"
sep
# =============================================================

log_info "Kiểm tra /proc/aicsemi_usbnet..."
if [ -d "$PROC_DIR" ] && [ -f "${PROC_DIR}/monitor" ]; then
    log_ok "Proc monitor: ${PROC_DIR}/monitor"
    log_info "Nội dung hiện tại:"
    echo ""
    cat "${PROC_DIR}/monitor" 2>/dev/null | while IFS= read -r line; do
        echo -e "    ${DIM}${line}${RESET}"
    done
    echo ""
else
    log_info "/proc/aicsemi_usbnet: chưa có"
    log_info "Sẽ xuất hiện sau khi thiết bị ở WiFi mode (0x8d80)"
fi
sep

# =============================================================
log_step "BƯỚC 7 — Kiểm tra dmesg"
sep
# =============================================================

log_info "Log kernel gần nhất từ driver:"
echo ""
# Lấy log của chính driver (ưu tiên) hoặc log USB
DMESG_LINES=$(dmesg | grep -E "\[aicsemi\]|a69c:5721|a69c:8d80" | tail -20)
if [ -n "$DMESG_LINES" ]; then
    echo "$DMESG_LINES" | while IFS= read -r line; do
        if echo "$line" | grep -q "✓\|thành công\|THÀNH CÔNG\|READY\|UP"; then
            echo -e "    ${GREEN}${line}${RESET}"
        elif echo "$line" | grep -q "✗\|THẤT BẠI\|error\|Error"; then
            echo -e "    ${RED}${line}${RESET}"
        elif echo "$line" | grep -q "⚠\|WARN\|warn"; then
            echo -e "    ${YELLOW}${line}${RESET}"
        else
            echo -e "    ${DIM}${line}${RESET}"
        fi
    done
else
    # Fallback: 15 dòng cuối bất kỳ
    dmesg | tail -15 | while IFS= read -r line; do
        echo -e "    ${DIM}${line}${RESET}"
    done
fi
echo ""
sep

# =============================================================
log_step "BƯỚC 8 — Tóm tắt trạng thái"
sep
# =============================================================

echo ""
echo -e "  ${BOLD}Module:${RESET}"
if lsmod | grep -qE "^(${MODULE_NAME}|${DRIVER_NAME})[[:space:]]"; then
    log_ok "lsmod: module đang chạy"
else
    log_warn "lsmod: module không thấy (có thể đã exit sau probe)"
fi

echo ""
echo -e "  ${BOLD}Network interface:${RESET}"
if ip link show "$IFACE" &>/dev/null 2>&1; then
    IFACE_STATE=$(ip link show "$IFACE" | grep -oP '(?<=state )\w+')
    IFACE_IP_SHOW=$(ip addr show "$IFACE" | grep "inet " | awk '{print $2}' || echo "(chưa có IP)")
    log_ok "${IFACE} — state=${IFACE_STATE} — IP=${IFACE_IP_SHOW}"
else
    log_warn "${IFACE}: chưa có (thiết bị chưa ở WiFi mode)"
fi

echo ""
echo -e "  ${BOLD}Proc filesystem:${RESET}"
if [ -f "${PROC_DIR}/monitor" ]; then
    log_ok "${PROC_DIR}/monitor: OK"
else
    log_warn "${PROC_DIR}/monitor: chưa tạo"
fi

sep

# =============================================================
sep_bold
echo -e "  ${GREEN}${BOLD}  ✓  DRIVER RESTART HOÀN THÀNH!${RESET}"
sep_bold
echo ""
echo -e "  ${BOLD}Lệnh để demo và thuyết trình:${RESET}"
echo ""
echo -e "  ${DIM}# Xem log real-time${RESET}"
echo -e "  ${CYAN}sudo dmesg -w${RESET}"
echo ""
echo -e "  ${DIM}# Gửi gói ICMP (cần interface UP)${RESET}"
echo -e "  ${CYAN}ping -c 5 192.168.99.2${RESET}"
echo ""
echo -e "  ${DIM}# Gửi raw packet đa dạng giao thức qua driver${RESET}"
echo -e "  ${CYAN}gcc -Wall -O2 -o demo demo.c && sudo ./demo${RESET}"
echo ""
echo -e "  ${DIM}# Xem thống kê packet realtime${RESET}"
echo -e "  ${CYAN}watch -n 1 cat /proc/aicsemi_usbnet/monitor${RESET}"
echo ""
echo -e "  ${DIM}# Thông tin interface${RESET}"
echo -e "  ${CYAN}ip addr show aic0${RESET}"
echo -e "  ${CYAN}ethtool aic0${RESET}"
echo ""
echo -e "  ${DIM}# Kiểm tra module${RESET}"
echo -e "  ${CYAN}lsmod | grep aicsemi${RESET}"
echo -e "  ${CYAN}modinfo ./usb.ko${RESET}"
echo ""
