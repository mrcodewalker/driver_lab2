#!/usr/bin/env bash
# =============================================================
# compile.bash — Build AIC Semi USB Kernel Module v4.0
# Build: usb.ko + monitor (ncurses) + demo (raw socket)
# =============================================================
set -euo pipefail

RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m';  MAGENTA='\033[0;35m'
BOLD='\033[1m';    DIM='\033[2m';      RESET='\033[0m'

DRIVER_NAME="usb"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_LOG="/tmp/aicsemi_build.log"

sep()      { echo -e "${DIM}${CYAN}  ────────────────────────────────────────────────────${RESET}"; }
sep_bold() { echo -e "${BOLD}${CYAN}  ════════════════════════════════════════════════════${RESET}"; }
log_info() { echo -e "  ${CYAN}[ℹ]${RESET}  $*"; }
log_ok()   { echo -e "  ${GREEN}[✓]${RESET}  $*"; }
log_warn() { echo -e "  ${YELLOW}[⚠]${RESET}  $*"; }
log_err()  { echo -e "  ${RED}[✗]${RESET}  $*"; }
log_step() { echo -e "\n${BOLD}${BLUE}  ┌─ $* ${RESET}"; }

echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║   AIC Semi USB WiFi — Build Script v4.0              ║"
echo "  ║   Build: usb.ko + monitor + demo                     ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
sep
echo -e "  ${BOLD}Driver${RESET}   : ${CYAN}${DRIVER_NAME}.ko${RESET}"
echo -e "  ${BOLD}Kernel${RESET}   : ${CYAN}$(uname -r)${RESET}"
echo -e "  ${BOLD}Arch${RESET}     : ${CYAN}$(uname -m)${RESET}"
echo -e "  ${BOLD}Thư mục${RESET} : ${CYAN}${SCRIPT_DIR}${RESET}"
echo -e "  ${BOLD}Thời gian${RESET}: ${CYAN}$(date '+%Y-%m-%d %H:%M:%S')${RESET}"
sep

# =============================================================
log_step "BƯỚC 1 — Kiểm tra môi trường"
sep
# =============================================================

KERNEL_DIR="/lib/modules/$(uname -r)/build"
[ -d "$KERNEL_DIR" ] && log_ok "Kernel headers: $KERNEL_DIR" || {
    log_err "Không tìm thấy kernel headers: $KERNEL_DIR"
    log_warn "Cài: sudo apt install linux-headers-$(uname -r)"
    exit 1
}

command -v make &>/dev/null && log_ok "make: $(make --version | head -1)" || {
    log_err "make không có. Cài: sudo apt install build-essential"; exit 1; }

command -v gcc &>/dev/null  && log_ok "gcc : $(gcc --version | head -1)" || {
    log_err "gcc không có. Cài: sudo apt install build-essential"; exit 1; }

[ -f "${SCRIPT_DIR}/${DRIVER_NAME}.c" ] && \
    log_ok "Source: ${DRIVER_NAME}.c ($(wc -l < "${SCRIPT_DIR}/${DRIVER_NAME}.c") dòng)" || {
    log_err "Không thấy ${DRIVER_NAME}.c"; exit 1; }

[ -f "${SCRIPT_DIR}/Makefile" ] && log_ok "Makefile: OK" || {
    log_err "Không thấy Makefile"; exit 1; }

[ -f "${SCRIPT_DIR}/monitor.c" ] && \
    log_ok "monitor.c: $(wc -l < "${SCRIPT_DIR}/monitor.c") dòng" || \
    log_warn "Không thấy monitor.c — sẽ bỏ qua build monitor"

[ -f "${SCRIPT_DIR}/demo.c" ] && \
    log_ok "demo.c   : $(wc -l < "${SCRIPT_DIR}/demo.c") dòng" || \
    log_warn "Không thấy demo.c — sẽ bỏ qua build demo"

# Kiểm tra ncurses cho monitor
if pkg-config --libs ncurses >/dev/null 2>&1; then
    NCURSES_LIBS=$(pkg-config --libs ncurses)
    log_ok "ncurses  : OK ($NCURSES_LIBS)"
elif [ -f /usr/lib/x86_64-linux-gnu/libncurses.so ] || \
     [ -f /usr/lib/libncurses.so ]; then
    NCURSES_LIBS="-lncurses"
    log_ok "ncurses  : OK (-lncurses)"
else
    NCURSES_LIBS="-lncurses"
    log_warn "ncurses: Nếu build monitor lỗi, cài: sudo apt install libncurses-dev"
fi

KVER_MAJOR=$(uname -r | cut -d. -f1)
KVER_MINOR=$(uname -r | cut -d. -f2)
if [ "$KVER_MAJOR" -ge 6 ] && [ "$KVER_MINOR" -ge 7 ]; then
    log_ok "Kernel ≥ 6.7: timer_container_of / timer_delete_sync ✓"
else
    log_ok "Kernel < 6.7: from_timer / del_timer_sync ✓"
fi
sep

# =============================================================
log_step "BƯỚC 2 — Dọn build cũ"
sep
# =============================================================

cd "$SCRIPT_DIR"
make clean 2>/dev/null || true
log_ok "Đã dọn sạch"
sep

# =============================================================
log_step "BƯỚC 3 — Build kernel module (usb.ko)"
sep
# =============================================================

log_info "Đang biên dịch ${DRIVER_NAME}.c → ${DRIVER_NAME}.ko ..."
echo ""

BUILD_START=$(date +%s%N)
make module 2>&1 | tee "$BUILD_LOG" | while IFS= read -r line; do
    if   echo "$line" | grep -qE "^  CC";     then echo -e "  ${DIM}${CYAN}⚙${RESET}  ${DIM}$line${RESET}"
    elif echo "$line" | grep -qE "^  LD|MODPOST|MODINFO"; then echo -e "  ${DIM}${BLUE}⚙${RESET}  ${DIM}$line${RESET}"
    elif echo "$line" | grep -qi "error:";   then echo -e "  ${RED}✗  $line${RESET}"
    elif echo "$line" | grep -qi "warning:"; then echo -e "  ${YELLOW}⚠  $line${RESET}"
    fi
done
BUILD_END=$(date +%s%N)
BUILD_MS=$(( (BUILD_END - BUILD_START) / 1000000 ))
echo ""

if [ ! -f "${SCRIPT_DIR}/${DRIVER_NAME}.ko" ]; then
    log_err "Build THẤT BẠI — usb.ko không được tạo!"
    grep -i "error:" "$BUILD_LOG" | head -10 | while IFS= read -r l; do
        echo -e "    ${RED}→ $l${RESET}"; done
    exit 1
fi

log_ok "usb.ko build xong trong ${BUILD_MS}ms"
WARN_COUNT=$(grep -c "warning:" "$BUILD_LOG" 2>/dev/null || echo "0")
[ "$WARN_COUNT" -gt 0 ] && \
    log_warn "${WARN_COUNT} warning — xem: grep warning: $BUILD_LOG" || \
    log_ok "Không có warning"
sep

# =============================================================
log_step "BƯỚC 4 — Build monitor (ncurses dashboard)"
sep
# =============================================================

if [ -f "${SCRIPT_DIR}/monitor.c" ]; then
    log_info "Build monitor.c → monitor ..."
    if gcc -Wall -O2 -o monitor monitor.c $NCURSES_LIBS 2>/tmp/monitor_build.log; then
        log_ok "monitor build xong ($(du -h monitor | cut -f1))"
        log_info "Dùng: sudo ./monitor aic0"
    else
        log_warn "Build monitor thất bại:"
        cat /tmp/monitor_build.log | grep "error:" | head -5 | while IFS= read -r l; do
            echo -e "    ${YELLOW}→ $l${RESET}"; done
        log_warn "Cài ncurses: sudo apt install libncurses-dev"
    fi
else
    log_warn "Không thấy monitor.c — bỏ qua"
fi
sep

# =============================================================
log_step "BƯỚC 5 — Build demo (raw packet sender)"
sep
# =============================================================

if [ -f "${SCRIPT_DIR}/demo.c" ]; then
    log_info "Build demo.c → demo ..."
    if gcc -Wall -O2 -o demo demo.c 2>/tmp/demo_build.log; then
        log_ok "demo build xong ($(du -h demo | cut -f1))"
        log_info "Dùng: sudo ./demo [interface]"
    else
        log_err "Build demo thất bại:"
        cat /tmp/demo_build.log | grep "error:" | head -5 | while IFS= read -r l; do
            echo -e "    ${RED}→ $l${RESET}"; done
    fi
else
    log_warn "Không thấy demo.c — bỏ qua"
fi
sep

# =============================================================
log_step "BƯỚC 6 — Thông tin module"
sep
# =============================================================

KO_FILE="${SCRIPT_DIR}/${DRIVER_NAME}.ko"
log_info "File     : $KO_FILE ($(du -h "$KO_FILE" | cut -f1))"
log_info "Phiên bản: ${MAGENTA}$(modinfo "$KO_FILE" 2>/dev/null | grep "^version" | awk '{print $2}')${RESET}"
log_info "Mô tả    : $(modinfo "$KO_FILE" 2>/dev/null | grep "^description" | cut -d: -f2 | xargs)"
log_info "Giấy phép: $(modinfo "$KO_FILE" 2>/dev/null | grep "^license" | awk '{$1="";print $0}' | xargs)"
log_info "vermagic : $(modinfo "$KO_FILE" 2>/dev/null | grep "^vermagic" | cut -d: -f2 | xargs | cut -d' ' -f1)"
sep
log_info "USB ID Table:"
log_info "  ${CYAN}a69c:5721${RESET}  →  USB Mass Storage (Mode 1 — modeswitch)"
log_info "  ${GREEN}a69c:8d80${RESET}  →  AIC WLAN Mode    (Mode 2 — tạo aic0)"
sep

# =============================================================
echo ""
sep_bold
echo -e "  ${GREEN}${BOLD}  ✓  BUILD HOÀN THÀNH!${RESET}"
sep_bold
echo ""
echo -e "  ${BOLD}Thứ tự chạy:${RESET}"
echo ""
echo -e "  ${DIM}# 1. Setup driver (cắm USB trước)${RESET}"
echo -e "  ${CYAN}  sudo ./setup.bash${RESET}"
echo ""
echo -e "  ${DIM}# 2. Mở monitor dashboard (terminal riêng)${RESET}"
echo -e "  ${CYAN}  sudo ./monitor aic0${RESET}"
echo ""
echo -e "  ${DIM}# 3. Gửi packets để xem trên monitor${RESET}"
echo -e "  ${CYAN}  sudo ./demo${RESET}"
echo ""
echo -e "  ${DIM}# Hoặc xem log thô${RESET}"
echo -e "  ${CYAN}  sudo dmesg -w | grep --color aicsemi${RESET}"
echo ""
