#!/usr/bin/env bash
# =============================================================
# compile.bash — Build AIC Semi USB Kernel Module
# Đề tài: USB Multi-Mode Network Driver
# =============================================================
set -euo pipefail

# ── Màu sắc ───────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';  YELLOW='\033[1;33m'
CYAN='\033[0;36m';   BLUE='\033[0;34m';  MAGENTA='\033[0;35m'
BOLD='\033[1m';      DIM='\033[2m';       RESET='\033[0m'

DRIVER_NAME="usb"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_LOG="/tmp/aicsemi_build.log"

# ── Helpers ────────────────────────────────────────────────────
sep()      { echo -e "${DIM}${CYAN}  ────────────────────────────────────────────────────${RESET}"; }
sep_bold() { echo -e "${BOLD}${CYAN}  ════════════════════════════════════════════════════${RESET}"; }
log_info() { echo -e "  ${CYAN}[ℹ]${RESET}  $*"; }
log_ok()   { echo -e "  ${GREEN}[✓]${RESET}  $*"; }
log_warn() { echo -e "  ${YELLOW}[⚠]${RESET}  $*"; }
log_err()  { echo -e "  ${RED}[✗]${RESET}  $*"; }
log_step() { echo -e "\n${BOLD}${BLUE}  ┌─ $* ${RESET}"; }
log_run()  { echo -e "  ${DIM}»${RESET}  ${DIM}$*${RESET}"; }

# ── Banner ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║        AIC Semi USB WiFi — Build Script              ║"
echo "  ║        Đề tài: USB Multi-Mode Network Driver         ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

sep
echo -e "  ${BOLD}Driver${RESET}  : ${CYAN}${DRIVER_NAME}.ko${RESET}"
echo -e "  ${BOLD}Kernel${RESET}  : ${CYAN}$(uname -r)${RESET}"
echo -e "  ${BOLD}Arch${RESET}    : ${CYAN}$(uname -m)${RESET}"
echo -e "  ${BOLD}Thư mục${RESET}: ${CYAN}${SCRIPT_DIR}${RESET}"
echo -e "  ${BOLD}Thời gian${RESET}: ${CYAN}$(date '+%Y-%m-%d %H:%M:%S')${RESET}"
sep

# =============================================================
log_step "BƯỚC 1 — Kiểm tra môi trường build"
sep
# =============================================================

# Kernel headers
KERNEL_DIR="/lib/modules/$(uname -r)/build"
log_info "Kiểm tra kernel headers..."
log_run  "ls $KERNEL_DIR"
if [ ! -d "$KERNEL_DIR" ]; then
    log_err "Kernel headers KHÔNG tìm thấy: $KERNEL_DIR"
    log_warn "Khắc phục: sudo apt install linux-headers-$(uname -r)"
    exit 1
fi
log_ok "Kernel headers : $KERNEL_DIR"

# make
log_info "Kiểm tra make..."
if ! command -v make &>/dev/null; then
    log_err "make không tìm thấy"
    log_warn "Khắc phục: sudo apt install build-essential"
    exit 1
fi
log_ok "make           : $(make --version | head -1)"

# gcc
log_info "Kiểm tra gcc..."
if ! command -v gcc &>/dev/null; then
    log_err "gcc không tìm thấy"
    log_warn "Khắc phục: sudo apt install build-essential"
    exit 1
fi
log_ok "gcc            : $(gcc --version | head -1)"

# Source file
log_info "Kiểm tra source file..."
if [ ! -f "${SCRIPT_DIR}/${DRIVER_NAME}.c" ]; then
    log_err "Không tìm thấy: ${DRIVER_NAME}.c"
    log_warn "Đảm bảo file usb.c nằm cùng thư mục với script này"
    exit 1
fi
LINES=$(wc -l < "${SCRIPT_DIR}/${DRIVER_NAME}.c")
SIZE=$(du -h  "${SCRIPT_DIR}/${DRIVER_NAME}.c" | cut -f1)
log_ok "Source         : ${DRIVER_NAME}.c  (${LINES} dòng, ${SIZE})"

# Makefile
log_info "Kiểm tra Makefile..."
if [ ! -f "${SCRIPT_DIR}/Makefile" ]; then
    log_err "Không tìm thấy Makefile"
    log_warn "Tạo Makefile với nội dung: obj-m := usb.o"
    exit 1
fi
log_ok "Makefile       : OK"

# Kiểm tra version kernel để thông báo compat
KVER_MAJOR=$(uname -r | cut -d. -f1)
KVER_MINOR=$(uname -r | cut -d. -f2)
if [ "$KVER_MAJOR" -ge 6 ] && [ "$KVER_MINOR" -ge 7 ]; then
    log_ok "Kernel ≥ 6.7   : Dùng timer_container_of / timer_delete_sync ✓"
else
    log_ok "Kernel < 6.7   : Dùng from_timer / del_timer_sync ✓"
fi

sep

# =============================================================
log_step "BƯỚC 2 — Dọn dẹp build cũ"
sep
# =============================================================

cd "$SCRIPT_DIR"

OLD_FILES=("${DRIVER_NAME}.ko" "${DRIVER_NAME}.o" "${DRIVER_NAME}.mod"
           "${DRIVER_NAME}.mod.c" "${DRIVER_NAME}.mod.o"
           "Module.symvers" "modules.order" ".tmp_versions")

log_info "Kiểm tra file build cũ..."
FOUND_OLD=0
for f in "${OLD_FILES[@]}"; do
    if [ -e "$f" ]; then
        log_run "rm -rf $f"
        FOUND_OLD=1
    fi
done

make clean 2>/dev/null || true

if [ "$FOUND_OLD" -eq 1 ]; then
    log_ok "Đã dọn sạch file build cũ"
else
    log_ok "Thư mục đã sạch — không có file cũ"
fi
sep

# =============================================================
log_step "BƯỚC 3 — Biên dịch kernel module"
sep
# =============================================================

log_info "Bắt đầu biên dịch..."
log_run  "make -C $KERNEL_DIR M=$SCRIPT_DIR modules"
echo ""

BUILD_START=$(date +%s%N)

# Chạy make, lưu log và hiện output CC/LD
make 2>&1 | tee "$BUILD_LOG" | while IFS= read -r line; do
    if echo "$line" | grep -qE "^  CC"; then
        echo -e "  ${DIM}${CYAN}⚙${RESET}  ${DIM}$line${RESET}"
    elif echo "$line" | grep -qE "^  LD|^  MODPOST|^  MODINFO"; then
        echo -e "  ${DIM}${BLUE}⚙${RESET}  ${DIM}$line${RESET}"
    elif echo "$line" | grep -qi "error:"; then
        echo -e "  ${RED}✗  $line${RESET}"
    elif echo "$line" | grep -qi "warning:"; then
        echo -e "  ${YELLOW}⚠  $line${RESET}"
    fi
done

BUILD_END=$(date +%s%N)
BUILD_MS=$(( (BUILD_END - BUILD_START) / 1000000 ))

echo ""

# Kiểm tra kết quả
if [ ! -f "${SCRIPT_DIR}/${DRIVER_NAME}.ko" ]; then
    log_err "Build THẤT BẠI — file .ko không được tạo!"
    sep
    echo -e "  ${RED}${BOLD}Chi tiết lỗi:${RESET}"
    grep -i "error:" "$BUILD_LOG" | head -20 | while IFS= read -r line; do
        echo -e "    ${RED}→ $line${RESET}"
    done
    sep
    log_warn "Kiểm tra log đầy đủ: cat $BUILD_LOG"
    exit 1
fi

log_ok "Biên dịch hoàn tất trong ${BUILD_MS}ms"

# Kiểm tra warning
WARN_COUNT=$(grep -c "warning:" "$BUILD_LOG" 2>/dev/null || true)
if [ "$WARN_COUNT" -gt 0 ]; then
    log_warn "${WARN_COUNT} warning — xem chi tiết: grep warning: $BUILD_LOG"
else
    log_ok "Không có warning"
fi

sep

# =============================================================
log_step "BƯỚC 4 — Thông tin module đã build"
sep
# =============================================================

KO_FILE="${SCRIPT_DIR}/${DRIVER_NAME}.ko"
KO_SIZE=$(du -h "$KO_FILE" | cut -f1)
KO_SIZE_BYTES=$(du -b "$KO_FILE" | cut -f1)

MODINFO_LICENSE=$(modinfo "$KO_FILE" 2>/dev/null | grep "^license" | awk '{$1=""; print $0}' | xargs)
MODINFO_AUTHOR=$(modinfo  "$KO_FILE" 2>/dev/null | grep "^author"  | cut -d: -f2 | xargs)
MODINFO_VER=$(modinfo     "$KO_FILE" 2>/dev/null | grep "^version" | awk '{print $2}')
MODINFO_DESC=$(modinfo    "$KO_FILE" 2>/dev/null | grep "^description" | cut -d: -f2 | xargs)
MODINFO_MAGIC=$(modinfo   "$KO_FILE" 2>/dev/null | grep "^vermagic"    | cut -d: -f2 | xargs | cut -d' ' -f1)
MODINFO_SRCVER=$(modinfo  "$KO_FILE" 2>/dev/null | grep "^srcversion"  | awk '{print $2}')

echo -e "  ${BOLD}Thông tin file:${RESET}"
log_info "File       : $KO_FILE"
log_info "Kích thước : $KO_SIZE ($KO_SIZE_BYTES bytes)"
sep
echo -e "  ${BOLD}Thông tin module:${RESET}"
log_info "Tên module : ${DRIVER_NAME}"
log_info "Phiên bản  : ${MAGENTA}${MODINFO_VER}${RESET}"
log_info "Mô tả      : ${MODINFO_DESC}"
log_info "Tác giả    : ${MODINFO_AUTHOR}"
log_info "Giấy phép  : ${MODINFO_LICENSE}"
log_info "vermagic   : ${MODINFO_MAGIC}"
log_info "srcversion : ${MODINFO_SRCVER}"
sep
echo -e "  ${BOLD}Thiết bị hỗ trợ (USB ID table):${RESET}"
log_info "VID:PID    : ${CYAN}a69c:5721${RESET}  →  USB Mass Storage (Mode 1)"
log_info "VID:PID    : ${GREEN}a69c:8d80${RESET}  →  AIC WLAN Mode    (Mode 2)"
sep

# =============================================================
echo ""
sep_bold
echo -e "  ${GREEN}${BOLD}  ✓  BUILD HOÀN THÀNH!${RESET}"
sep_bold
echo ""
echo -e "  ${BOLD}Bước tiếp theo:${RESET}"
echo -e "    ${CYAN}sudo ./restart.bash${RESET}          # load driver"
echo -e "    ${CYAN}sudo dmesg -w${RESET}                # xem log real-time"
echo -e "    ${CYAN}gcc -Wall -O2 -o demo demo.c && sudo ./demo${RESET}"
echo ""
