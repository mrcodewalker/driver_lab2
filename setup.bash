#!/usr/bin/env bash
# =============================================================
# setup.bash — Buộc driver aicsemi_multimode probe() thật sự
#
# Root cause (từ dmesg của bạn):
#   [12875.259851] usb-storage 1-1:1.0: USB Mass Storage device detected
#   → usb-storage bind TRƯỚC → driver không probe được → dmesg trống
#
# Flow đúng:
#   1. Tìm interface sysfs chính xác của thiết bị AIC
#   2. Unbind usb-storage khỏi interface đó
#   3. Load + bind driver → probe() chạy thật
#   4. Interface aic0 thật + /proc thật → dmesg có log
# =============================================================
set -euo pipefail

RED="\033[0;31m"; GRN="\033[0;32m"; YLW="\033[1;33m"
CYN="\033[0;36m"; BOLD="\033[1m";   DIM="\033[2m"; RST="\033[0m"

sep()      { echo -e "${DIM}${CYN}  ──────────────────────────────────────────────${RST}"; }
sep_bold() { echo -e "${BOLD}${CYN}  ══════════════════════════════════════════════${RST}"; }
ok()       { echo -e "  ${GRN}[✓]${RST}  $*"; }
info()     { echo -e "  ${CYN}[ℹ]${RST}  $*"; }
warn()     { echo -e "  ${YLW}[⚠]${RST}  $*"; }
err()      { echo -e "  ${RED}[✗]${RST}  $*"; }
step()     { echo -e "\n${BOLD}${CYN}  ┌─ $* ${RST}"; sep; }

[ "$EUID" -ne 0 ] && { err "Cần sudo!"; echo "  sudo ./setup.bash"; exit 1; }

echo ""
echo -e "${BOLD}${CYN}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║   AIC Semi — Driver Setup (probe() thật sự)      ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${RST}"

# =============================================================
step "BƯỚC 1 — Kiểm tra thiết bị USB"
# =============================================================

if ! lsusb | grep -q "a69c"; then
    err "Không thấy thiết bị AIC Semi (a69c:xxxx)"
    err "Cắm USB adapter vào trước rồi chạy lại."
    exit 1
fi

AIC_LINE=$(lsusb | grep "a69c")
ok "Phát hiện: $AIC_LINE"

if echo "$AIC_LINE" | grep -q "8d80"; then
    ok "Thiết bị đã ở WiFi mode (8d80)"
    CURRENT_MODE="wifi"
else
    warn "Thiết bị ở Storage mode (5721)"
    CURRENT_MODE="storage"
fi
sep

# =============================================================
step "BƯỚC 2 — Tìm đường dẫn sysfs chính xác"
# =============================================================
#
# Duyệt /sys/bus/usb/devices/, tìm device có idVendor=a69c
# Đây là cách đúng, không bị ảnh hưởng bởi số bus thay đổi.

AIC_DEV_PATH=""
for d in /sys/bus/usb/devices/*/; do
    [ -f "${d}idVendor" ] || continue
    vendor=$(cat "${d}idVendor" 2>/dev/null || true)
    if [ "$vendor" = "a69c" ]; then
        AIC_DEV_PATH="${d%/}"
        break
    fi
done

if [ -z "$AIC_DEV_PATH" ]; then
    err "Không tìm thấy a69c trong /sys/bus/usb/devices/"
    exit 1
fi

AIC_DEV_NAME=$(basename "$AIC_DEV_PATH")   # vd: 1-1
AIC_INTF="${AIC_DEV_NAME}:1.0"             # vd: 1-1:1.0
AIC_INTF_PATH="/sys/bus/usb/devices/${AIC_INTF}"

ok "sysfs device : $AIC_DEV_PATH"
ok "Interface    : $AIC_INTF"
info "idProduct  : $(cat ${AIC_DEV_PATH}/idProduct 2>/dev/null)"
info "Speed      : $(cat ${AIC_DEV_PATH}/speed 2>/dev/null) Mbps"
sep

# =============================================================
step "BƯỚC 3 — Unbind usb-storage (PHẢI làm TRƯỚC insmod)"
# =============================================================
#
# Lý do thứ tự này quan trọng:
#   - Nếu insmod trước: usbcore thấy 1-1:1.0 đã có usb-storage → bỏ qua
#   - Nếu unbind trước: usbcore thấy 1-1:1.0 trống → gọi probe() ngay khi insmod

BOUND_DRIVER=""
[ -L "${AIC_INTF_PATH}/driver" ] && \
    BOUND_DRIVER=$(readlink "${AIC_INTF_PATH}/driver" | xargs basename)

info "Driver đang bind vào ${AIC_INTF}: ${BOUND_DRIVER:-không có}"

if [ "$BOUND_DRIVER" = "usb-storage" ] || [ "$BOUND_DRIVER" = "usb_storage" ]; then
    warn "usb-storage đang chiếm thiết bị — unbind trước khi load driver..."

    if [ -d "/sys/bus/usb/drivers/usb-storage" ]; then
        DRIVER_DIR="/sys/bus/usb/drivers/usb-storage"
    else
        DRIVER_DIR="/sys/bus/usb/drivers/usb_storage"
    fi

    info "echo -n '${AIC_INTF}' > ${DRIVER_DIR}/unbind"
    echo -n "${AIC_INTF}" > "${DRIVER_DIR}/unbind" 2>/dev/null || {
        err "Unbind thất bại!"
        err "Thử thủ công: echo -n '${AIC_INTF}' > ${DRIVER_DIR}/unbind"
        exit 1
    }
    sleep 1

    BOUND_AFTER=""
    [ -L "${AIC_INTF_PATH}/driver" ] && \
        BOUND_AFTER=$(readlink "${AIC_INTF_PATH}/driver" | xargs basename)

    if [ -n "$BOUND_AFTER" ]; then
        err "usb-storage vẫn còn bind sau unbind: ${BOUND_AFTER}"
        exit 1
    fi
    ok "Đã unbind usb-storage — interface ${AIC_INTF} trống, sẵn sàng cho probe()"

elif [ -z "$BOUND_DRIVER" ]; then
    ok "Không có driver nào bind — sẵn sàng cho probe()"
else
    warn "Driver đang bind: ${BOUND_DRIVER} — thử unbind..."
    echo -n "${AIC_INTF}" > "/sys/bus/usb/drivers/${BOUND_DRIVER}/unbind" 2>/dev/null || true
    sleep 1
fi
sep

# =============================================================
step "BƯỚC 4 — Load driver aicsemi_multimode"
# =============================================================
#
# Sau khi unbind ở bước 3, interface ${AIC_INTF} không có driver.
# Khi insmod xong, usbcore tự động duyệt lại tất cả interface
# trống và match với id_table → gọi probe() NGAY LẬP TỨC.

KO_FILE="./usb.ko"
[ -f "$KO_FILE" ] || { err "Không thấy usb.ko — chạy ./compile.bash trước!"; exit 1; }

# Unload module cũ nếu còn
for mod in aicsemi_multimode usb; do
    lsmod | grep -q "^${mod} " && rmmod "$mod" 2>/dev/null && ok "Unload cũ: $mod" || true
done
sleep 0.5

info "insmod ${KO_FILE}..."
insmod "$KO_FILE" 2>/tmp/insmod_err && ok "insmod thành công" || {
    err "insmod thất bại: $(cat /tmp/insmod_err)"
    exit 1
}

info "Đợi usbcore gọi probe() và modeswitch xử lý..."
sleep 3   # modeswitch cần thêm thời gian
sep

# =============================================================
step "BƯỚC 5 — Chờ modeswitch & bind driver"
# =============================================================
#
# Khi probe() chạy với PID 5721, driver gửi modeswitch command.
# Thiết bị trả về -32 (EPIPE) rồi tự disconnect + re-enumerate
# với PID 8d80. Cần chờ và bind lại vào device mới.

info "Kiểm tra thiết bị sau modeswitch..."
REENUMERATED=0

for attempt in 1 2 3 4 5; do
    sleep 2
    info "Lần kiểm tra ${attempt}/5..."

    # Tìm lại device (PID có thể đã đổi sang 8d80)
    NEW_DEV_PATH=""
    for d in /sys/bus/usb/devices/*/; do
        [ -f "${d}idVendor" ] || continue
        vendor=$(cat "${d}idVendor" 2>/dev/null || true)
        if [ "$vendor" = "a69c" ]; then
            NEW_DEV_PATH="${d%/}"
            break
        fi
    done

    if [ -z "$NEW_DEV_PATH" ]; then
        warn "  Thiết bị chưa xuất hiện lại..."
        continue
    fi

    NEW_PID=$(cat "${NEW_DEV_PATH}/idProduct" 2>/dev/null || echo "????")
    NEW_DEV_NAME=$(basename "$NEW_DEV_PATH")
    NEW_INTF="${NEW_DEV_NAME}:1.0"
    NEW_INTF_PATH="/sys/bus/usb/devices/${NEW_INTF}"

    info "  Phát hiện: ${NEW_DEV_NAME} PID=0x${NEW_PID}"

    if [ "$NEW_PID" = "8d80" ]; then
        ok "Modeswitch THÀNH CÔNG! Thiết bị đã đổi sang 0x8d80 (WiFi mode)"
        AIC_INTF="$NEW_INTF"
        AIC_INTF_PATH="$NEW_INTF_PATH"
        REENUMERATED=1

        # Bind driver vào interface mới
        AICSEMI_DIR="/sys/bus/usb/drivers/aicsemi_multimode"
        BOUND_NEW=""
        [ -L "${AIC_INTF_PATH}/driver" ] && \
            BOUND_NEW=$(readlink "${AIC_INTF_PATH}/driver" | xargs basename)

        if [ "$BOUND_NEW" = "aicsemi_multimode" ]; then
            ok "Kernel đã tự bind driver vào ${AIC_INTF}!"
        elif [ -d "$AICSEMI_DIR" ]; then
            info "Bind driver vào ${AIC_INTF}..."
            echo -n "${AIC_INTF}" > "${AICSEMI_DIR}/bind" 2>/dev/null && \
                ok "Bind thành công!" || \
                warn "Bind thất bại — kernel có thể đã tự bind"
            sleep 2
        fi
        break

    elif [ "$NEW_PID" = "5721" ]; then
        # Vẫn ở 5721 — kiểm tra driver đã bind chưa
        BOUND_NEW=""
        [ -L "${NEW_INTF_PATH}/driver" ] && \
            BOUND_NEW=$(readlink "${NEW_INTF_PATH}/driver" | xargs basename)
        info "  Vẫn ở PID 5721, driver bind: ${BOUND_NEW:-không có}"

        if [ "$BOUND_NEW" = "aicsemi_multimode" ]; then
            ok "Driver đã bind vào 5721 — modeswitch đang được xử lý"
            AIC_INTF="$NEW_INTF"
            AIC_INTF_PATH="$NEW_INTF_PATH"
        fi
    fi
done

if [ "$REENUMERATED" -eq 0 ]; then
    warn "Thiết bị chưa chuyển sang WiFi mode (8d80) sau ${attempt} lần thử"
    warn "Thiết bị này có thể không hỗ trợ modeswitch tự động"
    warn ""
    warn "Giải pháp: Rút USB → cắm lại → chạy lại setup.bash ngay lập tức"
    warn "(để script unbind usb-storage trước khi nó kịp bind)"
fi
sep

# =============================================================
step "BƯỚC 6 — Log từ probe()"
# =============================================================

info "dmesg | grep aicsemi (20 dòng cuối):"
echo ""
dmesg | grep -E "\[aicsemi\]" | tail -20 | while IFS= read -r line; do
    if echo "$line" | grep -qE "WIFI MODE|aic0|tạo|thành công|READY|UP"; then
        echo -e "    ${GRN}${line}${RST}"
    elif echo "$line" | grep -qE "STORAGE MODE|modeswitch|5721"; then
        echo -e "    ${YLW}${line}${RST}"
    else
        echo -e "    ${DIM}${line}${RST}"
    fi
done
echo ""
sep

# =============================================================
step "BƯỚC 7 — Thiết lập interface aic0"
# =============================================================

sleep 1
FOUND_IFACE=""
for iface in aic0 aic1; do
    ip link show "$iface" &>/dev/null 2>&1 && FOUND_IFACE="$iface" && break
done

if [ -n "$FOUND_IFACE" ]; then
    ok "Interface ${FOUND_IFACE} được tạo bởi DRIVER THẬT!"

    ip link set "$FOUND_IFACE" up
    ip addr flush dev "$FOUND_IFACE" 2>/dev/null || true
    ip addr add 192.168.99.1/24 dev "$FOUND_IFACE" 2>/dev/null || true
    ok "IP gán: 192.168.99.1/24"

    if [ -f "/proc/aicsemi_usbnet/monitor" ]; then
        ok "/proc/aicsemi_usbnet/monitor: CÓ"
        echo ""
        cat /proc/aicsemi_usbnet/monitor | while IFS= read -r l; do
            echo -e "    ${DIM}${l}${RST}"
        done
    fi

else
    warn "Interface aic0/aic1 chưa có"
    warn ""
    warn "Thiết bị vẫn ở Storage mode — driver đã gửi modeswitch."
    warn "Hãy RÚT và CẮM LẠI USB, sau đó chạy lại:"
    warn "  sudo ./setup.bash"
    warn ""
    warn "Hoặc kiểm tra probe() có chạy không:"
    warn "  dmesg | grep aicsemi"
fi
sep

# =============================================================
step "BƯỚC 8 — Build demo"
# =============================================================

DEMO_READY=0
if [ ! -f "demo.c" ]; then
    warn "Không thấy demo.c — bỏ qua build"
elif [ -f "./demo" ] && [ "./demo" -nt "demo.c" ]; then
    ok "demo đã được build sẵn (mới hơn demo.c)"
    DEMO_READY=1
else
    info "Build demo.c..."
    if gcc -Wall -O2 -o demo demo.c 2>/tmp/demo_build.log; then
        ok "Build demo thành công"
        DEMO_READY=1
    else
        warn "Build demo thất bại:"
        cat /tmp/demo_build.log | grep "error:" | while IFS= read -r l; do
            echo -e "    ${RED}$l${RST}"
        done
    fi
fi
sep

# =============================================================
sep_bold
if [ -n "$FOUND_IFACE" ]; then
    echo -e "  ${GRN}${BOLD}  ✓  DRIVER THẬT ĐANG CHẠY — dmesg sẽ có log!${RST}"
else
    echo -e "  ${YLW}${BOLD}  ⚠  Rút và cắm lại USB để hoàn tất modeswitch${RST}"
fi
sep_bold
echo ""
echo -e "  ${BOLD}Gợi ý — mở terminal 2 để xem log realtime:${RST}"
echo -e "  ${CYN}sudo dmesg -w | grep --color aicsemi${RST}"
echo ""
echo -e "  ${BOLD}Xem thống kê sau khi gửi gói:${RST}"
echo -e "  ${CYN}watch -n 1 cat /proc/aicsemi_usbnet/monitor${RST}"
echo ""

# =============================================================
# Hỏi có muốn chạy demo không
# =============================================================

if [ "$DEMO_READY" -eq 1 ] && [ -n "$FOUND_IFACE" ]; then
    echo -e "  ${BOLD}Chạy demo ngay bây giờ? [Y/n]:${RST} \c"
    read -r ANS </dev/tty
    ANS="${ANS:-Y}"

    if [[ "$ANS" =~ ^[Yy]$ ]]; then
        echo ""
        sep_bold
        echo -e "  ${GRN}${BOLD}  ▶  CHẠY DEMO  ${RST}"
        sep_bold
        echo ""
        echo -e "  ${DIM}(Mở terminal khác: sudo dmesg -w | grep --color aicsemi)${RST}"
        echo ""
        sleep 1
        ./demo
        echo ""
        sep_bold
        echo -e "  ${GRN}${BOLD}  ✓  DEMO HOÀN TẤT${RST}"
        sep_bold
        echo ""
        echo -e "  ${BOLD}Xem lại log driver:${RST}"
        echo -e "  ${CYN}sudo dmesg | grep aicsemi | tail -40${RST}"
        echo ""
        echo -e "  ${BOLD}Thống kê gói tin:${RST}"
        echo -e "  ${CYN}cat /proc/aicsemi_usbnet/monitor${RST}"
        echo ""
    else
        echo ""
        info "Bỏ qua demo. Chạy thủ công bất cứ lúc nào:"
        echo -e "  ${CYN}sudo ./demo${RST}"
        echo ""
    fi

elif [ "$DEMO_READY" -eq 1 ] && [ -z "$FOUND_IFACE" ]; then
    warn "Interface chưa có — không thể chạy demo lúc này."
    warn "Rút và cắm lại USB, sau đó chạy lại: sudo ./setup.bash"
    echo ""

else
    warn "demo chưa build — không thể chạy."
    echo ""
fi
