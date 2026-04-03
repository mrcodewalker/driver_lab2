#!/usr/bin/env bash
# =============================================================
# start.bash — Khởi động AIC Semi USB Driver Web Monitor
# Tự động: cài Flask → chạy server → mở trình duyệt
# Chạy: sudo ./start.bash
# =============================================================
set -euo pipefail

RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m';     DIM='\033[2m'; RESET='\033[0m'

PORT=5000
URL="http://localhost:${PORT}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="/tmp/aic_monitor.pid"
LOG_FILE="/tmp/aic_monitor.log"

ok()   { echo -e "  ${GREEN}[✓]${RESET}  $*"; }
info() { echo -e "  ${CYAN}[ℹ]${RESET}  $*"; }
warn() { echo -e "  ${YELLOW}[⚠]${RESET}  $*"; }
err()  { echo -e "  ${RED}[✗]${RESET}  $*"; }

echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║   AIC Semi USB Driver — Web Monitor Launcher         ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Kiểm tra sudo ──────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    err "Cần sudo để gọi insmod/rmmod/ip link"
    echo ""
    echo -e "  Chạy lại: ${CYAN}sudo ./start.bash${RESET}"
    exit 1
fi

# ── Kill server cũ nếu đang chạy ──────────────────────────────
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null || true)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        info "Dừng server cũ (PID $OLD_PID)..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 1
        ok "Server cũ đã dừng"
    fi
    rm -f "$PID_FILE"
fi

# ── Kiểm tra port có bị chiếm không ──────────────────────────
if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    warn "Port ${PORT} đang bị chiếm — thử kill..."
    fuser -k "${PORT}/tcp" 2>/dev/null || true
    sleep 1
fi

# ── Kiểm tra Python ───────────────────────────────────────────
PYTHON=""
for py in python3 python; do
    command -v "$py" &>/dev/null && PYTHON="$py" && break
done

if [ -z "$PYTHON" ]; then
    err "Không tìm thấy Python 3"
    echo -e "  Cài: ${CYAN}sudo apt install python3 python3-pip${RESET}"
    exit 1
fi

PY_VER=$("$PYTHON" --version 2>&1)
ok "Python: $PY_VER"

# ── Cài Flask nếu chưa có ─────────────────────────────────────
if ! "$PYTHON" -c "import flask" 2>/dev/null; then
    info "Flask chưa có — đang cài..."
    "$PYTHON" -m pip install flask --quiet && ok "Flask đã cài" || {
        err "Cài Flask thất bại"
        echo -e "  Thử: ${CYAN}pip3 install flask${RESET}"
        exit 1
    }
else
    FLASK_VER=$("$PYTHON" -c "import flask; print(flask.__version__)" 2>/dev/null)
    ok "Flask: $FLASK_VER"
fi

# ── Khởi động server ──────────────────────────────────────────
info "Khởi động server tại ${URL} ..."
"$PYTHON" "${SCRIPT_DIR}/server.py" > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"
info "Server PID: $SERVER_PID  |  Log: $LOG_FILE"

# ── Chờ server sẵn sàng ───────────────────────────────────────
READY=0
for i in $(seq 1 15); do
    sleep 0.5
    if curl -sf "${URL}" -o /dev/null 2>/dev/null; then
        READY=1; break
    fi
    # Kiểm tra process còn sống không
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        err "Server đã crash! Xem log:"
        cat "$LOG_FILE" | tail -20
        exit 1
    fi
    printf "  ${DIM}Đang chờ server... (%d/15)${RESET}\r" "$i"
done
echo ""

if [ "$READY" -eq 0 ]; then
    err "Server không phản hồi sau 7.5 giây"
    info "Xem log: cat $LOG_FILE"
    exit 1
fi

ok "Server đang chạy tại ${CYAN}${URL}${RESET}"

# ── Mở trình duyệt ────────────────────────────────────────────
info "Mở trình duyệt..."
BROWSER_OPENED=0

# Thử các trình duyệt theo thứ tự ưu tiên
for browser in xdg-open google-chrome chromium-browser firefox sensible-browser; do
    if command -v "$browser" &>/dev/null; then
        # Chạy browser với user thường (không phải root) nếu có SUDO_USER
        if [ -n "${SUDO_USER:-}" ] && [ "$browser" != "xdg-open" ]; then
            sudo -u "$SUDO_USER" "$browser" "$URL" &>/dev/null &
        else
            DISPLAY="${DISPLAY:-:0}" "$browser" "$URL" &>/dev/null &
        fi
        ok "Đã mở: $browser"
        BROWSER_OPENED=1
        break
    fi
done

if [ "$BROWSER_OPENED" -eq 0 ]; then
    warn "Không tìm thấy trình duyệt — mở thủ công:"
    echo -e "  ${CYAN}${URL}${RESET}"
fi

# ── Hiển thị thông tin ────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${GREEN}  ✓  WEB MONITOR ĐANG CHẠY${RESET}"
echo ""
echo -e "  ${BOLD}URL${RESET}      : ${CYAN}${URL}${RESET}"
echo -e "  ${BOLD}PID${RESET}      : ${DIM}${SERVER_PID}${RESET}"
echo -e "  ${BOLD}Log${RESET}      : ${DIM}${LOG_FILE}${RESET}"
echo ""
echo -e "  ${DIM}Dừng server: ${RESET}${CYAN}sudo kill ${SERVER_PID}${RESET}"
echo -e "  ${DIM}Xem log    : ${RESET}${CYAN}tail -f ${LOG_FILE}${RESET}"
echo ""
echo -e "  ${BOLD}Nhấn Ctrl+C để dừng server...${RESET}"
echo ""

# ── Giữ script chạy, bắt Ctrl+C để cleanup ───────────────────
cleanup() {
    echo ""
    info "Đang dừng server (PID $SERVER_PID)..."
    kill "$SERVER_PID" 2>/dev/null || true
    rm -f "$PID_FILE"
    ok "Server đã dừng. Tạm biệt!"
    exit 0
}
trap cleanup INT TERM

# Tail log ra terminal
tail -f "$LOG_FILE" &
TAIL_PID=$!

wait "$SERVER_PID" 2>/dev/null || true
kill "$TAIL_PID" 2>/dev/null || true
rm -f "$PID_FILE"
echo ""
warn "Server đã dừng bất ngờ. Xem log: cat $LOG_FILE"
