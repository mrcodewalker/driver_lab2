# ================================================================
# Makefile - AIC Semi USB Multi-Mode Network Driver
# Hỗ trợ: auto-detect major number, /dev node, proc monitor
# ================================================================

obj-m      := usb.o
DRIVER     := usb
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD        := $(shell pwd)
DEV_NODE   := /dev/aicsemi_ctl

# ── Auto-detect major number từ /proc/devices ──────────────────
# Dùng sau khi insmod. Trả về rỗng nếu chưa load.
MAJOR := $(shell grep "$(DRIVER)\|aicsemi" /proc/devices 2>/dev/null | awk '{print $$1}' | head -1)

# ─────────────────────────────────────────────────────────────
all:
	@echo "======================================================"
	@echo " Building : $(DRIVER).ko"
	@echo " Kernel   : $(shell uname -r)"
	@echo " Arch     : $(shell uname -m)"
	@echo "======================================================"
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
	@echo ""
	@echo "  Size    : $(shell du -h $(DRIVER).ko 2>/dev/null | cut -f1)"
	@echo "  vermagic: $(shell modinfo $(DRIVER).ko 2>/dev/null | grep vermagic | awk '{print $$2}')"
	@echo ""
	@echo "Build OK: $(DRIVER).ko"

# ─────────────────────────────────────────────────────────────
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	@echo "Cleaned."

# ─────────────────────────────────────────────────────────────
# install: tháo module cũ + module cạnh tranh → insmod → tạo /dev
install: all
	@echo "[*] Gỡ module cũ nếu có..."
	-sudo rmmod $(DRIVER)    2>/dev/null || true
	@echo "[*] Gỡ module cạnh tranh..."
	-sudo rmmod usb_storage  2>/dev/null || true
	-sudo rmmod uas          2>/dev/null || true
	@echo "[*] Load driver mới..."
	sudo insmod $(DRIVER).ko
	@sleep 1
	@echo ""
	@$(MAKE) -s mknod_auto
	@echo ""
	@echo "Driver loaded. Xem log: sudo dmesg | tail -20"

# ─────────────────────────────────────────────────────────────
# mknod_auto: tự động đọc major từ /proc/devices và tạo /dev node
mknod_auto:
	$(eval MAJOR_NOW := $(shell grep "aicsemi" /proc/devices 2>/dev/null | awk '{print $$1}' | head -1))
	@if [ -n "$(MAJOR_NOW)" ]; then \
	    echo "[MAJOR] Tìm thấy major number = $(MAJOR_NOW)"; \
	    echo "[MKNOD] Tạo $(DEV_NODE) (char $(MAJOR_NOW):0)"; \
	    sudo rm -f $(DEV_NODE); \
	    sudo mknod $(DEV_NODE) c $(MAJOR_NOW) 0; \
	    sudo chmod 666 $(DEV_NODE); \
	    echo "  OK: $(DEV_NODE) → major=$(MAJOR_NOW), minor=0"; \
	else \
	    echo "[INFO] Không tìm thấy char device 'aicsemi' trong /proc/devices"; \
	    echo "[INFO] Driver dùng net_device (network interface, không cần /dev node)"; \
	    echo "[INFO] Kiểm tra: cat /proc/devices | grep -i usb"; \
	fi

# ─────────────────────────────────────────────────────────────
remove:
	@echo "[*] Hạ interface xuống..."
	-sudo ip link set usb0 down    2>/dev/null || true
	-sudo ip addr flush dev usb0   2>/dev/null || true
	@echo "[*] Xoá /dev node..."
	-sudo rm -f $(DEV_NODE)
	@echo "[*] Unload module..."
	sudo rmmod $(DRIVER) 2>/dev/null || true
	@echo "Driver removed."

# ─────────────────────────────────────────────────────────────
reload: remove
	@sleep 1
	$(MAKE) install

# ─────────────────────────────────────────────────────────────
# info: hiển thị thông tin đầy đủ về module đang chạy
info:
	@echo "======================================================"
	@echo " MODULE INFO"
	@echo "======================================================"
	@echo "  lsmod:"
	@lsmod | grep "$(DRIVER)" || echo "  (chưa load)"
	@echo ""
	@echo "  /proc/devices:"
	@grep "aicsemi" /proc/devices 2>/dev/null || echo "  (không có entry)"
	@echo ""
	@echo "  /dev node:"
	@ls -la $(DEV_NODE) 2>/dev/null || echo "  (không có)"
	@echo ""
	@echo "  Network interfaces:"
	@ip link show | grep -E "usb[0-9]" || echo "  (không có)"
	@echo ""
	@echo "  /proc monitor:"
	@ls /proc/aicsemi_usbnet/ 2>/dev/null || echo "  (chưa có - thiết bị chưa ở WiFi mode)"
	@echo "======================================================"

# ─────────────────────────────────────────────────────────────
log:
	@sudo dmesg | grep -E "\[aicsemi|aicsemi_" | tail -40

# ─────────────────────────────────────────────────────────────
monitor:
	@cat $(PROC_MONITOR) 2>/dev/null || echo "Monitor chưa khởi động (thiết bị ở Storage mode?)"

PROC_MONITOR := /proc/aicsemi_usbnet/monitor

# ─────────────────────────────────────────────────────────────
demo:
	@echo "[demo] Bật interface..."
	-sudo ip link set usb0 up
	@echo "[demo] Đặt IP..."
	-sudo ip addr add 192.168.99.1/24 dev usb0 2>/dev/null
	@echo "[demo] Ping test..."
	-ping -c 5 -W 1 192.168.99.2
	@echo "[demo] Thống kê:"
	@$(MAKE) -s monitor
	@echo "[demo] Log:"
	@$(MAKE) -s log

# ─────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  make              - Build module"
	@echo "  make install      - Build + insmod + tạo /dev node tự động"
	@echo "  make remove       - rmmod + xoá /dev node"
	@echo "  make reload       - remove + install"
	@echo "  make mknod_auto   - Chỉ tạo /dev node (sau khi insmod)"
	@echo "  make info         - Hiển thị trạng thái đầy đủ"
	@echo "  make log          - Xem dmesg filtered"
	@echo "  make monitor      - Xem packet stats (/proc)"
	@echo "  make demo         - Test nhanh: up interface + ping"
	@echo "  make clean        - Dọn file build"
	@echo ""

.PHONY: all clean install remove reload mknod_auto info log monitor demo help
