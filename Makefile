# ================================================================
# Makefile — AIC Semi USB Multi-Mode Network Driver v4.0
# Đề tài: Phát triển USB Network Driver + Packet Monitor
# ================================================================

obj-m      := usb.o
DRIVER     := usb
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD        := $(shell pwd)

# ─────────────────────────────────────────────────────────────
# all: build kernel module + monitor + demo
# ─────────────────────────────────────────────────────────────
all: module monitor_tool demo_tool
	@echo ""
	@echo "  ╔══════════════════════════════════════════════╗"
	@echo "  ║  BUILD HOÀN THÀNH                            ║"
	@echo "  ╠══════════════════════════════════════════════╣"
	@echo "  ║  usb.ko   — kernel driver                    ║"
	@echo "  ║  monitor  — packet monitor dashboard         ║"
	@echo "  ║  demo     — raw packet sender                ║"
	@echo "  ╠══════════════════════════════════════════════╣"
	@echo "  ║  Thứ tự chạy:                                ║"
	@echo "  ║  1. sudo ./setup.bash   (load driver)        ║"
	@echo "  ║  2. sudo ./monitor aic0 (mở dashboard)       ║"
	@echo "  ║  3. sudo ./demo         (gửi packets)        ║"
	@echo "  ╚══════════════════════════════════════════════╝"

module:
	@echo "======================================================"
	@echo " Building kernel module: $(DRIVER).ko"
	@echo " Kernel : $(shell uname -r)"
	@echo " Arch   : $(shell uname -m)"
	@echo "======================================================"
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
	@echo "  Size    : $(shell du -h $(DRIVER).ko 2>/dev/null | cut -f1)"
	@echo "  vermagic: $(shell modinfo $(DRIVER).ko 2>/dev/null | grep vermagic | awk '{print $$2}')"
	@echo "Build OK: $(DRIVER).ko"

monitor_tool: monitor.c
	@echo "[monitor] Building packet monitor..."
	@if pkg-config --libs ncurses >/dev/null 2>&1; then \
		gcc -Wall -O2 -o monitor monitor.c $$(pkg-config --libs ncurses) && \
		echo "  OK: monitor"; \
	else \
		gcc -Wall -O2 -o monitor monitor.c -lncurses && \
		echo "  OK: monitor"; \
	fi

demo_tool: demo.c
	@echo "[demo] Building demo..."
	gcc -Wall -O2 -o demo demo.c
	@echo "  OK: demo"

# ─────────────────────────────────────────────────────────────
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f monitor demo
	@echo "Cleaned."

# ─────────────────────────────────────────────────────────────
# install: build + unbind usb-storage + insmod + setup interface
# ─────────────────────────────────────────────────────────────
install: all
	@echo "[*] Gỡ module cũ nếu có..."
	-sudo rmmod $(DRIVER) 2>/dev/null || true
	@echo "[*] Unbind usb-storage nếu đang chiếm thiết bị AIC..."
	@for d in /sys/bus/usb/devices/*/; do \
		[ -f "$${d}idVendor" ] || continue; \
		v=$$(cat "$${d}idVendor" 2>/dev/null); \
		[ "$$v" = "a69c" ] || continue; \
		dev=$$(basename $$d); \
		intf="$${dev}:1.0"; \
		if [ -L "/sys/bus/usb/devices/$${intf}/driver" ]; then \
			drv=$$(readlink "/sys/bus/usb/devices/$${intf}/driver" | xargs basename); \
			if [ "$$drv" = "usb-storage" ] || [ "$$drv" = "usb_storage" ]; then \
				echo "  Unbind: $$drv từ $$intf"; \
				echo -n "$$intf" > /sys/bus/usb/drivers/usb-storage/unbind 2>/dev/null || true; \
			fi; \
		fi; \
	done
	@echo "[*] Load driver..."
	sudo insmod $(DRIVER).ko
	@sleep 2
	@echo "[*] Bật interface aic0 nếu có..."
	-sudo ip link set aic0 up 2>/dev/null || true
	-sudo ip addr add 192.168.99.1/24 dev aic0 2>/dev/null || true
	@echo ""
	@echo "Driver loaded. Các bước tiếp:"
	@echo "  sudo ./monitor aic0   # mở dashboard"
	@echo "  sudo ./demo           # gửi packets"
	@echo "  sudo dmesg | grep aicsemi | tail -20"

# ─────────────────────────────────────────────────────────────
remove:
	-sudo ip link set aic0 down    2>/dev/null || true
	-sudo ip addr flush dev aic0   2>/dev/null || true
	-sudo rmmod $(DRIVER)          2>/dev/null || true
	@echo "Driver removed."

reload: remove
	@sleep 1
	$(MAKE) install

# ─────────────────────────────────────────────────────────────
info:
	@echo "======================================================"
	@echo " TRẠNG THÁI DRIVER"
	@echo "======================================================"
	@echo "  lsmod:"
	@lsmod | grep -E "$(DRIVER)|aicsemi" || echo "  (chưa load)"
	@echo ""
	@echo "  Network interfaces:"
	@ip link show | grep -E "aic[0-9]|usb[0-9]" || echo "  (không có)"
	@echo ""
	@echo "  /proc monitor:"
	@ls /proc/aicsemi_usbnet/ 2>/dev/null && \
		cat /proc/aicsemi_usbnet/monitor 2>/dev/null || \
		echo "  (chưa có — thiết bị chưa ở WiFi mode)"
	@echo "======================================================"

log:
	@sudo dmesg | grep -E "\[aicsemi\]" | tail -40

# Xem /proc stats (không dùng ncurses)
proc_monitor:
	@watch -n 1 cat /proc/aicsemi_usbnet/monitor

help:
	@echo ""
	@echo "  make              - Build usb.ko + monitor + demo"
	@echo "  make install      - Build + load driver tự động"
	@echo "  make remove       - Unload driver"
	@echo "  make reload       - remove + install"
	@echo "  make info         - Xem trạng thái đầy đủ"
	@echo "  make log          - Xem dmesg filtered"
	@echo "  make proc_monitor - watch /proc/aicsemi_usbnet/monitor"
	@echo "  make clean        - Dọn file build"
	@echo ""
	@echo "  Thứ tự chạy tay:"
	@echo "    sudo ./setup.bash     # setup đầy đủ + hỏi Y/n chạy demo"
	@echo "    sudo ./monitor aic0   # dashboard (mở trước demo)"
	@echo "    sudo ./demo           # gửi packets"
	@echo ""

.PHONY: all module monitor_tool demo_tool clean install remove \
        reload info log proc_monitor help
