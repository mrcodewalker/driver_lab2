# AIC Semi USB Driver — Web Monitor

## Cài đặt

```bash
pip install flask
# hoặc
pip3 install -r requirements.txt
```

## Chạy

```bash
# Phải chạy với sudo vì cần đọc /proc, gọi insmod, rmmod, ip link
sudo python3 server.py
```

Mở trình duyệt: http://localhost:5000

## Tính năng

- Xem trạng thái USB device (Storage 5721 / WiFi 8d80)
- Xem module đã load chưa, interface aic0 UP/DOWN
- Thống kê TX/RX, phân loại giao thức (TCP/UDP/ICMP/ARP/IPv6)
- Biểu đồ donut phân bố giao thức
- Ping tool với kết quả realtime
- Các nút: Compile / Setup / Restart / Modeswitch / Demo / Unload
- Xem dmesg [aicsemi] log
- Xem /proc/aicsemi_usbnet/monitor
- Action log realtime
