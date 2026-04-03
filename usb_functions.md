# Chi tiết các hàm trong usb.c — AIC Semi USB Network Driver

## Mục lục

1. Hàm USB Driver Lifecycle
2. Hàm Modeswitch
3. Hàm Network Device Operations
4. Hàm Ring Buffer
5. Hàm ioctl Handler
6. Hàm Ethtool
7. Hàm /proc Interface
8. Hàm Timer và Workqueue
9. Struct và Data Types

---

## 1. HÀM USB DRIVER LIFECYCLE

### `aicsemi_probe()`

```c
static int aicsemi_probe(struct usb_interface *intf,
                         const struct usb_device_id *id)
```

**Mục đích:** Điểm vào chính của driver. Kernel gọi hàm này khi phát hiện thiết bị USB khớp với `id_table`.

**Tham số:**
- `intf` (struct usb_interface *): Con trỏ đến USB interface đang được probe. Chứa thông tin về endpoints, descriptors, và device parent.
- `id` (const struct usb_device_id *): Entry trong `aicsemi_id_table` mà kernel đã match. Chứa VID/PID.

**Return:**
- `0`: Probe thành công, driver chấp nhận thiết bị
- `< 0`: Lỗi (errno), kernel sẽ thử driver khác

**Luồng xử lý:**
1. Lấy `usb_device` từ interface: `udev = interface_to_usbdev(intf)`
2. Đọc PID hiện tại: `pid = le16_to_cpu(udev->descriptor.idProduct)`
3. In thông tin thiết bị: `aicsemi_log_device_info(udev, pid)`
4. Cấp phát private data: `priv = kzalloc(sizeof(*priv), GFP_KERNEL)`
5. Init atomic counters, timer, ring buffer
6. **Phân nhánh theo PID:**
   - `PID_STORAGE (0x5721)`: Gọi `aicsemi_trigger_modeswitch()`, return ngay
   - `PID_WIFI (0x8d80)`: Tạo workqueue, gọi `aicsemi_create_netdev()`, tạo /proc
7. Lưu priv vào interface: `usb_set_intfdata(intf, priv)`

**Đặc điểm quan trọng:**
- Chạy trong **process context** (có thể sleep, dùng GFP_KERNEL)
- Được gọi **2 lần** cho cùng một thiết bị vật lý (trước và sau modeswitch)
- Phải return nhanh — không được block lâu

---

### `aicsemi_disconnect()`

```c
static void aicsemi_disconnect(struct usb_interface *intf)
```

**Mục đích:** Dọn dẹp tài nguyên khi thiết bị bị rút ra hoặc driver bị unload.

**Tham số:**
- `intf` (struct usb_interface *): Interface đang bị disconnect

**Return:** void (không có return value)

**Luồng xử lý:**
