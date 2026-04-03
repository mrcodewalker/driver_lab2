# Phân tích chi tiết usb.c — AIC Semi USB Network Driver v4.0

## Tổng quan

`usb.c` là kernel module (`.ko`) chạy trong **kernel space**, đóng vai trò trung tâm của toàn bộ hệ thống. Nó không phải là chương trình userspace thông thường — nó được nạp vào kernel và chạy với đặc quyền cao nhất, có thể truy cập trực tiếp phần cứng USB, quản lý bộ nhớ kernel, và tạo ra network interface mà hệ điều hành nhìn thấy như một card mạng thật.

---

## 1. Nhận diện thiết bị USB — `aicsemi_id_table`

```c
static const struct usb_device_id aicsemi_id_table[] = {
    { USB_DEVICE(VENDOR_AIC, PID_STORAGE) },  // a69c:5721
    { USB_DEVICE(VENDOR_AIC, PID_WIFI)    },  // a69c:8d80
};
```

Khi cắm USB vào, kernel duyệt tất cả driver đã load và so sánh VID:PID của thiết bị với `id_table` của từng driver. Nếu khớp, kernel gọi `probe()`. Driver này đăng ký nhận diện **cả hai** PID của cùng một thiết bị vật lý:

- `a69c:5721` — thiết bị đang ở chế độ USB Mass Storage (giả lập ổ đĩa)
- `a69c:8d80` — thiết bị đã chuyển sang chế độ WiFi network adapter

Đây là kỹ thuật **ZeroCD** phổ biến trên các USB WiFi dongle: thiết bị ban đầu xuất hiện như ổ đĩa để cài driver trên Windows, sau đó cần được "eject" để chuyển sang chế độ network.

---

## 2. Hàm probe() — Điểm vào khi kernel nhận diện thiết bị

`probe()` là hàm quan trọng nhất. Kernel gọi nó ngay khi phát hiện thiết bị khớp với `id_table`. Toàn bộ quá trình khởi tạo xảy ra ở đây.

### 2.1 In thông tin thiết bị ra dmesg

```c
aicsemi_log_device_info(udev, pid);
```

Hàm này đọc các descriptor từ USB device và in ra dmesg:
- Tên nhà sản xuất, tên sản phẩm, số serial
- VID:PID hiện tại
- Tốc độ USB (Full/High speed)
- Bus number và device number
- Số lượng configuration

Mục đích: giúp developer xác nhận driver đã nhận đúng thiết bị.

### 2.2 Cấp phát private data

```c
priv = kzalloc(sizeof(*priv), GFP_KERNEL);
```

`kzalloc` cấp phát bộ nhớ trong kernel heap và zero toàn bộ. Struct `aicsemi_priv` chứa mọi thứ driver cần:
- Con trỏ đến `usb_device`, `net_device`, `usb_interface`
- Toàn bộ counters thống kê (atomic64)
- Ring buffer 1024 entries
- Watchdog timer
- Workqueue cho RX simulation

### 2.3 Khởi tạo ring buffer

```c
atomic_set(&priv->ring.head,  -1);
atomic_set(&priv->ring.count,  0);
spin_lock_init(&priv->ring.rd_lock);
priv->ring.filter     = 0;
priv->ring.start_time = ktime_get();
```

Ring buffer được khởi tạo với:
- `head = -1`: vị trí ghi bắt đầu từ 0 sau lần increment đầu tiên
- `count = 0`: chưa có entry nào
- `rd_lock`: spinlock chỉ dùng khi đọc toàn bộ ring (ioctl GETRING)
- `filter = 0`: chấp nhận tất cả giao thức
- `start_time`: lưu thời điểm khởi động để tính uptime

### 2.4 Phân nhánh theo PID

```c
if (pid == PID_STORAGE) {
    // Thực hiện modeswitch
} else if (pid == PID_WIFI) {
    // Tạo network interface
}
```

Đây là logic cốt lõi: cùng một `probe()` xử lý hai trường hợp hoàn toàn khác nhau.

---

## 3. Modeswitch — Chuyển thiết bị từ Storage sang WiFi

Khi `probe()` nhận PID `5721`, driver thực hiện modeswitch qua hàm `aicsemi_trigger_modeswitch()`.

### Phương pháp 1: SCSI EJECT qua Bulk OUT endpoint

```c
static const u8 eject_cmd[31] = {
    0x55, 0x53, 0x42, 0x43,  // "USBC" — CBW signature
    0x12, 0x34, 0x56, 0x78,  // tag
    0x00, 0x00, 0x00, 0x00,  // data length = 0
    0x00,                    // flags: host→device
    0x00,                    // LUN 0
    0x06,                    // command length
    0x1b, 0x00, 0x00, 0x00, 0x02, 0x00,  // SCSI START STOP UNIT, LoEj=1
    ...
};
```

Đây là **USB Mass Storage BBB protocol** (Bulk-Only Boot). Driver:
1. Tìm Bulk OUT endpoint trong interface descriptor
2. Gửi CBW (Command Block Wrapper) chứa lệnh SCSI `START STOP UNIT` với bit `LoEj=1` (eject)
3. Firmware thiết bị nhận lệnh, tự ngắt kết nối USB và re-enumerate với PID `8d80`

### Phương pháp 2: Vendor Control Transfer (fallback)

Nếu phương pháp 1 thất bại, driver thử 3 biến thể của vendor-specific control request:
```c
{ 0x02, 0x0001, 0x0000 },
{ 0x01, 0x0000, 0x0000 },
{ 0x03, 0x0001, 0x0001 },
```

Return code `-ENODEV` (-19) được coi là **thành công** vì nó có nghĩa thiết bị đã disconnect để re-enumerate.

### Sau modeswitch

Sau khi gửi lệnh eject, `probe()` return ngay. Kernel sẽ:
1. Gọi `disconnect()` cho PID `5721`
2. Phát hiện thiết bị mới với PID `8d80`
3. Gọi `probe()` lần thứ hai — lần này mới tạo interface

---

## 4. Tạo Network Interface — `aicsemi_create_netdev()`

Khi `probe()` nhận PID `8d80`, driver tạo một network interface thật sự mà kernel nhìn thấy như card mạng.

```c
dev = alloc_etherdev(0);
snprintf(dev->name, IFNAMSIZ, "aic%%d");  // → aic0, aic1, ...
eth_hw_addr_random(dev);                  // MAC ngẫu nhiên
dev->netdev_ops  = &aicsemi_netdev_ops;
dev->ethtool_ops = &aicsemi_ethtool_ops;
dev->mtu         = 1500;
register_netdev(dev);
```

Sau `register_netdev()`, interface `aic0` xuất hiện trong `ip link show` và có thể dùng như card mạng bình thường. Kernel biết cách gọi các hàm của driver thông qua `net_device_ops`.

---

## 5. net_device_ops — Bảng hàm driver

```c
static const struct net_device_ops aicsemi_netdev_ops = {
    .ndo_open            = aicsemi_net_open,
    .ndo_stop            = aicsemi_net_stop,
    .ndo_start_xmit      = aicsemi_net_xmit,
    .ndo_get_stats64     = aicsemi_get_stats64,
    .ndo_change_mtu      = aicsemi_change_mtu,
    .ndo_siocdevprivate  = aicsemi_ioctl,   // kernel >= 5.15
};
```

Đây là interface giữa kernel networking stack và driver. Mỗi khi userspace làm gì đó với `aic0`, kernel gọi hàm tương ứng trong bảng này.

### ndo_open — `ip link set aic0 up`

```c
netif_start_queue(dev);   // cho phép TX
netif_carrier_on(dev);    // báo có link
queue_delayed_work(...);  // bắt đầu RX simulation
mod_timer(&priv->watchdog, ...);  // bắt đầu watchdog
```

### ndo_stop — `ip link set aic0 down`

```c
netif_stop_queue(dev);
netif_carrier_off(dev);
cancel_delayed_work_sync(&priv->rx_work);
aic_timer_del_sync(&priv->watchdog);
```

In thống kê TX/RX ra dmesg trước khi tắt.

---

## 6. ndo_start_xmit — Xử lý gói tin TX (quan trọng nhất)

Đây là hàm được gọi mỗi khi có gói tin cần gửi đi. Kernel networking stack gọi hàm này sau khi `demo.c` gọi `sendto()`.

### Luồng xử lý một gói tin

```
demo.c: sendto()
    → kernel: dev_queue_xmit()
    → driver: aicsemi_net_xmit(skb, dev)
        → parse Ethernet header (ETH_P_IP / ARP / IPv6)
        → parse IP header (TCP / UDP / ICMP / DNS / DHCP)
        → extract: src IP, dst IP, src port, dst port, TCP flags
        → atomic64_inc(&priv->stats.xxx)   // cập nhật counter
        → ring_push(&priv->ring, &entry)   // lưu vào ring buffer
        → alog("[TX #N] ...")              // in ra dmesg
        → dev_kfree_skb(skb)              // giải phóng sk_buff
        → return NETDEV_TX_OK
```

### Phân tích giao thức theo tầng

**Tầng 2 — Ethernet:**
- `ETH_P_IP` (0x0800) → IPv4
- `ETH_P_ARP` (0x0806) → ARP
- `ETH_P_IPV6` (0x86DD) → IPv6

**Tầng 3 — IP:**
- `IPPROTO_TCP` (6) → parse TCP header, lấy src/dst port, TCP flags (SYN/ACK/FIN/RST/PSH)
- `IPPROTO_UDP` (17) → parse UDP header, nhận diện DNS (port 53), DHCP (port 67/68)
- `IPPROTO_ICMP` (1) → parse ICMP header, nhận diện Echo Request/Reply

**Log mẫu ra dmesg:**
```
[aicsemi] [TX #1   ] IPv4 / TCP bytes=54     src=aa:bb:cc:dd:ee:ff  dst=ff:ff:ff:ff:ff:ff
[aicsemi]            192.168.99.1:50000  →  192.168.99.2:80  |  flags=[SYN ]  |  TTL=64
[aicsemi] [TX #2   ] IPv4 / DNS bytes=72     src=...
[aicsemi]            192.168.99.1  →  8.8.8.8:53  |  truy vấn DNS
[aicsemi] [TX #3   ] ARP bytes=42     src=...
[aicsemi]            ai có IP này? (broadcast)
```

---

## 7. Ring Buffer — Lưu trữ packet metadata trong kernel

### Thiết kế

```
Ring buffer: 1024 entries × 56 bytes = ~56 KB trong kernel heap
                                        (rất nhỏ, an toàn)

Ghi (TX/RX path — hot path):
    idx = atomic_inc_return(&head) & MASK  // lock-free
    entries[idx] = entry

Đọc (ioctl GETRING — cold path):
    spin_lock_irqsave(&rd_lock)
    copy toàn bộ entries → userspace
    spin_unlock_irqrestore(&rd_lock)
```

### Struct pkt_entry — Mỗi entry lưu gì

| Field | Kích thước | Nội dung |
|---|---|---|
| `ts_ns` | 8 bytes | Timestamp nanoseconds (`ktime_get_real_ns()`) |
| `seq` | 4 bytes | Số thứ tự gói tin toàn cục |
| `len` | 4 bytes | Kích thước frame (bytes) |
| `eth_proto` | 2 bytes | EtherType (0x0800=IP, 0x0806=ARP...) |
| `ip_proto` | 1 byte | IP protocol (6=TCP, 17=UDP, 1=ICMP) |
| `direction` | 1 byte | 'T' = TX, 'R' = RX |
| `saddr/daddr` | 4+4 bytes | Source/Dest IP (network byte order) |
| `sport/dport` | 2+2 bytes | Source/Dest port |
| `tcp_flags` | 1 byte | SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04, PSH=0x08 |
| `icmp_type` | 1 byte | ICMP type code |

### Tại sao lock-free cho ghi?

TX path chạy trong **softirq context** — không được sleep, không được dùng mutex. `atomic_inc_return()` là thao tác atomic trên CPU, không cần lock. Mỗi goroutine/thread lấy một `idx` riêng và ghi vào slot của mình mà không xung đột.

---

## 8. ioctl API — Giao tiếp với userspace

Driver expose 4 lệnh ioctl qua `ndo_siocdevprivate` (kernel ≥ 5.15):

```
SIOCDEVPRIVATE + 0  →  CLEAR    : Xóa toàn bộ ring buffer và reset counters
SIOCDEVPRIVATE + 1  →  GETRING  : Copy toàn bộ 1024 entries → userspace (~56KB)
SIOCDEVPRIVATE + 2  →  SETFILT  : Đặt filter (0=all, 6=TCP, 17=UDP, 1=ICMP)
SIOCDEVPRIVATE + 3  →  GETSTATS : Copy struct thống kê tổng hợp → userspace
```

### Tại sao dùng SIOCDEVPRIVATE thay vì _IOR/_IOW?

Kernel chỉ route ioctl vào `ndo_siocdevprivate` khi `cmd` nằm trong range `0x89F0–0x89FF`. Nếu dùng `_IOR('A', n, ...)` thì `cmd = 0x804xxxxx` — kernel không biết route đến đâu, trả về `ENOTTY` (errno 25). Đây là một điểm tinh tế quan trọng trong Linux kernel networking API.

### Cách copy data an toàn giữa kernel và userspace

```c
// Kernel → Userspace (GETRING, GETSTATS)
if (copy_to_user(data, &st, sizeof(st)))
    return -EFAULT;

// Userspace → Kernel (SETFILT)
if (copy_from_user(&filt, data, sizeof(filt)))
    return -EFAULT;
```

Không được dùng `memcpy` trực tiếp với userspace pointer — kernel và userspace có address space riêng biệt. `copy_to_user` / `copy_from_user` xử lý page fault an toàn.

---

## 9. RX Simulation — Workqueue

Vì đây là driver học tập (không có firmware WiFi thật), RX được giả lập bằng workqueue:

```c
static void aicsemi_rx_work_fn(struct work_struct *work)
{
    // Tạo ARP frame giả
    skb = netdev_alloc_skb(dev, ETH_HLEN + 28);
    // Điền Ethernet + ARP header
    netif_rx(skb);  // đẩy lên networking stack
    // Cập nhật rx_total, rx_bytes
    // Reschedule sau 5-10 giây ngẫu nhiên
}
```

`netif_rx()` đẩy gói tin lên kernel networking stack như thể nó vừa được nhận từ phần cứng. Kernel xử lý tiếp (ARP cache, routing...).

---

## 10. Watchdog Timer

```c
static void aicsemi_watchdog(struct timer_list *t)
{
    if (netif_queue_stopped(dev)) {
        if (jiffies - priv->last_tx_jiffies > msecs_to_jiffies(500)) {
            netif_wake_queue(dev);  // mở lại TX queue nếu bị kẹt
        }
    }
    mod_timer(&priv->watchdog, jiffies + msecs_to_jiffies(1000));
}
```

Chạy mỗi 1 giây. Phát hiện TX queue bị kẹt quá 500ms và tự động mở lại. Đây là cơ chế phòng vệ quan trọng trong network driver thật — nếu không có watchdog, một lần TX queue bị kẹt có thể làm interface "chết" vĩnh viễn.

---

## 11. /proc interface

```
/proc/aicsemi_usbnet/monitor
```

Cung cấp thống kê dạng text, đọc bằng `cat`:
- Tên interface, trạng thái UP/DOWN
- TX: tổng gói, tổng bytes, số gói bị drop
- RX: tổng gói, tổng bytes
- Phân loại giao thức: IPv4, TCP, UDP, ICMP, IPv6, ARP, Khác

Dùng `seq_file` API — cách chuẩn để tạo proc entry có thể đọc an toàn với file lớn.

---

## 12. Kernel version compatibility

```c
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
  #define aic_timer_del_sync(t)  del_timer_sync(t)
#else
  #define aic_timer_del_sync(t)  timer_delete_sync(t)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
    .ndo_siocdevprivate = aicsemi_ioctl,
#else
    .ndo_do_ioctl       = aicsemi_ioctl,
#endif
```

Driver xử lý 2 điểm thay đổi API:
- Kernel 5.15: `ndo_do_ioctl` → `ndo_siocdevprivate` (thêm tham số `data` riêng)
- Kernel 6.7: `del_timer_sync` → `timer_delete_sync`, `from_timer` → `timer_container_of`

---

## 13. disconnect() — Dọn dẹp khi rút USB

```c
static void aicsemi_disconnect(struct usb_interface *intf)
{
    // In thống kê phiên làm việc
    // cancel_delayed_work_sync()  — dừng RX workqueue
    // aic_timer_del_sync()        — hủy watchdog
    // proc_remove()               — xóa /proc entry
    // unregister_netdev()         — gỡ interface khỏi kernel
    // free_netdev()               — giải phóng net_device
    // kfree(priv)                 — giải phóng private data
    // usb_set_intfdata(NULL)      — xóa pointer
}
```

Thứ tự dọn dẹp rất quan trọng: phải dừng workqueue và timer **trước** khi giải phóng memory, nếu không sẽ có use-after-free bug.

---

## 14. Đánh giá — Thực sự hữu ích không?

### Những gì đã làm đúng và có giá trị thật

| Kỹ thuật | Mức độ |
|---|---|
| USB probe/disconnect lifecycle | Đúng hoàn toàn |
| net_device_ops registration | Đúng hoàn toàn |
| Modeswitch SCSI CBW protocol | Đúng về giao thức |
| Lock-free ring buffer với atomic | Đúng, production-grade |
| copy_to_user / copy_from_user | Đúng, an toàn |
| SIOCDEVPRIVATE ioctl routing | Đúng, đã fix bug phổ biến |
| Kernel version compat macros | Đúng, cần thiết |
| Watchdog timer pattern | Đúng, dùng trong driver thật |
| Workqueue cho deferred work | Đúng pattern |
| seq_file cho /proc | Đúng API |

### Giới hạn hiện tại

- **Không có USB bulk transfer thật**: `ndo_start_xmit` log và drop gói, không thật sự gửi qua USB endpoint. Driver thật cần `usb_submit_urb()` để truyền data qua USB.
- **RX là giả lập**: Không đọc data từ USB IN endpoint, chỉ tạo ARP frame ngẫu nhiên.
- **Không có firmware interaction**: WiFi thật cần giao tiếp với firmware chip (init, scan, associate, encrypt...).

### Kết luận

Đây là một **driver framework hoàn chỉnh và đúng kỹ thuật** — tất cả skeleton, lifecycle, API, và cơ chế giám sát đều được implement đúng cách. Phần còn thiếu là lớp transport thật (URB submission) và firmware protocol, nhưng đó là phần phụ thuộc vào datasheet của chip AIC Semi cụ thể.

---

## Sơ đồ tổng thể

```
┌─────────────────────────────────────────────────────────┐
│                    KERNEL SPACE                         │
│                                                         │
│  USB Core                                               │
│    ↓ probe(a69c:5721)                                   │
│  aicsemi_probe()                                        │
│    → modeswitch (SCSI EJECT / Control Transfer)         │
│    ↓ probe(a69c:8d80)                                   │
│  aicsemi_probe()                                        │
│    → alloc_etherdev() → register_netdev() → "aic0"      │
│    → init ring buffer (1024 × 56B)                      │
│    → init watchdog timer (1s)                           │
│    → create /proc/aicsemi_usbnet/monitor                │
│                                                         │
│  ndo_start_xmit(skb)  ←── kernel networking stack      │
│    → parse ETH/IP/TCP/UDP/ICMP                          │
│    → atomic64_inc(stats)                                │
│    → ring_push(entry)  [lock-free]                      │
│    → alog(dmesg)                                        │
│                                                         │
│  ndo_siocdevprivate(cmd)  ←── ioctl từ userspace        │
│    → CLEAR / GETRING / SETFILT / GETSTATS               │
│    → copy_to_user / copy_from_user                      │
│                                                         │
└─────────────────────────────────────────────────────────┘
         ↑ sendto()              ↑ ioctl()
┌────────────────────┐  ┌────────────────────┐
│     demo.c         │  │    monitor.c        │
│  AF_PACKET socket  │  │  ncurses dashboard  │
│  ARP/ICMP/TCP/DNS  │  │  ring + stats       │
└────────────────────┘  └────────────────────┘
```
