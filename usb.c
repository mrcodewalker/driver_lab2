// SPDX-License-Identifier: GPL-2.0
/*
 * usb.c — AIC Semi USB WiFi Multi-Mode Driver v3.2.0
 *
 * ĐỀ TÀI: Phát triển USB Multi-Mode Network Driver
 *         và cơ chế nhận diện thiết bị tự chuyển đổi trạng thái
 *
 * Thiết bị: AIC Semi (a69c:5721 → a69c:8d80)
 *   Mode 1 (0x5721): USB Mass Storage — chứa driver Windows
 *   Mode 2 (0x8d80): AIC WLAN — sau khi chuyển đổi mode
 *
 * v3.2: Log tiếng Việt chi tiết, đẹp, nhiều thông tin
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/usb.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/atomic.h>

/* ================================================================
 * KERNEL VERSION COMPAT — timer API đổi ở kernel 6.7
 * ================================================================ */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
  #define aic_timer_of(ptr, type, member)  from_timer(ptr, t, member)
  #define aic_timer_del_sync(t)            del_timer_sync(t)
  #define aic_timer_del(t)                 del_timer(t)
#else
  #define aic_timer_of(ptr, type, member)  timer_container_of(ptr, t, member)
  #define aic_timer_del_sync(t)            timer_delete_sync(t)
  #define aic_timer_del(t)                 timer_delete(t)
#endif

/* ================================================================
 * MODULE INFO
 * ================================================================ */
#define DRIVER_NAME     "aicsemi_multimode"
#define DRIVER_VERSION  "3.2.0"
#define DRIVER_DESC     "AIC Semi USB WiFi Multi-Mode Driver (Log TV)"

#define VENDOR_AIC   0xa69c
#define PID_STORAGE  0x5721
#define PID_WIFI     0x8d80

MODULE_AUTHOR("SinhVien <sinhvien@example.com>");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");

/* ================================================================
 * LOG HELPERS — in đẹp hơn pr_info thuần
 *
 * Dùng pr_info thay vì printk để tự động thêm KERN_INFO.
 * Các macro bên dưới thêm prefix có màu khi xem qua dmesg --color
 * (kernel 5.10+ hỗ trợ KERN_CONT để nối dòng).
 * ================================================================ */
#define AIC_TAG   "[aicsemi] "
#define AIC_SEP   "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
#define AIC_SEP2  "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ "
#define AIC_STAR  "★ "
#define AIC_OK    "✓ "
#define AIC_WARN  "⚠ "
#define AIC_ERR   "✗ "
#define AIC_ARR   "→ "

#define alog(fmt, ...)   pr_info(AIC_TAG fmt "\n", ##__VA_ARGS__)
#define alog_sep()       pr_info(AIC_TAG AIC_SEP "\n")
#define alog_sep2()      pr_info(AIC_TAG AIC_SEP2 "\n")
#define alog_ok(fmt, ...) pr_info(AIC_TAG AIC_OK fmt "\n", ##__VA_ARGS__)
#define alog_warn(fmt, ...) pr_warn(AIC_TAG AIC_WARN fmt "\n", ##__VA_ARGS__)
#define alog_err(fmt, ...) pr_err(AIC_TAG AIC_ERR fmt "\n", ##__VA_ARGS__)

/* ================================================================
 * PACKET STATS
 * ================================================================ */
struct pkt_stats {
    atomic64_t total, ipv4, ipv6, arp, other;
    atomic64_t tcp, udp, icmp;
    atomic64_t bytes_total;
    atomic64_t rx_total, rx_bytes;
    atomic64_t tx_dropped;
};

/* ================================================================
 * PRIVATE DATA
 * ================================================================ */
struct aicsemi_priv {
    struct usb_device       *udev;
    struct net_device       *netdev;
    struct usb_interface    *intf;
    u16                      pid;
    bool                     is_wifi;
    bool                     carrier_on;

    struct pkt_stats         stats;
    struct proc_dir_entry   *proc_entry;

    struct timer_list        watchdog;
    unsigned long            last_tx_jiffies;

    struct workqueue_struct *rx_wq;
    struct delayed_work      rx_work;
};

static struct proc_dir_entry *g_proc_dir;

/* ================================================================
 * IN THÔNG TIN CHI TIẾT THIẾT BỊ USB
 * ================================================================ */
static void aicsemi_log_device_info(struct usb_device *udev, u16 pid)
{
    alog_sep();
    alog("    AIC SEMI USB WIFI — NHẬN DIỆN THIẾT BỊ");
    alog_sep();
    alog("  Nhà sản xuất  : %s",
         udev->manufacturer ? udev->manufacturer : "(không rõ)");
    alog("  Tên sản phẩm  : %s",
         udev->product      ? udev->product      : "(không rõ)");
    alog("  Số serial      : %s",
         udev->serial       ? udev->serial       : "(không có)");
    alog("  VID:PID        : %04x:%04x",
         le16_to_cpu(udev->descriptor.idVendor),
         le16_to_cpu(udev->descriptor.idProduct));
    alog("  USB version    : %s",
         usb_speed_string(udev->speed));
    alog("  Bus / Device   : %03d / %03d",
         udev->bus->busnum, udev->devnum);
    alog("  Số cấu hình    : %d",
         udev->descriptor.bNumConfigurations);

    if (pid == PID_STORAGE) {
        alog_sep2();
        alog("  " AIC_WARN "CHẾ ĐỘ HIỆN TẠI : USB Mass Storage (0x5721)");
        alog("  Ý nghĩa        : Thiết bị đang giả lập ổ đĩa USB");
        alog("                   Bên trong chứa driver .exe cho Windows");
        alog("                   Trên Linux: cần gửi lệnh chuyển mode");
    } else {
        alog_sep2();
        alog("  " AIC_OK "CHẾ ĐỘ HIỆN TẠI : AIC WLAN Mode (0x8d80)");
        alog("  Ý nghĩa        : Thiết bị đã sẵn sàng hoạt động WiFi");
        alog("                   Driver sẽ tạo network interface aic0");
    }
    alog_sep();
}

/* ================================================================
 * MODESWITCH — Chuyển thiết bị từ Storage (5721) → WiFi (8d80)
 *
 * Thiết bị AIC Semi dùng cơ chế "ZeroCD" / "Eject":
 * Gửi SCSI EJECT command qua Bulk endpoint để firmware
 * tự ngắt kết nối và re-enumerate với PID WiFi.
 *
 * Tham khảo: usb-modeswitch database, các thiết bị tương tự
 * dùng MessageContent kiểu BBB (Bulk-Only Boot) hoặc eject SCSI.
 * ================================================================ */
static int aicsemi_trigger_modeswitch(struct aicsemi_priv *priv)
{
    int ret;

    alog_sep2();
    alog("  MODESWITCH: Chuyển từ Storage (5721) → WiFi (8d80)");
    alog_sep2();

    /*
     * Phương pháp 1: SCSI EJECT qua Bulk OUT endpoint
     * Đây là cách usb_modeswitch dùng cho hầu hết thiết bị ZeroCD.
     * CBW = Command Block Wrapper (USB Mass Storage BBB protocol)
     *
     * Byte sequence:
     *   55 53 42 43  = "USBC" (CBW signature)
     *   xx xx xx xx  = tag
     *   00 00 00 00  = data transfer length = 0
     *   00           = flags (host→device)
     *   00           = LUN 0
     *   06           = command length
     *   1b 00 00 00 02 00  = SCSI START/STOP UNIT (eject)
     *   + padding đến 31 bytes
     */
    {
        /* SCSI START STOP UNIT với LoEj=1 (eject) */
        static const u8 eject_cmd[31] = {
            0x55, 0x53, 0x42, 0x43,  /* "USBC" signature */
            0x12, 0x34, 0x56, 0x78,  /* tag */
            0x00, 0x00, 0x00, 0x00,  /* data length = 0 */
            0x00,                    /* flags = host→device */
            0x00,                    /* LUN */
            0x06,                    /* command length */
            0x1b, 0x00, 0x00, 0x00, /* SCSI: START STOP UNIT */
            0x02, 0x00,              /* LoEj=1 → eject */
            0x00, 0x00, 0x00, 0x00, /* padding */
            0x00, 0x00, 0x00, 0x00,
            0x00
        };

        u8 *buf = kmemdup(eject_cmd, sizeof(eject_cmd), GFP_KERNEL);
        if (buf) {
            /* Tìm bulk OUT endpoint */
            struct usb_host_interface *iface_desc =
                priv->intf->cur_altsetting;
            int ep_out = -1;
            int i;

            for (i = 0; i < iface_desc->desc.bNumEndpoints; i++) {
                struct usb_endpoint_descriptor *ep =
                    &iface_desc->endpoint[i].desc;
                if (usb_endpoint_is_bulk_out(ep)) {
                    ep_out = ep->bEndpointAddress;
                    break;
                }
            }

            if (ep_out >= 0) {
                int actual = 0;
                alog("  Phương pháp 1: SCSI EJECT qua Bulk OUT (ep=0x%02x)",
                     ep_out);
                ret = usb_bulk_msg(priv->udev,
                                   usb_sndbulkpipe(priv->udev, ep_out),
                                   buf, sizeof(eject_cmd),
                                   &actual, 5000);
                alog("  Bulk EJECT: ret=%d, actual=%d bytes", ret, actual);
            } else {
                alog_warn("Không tìm thấy Bulk OUT endpoint");
                ret = -ENODEV;
            }
            kfree(buf);
        } else {
            ret = -ENOMEM;
        }
    }

    if (ret == 0) {
        alog_ok("Phương pháp 1 thành công! Thiết bị sẽ re-enumerate → 0x8d80");
        return 0;
    }

    alog_warn("Phương pháp 1 thất bại (ret=%d) — thử Vendor Control Transfer", ret);

    /*
     * Phương pháp 2: Vendor Control Transfer
     * Một số firmware AIC dùng custom control request.
     * Thử nhiều bRequest khác nhau.
     */
    {
        struct { u8 req; u16 val; u16 idx; } attempts[] = {
            { 0x02, 0x0001, 0x0000 },  /* standard switch */
            { 0x01, 0x0000, 0x0000 },  /* alternate */
            { 0x03, 0x0001, 0x0001 },  /* alternate 2 */
        };
        int i;

        for (i = 0; i < (int)ARRAY_SIZE(attempts); i++) {
            alog("  Phương pháp 2.%d: Control bmReq=0x40 bReq=0x%02x "
                 "wVal=0x%04x wIdx=0x%04x",
                 i+1, attempts[i].req, attempts[i].val, attempts[i].idx);

            ret = usb_control_msg(priv->udev,
                                  usb_sndctrlpipe(priv->udev, 0),
                                  attempts[i].req,
                                  0x40,              /* vendor, device */
                                  attempts[i].val,
                                  attempts[i].idx,
                                  NULL, 0, 3000);

            alog("  → ret=%d %s", ret,
                 ret == 0 ? "(OK)" :
                 ret == -32 ? "(EPIPE - stall)" :
                 ret == -110 ? "(ETIMEDOUT)" :
                 ret == -19 ? "(ENODEV - disconnected!)" : "");

            if (ret == 0) {
                alog_ok("Phương pháp 2.%d thành công!", i+1);
                return 0;
            }
            /* -19 = thiết bị đã disconnect → modeswitch đang xảy ra */
            if (ret == -ENODEV) {
                alog_ok("Thiết bị đã disconnect (re-enumerating...) → modeswitch OK!");
                return 0;
            }
        }
    }

    alog_sep2();
    alog_warn("Tất cả phương pháp modeswitch thất bại");
    alog("  Thiết bị này cần capture Wireshark trên Windows để lấy");
    alog("  đúng command sequence từ driver gốc.");
    alog("  Driver vẫn tiếp tục — interface sẽ được tạo ở Storage mode.");
    alog_sep2();

    return ret;
}

/* ================================================================
 * WATCHDOG TIMER
 * ================================================================ */
static void aicsemi_watchdog(struct timer_list *t)
{
    struct aicsemi_priv *priv = aic_timer_of(priv, struct aicsemi_priv, watchdog);
    struct net_device   *dev  = priv->netdev;

    if (!dev || !netif_running(dev))
        return;

    if (netif_queue_stopped(dev)) {
        unsigned long diff = jiffies - priv->last_tx_jiffies;
        if (diff > msecs_to_jiffies(500)) {
            alog_warn("Watchdog: TX queue bị kẹt %u ms — đang mở lại...",
                      jiffies_to_msecs(diff));
            netif_wake_queue(dev);
            alog_ok("TX queue đã được mở lại");
        }
    }
    mod_timer(&priv->watchdog, jiffies + msecs_to_jiffies(1000));
}

/* ================================================================
 * RX SIMULATION
 * ================================================================ */
static void aicsemi_rx_work_fn(struct work_struct *work)
{
    struct aicsemi_priv *priv =
        container_of(to_delayed_work(work), struct aicsemi_priv, rx_work);
    struct net_device *dev = priv->netdev;
    struct sk_buff    *skb;
    struct ethhdr     *eth;

    if (!dev || !netif_running(dev))
        goto reschedule;

    skb = netdev_alloc_skb(dev, ETH_HLEN + 28);
    if (!skb)
        goto reschedule;

    skb_reset_mac_header(skb);
    eth = skb_put(skb, ETH_HLEN + 28);
    memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
    eth_broadcast_addr(eth->h_dest);
    eth->h_proto   = htons(ETH_P_ARP);
    skb->protocol  = htons(ETH_P_ARP);
    skb->ip_summed = CHECKSUM_UNNECESSARY;
    skb->dev       = dev;

    netif_rx(skb);

    atomic64_inc(&priv->stats.rx_total);
    atomic64_add(ETH_HLEN + 28, &priv->stats.rx_bytes);
    dev->stats.rx_packets++;
    dev->stats.rx_bytes += ETH_HLEN + 28;

    alog("  [RX SIM] Nhận gói ARP giả lập | %zu bytes | "
         "tổng RX: %llu",
         ETH_HLEN + 28UL,
         atomic64_read(&priv->stats.rx_total));

reschedule:
    queue_delayed_work(priv->rx_wq, &priv->rx_work,
                       msecs_to_jiffies(5000 + get_random_u32() % 5000));
}

/* ================================================================
 * PROC: /proc/aicsemi_usbnet/monitor
 * ================================================================ */
static int monitor_show(struct seq_file *m, void *v)
{
    struct aicsemi_priv *priv = m->private;
    if (!priv || !priv->is_wifi) {
        seq_puts(m, "Thiết bị chưa ở WiFi mode.\n");
        return 0;
    }
    seq_puts(m,   "============================================\n");
    seq_puts(m,   "  AIC Semi — Bảng thống kê gói tin\n");
    seq_puts(m,   "============================================\n");
    seq_printf(m, "  Interface : %s\n",  priv->netdev->name);
    seq_printf(m, "  Trạng thái: %s\n",
               priv->carrier_on ? "UP (đang hoạt động)" : "DOWN");
    seq_puts(m,   "--------------------------------------------\n");
    seq_printf(m, "  TX tổng   : %llu gói\n",
               atomic64_read(&priv->stats.total));
    seq_printf(m, "  TX bytes  : %llu bytes\n",
               atomic64_read(&priv->stats.bytes_total));
    seq_printf(m, "  TX bị rớt : %llu\n",
               atomic64_read(&priv->stats.tx_dropped));
    seq_puts(m,   "--------------------------------------------\n");
    seq_printf(m, "  RX tổng   : %llu gói\n",
               atomic64_read(&priv->stats.rx_total));
    seq_printf(m, "  RX bytes  : %llu bytes\n",
               atomic64_read(&priv->stats.rx_bytes));
    seq_puts(m,   "--------------------------------------------\n");
    seq_puts(m,   "  Phân loại giao thức (TX):\n");
    seq_printf(m, "    IPv4    : %llu\n", atomic64_read(&priv->stats.ipv4));
    seq_printf(m, "      TCP   : %llu\n", atomic64_read(&priv->stats.tcp));
    seq_printf(m, "      UDP   : %llu\n", atomic64_read(&priv->stats.udp));
    seq_printf(m, "      ICMP  : %llu\n", atomic64_read(&priv->stats.icmp));
    seq_printf(m, "    IPv6    : %llu\n", atomic64_read(&priv->stats.ipv6));
    seq_printf(m, "    ARP     : %llu\n", atomic64_read(&priv->stats.arp));
    seq_printf(m, "    Khác    : %llu\n", atomic64_read(&priv->stats.other));
    seq_puts(m,   "============================================\n");
    return 0;
}
static int monitor_open(struct inode *inode, struct file *file)
{
    return single_open(file, monitor_show, pde_data(inode));
}
static const struct proc_ops monitor_proc_ops = {
    .proc_open    = monitor_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ================================================================
 * ETHTOOL
 * ================================================================ */
static void aicsemi_get_drvinfo(struct net_device *dev,
                                 struct ethtool_drvinfo *info)
{
    struct aicsemi_priv *priv = dev->ml_priv;
    strscpy(info->driver,   DRIVER_NAME,    sizeof(info->driver));
    strscpy(info->version,  DRIVER_VERSION, sizeof(info->version));
    strscpy(info->bus_info, dev_name(&priv->udev->dev),
            sizeof(info->bus_info));
}
static int aicsemi_get_link_ksettings(struct net_device *dev,
                                       struct ethtool_link_ksettings *cmd)
{
    ethtool_link_ksettings_zero_link_mode(cmd, supported);
    ethtool_link_ksettings_add_link_mode(cmd, supported, 100baseT_Full);
    cmd->base.speed  = SPEED_100;
    cmd->base.duplex = DUPLEX_FULL;
    return 0;
}
static u32 aicsemi_get_link(struct net_device *dev)
{
    return ((struct aicsemi_priv *)dev->ml_priv)->carrier_on ? 1 : 0;
}
static const struct ethtool_ops aicsemi_ethtool_ops = {
    .get_drvinfo        = aicsemi_get_drvinfo,
    .get_link           = aicsemi_get_link,
    .get_link_ksettings = aicsemi_get_link_ksettings,
};

/* ================================================================
 * NET DEVICE OPS
 * ================================================================ */
static int aicsemi_net_open(struct net_device *dev)
{
    struct aicsemi_priv *priv = dev->ml_priv;

    alog_sep2();
    alog("  NDO OPEN — Interface '%s' được bật lên", dev->name);
    alog("  MAC address   : %pM", dev->dev_addr);
    alog("  MTU           : %d bytes", dev->mtu);
    alog("  Trạng thái    : TX queue đang khởi động...");

    netif_start_queue(dev);
    netif_carrier_on(dev);
    priv->carrier_on    = true;
    priv->last_tx_jiffies = jiffies;

    queue_delayed_work(priv->rx_wq, &priv->rx_work,
                       msecs_to_jiffies(3000));
    mod_timer(&priv->watchdog, jiffies + msecs_to_jiffies(1000));

    alog_ok("Interface '%s' đã UP — carrier detected", dev->name);
    alog_sep2();
    alog("  Gợi ý lệnh tiếp theo:");
    alog("    ip addr add 192.168.99.1/24 dev %s", dev->name);
    alog("    ping -c 5 192.168.99.2  (demo gửi ICMP)");
    alog("    sudo ./demo             (gửi gói thủ công qua raw socket)");
    alog_sep2();
    return 0;
}

static int aicsemi_net_stop(struct net_device *dev)
{
    struct aicsemi_priv *priv = dev->ml_priv;

    alog_sep2();
    alog("  NDO STOP — Interface '%s' đang tắt xuống", dev->name);
    alog("  TX đã gửi   : %llu gói / %llu bytes",
         atomic64_read(&priv->stats.total),
         atomic64_read(&priv->stats.bytes_total));
    alog("  RX đã nhận  : %llu gói / %llu bytes",
         atomic64_read(&priv->stats.rx_total),
         atomic64_read(&priv->stats.rx_bytes));

    netif_stop_queue(dev);
    netif_carrier_off(dev);
    priv->carrier_on = false;

    cancel_delayed_work_sync(&priv->rx_work);
    aic_timer_del_sync(&priv->watchdog);

    alog_ok("Interface '%s' đã DOWN — carrier mất", dev->name);
    alog_sep2();
    return 0;
}

/*
 * ndo_start_xmit — Nhận gói từ network stack, phân tích và log
 *
 * Đây là điểm "chặn" gói khi userspace gửi:
 *   ping / demo.c / nc / curl → kernel stack → hàm này
 */
static netdev_tx_t aicsemi_net_xmit(struct sk_buff *skb,
                                     struct net_device *dev)
{
    struct aicsemi_priv *priv = dev->ml_priv;
    struct ethhdr *eth;
    __be16  proto;
    u64     seq;
    char    src_mac[18], dst_mac[18];
    char    proto_str[20] = "KHÔNG RÕ";
    char    detail[120]   = "";

    if (skb->len < ETH_HLEN) {
        alog_warn("TX: gói quá ngắn (%d bytes) — bỏ qua", skb->len);
        atomic64_inc(&priv->stats.tx_dropped);
        dev->stats.tx_dropped++;
        goto done;
    }

    eth   = (struct ethhdr *)skb->data;
    proto = eth->h_proto;
    seq   = atomic64_inc_return(&priv->stats.total);
    atomic64_add(skb->len, &priv->stats.bytes_total);
    priv->last_tx_jiffies = jiffies;

    /* Format MAC */
    snprintf(src_mac, sizeof(src_mac), "%pM", eth->h_source);
    snprintf(dst_mac, sizeof(dst_mac), "%pM", eth->h_dest);

    /* ── Phân tích EtherType ── */
    if (proto == htons(ETH_P_IP)) {
        struct iphdr *iph;
        atomic64_inc(&priv->stats.ipv4);

        if (skb->len < ETH_HLEN + sizeof(*iph))
            goto log_it;

        iph = (struct iphdr *)(skb->data + ETH_HLEN);

        if (iph->protocol == IPPROTO_TCP) {
            atomic64_inc(&priv->stats.tcp);
            strscpy(proto_str, "IPv4 / TCP", sizeof(proto_str));

            if (skb->len >= ETH_HLEN + iph->ihl*4 +
                            (int)sizeof(struct tcphdr)) {
                struct tcphdr *th = (struct tcphdr *)
                    (skb->data + ETH_HLEN + iph->ihl*4);
                snprintf(detail, sizeof(detail),
                         "  %pI4:%u  →  %pI4:%u  |  flags=[%s%s%s%s%s]  |  TTL=%u",
                         &iph->saddr, ntohs(th->source),
                         &iph->daddr, ntohs(th->dest),
                         th->syn ? "SYN " : "",
                         th->ack ? "ACK " : "",
                         th->fin ? "FIN " : "",
                         th->rst ? "RST " : "",
                         th->psh ? "PSH"  : "",
                         iph->ttl);
            }

        } else if (iph->protocol == IPPROTO_UDP) {
            atomic64_inc(&priv->stats.udp);

            if (skb->len >= ETH_HLEN + iph->ihl*4 +
                            (int)sizeof(struct udphdr)) {
                struct udphdr *uh = (struct udphdr *)
                    (skb->data + ETH_HLEN + iph->ihl*4);
                u16 dp = ntohs(uh->dest);

                if (dp == 53) {
                    strscpy(proto_str, "IPv4 / DNS", sizeof(proto_str));
                    snprintf(detail, sizeof(detail),
                             "  %pI4  →  %pI4:53  |  truy vấn DNS",
                             &iph->saddr, &iph->daddr);
                } else if (dp == 67 || dp == 68) {
                    strscpy(proto_str, "IPv4 / DHCP", sizeof(proto_str));
                    snprintf(detail, sizeof(detail),
                             "  %pI4  →  %pI4:%u  |  yêu cầu DHCP",
                             &iph->saddr, &iph->daddr, dp);
                } else {
                    strscpy(proto_str, "IPv4 / UDP", sizeof(proto_str));
                    snprintf(detail, sizeof(detail),
                             "  %pI4:%u  →  %pI4:%u  |  TTL=%u",
                             &iph->saddr, ntohs(uh->source),
                             &iph->daddr, dp,
                             iph->ttl);
                }
            }

        } else if (iph->protocol == IPPROTO_ICMP) {
            atomic64_inc(&priv->stats.icmp);
            strscpy(proto_str, "IPv4 / ICMP", sizeof(proto_str));

            if (skb->len >= ETH_HLEN + iph->ihl*4 +
                            (int)sizeof(struct icmphdr)) {
                struct icmphdr *ich = (struct icmphdr *)
                    (skb->data + ETH_HLEN + iph->ihl*4);
                const char *icmp_type =
                    (ich->type == ICMP_ECHO)     ? "Echo Request (ping)" :
                    (ich->type == ICMP_ECHOREPLY) ? "Echo Reply"         :
                    (ich->type == ICMP_DEST_UNREACH) ? "Dest Unreachable" :
                    "khác";
                snprintf(detail, sizeof(detail),
                         "  %pI4  →  %pI4  |  type=%u (%s)  |  TTL=%u",
                         &iph->saddr, &iph->daddr,
                         ich->type, icmp_type,
                         iph->ttl);
            }

        } else {
            snprintf(proto_str, sizeof(proto_str),
                     "IPv4 / proto=%u", iph->protocol);
            snprintf(detail, sizeof(detail),
                     "  %pI4  →  %pI4",
                     &iph->saddr, &iph->daddr);
        }

    } else if (proto == htons(ETH_P_IPV6)) {
        atomic64_inc(&priv->stats.ipv6);
        strscpy(proto_str, "IPv6", sizeof(proto_str));
        snprintf(detail, sizeof(detail), "  (gói IPv6)");

    } else if (proto == htons(ETH_P_ARP)) {
        atomic64_inc(&priv->stats.arp);
        strscpy(proto_str, "ARP", sizeof(proto_str));
        snprintf(detail, sizeof(detail),
                 "  ai có IP này? (broadcast)");

    } else {
        atomic64_inc(&priv->stats.other);
        snprintf(proto_str, sizeof(proto_str),
                 "Không rõ (0x%04x)", ntohs(proto));
    }

log_it:
    /* ── In log gói tin ── */
    alog("  [TX #%-4llu] %s bytes=%-5d  src=%s  dst=%s",
         seq, proto_str, skb->len, src_mac, dst_mac);
    if (detail[0])
        alog("           %s", detail);

    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;

done:
    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static void aicsemi_get_stats64(struct net_device *dev,
                                 struct rtnl_link_stats64 *s)
{
    struct aicsemi_priv *priv = dev->ml_priv;
    s->tx_packets = dev->stats.tx_packets;
    s->tx_bytes   = dev->stats.tx_bytes;
    s->rx_packets = atomic64_read(&priv->stats.rx_total);
    s->rx_bytes   = atomic64_read(&priv->stats.rx_bytes);
    s->tx_dropped = atomic64_read(&priv->stats.tx_dropped);
}

static int aicsemi_change_mtu(struct net_device *dev, int new_mtu)
{
    if (new_mtu < 68 || new_mtu > 1500)
        return -EINVAL;
    alog("  MTU thay đổi: %d → %d bytes", dev->mtu, new_mtu);
    WRITE_ONCE(dev->mtu, new_mtu);
    return 0;
}

static const struct net_device_ops aicsemi_netdev_ops = {
    .ndo_open        = aicsemi_net_open,
    .ndo_stop        = aicsemi_net_stop,
    .ndo_start_xmit  = aicsemi_net_xmit,
    .ndo_get_stats64 = aicsemi_get_stats64,
    .ndo_change_mtu  = aicsemi_change_mtu,
};

/* ================================================================
 * TẠO NETWORK INTERFACE
 * ================================================================ */
static int aicsemi_create_netdev(struct usb_interface *intf,
                                  struct aicsemi_priv *priv)
{
    struct net_device *dev;
    int ret;

    alog("  Đang cấp phát network device...");

    dev = alloc_etherdev(0);
    if (!dev) {
        alog_err("alloc_etherdev thất bại — không đủ bộ nhớ kernel!");
        return -ENOMEM;
    }

    /* Tên interface động — tránh EEXIST (-17) nếu aic0 đã tồn tại */
    snprintf(dev->name, IFNAMSIZ, "aic%%d");
    eth_hw_addr_random(dev);

    alog("  Tên interface  : %s", dev->name);
    alog("  MAC (ngẫu nhiên): %pM", dev->dev_addr);
    alog("  MTU mặc định   : %d bytes", dev->mtu);

    dev->netdev_ops  = &aicsemi_netdev_ops;
    dev->ethtool_ops = &aicsemi_ethtool_ops;
    dev->mtu         = 1500;
    dev->min_mtu     = 68;
    dev->max_mtu     = 1500;

    SET_NETDEV_DEV(dev, &intf->dev);
    netif_carrier_off(dev);
    dev->ml_priv = priv;
    priv->netdev = dev;

    alog("  Đang đăng ký interface với kernel...");
    ret = register_netdev(dev);
    if (ret) {
        alog_err("register_netdev thất bại, mã lỗi: %d", ret);
        free_netdev(dev);
        priv->netdev = NULL;
        return ret;
    }

    alog_ok("Interface '%s' đã được đăng ký với kernel!", dev->name);
    return 0;
}

/* ================================================================
 * USB PROBE — Điểm vào khi kernel nhận diện thiết bị
 * ================================================================ */
static int aicsemi_probe(struct usb_interface *intf,
                          const struct usb_device_id *id)
{
    struct usb_device   *udev = interface_to_usbdev(intf);
    struct aicsemi_priv *priv;
    u16 pid = le16_to_cpu(udev->descriptor.idProduct);
    int ret = 0;

    /* In thông tin thiết bị */
    aicsemi_log_device_info(udev, pid);

    /* Cấp phát private data */
    alog("  Đang cấp phát bộ nhớ private data (%zu bytes)...",
         sizeof(*priv));
    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        alog_err("kzalloc thất bại — kernel hết bộ nhớ!");
        return -ENOMEM;
    }
    alog_ok("Cấp phát %zu bytes bộ nhớ kernel thành công", sizeof(*priv));

    priv->udev = udev;
    priv->intf = intf;
    priv->pid  = pid;

    /* Init atomic counters */
    atomic64_set(&priv->stats.total,       0);
    atomic64_set(&priv->stats.ipv4,        0);
    atomic64_set(&priv->stats.ipv6,        0);
    atomic64_set(&priv->stats.arp,         0);
    atomic64_set(&priv->stats.other,       0);
    atomic64_set(&priv->stats.tcp,         0);
    atomic64_set(&priv->stats.udp,         0);
    atomic64_set(&priv->stats.icmp,        0);
    atomic64_set(&priv->stats.bytes_total, 0);
    atomic64_set(&priv->stats.rx_total,    0);
    atomic64_set(&priv->stats.rx_bytes,    0);
    atomic64_set(&priv->stats.tx_dropped,  0);

    timer_setup(&priv->watchdog, aicsemi_watchdog, 0);
    alog_ok("Watchdog timer đã khởi tạo (chu kỳ 1000ms)");

    /* ── Xử lý theo mode ── */
    if (pid == PID_STORAGE) {
        priv->is_wifi = false;
        alog_sep2();
        alog("  " AIC_WARN "STORAGE MODE (0x5721) — Thực hiện modeswitch");
        alog("  Mục tiêu      : Chuyển thiết bị sang WiFi mode (0x8d80)");
        alog("  Phương pháp   : SCSI Eject → Vendor Control Transfer");
        alog_sep2();

        aicsemi_trigger_modeswitch(priv);

        /*
         * Sau modeswitch, thiết bị sẽ:
         *   - Disconnect (kernel gọi disconnect() cho PID 5721)
         *   - Re-enumerate với PID 8d80
         *   - Kernel gọi probe() lần nữa với PID 8d80
         *   - Lúc đó mới tạo interface aic0
         *
         * Ở đây chỉ lưu priv và return — KHÔNG tạo interface.
         */
        alog("  Đang chờ thiết bị re-enumerate...");
        alog("  → Kernel sẽ gọi probe() lại với PID 0x8d80");

    } else if (pid == PID_WIFI) {
        priv->is_wifi = true;
        alog_sep2();
        alog("  " AIC_STAR "WIFI MODE (0x8d80) — Khởi tạo network interface");
        alog_sep2();

        /* Workqueue cho RX simulation */
        alog("  Tạo workqueue 'aicsemi_rx'...");
        priv->rx_wq = alloc_workqueue("aicsemi_rx",
                                       WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
        if (!priv->rx_wq) {
            alog_err("alloc_workqueue thất bại!");
            kfree(priv);
            return -ENOMEM;
        }
        INIT_DELAYED_WORK(&priv->rx_work, aicsemi_rx_work_fn);
        alog_ok("Workqueue RX đã sẵn sàng");

        /* Tạo network interface */
        alog_sep2();
        ret = aicsemi_create_netdev(intf, priv);
        if (ret) {
            destroy_workqueue(priv->rx_wq);
            kfree(priv);
            return ret;
        }

        /* /proc interface */
        alog_sep2();
        alog("  Tạo /proc/aicsemi_usbnet/monitor...");
        g_proc_dir = proc_mkdir("aicsemi_usbnet", NULL);
        if (g_proc_dir) {
            priv->proc_entry = proc_create_data(
                "monitor", 0444, g_proc_dir,
                &monitor_proc_ops, priv);
            if (priv->proc_entry)
                alog_ok("/proc/aicsemi_usbnet/monitor: OK");
        }

        /* Tóm tắt */
        alog_sep();
        alog("  " AIC_STAR "DRIVER KHỞI ĐỘNG THÀNH CÔNG!");
        alog_sep();
        alog("  Kernel ver    : %d.%d.%d",
             (LINUX_VERSION_CODE >> 16) & 0xff,
             (LINUX_VERSION_CODE >>  8) & 0xff,
             LINUX_VERSION_CODE & 0xff);
        alog("  Driver ver    : %s", DRIVER_VERSION);
        alog("  Interface     : %s", priv->netdev->name);
        alog("  MAC address   : %pM", priv->netdev->dev_addr);
        alog_sep2();
        alog("  Lệnh để test:");
        alog("    sudo ip link set aic0 up");
        alog("    sudo ip addr add 192.168.99.1/24 dev aic0");
        alog("    ping -c 5 192.168.99.2");
        alog("    sudo ./demo");
        alog("    cat /proc/aicsemi_usbnet/monitor");
        alog_sep();
    }

    usb_set_intfdata(intf, priv);
    return 0;
}

/* ================================================================
 * USB DISCONNECT — Được gọi khi rút thiết bị
 * ================================================================ */
static void aicsemi_disconnect(struct usb_interface *intf)
{
    struct aicsemi_priv *priv = usb_get_intfdata(intf);
    u64 tx, rx, tcp, udp, icmp, arp, dropped;

    if (!priv)
        return;

    alog_sep();
    alog("  " AIC_WARN "THIẾT BỊ BỊ RÚT RA — Bắt đầu dọn dẹp tài nguyên");
    alog("  PID         : 0x%04x", priv->pid);
    alog("  Mode        : %s",
         priv->is_wifi ? "WiFi (8d80)" : "Storage (5721)");
    alog_sep2();

    if (priv->is_wifi && priv->netdev) {
        tx      = atomic64_read(&priv->stats.total);
        rx      = atomic64_read(&priv->stats.rx_total);
        tcp     = atomic64_read(&priv->stats.tcp);
        udp     = atomic64_read(&priv->stats.udp);
        icmp    = atomic64_read(&priv->stats.icmp);
        arp     = atomic64_read(&priv->stats.arp);
        dropped = atomic64_read(&priv->stats.tx_dropped);

        /* In thống kê phiên làm việc */
        alog("  THỐNG KÊ PHIÊN LÀM VIỆC:");
        alog("    TX gửi đi   : %llu gói  /  %llu bytes",
             tx, atomic64_read(&priv->stats.bytes_total));
        alog("    RX nhận về  : %llu gói  /  %llu bytes",
             rx, atomic64_read(&priv->stats.rx_bytes));
        alog("    TX bị rớt   : %llu gói", dropped);
        alog_sep2();
        /*
         * QUAN TRỌNG: Kernel KHÔNG cho phép dùng float/double!
         * FPU bị tắt trong kernel context → dùng integer arithmetic.
         * Tính phần trăm: (count * 100) / total  →  xx%
         * Tính phần lẻ:  (count * 1000 / total) % 10  →  .x
         */
        alog("    Giao thức TX:");
        alog("      TCP        : %llu gói  (%llu.%llu%%)",
             tcp,
             tx ? (tcp  * 100) / tx : 0,
             tx ? (tcp  * 1000 / tx) % 10 : 0);
        alog("      UDP        : %llu gói  (%llu.%llu%%)",
             udp,
             tx ? (udp  * 100) / tx : 0,
             tx ? (udp  * 1000 / tx) % 10 : 0);
        alog("      ICMP       : %llu gói  (%llu.%llu%%)",
             icmp,
             tx ? (icmp * 100) / tx : 0,
             tx ? (icmp * 1000 / tx) % 10 : 0);
        alog("      ARP        : %llu gói  (%llu.%llu%%)",
             arp,
             tx ? (arp  * 100) / tx : 0,
             tx ? (arp  * 1000 / tx) % 10 : 0);
        alog_sep2();

        /* Dọn workqueue */
        alog("  Dừng RX workqueue...");
        if (priv->rx_wq) {
            cancel_delayed_work_sync(&priv->rx_work);
            destroy_workqueue(priv->rx_wq);
        }
        alog_ok("RX workqueue đã dừng");

        /* Dọn timer */
        alog("  Hủy watchdog timer...");
        aic_timer_del_sync(&priv->watchdog);
        alog_ok("Watchdog timer đã hủy");

        /* Dọn proc */
        alog("  Xóa /proc/aicsemi_usbnet...");
        if (priv->proc_entry)
            proc_remove(priv->proc_entry);
        if (g_proc_dir) {
            proc_remove(g_proc_dir);
            g_proc_dir = NULL;
        }
        alog_ok("Proc entry đã xóa");

        /* Hủy interface */
        alog("  Hủy đăng ký interface '%s'...", priv->netdev->name);
        unregister_netdev(priv->netdev);
        free_netdev(priv->netdev);
        alog_ok("Interface đã được gỡ khỏi kernel");

    } else {
        /* Storage mode: chỉ dọn timer */
        aic_timer_del(&priv->watchdog);
        alog("  Storage mode: không có interface cần dọn");
    }

    kfree(priv);
    usb_set_intfdata(intf, NULL);

    alog_sep2();
    alog_ok("Tất cả tài nguyên kernel đã được giải phóng");
    alog_ok("Driver đã gỡ thiết bị hoàn toàn — an toàn để unplug");
    alog_sep();
}

/* ================================================================
 * USB ID TABLE & DRIVER REGISTRATION
 * ================================================================ */
static const struct usb_device_id aicsemi_id_table[] = {
    { USB_DEVICE(VENDOR_AIC, PID_STORAGE) },
    { USB_DEVICE(VENDOR_AIC, PID_WIFI)    },
    { }
};
MODULE_DEVICE_TABLE(usb, aicsemi_id_table);

static struct usb_driver aicsemi_usb_driver = {
    .name       = DRIVER_NAME,
    .id_table   = aicsemi_id_table,
    .probe      = aicsemi_probe,
    .disconnect = aicsemi_disconnect,
};

/* ================================================================
 * MODULE INIT / EXIT — dùng macro thay vì viết tay
 * ================================================================ */
module_usb_driver(aicsemi_usb_driver);
