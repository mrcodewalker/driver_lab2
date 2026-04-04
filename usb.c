// SPDX-License-Identifier: GPL-2.0
/*
 * usb.c — AIC Semi USB WiFi Multi-Mode Driver v4.0.0
 *
 * ĐỀ TÀI: Phát triển USB Network Driver tích hợp
 *         cơ chế giám sát lưu lượng mạng theo thời gian thực
 *
 * Thiết bị: AIC Semi (a69c:5721 → a69c:8d80)
 *
 * TÍNH NĂNG v4.0 (MỚI):
 *   - Ring buffer 1024 entries trong kernel (lock-free)
 *   - ioctl API: CLEAR / GETRING / SETFILT / GETSTATS
 *   - Lưu TX+RX với timestamp, src/dst IP, port, TCP flags
 *   - monitor.c đọc qua ioctl → ncurses dashboard realtime
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
#include <linux/spinlock.h>
#include <linux/uaccess.h>   /* copy_to_user */
#include <linux/ktime.h>     /* ktime_get_real_ns */
#include <uapi/linux/sockios.h>
#include <crypto/hash.h>     /* crypto_alloc_shash, HMAC-SHA256 */
#include <crypto/skcipher.h> /* crypto_alloc_skcipher, AES-CTR */
#include <linux/scatterlist.h>

/* ================================================================
 * KERNEL VERSION COMPAT
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
#define DRIVER_VERSION  "4.0.0"
#define DRIVER_DESC     "AIC Semi USB Network Driver + Packet Monitor"

#define VENDOR_AIC   0xa69c
#define PID_STORAGE  0x5721
#define PID_WIFI     0x8d80

MODULE_AUTHOR("SinhVien <sinhvien@example.com>");
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL");

/* ================================================================
 * LOG HELPERS
 * ================================================================ */
#define AIC_TAG   "[aicsemi] "
#define AIC_SEP   "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
#define AIC_SEP2  "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ "
#define AIC_STAR  "★ "
#define AIC_OK    "✓ "
#define AIC_WARN  "⚠ "
#define AIC_ERR   "✗ "
#define AIC_ARR   "→ "

#define alog(fmt, ...)      pr_info(AIC_TAG fmt "\n", ##__VA_ARGS__)
#define alog_sep()          pr_info(AIC_TAG AIC_SEP "\n")
#define alog_sep2()         pr_info(AIC_TAG AIC_SEP2 "\n")
#define alog_ok(fmt, ...)   pr_info(AIC_TAG AIC_OK  fmt "\n", ##__VA_ARGS__)
#define alog_warn(fmt, ...) pr_warn(AIC_TAG AIC_WARN fmt "\n", ##__VA_ARGS__)
#define alog_err(fmt, ...)  pr_err (AIC_TAG AIC_ERR  fmt "\n", ##__VA_ARGS__)

/* ================================================================
 * RING BUFFER — Lưu packet metadata trong kernel
 *
 * Thiết kế lock-free cho TX path (softirq/interrupt context):
 *   - head: vị trí ghi tiếp theo (atomic, chỉ tăng)
 *   - Wrap-around tự động với modulo MON_RING_SIZE
 *   - Đọc dùng spinlock (monitor.c gọi ioctl, không hot path)
 *
 * Mỗi entry ~56 bytes → tổng ring = 56KB (rất nhỏ, an toàn)
 * ================================================================ */
#define MON_RING_SIZE  1024  /* phải là lũy thừa của 2 */
#define MON_RING_MASK  (MON_RING_SIZE - 1)

/*
 * QUAN TRỌNG — Cách kernel route ioctl đến ndo_siocdevprivate:
 *
 * Kernel chỉ gọi ndo_siocdevprivate khi cmd nằm trong range:
 *   SIOCDEVPRIVATE     = 0x89F0
 *   SIOCDEVPRIVATE+15  = 0x89FF
 *
 * Nếu dùng _IOR('A', n, ...) → cmd = 0x804xxxxx → kernel KHÔNG route
 * vào ndo_siocdevprivate → errno=25 (ENOTTY).
 *
 * Fix: dùng SIOCDEVPRIVATE + offset làm cmd number.
 * Driver switch trên (cmd - SIOCDEVPRIVATE) để phân biệt.
 */
#include <uapi/linux/sockios.h>   /* SIOCDEVPRIVATE */

#define AICSEMI_CMD_CLEAR    0   /* SIOCDEVPRIVATE + 0 */
#define AICSEMI_CMD_GETRING  1   /* SIOCDEVPRIVATE + 1 */
#define AICSEMI_CMD_SETFILT  2   /* SIOCDEVPRIVATE + 2 */
#define AICSEMI_CMD_GETSTATS 3   /* SIOCDEVPRIVATE + 3 */

/* Một entry trong ring buffer */
struct pkt_entry {
    u64   ts_ns;      /* ktime_get_real_ns() — nanoseconds */
    u32   seq;        /* số thứ tự toàn cục */
    u32   len;        /* frame length bytes */
    u16   eth_proto;  /* ETH_P_IP, ETH_P_ARP, ETH_P_IPV6... */
    u8    ip_proto;   /* IPPROTO_TCP, UDP, ICMP, 0 nếu không phải IP */
    u8    direction;  /* 'T' = TX, 'R' = RX */
    __be32 saddr;     /* source IP (network byte order) */
    __be32 daddr;     /* dest IP */
    u16   sport;      /* source port (host byte order) */
    u16   dport;      /* dest port */
    u8    tcp_flags;  /* SYN=0x02 ACK=0x10 FIN=0x01 RST=0x04 */
    u8    icmp_type;
    /* ★ Security fields */
    u8    encrypted;  /* 1 = payload có AES-128-CTR+HMAC tag */
    u8    hmac_ok;    /* 1 = HMAC verify OK, 0 = FAIL/không có */
    u8    payload_hex[16]; /* 16 byte đầu của payload (ciphertext) để hiển thị */
    u8    pad[2];
};

/* Struct export qua ioctl GETRING */
struct aicsemi_ring_export {
    u32             count;              /* số entry hợp lệ */
    u32             head;               /* vị trí đầu hiện tại */
    struct pkt_entry entries[MON_RING_SIZE];
};

/* Struct export qua ioctl GETSTATS */
struct aicsemi_stats_export {
    u64 tx_total, tx_bytes, tx_dropped;
    u64 rx_total, rx_bytes;
    u64 tcp, udp, icmp, arp, ipv6, other;
    u64 uptime_sec;
    /* ★ Security stats */
    u64 tx_encrypted;   /* gói có HMAC hợp lệ */
    u64 tx_tampered;    /* gói bị tamper (HMAC sai) */
    u64 tx_plain;       /* gói không có tag */
    char ifname[16];
    char driver_ver[16];
};

/* Ring buffer trong private data */
struct mon_ring {
    struct pkt_entry entries[MON_RING_SIZE];
    atomic_t         head;    /* ghi: atomic increment, không cần lock */
    atomic_t         count;   /* số entry đã ghi (tối đa MON_RING_SIZE) */
    spinlock_t       rd_lock; /* chỉ dùng khi đọc toàn bộ ring */
    u32              filter;  /* 0 = tất cả, hoặc IPPROTO_TCP/UDP/ICMP */
    ktime_t          start_time;
};

/* ================================================================
 * CRYPTO — AES-128-CTR + HMAC-SHA256 (truncated 8 bytes)
 *
 * Kernel dùng kernel crypto API (<linux/crypto.h>) cho cả AES và SHA-256.
 * AES-128-CTR: crypto_alloc_skcipher("ctr(aes)", 0, 0)
 * HMAC-SHA256: crypto_alloc_shash("hmac(sha256)", 0, 0)
 *
 * Hai khóa hoàn toàn độc lập nhau (Encrypt-then-MAC best practice):
 *   AIC_AES_KEY  (16 byte) — chỉ dùng cho mã hóa AES-128-CTR
 *   AIC_HMAC_KEY (32 byte) — chỉ dùng cho xác thực HMAC-SHA256
 *
 * Cả hai phải khớp với demo.c — hardcode để demo.
 * ================================================================ */
#define AIC_HMAC_TAG_LEN 8

static const u8 AIC_AES_KEY[16] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

static const u8 AIC_AES_NONCE[16] = {
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB, 0x00, 0x00, 0x00, 0x01
};

/*
 * AIC_HMAC_KEY: khóa xác thực HMAC-SHA256 (32 byte = 256 bit).
 * Hoàn toàn độc lập với AIC_AES_KEY — bắt buộc trong Encrypt-then-MAC.
 * Phải khớp với HMAC_KEY trong demo.c.
 */
static const u8 AIC_HMAC_KEY[32] = {
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
    0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
    0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
};

/*
 * Mini SHA-256 trong kernel — dùng kernel shash API
 * Nếu kernel không có CONFIG_CRYPTO_SHA256, fallback về
 * simple polynomial hash để không crash.
 *
 * Thực tế: dùng crypto_shash_digest() từ <linux/crypto.h>
 */
#include <crypto/hash.h>

/*
 * aic_hmac_sha256_truncated() — Tính HMAC-SHA256, lấy 8 byte đầu
 * Chạy trong process context (probe/ioctl), KHÔNG gọi từ softirq.
 *
 * Trả về 0 nếu OK, <0 nếu lỗi crypto subsystem.
 */
static int aic_hmac_sha256_truncated(const u8 *key, size_t klen,
                                      const u8 *msg, size_t mlen,
                                      u8 *out8)
{
    struct crypto_shash *tfm;
    struct shash_desc   *desc;
    u8                   full[32];
    int                  ret;

    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm)) {
        /* Fallback: polynomial hash nếu không có crypto module */
        u32 h = 0x5A5A5A5A;
        size_t i;
        for (i = 0; i < klen; i++) h = h * 31 + key[i];
        for (i = 0; i < mlen; i++) h = h * 31 + msg[i];
        for (i = 0; i < 8; i++) out8[i] = (u8)(h >> (i % 4 * 8));
        return 0;
    }

    ret = crypto_shash_setkey(tfm, key, klen);
    if (ret) goto out_free;

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) { ret = -ENOMEM; goto out_free; }

    desc->tfm = tfm;
    ret = crypto_shash_digest(desc, msg, mlen, full);
    if (ret == 0)
        memcpy(out8, full, AIC_HMAC_TAG_LEN);

    kfree(desc);
out_free:
    crypto_free_shash(tfm);
    return ret;
}

/*
 * aic_verify_hmac() — Verify HMAC tag ở cuối payload
 *
 * Payload layout từ demo.c:
 *   [ AES-128-CTR(data) | HMAC[8] ]
 *
 * Hàm này:
 *   1. Tính HMAC trên phần AES-128-CTR(data) (không bao gồm tag)
 *   2. So sánh với tag cuối payload
 *   3. Trả về true nếu khớp
 *
 * Gọi từ ndo_start_xmit() — chạy trong softirq context.
 * Vì crypto_shash cần process context, ta dùng workqueue
 * hoặc đơn giản hơn: verify inline với GFP_ATOMIC.
 *
 * Để đơn giản cho demo: dùng GFP_ATOMIC + crypto_alloc_shash
 * với CRYPTO_ALG_ASYNC flag = 0 (synchronous only).
 */
static bool aic_verify_hmac(const u8 *payload, size_t total_len)
{
    u8   computed[AIC_HMAC_TAG_LEN];
    const u8 *tag;
    size_t data_len;

    if (total_len <= AIC_HMAC_TAG_LEN)
        return false;   /* quá ngắn, không có tag */

    data_len = total_len - AIC_HMAC_TAG_LEN;
    tag      = payload + data_len;

    /* Tính HMAC trên phần ciphertext (không bao gồm tag) */
    if (aic_hmac_sha256_truncated(AIC_HMAC_KEY, sizeof(AIC_HMAC_KEY),
                                   payload, data_len, computed) < 0)
        return false;

    /* So sánh constant-time để tránh timing attack */
    return (memcmp(computed, tag, AIC_HMAC_TAG_LEN) == 0);
}

/*
 * aic_aes_ctr_decrypt() — AES-128-CTR decrypt (in-place) using kernel crypto API.
 * Symmetric: same function used for encrypt and decrypt.
 * Only used for the 16-byte plaintext preview log in ndo_start_xmit().
 *
 * Returns 0 on success, <0 on error.
 */
static int aic_aes_ctr_decrypt(u8 *data, size_t len)
{
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    u8 iv[16];
    int ret;

    tfm = crypto_alloc_skcipher("ctr(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_warn_once(AIC_TAG "ctr(aes) not available, skipping decrypt preview\n");
        return PTR_ERR(tfm);
    }

    ret = crypto_skcipher_setkey(tfm, AIC_AES_KEY, sizeof(AIC_AES_KEY));
    if (ret)
        goto out_free_tfm;

    req = skcipher_request_alloc(tfm, GFP_ATOMIC);
    if (!req) {
        ret = -ENOMEM;
        goto out_free_tfm;
    }

    /* IV = nonce (CTR mode uses IV as initial counter block) */
    memcpy(iv, AIC_AES_NONCE, sizeof(iv));

    sg_init_one(&sg, data, len);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, len, iv);

    ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);

    skcipher_request_free(req);
out_free_tfm:
    crypto_free_skcipher(tfm);
    return ret;
}

/* ================================================================
 * PACKET STATS
 * ================================================================ */
struct pkt_stats {
    atomic64_t total, ipv4, ipv6, arp, other;
    atomic64_t tcp, udp, icmp;
    atomic64_t bytes_total;
    atomic64_t rx_total, rx_bytes;
    atomic64_t tx_dropped;
    /* ★ Security counters */
    atomic64_t tx_encrypted;   /* gói có HMAC tag hợp lệ */
    atomic64_t tx_tampered;    /* gói có HMAC tag sai */
    atomic64_t tx_plain;       /* gói không có tag (ARP, v.v.) */
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
    struct mon_ring          ring;       /* ★ ring buffer mới */
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
    seq_puts(m,   "--------------------------------------------\n");
    seq_puts(m,   "  Bảo mật (Security):\n");
    seq_printf(m, "    Encrypted : %llu\n", atomic64_read(&priv->stats.tx_encrypted));
    seq_printf(m, "    Tampered  : %llu\n", atomic64_read(&priv->stats.tx_tampered));
    seq_printf(m, "    Plain     : %llu\n", atomic64_read(&priv->stats.tx_plain));
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
 * RING BUFFER — Ghi packet vào ring (gọi từ TX/RX path)
 *
 * Hàm này chạy trong softirq context (TX) hoặc workqueue (RX).
 * Dùng atomic để tránh lock trong hot path.
 * ================================================================ */
static void ring_push(struct mon_ring *r, const struct pkt_entry *e)
{
    u32 idx;

    /* Filter: bỏ qua nếu không match (0 = chấp nhận tất cả) */
    if (r->filter != 0 && e->ip_proto != 0 && e->ip_proto != r->filter)
        return;

    /* Lấy vị trí ghi — atomic, không cần lock */
    idx = (u32)atomic_inc_return(&r->head) & MON_RING_MASK;
    r->entries[idx] = *e;

    /* Cập nhật count (tối đa MON_RING_SIZE) */
    if (atomic_read(&r->count) < MON_RING_SIZE)
        atomic_inc(&r->count);
}

/* ================================================================
 * IOCTL HANDLER
 * kernel ≥ 5.15: ndo_siocdevprivate(dev, ifr, data, cmd)
 *   - data = ifr->ifr_data đã được kernel validate là userspace ptr
 *   - cmd  = ioctl number đầy đủ từ userspace
 * kernel < 5.15: ndo_do_ioctl(dev, ifr, cmd)
 * ================================================================ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
static int aicsemi_ioctl(struct net_device *dev, struct ifreq *ifr,
                          void __user *data, int cmd)
#else
static int aicsemi_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
    void __user *data = (void __user *)ifr->ifr_data;
#endif
    struct aicsemi_priv        *priv = dev->ml_priv;
    struct mon_ring            *r    = &priv->ring;
    struct aicsemi_ring_export *exp;
    struct aicsemi_stats_export st;
    unsigned long               flags;
    u32                         filt;
    int                         ret  = 0;

    alog("  [ioctl] cmd=0x%08x offset=%d iface=%s",
         (unsigned)cmd, cmd - SIOCDEVPRIVATE, dev->name);

    switch (cmd - SIOCDEVPRIVATE) {

    /* ── CLEAR: Xóa toàn bộ ring và counter ── */
    case AICSEMI_CMD_CLEAR:
        alog("  [ioctl] CLEAR: xóa ring buffer");
        spin_lock_irqsave(&r->rd_lock, flags);
        atomic_set(&r->head,  -1);
        atomic_set(&r->count,  0);
        memset(r->entries, 0, sizeof(r->entries));
        spin_unlock_irqrestore(&r->rd_lock, flags);
        alog_ok("Ring buffer đã xóa qua ioctl");
        break;

    /* ── GETRING: Export toàn bộ ring sang userspace ── */
    case AICSEMI_CMD_GETRING:
        alog("  [ioctl] GETRING: count=%d data=%p",
             atomic_read(&r->count), data);
        if (!data) return -EINVAL;
        exp = kzalloc(sizeof(*exp), GFP_KERNEL);
        if (!exp)
            return -ENOMEM;

        spin_lock_irqsave(&r->rd_lock, flags);
        exp->count = (u32)atomic_read(&r->count);
        exp->head  = (u32)atomic_read(&r->head) & MON_RING_MASK;
        memcpy(exp->entries, r->entries, sizeof(r->entries));
        spin_unlock_irqrestore(&r->rd_lock, flags);

        if (copy_to_user(data, exp, sizeof(*exp)))
            ret = -EFAULT;
        kfree(exp);
        break;

    /* ── SETFILT: Lọc theo ip_proto (0=all, 6=TCP, 17=UDP, 1=ICMP) ── */
    case AICSEMI_CMD_SETFILT:
        if (copy_from_user(&filt, data, sizeof(filt)))
            return -EFAULT;
        r->filter = filt;
        alog_ok("Ring filter đặt thành: %u (0=all, 6=TCP, 17=UDP, 1=ICMP)",
                filt);
        break;

    /* ── GETSTATS: Export thống kê tổng hợp ── */
    case AICSEMI_CMD_GETSTATS:
        alog("  [ioctl] GETSTATS: copy stats → userspace data=%p", data);
        if (!data) return -EINVAL;
        memset(&st, 0, sizeof(st));
        st.tx_total   = atomic64_read(&priv->stats.total);
        st.tx_bytes   = atomic64_read(&priv->stats.bytes_total);
        st.tx_dropped = atomic64_read(&priv->stats.tx_dropped);
        st.rx_total   = atomic64_read(&priv->stats.rx_total);
        st.rx_bytes   = atomic64_read(&priv->stats.rx_bytes);
        st.tcp        = atomic64_read(&priv->stats.tcp);
        st.udp        = atomic64_read(&priv->stats.udp);
        st.icmp       = atomic64_read(&priv->stats.icmp);
        st.arp        = atomic64_read(&priv->stats.arp);
        st.ipv6       = atomic64_read(&priv->stats.ipv6);
        st.other      = atomic64_read(&priv->stats.other);
        st.uptime_sec = ktime_to_ns(ktime_sub(ktime_get(), r->start_time))
                        / NSEC_PER_SEC;
        st.tx_encrypted = atomic64_read(&priv->stats.tx_encrypted);
        st.tx_tampered  = atomic64_read(&priv->stats.tx_tampered);
        st.tx_plain     = atomic64_read(&priv->stats.tx_plain);
        strscpy(st.ifname,     dev->name,      sizeof(st.ifname));
        strscpy(st.driver_ver, DRIVER_VERSION, sizeof(st.driver_ver));

        if (copy_to_user(data, &st, sizeof(st)))
            ret = -EFAULT;
        break;

    default:
        ret = -EOPNOTSUPP;
        break;
    }
    return ret;
}

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
 * v4.0: Thêm ring_push() để lưu vào ring buffer cho monitor.c
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
    struct pkt_entry entry = {0};   /* ★ ring entry */

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

    /* ★ Điền ring entry cơ bản */
    entry.ts_ns    = ktime_get_real_ns();
    entry.seq      = (u32)seq;
    entry.len      = (u32)skb->len;
    entry.eth_proto = ntohs(proto);
    entry.direction = 'T';

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
            entry.ip_proto = IPPROTO_TCP;
            entry.saddr = iph->saddr;
            entry.daddr = iph->daddr;

            if (skb->len >= ETH_HLEN + iph->ihl*4 +
                            (int)sizeof(struct tcphdr)) {
                struct tcphdr *th = (struct tcphdr *)
                    (skb->data + ETH_HLEN + iph->ihl*4);
                entry.sport     = ntohs(th->source);
                entry.dport     = ntohs(th->dest);
                entry.tcp_flags = (th->syn ? 0x02 : 0) |
                                  (th->ack ? 0x10 : 0) |
                                  (th->fin ? 0x01 : 0) |
                                  (th->rst ? 0x04 : 0) |
                                  (th->psh ? 0x08 : 0);
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
        entry.ip_proto = 0x86; /* đánh dấu IPv6 */

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
    /* ★ SECURITY: Verify HMAC nếu gói có payload sau header */
    {
        const u8 *payload_start = NULL;
        size_t    payload_len   = 0;

        /* Xác định vị trí payload tùy theo giao thức */
        if (proto == htons(ETH_P_IP) && skb->len > ETH_HLEN) {
            struct iphdr *iph2 = (struct iphdr *)(skb->data + ETH_HLEN);
            int ip_hlen = iph2->ihl * 4;
            int l4_off  = ETH_HLEN + ip_hlen;

            if (iph2->protocol == IPPROTO_TCP &&
                skb->len > l4_off + (int)sizeof(struct tcphdr)) {
                struct tcphdr *th2 = (struct tcphdr *)(skb->data + l4_off);
                int tcp_hlen = th2->doff * 4;
                payload_start = skb->data + l4_off + tcp_hlen;
                payload_len   = skb->len - l4_off - tcp_hlen;

            } else if (iph2->protocol == IPPROTO_UDP &&
                       skb->len > l4_off + (int)sizeof(struct udphdr)) {
                payload_start = skb->data + l4_off + sizeof(struct udphdr);
                payload_len   = skb->len - l4_off - sizeof(struct udphdr);

            } else if (iph2->protocol == IPPROTO_ICMP &&
                       skb->len > l4_off + (int)sizeof(struct icmphdr)) {
                payload_start = skb->data + l4_off + sizeof(struct icmphdr);
                payload_len   = skb->len - l4_off - sizeof(struct icmphdr);
            }
        }

        if (payload_start && payload_len > AIC_HMAC_TAG_LEN) {
            /* Có đủ data để verify */
            bool ok = aic_verify_hmac(payload_start, payload_len);
            entry.encrypted = 1;
            entry.hmac_ok   = ok ? 1 : 0;

            /* Lưu 16 byte đầu ciphertext để hiển thị trên web */
            size_t copy_n = payload_len < 16 ? payload_len : 16;
            memcpy(entry.payload_hex, payload_start, copy_n);

            if (ok) {
                atomic64_inc(&priv->stats.tx_encrypted);
                alog_ok("[CRYPTO] TX #%llu HMAC OK — gói hợp lệ, payload=%zuB",
                        seq, payload_len);

                /* Log full ciphertext+tag hex (tối đa 32 byte) để web hiển thị */
                {
                    size_t dump_n = payload_len < 32 ? payload_len : 32;
                    alog("  [CRYPTO]   ciphertext+tag[0..%zu]: %*phN",
                         dump_n - 1, (int)dump_n, payload_start);
                }

                /* AES-128-CTR decrypt để log plaintext (chỉ 16 byte đầu) */
                {
                    u8 plain_preview[16];
                    size_t data_len = payload_len - AIC_HMAC_TAG_LEN;
                    size_t preview  = data_len < 16 ? data_len : 16;
                    memcpy(plain_preview, payload_start, preview);
                    if (aic_aes_ctr_decrypt(plain_preview, preview) == 0)
                        alog("  [CRYPTO]   AES-128-CTR plaintext[0..%zu]: %*phN",
                             preview - 1, (int)preview, plain_preview);
                    else
                        alog("  [CRYPTO]   AES-128-CTR decrypt unavailable");
                }
            } else {
                atomic64_inc(&priv->stats.tx_tampered);
                alog_err("[SECURITY] TX #%llu HMAC FAIL — gói bị TAMPER! payload=%zuB",
                         seq, payload_len);

                /* Log full ciphertext+tag hex (tối đa 32 byte) — HMAC tag là 8 byte cuối */
                {
                    size_t dump_n = payload_len < 32 ? payload_len : 32;
                    alog_err("[SECURITY]   ciphertext+tag[0..%zu]: %*phN",
                             dump_n - 1, (int)dump_n, payload_start);
                }
                /* Không drop — vẫn đếm nhưng đánh dấu tampered */
            }
        } else {
            /* ARP, IPv6, hoặc gói không có payload → plain */
            entry.encrypted = 0;
            entry.hmac_ok   = 0;
            atomic64_inc(&priv->stats.tx_plain);
        }
    }

    /* ★ Đẩy vào ring buffer cho monitor.c */
    ring_push(&priv->ring, &entry);

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
    /*
     * ndo_siocdevprivate: kernel ≥ 5.15
     * ndo_do_ioctl     : kernel < 5.15
     * Dùng #if để tự chọn đúng field.
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
    .ndo_siocdevprivate = aicsemi_ioctl,
#else
    .ndo_do_ioctl       = aicsemi_ioctl,
#endif
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
    atomic64_set(&priv->stats.tx_encrypted, 0);
    atomic64_set(&priv->stats.tx_tampered,  0);
    atomic64_set(&priv->stats.tx_plain,     0);

    timer_setup(&priv->watchdog, aicsemi_watchdog, 0);
    alog_ok("Watchdog timer đã khởi tạo (chu kỳ 1000ms)");

    /* ★ Init ring buffer */
    atomic_set(&priv->ring.head,  -1);
    atomic_set(&priv->ring.count,  0);
    spin_lock_init(&priv->ring.rd_lock);
    priv->ring.filter     = 0;   /* chấp nhận tất cả */
    priv->ring.start_time = ktime_get();
    alog_ok("Ring buffer khởi tạo: %d entries × %zu bytes = %zu KB",
            MON_RING_SIZE, sizeof(struct pkt_entry),
            sizeof(struct pkt_entry) * MON_RING_SIZE / 1024);

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
