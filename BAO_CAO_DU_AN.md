

## 4. usb.c — Kernel Driver Làm Gì?

### 4.1 Đăng ký với USB Subsystem

```c
static struct usb_driver aicsemi_usb_driver = {
    .name     = "aicsemi_multimode",
    .id_table = aicsemi_id_table,   // match a69c:5721 và a69c:8d80
    .probe    = aicsemi_probe,      // gọi khi cắm thiết bị
    .disconnect = aicsemi_disconnect,
};
module_usb_driver(aicsemi_usb_driver);
```

Khi kernel nhận diện thiết bị USB có VID:PID khớp bảng `id_table`,
nó tự động gọi `aicsemi_probe()`. Đây là điểm vào của toàn bộ driver.

### 4.2 Modeswitch — Chuyển từ Storage sang WiFi

Thiết bị AIC Semi khi mới cắm vào xuất hiện với PID `0x5721` (USB Mass Storage).
Đây là cơ chế "ZeroCD" — thiết bị giả lập ổ đĩa USB chứa driver Windows bên trong.

Để chuyển sang WiFi mode (PID `0x8d80`), driver gửi lệnh SCSI EJECT:

```
CBW (Command Block Wrapper) gửi qua Bulk OUT endpoint:
  55 53 42 43  ← "USBC" signature
  12 34 56 78  ← tag
  00 00 00 00  ← data length = 0
  00           ← flags
  00           ← LUN 0
  06           ← command length
  1b 00 00 00 02 00  ← SCSI START STOP UNIT (LoEj=1 = eject)
```

Sau khi nhận lệnh này, firmware tự ngắt kết nối và re-enumerate với PID `0x8d80`.
Kernel gọi lại `aicsemi_probe()` lần nữa, lần này tạo interface mạng `aic0`.

### 4.3 Tạo Network Interface

```c
dev = alloc_etherdev(0);          // cấp phát net_device
snprintf(dev->name, IFNAMSIZ, "aic%%d");  // tên động: aic0, aic1...
eth_hw_addr_random(dev);          // MAC ngẫu nhiên
dev->netdev_ops = &aicsemi_netdev_ops;    // gán các hàm callback
register_netdev(dev);             // đăng ký với kernel
```

Sau bước này, `ip link show` sẽ thấy interface `aic0`.

### 4.4 Các hàm callback quan trọng (net_device_ops)

| Callback | Hàm trong driver | Khi nào được gọi |
|----------|-----------------|-----------------|
| `ndo_open` | `aicsemi_net_open()` | `ip link set aic0 up` |
| `ndo_stop` | `aicsemi_net_stop()` | `ip link set aic0 down` |
| `ndo_start_xmit` | `aicsemi_net_xmit()` | Mỗi khi có gói TX |
| `ndo_get_stats64` | `aicsemi_get_stats64()` | `ip -s link show aic0` |
| `ndo_siocdevprivate` | `aicsemi_ioctl()` | monitor.c gọi ioctl |

### 4.5 Ring Buffer — Lưu metadata gói tin

Driver duy trì một ring buffer 1024 entries trong kernel memory:

```c
#define MON_RING_SIZE 1024   // phải là lũy thừa của 2

struct pkt_entry {
    u64   ts_ns;        // timestamp nanoseconds
    u32   seq;          // số thứ tự gói
    u32   len;          // kích thước frame
    u16   eth_proto;    // ETH_P_IP, ETH_P_ARP...
    u8    ip_proto;     // IPPROTO_TCP, UDP, ICMP
    u8    direction;    // 'T' = TX, 'R' = RX
    __be32 saddr, daddr; // src/dst IP
    u16   sport, dport; // src/dst port
    u8    tcp_flags;    // SYN/ACK/FIN/RST/PSH
    u8    encrypted;    // 1 = có AES+HMAC
    u8    hmac_ok;      // 1 = HMAC verify OK
    u8    payload_hex[16]; // 16 byte đầu ciphertext
};
```

**Thiết kế lock-free cho TX path:**
- Ghi dùng `atomic_inc_return()` — không cần mutex
- Đọc (từ monitor.c qua ioctl) dùng spinlock
- Wrap-around tự động: `idx = atomic_inc_return(&head) & MON_RING_MASK`

### 4.6 ioctl API

monitor.c và web_monitor giao tiếp với driver qua ioctl:

```
SIOCDEVPRIVATE + 0  →  CLEAR    : xóa ring buffer
SIOCDEVPRIVATE + 1  →  GETRING  : copy toàn bộ ring sang userspace
SIOCDEVPRIVATE + 2  →  SETFILT  : lọc theo protocol (TCP/UDP/ICMP)
SIOCDEVPRIVATE + 3  →  GETSTATS : lấy thống kê tổng hợp
```

**Tại sao dùng SIOCDEVPRIVATE thay vì _IOR/_IOW?**
Kernel chỉ route ioctl vào `ndo_siocdevprivate` khi cmd nằm trong range
`0x89F0 – 0x89FF`. Nếu dùng `_IOR('A', n, ...)` → cmd = `0x804xxxxx`
→ kernel trả về `ENOTTY` (errno 25).

### 4.7 Watchdog Timer

```c
// Chạy mỗi 1000ms
static void aicsemi_watchdog(struct timer_list *t) {
    if (netif_queue_stopped(dev)) {
        if (jiffies - priv->last_tx_jiffies > msecs_to_jiffies(500)) {
            netif_wake_queue(dev);  // mở lại TX queue nếu bị kẹt
        }
    }
    mod_timer(&priv->watchdog, jiffies + msecs_to_jiffies(1000));
}
```

---

## 5. demo.c — Userspace Gửi Gói Tin Như Thế Nào?

### 5.1 Raw Socket AF_PACKET

demo.c không dùng TCP/UDP socket thông thường mà dùng **raw socket layer 2**:

```c
g_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
```

Điều này cho phép tự xây dựng toàn bộ frame từ Ethernet header trở xuống,
bỏ qua hoàn toàn TCP/IP stack của kernel. Gói tin được gửi trực tiếp
xuống `ndo_start_xmit()` của driver.

### 5.2 Hàm encrypt_and_tag() — Trái tim của demo.c

```c
static size_t encrypt_and_tag(uint8_t *payload, size_t plen,
                               uint8_t *out_buf, size_t out_max)
{
    // Bước 1: Copy plaintext vào buffer
    memcpy(out_buf, payload, plen);

    // Bước 2: AES-128-CTR encrypt in-place
    aes128_ctr_crypt(AES_KEY, AES_NONCE, out_buf, plen);
    //  out_buf giờ chứa ciphertext

    // Bước 3: Tính HMAC-SHA256 trên CIPHERTEXT (không phải plaintext!)
    uint8_t tag[8];
    hmac_sha256_truncated(HMAC_KEY, 32, out_buf, plen, tag);

    // Bước 4: Append 8 byte tag vào cuối
    memcpy(out_buf + plen, tag, 8);

    return plen + 8;  // tổng kích thước payload mới
}
```

**Tại sao HMAC tính trên ciphertext, không phải plaintext?**
Đây là mô hình **Encrypt-then-MAC** — xem mục 8.

### 5.3 Các loại gói tin demo gửi

| Loại | Payload gốc | Ghi chú |
|------|------------|---------|
| ARP | (không có) | Không mã hóa, không HMAC |
| ICMP Echo | `"AIC-Ping-001-SECRET"` | Mã hóa + HMAC |
| TCP SYN | `"CONNECT-HTTP-001"` | Mã hóa + HMAC |
| UDP/DNS | DNS query bytes | Mã hóa + HMAC |
| TAMPERED | Gói ICMP bình thường | Sau khi encrypt, flip byte HMAC[3] XOR 0xFF |

### 5.4 Demo Tampered Packet

```c
// Tạo gói bình thường
encrypt_and_tag((uint8_t*)plain, plen, enc_buf, sizeof(enc_buf));

// Cố tình sửa 1 byte trong HMAC tag → driver sẽ phát hiện
enc_buf[plen + 3] ^= 0xFF;
//  byte thứ 4 của HMAC tag bị flip tất cả các bit
```

Khi driver nhận gói này, nó tính lại HMAC → kết quả khác với tag
→ log `[SECURITY] HMAC FAIL — gói bị TAMPER!`

---

## 6. Thuật Toán AES-128-CTR

### 6.1 AES là gì?

**AES (Advanced Encryption Standard)** là thuật toán mã hóa khối (block cipher)
được NIST chuẩn hóa năm 2001 (FIPS 197). Đây là chuẩn mã hóa đối xứng
phổ biến nhất thế giới hiện nay.

- **Đối xứng:** cùng một khóa dùng để mã hóa và giải mã
- **Block cipher:** xử lý dữ liệu theo từng khối 16 byte (128 bit)
- **AES-128:** khóa dài 128 bit (16 byte) → 10 vòng (rounds)
- **AES-192:** khóa 192 bit → 12 vòng
- **AES-256:** khóa 256 bit → 14 vòng

### 6.2 Cấu trúc bên trong AES-128

AES hoạt động trên một **state** — ma trận 4×4 bytes (16 byte = 128 bit).

```
State (4×4 bytes):
┌────┬────┬────┬────┐
│ s0 │ s4 │ s8 │ s12│
│ s1 │ s5 │ s9 │ s13│
│ s2 │ s6 │ s10│ s14│
│ s3 │ s7 │ s11│ s15│
└────┴────┴────┴────┘
```

Mỗi vòng AES gồm 4 phép biến đổi:

#### SubBytes — Thay thế phi tuyến
Mỗi byte được thay thế bằng giá trị tương ứng trong bảng S-box (256 phần tử).
S-box được xây dựng từ nghịch đảo trong trường GF(2⁸) + phép biến đổi affine.

```
Ví dụ: byte 0x53 → S-box[0x53] = 0xED
```

Mục đích: tạo tính **confusion** (làm mờ quan hệ giữa key và ciphertext).

#### ShiftRows — Dịch hàng
Mỗi hàng của state được dịch vòng trái:

```
Hàng 0: không dịch    [s0,  s4,  s8,  s12]
Hàng 1: dịch 1 byte   [s5,  s9,  s13, s1 ]
Hàng 2: dịch 2 byte   [s10, s14, s2,  s6 ]
Hàng 3: dịch 3 byte   [s15, s3,  s7,  s11]
```

Mục đích: đảm bảo các byte từ các cột khác nhau được trộn lẫn.

#### MixColumns — Trộn cột
Mỗi cột 4 byte được nhân với ma trận cố định trong trường GF(2⁸):

```
┌ 2 3 1 1 ┐   ┌ a0 ┐   ┌ b0 ┐
│ 1 2 3 1 │ × │ a1 │ = │ b1 │  (phép nhân trong GF(2⁸))
│ 1 1 2 3 │   │ a2 │   │ b2 │
└ 3 1 1 2 ┘   └ a3 ┘   └ b3 ┘
```

Mục đích: tạo tính **diffusion** (1 bit thay đổi ảnh hưởng nhiều byte output).
**Bỏ qua ở vòng cuối (round 10).**

#### AddRoundKey — XOR với round key
State XOR với round key tương ứng của vòng đó:

```
state[i] = state[i] XOR round_key[i]
```

### 6.3 Key Schedule — Mở rộng khóa

Từ 16 byte khóa gốc, AES tạo ra **11 round keys** (176 byte tổng):

```
Key gốc (16 byte) → Round Key 0
                  → Round Key 1
                  → ...
                  → Round Key 10

Mỗi round key = 16 byte
Tổng: 11 × 16 = 176 byte
```

Công thức tạo round key tiếp theo (đơn giản hóa):

```
W[i] = W[i-4] XOR SubWord(RotWord(W[i-1])) XOR Rcon[i/4]
```

Trong code dự án (`aes128_key_expand()`):
```c
cur[0] = sbox[prev[13]] ^ rcon[i] ^ prev[0];  // RotWord + SubWord + Rcon
cur[1] = sbox[prev[14]]            ^ prev[1];
cur[2] = sbox[prev[15]]            ^ prev[2];
cur[3] = sbox[prev[12]]            ^ prev[3];
// 3 word còn lại: XOR đơn giản
cur[4] = cur[0] ^ prev[4]; ...
```

### 6.4 CTR Mode — Biến Block Cipher thành Stream Cipher

AES thuần túy chỉ mã hóa được đúng 16 byte một lần (ECB mode).
**CTR (Counter) mode** giải quyết vấn đề này bằng cách biến AES thành stream cipher:

```
Nguyên lý CTR:

Counter block 0:  [ Nonce (12 byte) | Counter = 1 ]
Counter block 1:  [ Nonce (12 byte) | Counter = 2 ]
Counter block 2:  [ Nonce (12 byte) | Counter = 3 ]
...

Keystream block i = AES_ECB_Encrypt(Key, Counter_block_i)

Ciphertext[i] = Plaintext[i] XOR Keystream[i]
```

**Sơ đồ mã hóa CTR:**

```
Nonce+Counter[0]  Nonce+Counter[1]  Nonce+Counter[2]
      │                  │                  │
      ▼                  ▼                  ▼
  AES_Enc(K)         AES_Enc(K)         AES_Enc(K)
      │                  │                  │
      ▼                  ▼                  ▼
  Keystream[0]       Keystream[1]       Keystream[2]
      │                  │                  │
      ⊕                  ⊕                  ⊕
      │                  │                  │
  Plaintext[0..15]   Plaintext[16..31]  Plaintext[32..47]
      │                  │                  │
      ▼                  ▼                  ▼
  Ciphertext[0..15]  Ciphertext[16..31] Ciphertext[32..47]
```

**Ưu điểm của CTR mode:**
- Mã hóa/giải mã **cùng một hàm** (symmetric) — chỉ cần AES encrypt
- Xử lý được payload **bất kỳ độ dài** (không cần padding)
- Có thể **song song hóa** (mỗi block độc lập)
- **Không lan truyền lỗi** (1 bit lỗi chỉ ảnh hưởng 1 block)

### 6.5 Triển khai trong dự án (demo.c)

```c
static void aes128_ctr_crypt(const uint8_t *key, const uint8_t *nonce,
                              uint8_t *data, size_t len)
{
    uint8_t rk[176];       // 11 round keys
    uint8_t counter[16];   // counter block = nonce ban đầu
    uint8_t keystream[16]; // output của AES_Encrypt(counter)
    size_t  pos = 0;

    aes128_key_expand(key, rk);    // tạo 11 round keys
    memcpy(counter, nonce, 16);    // counter[0] = nonce

    while (pos < len) {
        // Bước 1: Mã hóa counter block → keystream
        aes128_encrypt_block(rk, counter, keystream);

        // Bước 2: XOR keystream vào data
        size_t block = (len - pos < 16) ? (len - pos) : 16;
        for (size_t i = 0; i < block; i++)
            data[pos + i] ^= keystream[i];
        pos += block;

        // Bước 3: Tăng counter (big-endian 128-bit)
        for (int i = 15; i >= 0; i--)
            if (++counter[i]) break;
    }
}
```

**Các tham số trong dự án:**

```
AES_KEY   = 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C  (128-bit)
AES_NONCE = F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB 00 00 00 01  (counter bắt đầu = 1)
```

### 6.6 Giải mã trong Kernel (usb.c)

Kernel dùng **Linux Crypto API** thay vì tự implement:

```c
static int aic_aes_ctr_decrypt(u8 *data, size_t len)
{
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg;
    u8 iv[16];

    // Cấp phát transform object cho "ctr(aes)"
    tfm = crypto_alloc_skcipher("ctr(aes)", 0, 0);

    // Set key
    crypto_skcipher_setkey(tfm, AIC_AES_KEY, 16);

    // IV = nonce (CTR mode dùng IV làm counter block ban đầu)
    memcpy(iv, AIC_AES_NONCE, 16);

    // Setup scatter-gather list (in-place decrypt)
    sg_init_one(&sg, data, len);
    skcipher_request_set_crypt(req, &sg, &sg, len, iv);

    // Decrypt (CTR: decrypt = encrypt, cùng keystream)
    crypto_skcipher_decrypt(req);
}
```

**Lưu ý:** CTR mode là **symmetric** — encrypt và decrypt dùng cùng một thao tác.
Kernel gọi `crypto_skcipher_decrypt()` nhưng thực chất vẫn là AES encrypt counter.

---

## 7. HMAC-SHA256 và Kiểm Tra 8 Bytes

### 7.1 SHA-256 là gì?

**SHA-256 (Secure Hash Algorithm 256-bit)** là hàm băm mật mã thuộc họ SHA-2,
được NIST chuẩn hóa (FIPS 180-4).

**Tính chất quan trọng:**
- **Deterministic:** cùng input → cùng output
- **One-way:** không thể tính ngược từ hash ra input
- **Avalanche effect:** thay đổi 1 bit input → ~50% bit output thay đổi
- **Collision resistant:** cực kỳ khó tìm 2 input khác nhau có cùng hash
- Output luôn **256 bit (32 byte)** bất kể input dài bao nhiêu

### 7.2 SHA-256 hoạt động như thế nào?

SHA-256 xử lý dữ liệu theo từng **block 512 bit (64 byte)**:

**Bước 1 — Padding:**
```
Message M → M || 1 || 0...0 || length(64-bit)
Đảm bảo tổng độ dài là bội số của 512 bit
```

**Bước 2 — Khởi tạo state (8 word × 32-bit):**
```c
H[0] = 0x6a09e667;  H[1] = 0xbb67ae85;
H[2] = 0x3c6ef372;  H[3] = 0xa54ff53a;
H[4] = 0x510e527f;  H[5] = 0x9b05688c;
H[6] = 0x1f83d9ab;  H[7] = 0x5be0cd19;
// Đây là 32 bit đầu của phần thập phân căn bậc 2 của 8 số nguyên tố đầu tiên
```

**Bước 3 — Compression function (64 vòng cho mỗi block):**

Mỗi vòng dùng một hằng số K[i] (lấy từ căn bậc 3 của 64 số nguyên tố đầu):

```
t1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
t2 = Σ0(a) + Maj(a,b,c)
h=g, g=f, f=e, e=d+t1, d=c, c=b, b=a, a=t1+t2
```

Trong đó:
```
Ch(x,y,z)  = (x AND y) XOR (NOT x AND z)   — "Choose"
Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)  — "Majority"
Σ0(x) = ROTR²(x) XOR ROTR¹³(x) XOR ROTR²²(x)
Σ1(x) = ROTR⁶(x) XOR ROTR¹¹(x) XOR ROTR²⁵(x)
```

**Bước 4 — Cộng vào state:**
```
H[0..7] += a..h  (sau 64 vòng)
```

**Bước 5 — Lặp lại cho block tiếp theo, output cuối = H[0]||H[1]||...||H[7]**

### 7.3 HMAC là gì?

**HMAC (Hash-based Message Authentication Code)** là cơ chế xác thực toàn vẹn
dùng hàm băm kết hợp với khóa bí mật.

**Tại sao không dùng SHA-256(key || message) trực tiếp?**
Cách đơn giản đó dễ bị tấn công **length extension attack** — attacker có thể
thêm dữ liệu vào cuối message mà không cần biết key.

**HMAC giải quyết bằng cấu trúc 2 lớp:**

```
HMAC(K, M) = SHA256( (K ⊕ opad) || SHA256( (K ⊕ ipad) || M ) )

Trong đó:
  ipad = 0x36 lặp lại 64 lần  (inner padding)
  opad = 0x5C lặp lại 64 lần  (outer padding)
  K    = key được pad/hash về đúng 64 byte
```

**Sơ đồ tính HMAC:**

```
Key (32 byte)
    │
    ├─ pad về 64 byte: K' = Key || 0x00...0x00
    │
    ├─ K' XOR ipad (0x36×64) → K_ipad
    │       │
    │       ▼
    │   SHA256( K_ipad || Message ) → inner_hash (32 byte)
    │
    └─ K' XOR opad (0x5C×64) → K_opad
            │
            ▼
        SHA256( K_opad || inner_hash ) → HMAC_full (32 byte)
                                              │
                                              ▼
                                    Lấy 8 byte đầu = TAG
```

### 7.4 Tại sao chỉ lấy 8 bytes?

Trong dự án dùng **HMAC-SHA256 truncated 8 bytes**:

```c
memcpy(out8, full_hmac, 8);  // chỉ lấy 8 byte đầu của 32 byte HMAC
```

**Lý do:**
- HMAC-SHA256 đầy đủ = 32 byte → thêm 32 byte vào mỗi gói tin là quá nhiều overhead
- 8 byte = 64 bit → xác suất đoán đúng ngẫu nhiên = 1/2⁶⁴ ≈ 5.4 × 10⁻²⁰ (cực kỳ nhỏ)
- NIST SP 800-107 cho phép truncate HMAC xuống tối thiểu 4 byte
- 8 byte là trade-off tốt giữa **bảo mật** và **overhead**

**Tấn công brute-force 8 byte HMAC:**
```
Số lần thử cần thiết: 2⁶⁴ ≈ 18.4 tỷ tỷ lần
Với máy tính 10⁹ hash/giây → cần ~585 năm
```

### 7.5 Triển khai trong demo.c

```c
static void hmac_sha256_truncated(const uint8_t *key, size_t klen,
                                   const uint8_t *msg, size_t mlen,
                                   uint8_t *out8)
{
    uint8_t k[64] = {0};   // key được pad về 64 byte
    uint8_t ipad[64], opad[64];
    uint8_t inner[32], full[32];
    sha256_ctx ctx;

    // Bước 1: Chuẩn bị key
    if (klen > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, klen);
        sha256_final(&ctx, k);   // hash key nếu dài hơn 64 byte
    } else {
        memcpy(k, key, klen);    // pad bằng 0 nếu ngắn hơn
    }

    // Bước 2: Tạo ipad và opad
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    // Bước 3: Inner hash = SHA256(ipad || message)
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, msg, mlen);
    sha256_final(&ctx, inner);

    // Bước 4: Outer hash = SHA256(opad || inner)
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, full);

    // Bước 5: Truncate — chỉ lấy 8 byte đầu
    memcpy(out8, full, 8);
}
```

### 7.6 Triển khai trong usb.c (kernel)

Kernel dùng **Linux Crypto API** (`crypto/hash.h`):

```c
static int aic_hmac_sha256_truncated(const u8 *key, size_t klen,
                                      const u8 *msg, size_t mlen,
                                      u8 *out8)
{
    struct crypto_shash *tfm;
    struct shash_desc   *desc;
    u8 full[32];

    // Cấp phát transform cho "hmac(sha256)"
    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm)) {
        // Fallback: polynomial hash nếu không có crypto module
        // (không dùng trong production)
        ...
        return 0;
    }

    // Set HMAC key
    crypto_shash_setkey(tfm, key, klen);

    // Tính HMAC một lần (API tự xử lý ipad/opad)
    desc->tfm = tfm;
    crypto_shash_digest(desc, msg, mlen, full);  // full = 32 byte HMAC

    // Truncate
    memcpy(out8, full, 8);
}
```

### 7.7 Quá trình verify HMAC trong driver

```c
static bool aic_verify_hmac(const u8 *payload, size_t total_len)
{
    // Layout: [ ciphertext (N byte) | HMAC_tag (8 byte) ]
    size_t data_len = total_len - 8;
    const u8 *tag   = payload + data_len;  // trỏ đến 8 byte cuối

    u8 computed[8];

    // Tính lại HMAC trên phần ciphertext
    aic_hmac_sha256_truncated(AIC_HMAC_KEY, 32,
                               payload, data_len,
                               computed);

    // So sánh constant-time (tránh timing attack)
    return (memcmp(computed, tag, 8) == 0);
}
```

**Tại sao dùng `memcmp` thay vì so sánh từng byte?**
So sánh từng byte với `if (a[i] != b[i]) return false` có thể bị
**timing attack** — attacker đo thời gian phản hồi để đoán từng byte.
`memcmp` so sánh toàn bộ trong thời gian cố định.

*(Lưu ý: `memcmp` trong kernel không đảm bảo constant-time hoàn toàn.
Production nên dùng `crypto_memneq()` của kernel.)*

---

## 8. Mô Hình Encrypt-then-MAC

### 8.1 Ba mô hình kết hợp mã hóa và MAC

| Mô hình | Công thức | Bảo mật |
|---------|-----------|---------|
| **MAC-then-Encrypt** | `Enc(M \|\| MAC(M))` | ❌ Yếu — SSL/TLS 3.0 dùng, đã bị tấn công |
| **Encrypt-then-MAC** | `C = Enc(M); T = MAC(C)` | ✅ Mạnh nhất — dự án này dùng |
| **Encrypt-and-MAC** | `C = Enc(M); T = MAC(M)` | ⚠ Trung bình — SSH dùng |

### 8.2 Tại sao Encrypt-then-MAC là tốt nhất?

**Lý do 1 — Fail-fast:**
Driver verify HMAC TRƯỚC khi decrypt. Nếu HMAC sai → từ chối ngay,
không tốn CPU để decrypt gói rác.

**Lý do 2 — Không lộ thông tin plaintext:**
MAC tính trên ciphertext → attacker không thể suy ra gì về plaintext
từ việc MAC pass hay fail.

**Lý do 3 — Chống chosen-ciphertext attack:**
Attacker không thể tạo ciphertext hợp lệ mà không biết HMAC_KEY.

**Lý do 4 — Hai khóa độc lập:**
```
AES_KEY  ≠ HMAC_KEY   (bắt buộc!)
```
Dùng chung key cho cả encrypt và MAC có thể tạo ra các tấn công
cross-protocol. Dự án dùng hai khóa hoàn toàn khác nhau:
```
AES_KEY  = 2B 7E 15 16 ... (128-bit, NIST AES test vector)
HMAC_KEY = 60 3D EB 10 ... (256-bit, hoàn toàn khác)
```

### 8.3 Luồng Encrypt-then-MAC trong dự án

```
USERSPACE (demo.c):
─────────────────────────────────────────────────────
Plaintext: "AIC-Ping-001-SECRET"
    │
    ▼ AES-128-CTR(AES_KEY, NONCE)
Ciphertext: e3 4f 2a 91 b7 ... (cùng độ dài plaintext)
    │
    ▼ HMAC-SHA256(HMAC_KEY, Ciphertext)[0..7]
Tag: a1 b2 c3 d4 e5 f6 07 18  (8 bytes)
    │
    ▼ Ghép lại
Payload gửi đi: [ Ciphertext | Tag[8] ]
─────────────────────────────────────────────────────

KERNEL (usb.c):
─────────────────────────────────────────────────────
Nhận: [ Ciphertext | Tag[8] ]
    │
    ▼ Tách: data = payload[0..len-9], tag = payload[len-8..len-1]
    │
    ▼ HMAC-SHA256(HMAC_KEY, data)[0..7] → computed
    │
    ├─ computed == tag? → HMAC OK → tx_encrypted++
    │       └─ AES-128-CTR decrypt → log plaintext preview
    │
    └─ computed ≠ tag? → HMAC FAIL → tx_tampered++
            └─ Log [SECURITY] cảnh báo
─────────────────────────────────────────────────────
```

---

## 9. Cấu Trúc Gói Tin Trong Dự Án

### 9.1 Layout đầy đủ

```
Byte offset:
┌──────────────────────────────────────────────────────────────────┐
│ 0        13 │ 14      33 │ 34    hdr │ hdr    N │ N      N+7    │
├─────────────┼────────────┼───────────┼──────────┼───────────────┤
│ Ethernet    │ IP header  │ L4 header │Ciphertext│  HMAC tag     │
│ (14 bytes)  │ (20 bytes) │(8-20 byte)│ (N byte) │  (8 bytes)    │
│             │            │           │          │               │
│ dst MAC     │ ver/ihl    │ TCP: 20B  │AES-128   │HMAC-SHA256    │
│ src MAC     │ TTL=64     │ UDP: 8B   │CTR enc   │truncated      │
│ EtherType   │ proto      │ ICMP: 8B  │payload   │8 byte đầu     │
│ 0x0800=IP   │ src/dst IP │           │          │               │
└─────────────┴────────────┴───────────┴──────────┴───────────────┘
```

### 9.2 Ví dụ gói ICMP cụ thể

```
Plaintext payload: "AIC-Ping-001-SECRET" (19 bytes)

Sau encrypt_and_tag():
  Ciphertext: 19 bytes (AES-128-CTR)
  HMAC tag:    8 bytes
  Tổng payload: 27 bytes

Frame hoàn chỉnh:
  ETH header:  14 bytes
  IP header:   20 bytes
  ICMP header:  8 bytes
  Payload:     27 bytes
  ─────────────────────
  Tổng frame:  69 bytes
```

### 9.3 Gói ARP — không mã hóa

ARP không có application payload → driver đếm vào `tx_plain`:

```
[ ETH (14B) | ARP header (28B) ]
Tổng: 42 bytes — không có ciphertext, không có HMAC tag
```

### 9.4 Gói TAMPERED

```
Gói bình thường:  [ Ciphertext | a1 b2 c3 d4 e5 f6 07 18 ]
                                  ↑ byte index 3 = 0xd4

Sau khi flip:     [ Ciphertext | a1 b2 c3 2B e5 f6 07 18 ]
                                              ↑ 0xd4 XOR 0xFF = 0x2B

Driver tính lại HMAC → computed = a1 b2 c3 d4 e5 f6 07 18
So sánh với tag  = a1 b2 c3 2B e5 f6 07 18
→ KHÔNG KHỚP → HMAC FAIL
```

---

## 10. Web Monitor

### 10.1 Kiến trúc

```
Browser (index.html + app.js)
    │ HTTP GET/POST
    ▼
Flask server (server.py) — chạy với sudo
    │
    ├─ /api/status      → lsusb + ip link + /proc/aicsemi_usbnet/monitor
    ├─ /api/security    → parse dmesg | grep aicsemi
    ├─ /api/raw_packets → parse dmesg (2-pass) → hmac_ok/tampered per packet
    ├─ /api/crypto_keys → trả về AES_KEY, HMAC_KEY, NONCE
    ├─ /api/action/demo → chạy ./demo, lưu stdout
    └─ /api/action/compile → chạy compile.bash
```

### 10.2 Parse dmesg 2-pass

Vấn đề: Driver log HMAC OK/FAIL **trước** khi log `[TX #N]`:

```
dmesg thực tế:
[123.456] [aicsemi] ✓ [CRYPTO] TX #5 HMAC OK — payload=87B   ← HMAC line
[123.457] [aicsemi]   [TX #5  ] IPv4 / ICMP bytes=101 ...    ← TX line
```

Giải pháp 2-pass:
- **Pass 1:** Quét tất cả `[TX #N]` lines → build `pkt_map[seq]`
- **Pass 2:** Quét lại, gán `hmac_ok/tampered` theo `TX #N` trong HMAC lines

### 10.3 Hiển thị hex dump với highlight

Khi click vào gói trong Raw Packet Hex panel:
- Byte ciphertext: màu **cyan**
- HMAC tag (8 byte cuối): màu **xanh lá** nếu OK
- HMAC tag: màu **đỏ phát sáng** (`text-shadow: 0 0 8px red`) nếu TAMPERED

---

## 11. Câu Hỏi Bảo Vệ Thường Gặp

**Q: Tại sao dùng AES-128 mà không phải AES-256?**
A: AES-128 đã đủ an toàn cho mục đích demo. Không có tấn công thực tế nào
phá được AES-128. AES-256 chỉ cần thiết khi lo ngại về quantum computing
(Grover's algorithm giảm security xuống 64-bit với AES-128).

**Q: CTR mode có cần padding không?**
A: Không. Đây là ưu điểm lớn của CTR — keystream được tạo theo từng byte,
không cần padding như CBC hay ECB mode.

**Q: Nonce cố định có an toàn không?**
A: Trong thực tế KHÔNG an toàn. Nếu dùng cùng (Key, Nonce) cho 2 gói khác nhau,
attacker có thể XOR 2 ciphertext để loại bỏ keystream và suy ra quan hệ giữa
2 plaintext. Dự án dùng nonce cố định chỉ để đơn giản hóa demo.
Thực tế phải dùng nonce ngẫu nhiên 12 byte + counter 4 byte (theo RFC 3686).

**Q: Tại sao HMAC_KEY phải khác AES_KEY?**
A: Nếu dùng chung key, có thể xảy ra tấn công cross-protocol:
attacker dùng oracle của AES để tấn công HMAC hoặc ngược lại.
Nguyên tắc: mỗi primitive mật mã phải có khóa riêng độc lập.

**Q: Driver có drop gói bị tamper không?**
A: Không. Driver chỉ log cảnh báo và tăng counter `tx_tampered`.
Gói vẫn được xử lý bình thường. Trong hệ thống thực tế nên drop gói
và có thể blacklist source MAC/IP.

**Q: Ring buffer 1024 entries có đủ không?**
A: Với tốc độ demo (~1 gói/300ms), 1024 entries đủ cho ~5 phút.
Khi đầy, entry cũ bị ghi đè (circular buffer). Có thể tăng
`MON_RING_SIZE` nhưng phải là lũy thừa của 2.

**Q: Tại sao dùng AF_PACKET thay vì socket thông thường?**
A: AF_PACKET cho phép gửi raw frame layer 2, bỏ qua hoàn toàn
TCP/IP stack. Điều này cần thiết để demo có thể tự xây dựng
Ethernet/IP/TCP header và đặt payload đã mã hóa vào đúng vị trí.
Cần quyền root (sudo) để mở AF_PACKET socket.

**Q: Modeswitch hoạt động như thế nào?**
A: Thiết bị AIC Semi dùng cơ chế "ZeroCD" — khi cắm vào, xuất hiện
như USB Mass Storage (PID 0x5721) chứa driver Windows. Driver Linux
gửi lệnh SCSI EJECT (CBW với command 0x1b) qua Bulk OUT endpoint.
Firmware nhận lệnh → tự disconnect → re-enumerate với PID WiFi (0x8d80).

**Q: Kernel Crypto API khác gì với tự implement?**
A: Kernel Crypto API (`crypto/hash.h`, `crypto/skcipher.h`) dùng
implementation được tối ưu hóa (có thể dùng AES-NI hardware instruction
nếu CPU hỗ trợ), đã được kiểm tra bảo mật, và tích hợp với kernel
key management. Tự implement (như trong demo.c) chỉ phù hợp cho
userspace demo, không nên dùng trong production kernel code.

---

## Tóm Tắt Nhanh Cho Bảo Vệ

```
Dự án làm gì?
→ Viết Linux kernel module cho USB WiFi AIC Semi
→ Tích hợp AES-128-CTR (mã hóa) + HMAC-SHA256 (xác thực toàn vẹn)
→ Demo gửi gói tin mã hóa, driver verify và phát hiện tamper

AES-128-CTR là gì?
→ Block cipher AES (16 byte block, 10 rounds, 128-bit key)
→ CTR mode: mã hóa counter block → keystream → XOR với plaintext
→ Ưu điểm: không cần padding, song song hóa được, symmetric

HMAC-SHA256 là gì?
→ MAC = SHA256((K⊕opad) || SHA256((K⊕ipad) || ciphertext))
→ Dùng 8 byte đầu làm tag → 64-bit security
→ Verify: tính lại HMAC, so sánh với tag cuối payload

Encrypt-then-MAC là gì?
→ Mã hóa trước, tính MAC trên ciphertext
→ Mạnh nhất trong 3 mô hình kết hợp
→ Fail-fast: verify HMAC trước khi decrypt

Hai khóa độc lập:
→ AES_KEY  (128-bit): chỉ dùng cho mã hóa
→ HMAC_KEY (256-bit): chỉ dùng cho xác thực
→ Không bao giờ dùng chung key cho 2 mục đích khác nhau
```

---

*Tài liệu này được tạo tự động từ source code của dự án.*
*Phiên bản driver: 4.0.0 | Demo: v5.0 | Web Monitor: v5.0*
