# Mã hóa AES-128-CTR và Xác thực HMAC-SHA256
## Dự án: AICNet Secure — USB Network Driver với bảo mật tầng kernel

---

## Mục lục

1. [Tổng quan kiến trúc bảo mật](#1-tổng-quan-kiến-trúc-bảo-mật)
2. [AES-128 — Thuật toán mã hóa khối](#2-aes-128--thuật-toán-mã-hóa-khối)
3. [CTR Mode — Biến block cipher thành stream cipher](#3-ctr-mode--biến-block-cipher-thành-stream-cipher)
4. [SHA-256 — Hàm băm mật mã](#4-sha-256--hàm-băm-mật-mã)
5. [HMAC-SHA256 — Xác thực toàn vẹn](#5-hmac-sha256--xác-thực-toàn-vẹn)
6. [Encrypt-then-MAC — Mô hình kết hợp](#6-encrypt-then-mac--mô-hình-kết-hợp)
7. [Triển khai trong demo.c (userspace)](#7-triển-khai-trong-democ-userspace)
8. [Triển khai trong usb.c (kernel driver)](#8-triển-khai-trong-usbc-kernel-driver)
9. [Luồng xử lý đầy đủ end-to-end](#9-luồng-xử-lý-đầy-đủ-end-to-end)
10. [Phân tích bảo mật và hạn chế](#10-phân-tích-bảo-mật-và-hạn-chế)

---

## 1. Tổng quan kiến trúc bảo mật

Dự án áp dụng mô hình **Encrypt-then-MAC** cho payload của mỗi gói tin IP
trước khi gửi qua interface `aic0`. Driver kernel nhận gói, verify HMAC,
và decrypt để lấy plaintext preview.

```
┌─────────────────────────────────────────────────────────────────┐
│                        USERSPACE (demo.c)                       │
│                                                                 │
│  plaintext ──► AES-128-CTR encrypt ──► ciphertext               │
│                                            │                    │
│                                            ▼                    │
│                              HMAC-SHA256(HMAC_KEY, ciphertext)  │
│                                            │                    │
│                                            ▼                    │
│              [ ETH | IP | L4 | ciphertext | HMAC[8] ]           │
│                                            │                    │
│                              AF_PACKET sendto()                 │
└────────────────────────────────────────────┼────────────────────┘
                                             │ skb
┌────────────────────────────────────────────▼────────────────────┐
│                    KERNEL DRIVER (usb.c)                        │
│                                                                 │
│  ndo_start_xmit() ──► tìm payload ──► aic_verify_hmac()        │
│                                            │                    │
│                              ┌─────────────┴──────────────┐    │
│                           HMAC OK                      HMAC FAIL│
│                              │                              │   │
│                    aic_aes_ctr_decrypt()          tx_tampered++ │
│                    log plaintext preview          [SECURITY] log│
│                    tx_encrypted++                               │
└─────────────────────────────────────────────────────────────────┘
```

**Các khóa dùng trong dự án (hardcode cho mục đích demo):**

| Tên | Giá trị (hex) | Mục đích |
|-----|---------------|----------|
| `AES_KEY` | `A1 C5 E1 1B 5B 4D 3C 1D E4 0D E5 16 4E 0A 1F 2B` | Mã hóa AES-128 |
| `AES_NONCE` | `00 01 02 03 04 05 06 07 08 09 0A 0B 00 00 00 01` | Counter block khởi đầu |
| `HMAC_KEY` | `A1 C5 E1 1B 5B 4D 3C 1D E4 0D E5 16 4E 0A 1F 2B` | Xác thực HMAC |

> Trong thực tế, AES_KEY và HMAC_KEY nên là hai khóa độc lập,
> được trao đổi qua kênh an toàn (TLS, key exchange protocol).

---
