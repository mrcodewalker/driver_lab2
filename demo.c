/*
 * demo.c — AIC Semi USB Network Driver Demo v5.0
 *
 * TÍNH NĂNG MỚI (Hướng 2+4):
 *   - AES-128-CTR encrypt payload trước khi gửi
 *   - HMAC-SHA256 (truncated 8 bytes) append vào cuối payload
 *   - Driver kernel verify HMAC → phát hiện gói bị tamper
 *
 * Cấu trúc gói có mã hóa:
 *   [ Ethernet | IP | TCP/UDP/ICMP | AES-128-CTR(payload) | HMAC[8] ]
 *
 * Build:  gcc -Wall -O2 -o demo demo.c
 * Chạy:   sudo ./demo [interface]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define RST  "\033[0m"
#define BOLD "\033[1m"
#define DIM  "\033[2m"
#define CYN  "\033[36m"
#define GRN  "\033[32m"
#define YLW  "\033[33m"
#define RED  "\033[31m"
#define MAG  "\033[35m"

#define SRC_IP   "192.168.99.1"
#define DST_IP   "192.168.99.2"
#define DNS_SRV  "8.8.8.8"

/* ── Crypto constants ── */
#define HMAC_TAG_LEN  8             /* truncated HMAC: 8 bytes append vào cuối payload */

/*
 * AES_KEY: khóa AES-128 chia sẻ giữa demo.c và usb.c (driver).
 * Trong thực tế sẽ được trao đổi qua kênh an toàn.
 * Ở đây hardcode để demo — driver dùng cùng key này để decrypt.
 */
static const uint8_t AES_KEY[16] = {
    0xA1, 0xC5, 0xE1, 0x1B, 0x5B, 0x4D, 0x3C, 0x1D,
    0xE4, 0x0D, 0xE5, 0x16, 0x4E, 0x0A, 0x1F, 0x2B
};

/*
 * AES_NONCE: nonce cố định 16 byte cho CTR mode (demo simplicity).
 * Trong thực tế phải dùng nonce ngẫu nhiên và truyền kèm gói.
 */
static const uint8_t AES_NONCE[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x00, 0x00, 0x00, 0x01
};

/*
 * HMAC_KEY: khóa bí mật chia sẻ giữa demo.c và usb.c (driver).
 * Trong thực tế sẽ được trao đổi qua kênh an toàn.
 * Ở đây hardcode để demo — driver dùng cùng key này để verify.
 */
static const uint8_t HMAC_KEY[16] = {
    0xA1, 0xC5, 0xE1, 0x1B, 0x5B, 0x4D, 0x3C, 0x1D,
    0xE4, 0x0D, 0xE5, 0x16, 0x4E, 0x0A, 0x1F, 0x2B
};

/* ================================================================
 * MINI AES-128 + CTR MODE — Public domain, no OpenSSL dependency
 *
 * AES core from Kokke's tiny-AES-c (public domain):
 *   https://github.com/kokke/tiny-AES-c
 * CTR mode implemented inline below.
 * ================================================================ */

/* AES S-box */
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Rcon table for key expansion */
static const uint8_t rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* GF(2^8) multiply by 2 */
static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) ? 0x1b : 0));
}

/* AES key schedule: expand 16-byte key into 176-byte round keys */
static void aes128_key_expand(const uint8_t *key, uint8_t *rk) {
    int i;
    memcpy(rk, key, 16);
    for (i = 1; i <= 10; i++) {
        uint8_t *prev = rk + (i-1)*16;
        uint8_t *cur  = rk + i*16;
        /* RotWord + SubWord + Rcon on last word of previous round */
        cur[0]  = sbox[prev[13]] ^ rcon[i] ^ prev[0];
        cur[1]  = sbox[prev[14]]            ^ prev[1];
        cur[2]  = sbox[prev[15]]            ^ prev[2];
        cur[3]  = sbox[prev[12]]            ^ prev[3];
        /* Remaining 3 words */
        cur[4]  = cur[0] ^ prev[4];  cur[5]  = cur[1] ^ prev[5];
        cur[6]  = cur[2] ^ prev[6];  cur[7]  = cur[3] ^ prev[7];
        cur[8]  = cur[4] ^ prev[8];  cur[9]  = cur[5] ^ prev[9];
        cur[10] = cur[6] ^ prev[10]; cur[11] = cur[7] ^ prev[11];
        cur[12] = cur[8] ^ prev[12]; cur[13] = cur[9] ^ prev[13];
        cur[14] = cur[10]^ prev[14]; cur[15] = cur[11]^ prev[15];
    }
}

/* AES-128 encrypt a single 16-byte block (ECB) */
static void aes128_encrypt_block(const uint8_t *rk, const uint8_t *in, uint8_t *out) {
    uint8_t s[16]; int r, i;
    /* AddRoundKey (round 0) */
    for (i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];

    for (r = 1; r <= 10; r++) {
        const uint8_t *k = rk + r*16;
        uint8_t t[16];
        /* SubBytes */
        for (i = 0; i < 16; i++) t[i] = sbox[s[i]];
        /* ShiftRows */
        uint8_t tmp;
        tmp=t[1]; t[1]=t[5]; t[5]=t[9]; t[9]=t[13]; t[13]=tmp;
        tmp=t[2]; t[2]=t[10]; t[10]=tmp; tmp=t[6]; t[6]=t[14]; t[14]=tmp;
        tmp=t[15]; t[15]=t[11]; t[11]=t[7]; t[7]=t[3]; t[3]=tmp;
        /* MixColumns (skip on last round) */
        if (r < 10) {
            for (i = 0; i < 4; i++) {
                uint8_t a0=t[i*4],a1=t[i*4+1],a2=t[i*4+2],a3=t[i*4+3];
                s[i*4]   = xtime(a0)^xtime(a1)^a1^a2^a3;
                s[i*4+1] = a0^xtime(a1)^xtime(a2)^a2^a3;
                s[i*4+2] = a0^a1^xtime(a2)^xtime(a3)^a3;
                s[i*4+3] = xtime(a0)^a0^a1^a2^xtime(a3);
            }
        } else {
            memcpy(s, t, 16);
        }
        /* AddRoundKey */
        for (i = 0; i < 16; i++) s[i] ^= k[i];
    }
    memcpy(out, s, 16);
}

/*
 * aes128_ctr_crypt() — AES-128-CTR encrypt/decrypt (symmetric)
 *
 * counter block = nonce (16 bytes), incremented as big-endian 128-bit
 * for each 16-byte keystream block.
 */
static void aes128_ctr_crypt(const uint8_t *key, const uint8_t *nonce,
                               uint8_t *data, size_t len)
{
    uint8_t rk[176];          /* 11 round keys × 16 bytes */
    uint8_t counter[16];
    uint8_t keystream[16];
    size_t  i, pos = 0;

    aes128_key_expand(key, rk);
    memcpy(counter, nonce, 16);

    while (pos < len) {
        /* Encrypt counter block to get keystream */
        aes128_encrypt_block(rk, counter, keystream);

        /* XOR keystream into data */
        size_t block = (len - pos < 16) ? (len - pos) : 16;
        for (i = 0; i < block; i++)
            data[pos + i] ^= keystream[i];
        pos += block;

        /* Increment counter (big-endian) */
        for (i = 15; i < 16; i--) {
            if (++counter[i]) break;
        }
    }
}

/* ================================================================
 * MINI SHA-256 — Không dùng OpenSSL, tự implement để không cần dep
 * Nguồn: public domain SHA-256 (FIPS 180-4)
 * ================================================================ */
typedef struct { uint32_t s[8]; uint8_t buf[64]; uint64_t len; uint32_t blen; } sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROR32(x,2)^ROR32(x,13)^ROR32(x,22))
#define EP1(x) (ROR32(x,6)^ROR32(x,11)^ROR32(x,25))
#define SIG0(x)(ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define SIG1(x)(ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256_transform(sha256_ctx *c, const uint8_t *d) {
    uint32_t a,b,e,f,g,h,t1,t2,m[64]; int i;
    uint32_t *s=c->s;
    for(i=0;i<16;i++) m[i]=((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];
    for(;i<64;i++) m[i]=SIG1(m[i-2])+m[i-7]+SIG0(m[i-15])+m[i-16];
    a=s[0];b=s[1];uint32_t cc=s[2];uint32_t dd=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for(i=0;i<64;i++){
        t1=h+EP1(e)+CH(e,f,g)+K256[i]+m[i];
        t2=EP0(a)+MAJ(a,b,cc);
        h=g;g=f;f=e;e=dd+t1;dd=cc;cc=b;b=a;a=t1+t2;
    }
    s[0]+=a;s[1]+=b;s[2]+=cc;s[3]+=dd;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
static void sha256_init(sha256_ctx *c){
    c->len=0;c->blen=0;
    c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;
}
static void sha256_update(sha256_ctx *c, const uint8_t *d, size_t n){
    for(size_t i=0;i<n;i++){
        c->buf[c->blen++]=d[i];
        if(c->blen==64){sha256_transform(c,c->buf);c->blen=0;c->len+=512;}
    }
}
static void sha256_final(sha256_ctx *c, uint8_t *h){
    uint32_t i=c->blen; c->buf[i++]=0x80;
    if(i>56){while(i<64)c->buf[i++]=0;sha256_transform(c,c->buf);i=0;}
    while(i<56)c->buf[i++]=0;
    uint64_t bits=c->len+(uint64_t)c->blen*8;
    for(int j=7;j>=0;j--){c->buf[56+j]=(uint8_t)(bits&0xff);bits>>=8;}
    sha256_transform(c,c->buf);
    for(i=0;i<8;i++){h[i*4]=(c->s[i]>>24)&0xff;h[i*4+1]=(c->s[i]>>16)&0xff;h[i*4+2]=(c->s[i]>>8)&0xff;h[i*4+3]=c->s[i]&0xff;}
}

/*
 * hmac_sha256_truncated() — Tính HMAC-SHA256 và lấy 8 byte đầu
 *
 * HMAC(K, m) = SHA256( (K⊕opad) || SHA256( (K⊕ipad) || m ) )
 * ipad = 0x36 repeated, opad = 0x5c repeated
 */
static void hmac_sha256_truncated(const uint8_t *key, size_t klen,
                                   const uint8_t *msg, size_t mlen,
                                   uint8_t *out8)
{
    uint8_t k[64]={0}, ipad[64], opad[64], inner[32], full[32];
    sha256_ctx ctx;
    if(klen>64){sha256_init(&ctx);sha256_update(&ctx,key,klen);sha256_final(&ctx,k);}
    else memcpy(k,key,klen);
    for(int i=0;i<64;i++){ipad[i]=k[i]^0x36;opad[i]=k[i]^0x5c;}
    sha256_init(&ctx);sha256_update(&ctx,ipad,64);sha256_update(&ctx,msg,mlen);sha256_final(&ctx,inner);
    sha256_init(&ctx);sha256_update(&ctx,opad,64);sha256_update(&ctx,inner,32);sha256_final(&ctx,full);
    memcpy(out8,full,8);
}

/* In hex dump đẹp */
static void hexdump(const char *label, const uint8_t *d, size_t n) {
    printf("  %s%s%s  ", MAG, label, RST);
    for(size_t i=0;i<n&&i<16;i++) printf("%02x ",d[i]);
    if(n>16) printf("...");
    printf("\n");
}

/* ── Global state ── */
static char          g_iface[IFNAMSIZ];
static int           g_sock=-1, g_ifindex=0;
static unsigned char g_src_mac[6];
static unsigned char g_bcast[6]={0xff,0xff,0xff,0xff,0xff,0xff};
static int           g_total=0, g_ok=0, g_fail=0;
static volatile int  g_running=1;
static void on_sig(int s){(void)s;g_running=0;}

static uint16_t cksum(const void *d,size_t n){
    const uint16_t *p=d;uint32_t s=0;
    while(n>1){s+=*p++;n-=2;}
    if(n)s+=*(const uint8_t*)p;
    s=(s>>16)+(s&0xffff);s+=(s>>16);return(uint16_t)~s;
}
static void sep(void) {printf(DIM"  ─────────────────────────────────────────────────\n"RST);}
static void sep2(void){printf(BOLD CYN"  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"RST);}

static int find_iface(const char *hint){
    const char *c[]={"aic0","aic1","usb0",NULL};
    struct ifreq ifr;int s=socket(AF_INET,SOCK_DGRAM,0);if(s<0)return 0;
    if(hint&&hint[0]){
        memset(&ifr,0,sizeof(ifr));snprintf(ifr.ifr_name,IFNAMSIZ,"%s",hint);
        if(ioctl(s,SIOCGIFINDEX,&ifr)==0){ioctl(s,SIOCGIFFLAGS,&ifr);
            if(ifr.ifr_flags&IFF_UP){snprintf(g_iface,IFNAMSIZ,"%s",hint);close(s);return 1;}}
        close(s);return 0;
    }
    for(int i=0;c[i];i++){
        memset(&ifr,0,sizeof(ifr));snprintf(ifr.ifr_name,IFNAMSIZ,"%s",c[i]);
        if(ioctl(s,SIOCGIFINDEX,&ifr)<0)continue;
        ioctl(s,SIOCGIFFLAGS,&ifr);
        if(ifr.ifr_flags&IFF_UP){snprintf(g_iface,IFNAMSIZ,"%s",c[i]);close(s);return 1;}
    }
    close(s);return 0;
}
static int open_sock(void){
    struct ifreq a,b;
    g_sock=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(g_sock<0)return 0;
    memset(&a,0,sizeof(a));snprintf(a.ifr_name,IFNAMSIZ,"%s",g_iface);
    if(ioctl(g_sock,SIOCGIFINDEX,&a)<0)return 0;
    g_ifindex=a.ifr_ifindex;
    memset(&b,0,sizeof(b));snprintf(b.ifr_name,IFNAMSIZ,"%s",g_iface);
    if(ioctl(g_sock,SIOCGIFHWADDR,&b)<0)return 0;
    memcpy(g_src_mac,b.ifr_hwaddr.sa_data,6);return 1;
}
static ssize_t tx_raw(const void *buf,size_t len){
    struct sockaddr_ll sa={0};
    sa.sll_family=AF_PACKET;sa.sll_ifindex=g_ifindex;
    sa.sll_halen=ETH_ALEN;memcpy(sa.sll_addr,g_bcast,ETH_ALEN);
    return sendto(g_sock,buf,len,0,(struct sockaddr*)&sa,sizeof(sa));
}
static void pkt_log(int ok,const char *type,const char *det){
    g_total++;
    if(ok){printf("  "GRN"[✓]"RST" #%-4d "CYN"%-16s"RST" %s\n",g_total,type,det);g_ok++;}
    else  {printf("  "RED"[✗]"RST" #%-4d %-16s %s → %s\n",g_total,type,det,strerror(errno));g_fail++;}
}

/* ================================================================
 * ENCRYPT + HMAC WRAPPER
 *
 * Hàm này nhận buffer chứa payload (phần sau header IP/TCP/UDP/ICMP),
 * thực hiện:
 *   1. AES-128-CTR encrypt toàn bộ payload
 *   2. Tính HMAC-SHA256(HMAC_KEY, encrypted_payload)
 *   3. Append 8 byte HMAC tag vào cuối buffer
 *
 * Trả về tổng số byte sau khi thêm tag (payload_len + HMAC_TAG_LEN)
 * ================================================================ */
static size_t encrypt_and_tag(uint8_t *payload, size_t plen,
                               uint8_t *out_buf, size_t out_max)
{
    if(plen + HMAC_TAG_LEN > out_max) return 0;

    /* Bước 1: Copy payload vào out_buf */
    memcpy(out_buf, payload, plen);

    /* Bước 2: AES-128-CTR encrypt */
    aes128_ctr_crypt(AES_KEY, AES_NONCE, out_buf, plen);

    /* Bước 3: Tính HMAC trên ciphertext */
    uint8_t tag[HMAC_TAG_LEN];
    hmac_sha256_truncated(HMAC_KEY, sizeof(HMAC_KEY), out_buf, plen, tag);

    /* Bước 4: Append tag */
    memcpy(out_buf + plen, tag, HMAC_TAG_LEN);

    return plen + HMAC_TAG_LEN;
}

/* ── Demo ARP (không encrypt — ARP không có payload) ── */
static void demo_arp(void)
{
    struct {
        struct ethhdr e;
        struct arphdr a;
        unsigned char sha[6],spa[4],tha[6],tpa[4];
    } __attribute__((packed)) f;

    printf("\n"BOLD"  [1] ARP Request"RST" — không encrypt (không có payload)\n");sep();
    memset(&f,0,sizeof(f));
    memcpy(f.e.h_source,g_src_mac,6);memcpy(f.e.h_dest,g_bcast,6);
    f.e.h_proto=htons(ETH_P_ARP);
    f.a.ar_hrd=htons(ARPHRD_ETHER);f.a.ar_pro=htons(ETH_P_IP);
    f.a.ar_hln=6;f.a.ar_pln=4;f.a.ar_op=htons(ARPOP_REQUEST);
    memcpy(f.sha,g_src_mac,6);
    inet_pton(AF_INET,SRC_IP,f.spa);inet_pton(AF_INET,DST_IP,f.tpa);
    pkt_log(tx_raw(&f,sizeof(f))>0,"ARP","Who has 192.168.99.2?");
    usleep(300000);
}

/* ── Demo ICMP với AES-128-CTR + HMAC ── */
static void demo_icmp_enc(int n)
{
    printf("\n"BOLD"  [2] ICMP Echo + AES-128-CTR encrypt + HMAC"RST" ×%d\n",n);sep();
    printf("  "DIM"Payload: AES-128-CTR → append HMAC[8 bytes]\n"RST);sep();

    for(int i=0;i<n&&g_running;i++){
        /* Payload gốc */
        char plain[48];
        snprintf(plain,sizeof(plain),"AIC-Ping-%03d-SECRET",i+1);
        size_t plen=strlen(plain);

        /* Buffer cho encrypted payload + HMAC tag */
        uint8_t enc_buf[64];
        size_t enc_len = encrypt_and_tag((uint8_t*)plain, plen, enc_buf, sizeof(enc_buf));

        /* Build frame: ETH + IP + ICMP + enc_buf */
        uint8_t frame[256];
        size_t  flen=0;

        /* Ethernet */
        struct ethhdr *eth=(struct ethhdr*)frame;
        memcpy(eth->h_source,g_src_mac,6);memcpy(eth->h_dest,g_bcast,6);
        eth->h_proto=htons(ETH_P_IP);
        flen+=ETH_HLEN;

        /* IP */
        struct iphdr *ip=(struct iphdr*)(frame+flen);
        ip->version=4;ip->ihl=5;ip->ttl=64;ip->protocol=IPPROTO_ICMP;
        ip->tot_len=htons(sizeof(*ip)+sizeof(struct icmphdr)+enc_len);
        inet_pton(AF_INET,SRC_IP,&ip->saddr);inet_pton(AF_INET,DST_IP,&ip->daddr);
        ip->check=cksum(ip,sizeof(*ip));
        flen+=sizeof(*ip);

        /* ICMP */
        struct icmphdr *ic=(struct icmphdr*)(frame+flen);
        ic->type=ICMP_ECHO;ic->un.echo.id=htons(0xA1C0);ic->un.echo.sequence=htons(i+1);
        flen+=sizeof(*ic);

        /* Encrypted payload */
        memcpy(frame+flen,enc_buf,enc_len);
        flen+=enc_len;

        /* ICMP checksum (bao gồm cả payload) */
        ic->checksum=cksum(ic,sizeof(*ic)+enc_len);

        /* Log */
        printf("  "DIM"  plain  : \"%s\"\n"RST, plain);
        hexdump("cipher+tag:", enc_buf, enc_len);

        char det[80];
        snprintf(det,sizeof(det),"%s→%s seq=%d [AES-128-CTR+HMAC] %zuB",SRC_IP,DST_IP,i+1,flen);
        pkt_log(tx_raw(frame,flen)>0,"ICMP+ENC",det);
        usleep(350000);
    }
}

/* ── Demo TCP SYN với AES-128-CTR + HMAC trên options field ── */
static void demo_tcp_enc(int n)
{
    uint16_t dp[]={80,443,22,8080,3000};
    const char *sv[]={"HTTP","HTTPS","SSH","HTTP-alt","App"};

    printf("\n"BOLD"  [3] TCP SYN + AES-128-CTR encrypt + HMAC"RST" ×%d\n",n);sep();
    printf("  "DIM"Payload: app data AES-128-CTR → HMAC[8]\n"RST);sep();

    for(int i=0;i<n&&g_running;i++){
        char plain[32];
        snprintf(plain,sizeof(plain),"CONNECT-%s-%03d",sv[i%5],i+1);
        size_t plen=strlen(plain);

        uint8_t enc_buf[48];
        size_t enc_len=encrypt_and_tag((uint8_t*)plain,plen,enc_buf,sizeof(enc_buf));

        uint8_t frame[256];size_t flen=0;
        struct ethhdr *eth=(struct ethhdr*)frame;
        memcpy(eth->h_source,g_src_mac,6);memcpy(eth->h_dest,g_bcast,6);
        eth->h_proto=htons(ETH_P_IP);flen+=ETH_HLEN;

        struct iphdr *ip=(struct iphdr*)(frame+flen);
        ip->version=4;ip->ihl=5;ip->ttl=64;ip->protocol=IPPROTO_TCP;
        ip->tot_len=htons(sizeof(*ip)+sizeof(struct tcphdr)+enc_len);
        inet_pton(AF_INET,SRC_IP,&ip->saddr);inet_pton(AF_INET,DST_IP,&ip->daddr);
        ip->check=cksum(ip,sizeof(*ip));flen+=sizeof(*ip);

        struct tcphdr *tcp=(struct tcphdr*)(frame+flen);
        tcp->source=htons(50000+i);tcp->dest=htons(dp[i%5]);
        tcp->seq=htonl(0xA1C00000+i);tcp->doff=5;tcp->syn=1;tcp->window=htons(65535);
        flen+=sizeof(*tcp);

        memcpy(frame+flen,enc_buf,enc_len);flen+=enc_len;

        /* TCP checksum với pseudo header */
        struct{uint32_t s,d;uint8_t z,p;uint16_t l;}ph;
        memset(&ph,0,sizeof(ph));ph.s=ip->saddr;ph.d=ip->daddr;ph.p=IPPROTO_TCP;
        ph.l=htons(sizeof(*tcp)+enc_len);
        uint8_t cs_buf[sizeof(ph)+sizeof(*tcp)+enc_len];
        memcpy(cs_buf,&ph,sizeof(ph));
        memcpy(cs_buf+sizeof(ph),tcp,sizeof(*tcp));
        memcpy(cs_buf+sizeof(ph)+sizeof(*tcp),enc_buf,enc_len);
        tcp->check=cksum(cs_buf,sizeof(cs_buf));

        hexdump("cipher+tag:", enc_buf, enc_len);
        char det[80];
        snprintf(det,sizeof(det),"%s:%u→%s:%u(%s)[SYN+AES-CTR]",SRC_IP,50000+i,DST_IP,dp[i%5],sv[i%5]);
        pkt_log(tx_raw(frame,flen)>0,"TCP+ENC",det);
        usleep(300000);
    }
}

/* ── Demo UDP/DNS với AES-128-CTR + HMAC ── */
static void demo_dns_enc(int n)
{
    static const uint8_t Q[]={
        0xA1,0xC0,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x07,'a','i','c','s','e','m','i',0x05,'l','o','c','a','l',0x00,
        0x00,0x01,0x00,0x01
    };

    printf("\n"BOLD"  [4] UDP DNS + AES-128-CTR encrypt + HMAC"RST" ×%d\n",n);sep();
    printf("  "DIM"DNS query payload AES-128-CTR → HMAC[8]\n"RST);sep();

    for(int i=0;i<n&&g_running;i++){
        uint8_t dns_copy[sizeof(Q)];
        memcpy(dns_copy,Q,sizeof(Q));
        dns_copy[0]=(uint8_t)((0xA1C0+i)>>8);
        dns_copy[1]=(uint8_t)((0xA1C0+i)&0xff);

        uint8_t enc_buf[sizeof(Q)+HMAC_TAG_LEN+4];
        size_t enc_len=encrypt_and_tag(dns_copy,sizeof(Q),enc_buf,sizeof(enc_buf));

        uint8_t frame[256];size_t flen=0;
        struct ethhdr *eth=(struct ethhdr*)frame;
        memcpy(eth->h_source,g_src_mac,6);memcpy(eth->h_dest,g_bcast,6);
        eth->h_proto=htons(ETH_P_IP);flen+=ETH_HLEN;

        struct iphdr *ip=(struct iphdr*)(frame+flen);
        ip->version=4;ip->ihl=5;ip->ttl=64;ip->protocol=IPPROTO_UDP;
        ip->tot_len=htons(sizeof(*ip)+sizeof(struct udphdr)+enc_len);
        inet_pton(AF_INET,SRC_IP,&ip->saddr);inet_pton(AF_INET,DNS_SRV,&ip->daddr);
        ip->check=cksum(ip,sizeof(*ip));flen+=sizeof(*ip);

        struct udphdr *udp=(struct udphdr*)(frame+flen);
        udp->source=htons(40000+i);udp->dest=htons(53);
        udp->len=htons(sizeof(*udp)+enc_len);flen+=sizeof(*udp);

        memcpy(frame+flen,enc_buf,enc_len);flen+=enc_len;

        struct{uint32_t s,d;uint8_t z,p;uint16_t l;}ph;
        memset(&ph,0,sizeof(ph));ph.s=ip->saddr;ph.d=ip->daddr;ph.p=IPPROTO_UDP;ph.l=udp->len;
        uint8_t cs_buf[sizeof(ph)+sizeof(*udp)+enc_len];
        memcpy(cs_buf,&ph,sizeof(ph));memcpy(cs_buf+sizeof(ph),udp,sizeof(*udp));
        memcpy(cs_buf+sizeof(ph)+sizeof(*udp),enc_buf,enc_len);
        udp->check=cksum(cs_buf,sizeof(cs_buf));

        hexdump("cipher+tag:", enc_buf, enc_len);
        char det[64];
        snprintf(det,sizeof(det),"%s→%s:53[DNS+ENC]",SRC_IP,DNS_SRV);
        pkt_log(tx_raw(frame,flen)>0,"DNS+ENC",det);
        usleep(450000);
    }
}

/* ── Demo gói TAMPERED — HMAC sai để test driver phát hiện ── */
static void demo_tampered(void)
{
    printf("\n"BOLD"  [5] TAMPERED packet"RST" — HMAC sai để test driver detect\n");sep();
    printf("  "RED"  Driver sẽ log: [SECURITY] HMAC FAIL — gói bị tamper!\n"RST);sep();

    char plain[]="TAMPERED-PAYLOAD-TEST";
    size_t plen=strlen(plain);
    uint8_t enc_buf[40];
    encrypt_and_tag((uint8_t*)plain,plen,enc_buf,sizeof(enc_buf));

    /* Cố tình sửa 1 byte trong HMAC tag → driver sẽ detect */
    enc_buf[plen + 3] ^= 0xFF;
    printf("  "YLW"  Đã flip byte HMAC[3] → 0xFF để giả lập tamper\n"RST);
    hexdump("tampered  :", enc_buf, plen+HMAC_TAG_LEN);

    uint8_t frame[256];size_t flen=0;
    struct ethhdr *eth=(struct ethhdr*)frame;
    memcpy(eth->h_source,g_src_mac,6);memcpy(eth->h_dest,g_bcast,6);
    eth->h_proto=htons(ETH_P_IP);flen+=ETH_HLEN;

    struct iphdr *ip=(struct iphdr*)(frame+flen);
    ip->version=4;ip->ihl=5;ip->ttl=64;ip->protocol=IPPROTO_ICMP;
    size_t enc_len=plen+HMAC_TAG_LEN;
    ip->tot_len=htons(sizeof(*ip)+sizeof(struct icmphdr)+enc_len);
    inet_pton(AF_INET,SRC_IP,&ip->saddr);inet_pton(AF_INET,DST_IP,&ip->daddr);
    ip->check=cksum(ip,sizeof(*ip));flen+=sizeof(*ip);

    struct icmphdr *ic=(struct icmphdr*)(frame+flen);
    ic->type=ICMP_ECHO;ic->un.echo.id=htons(0xDEAD);ic->un.echo.sequence=htons(1);
    flen+=sizeof(*ic);
    memcpy(frame+flen,enc_buf,enc_len);flen+=enc_len;
    ic->checksum=cksum(ic,sizeof(*ic)+enc_len);

    pkt_log(tx_raw(frame,flen)>0,"TAMPERED","HMAC intentionally broken → driver should WARN");
    usleep(300000);
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(int argc, char *argv[])
{
    signal(SIGINT,on_sig);signal(SIGTERM,on_sig);

    printf("\n");sep2();
    printf("  "BOLD CYN"  AIC SEMI USB WIFI — Crypto Demo v5.0\n"RST);
    printf("  "DIM"  AES-128-CTR Encrypt + HMAC-SHA256 Integrity\n"RST);
    sep2();
    printf("\n");
    printf("  "DIM"Luồng: demo.c → AES-128-CTR(payload) + HMAC[8] → AF_PACKET\n"RST);
    printf("  "DIM"        → ndo_start_xmit() → verify HMAC → log dmesg\n"RST);
    printf("  "BOLD"Xem log: "RST CYN"sudo dmesg -w | grep --color aicsemi\n"RST"\n");

    printf(BOLD"  Bước 1: Tìm interface\n"RST);sep();
    if(!find_iface(argc>1?argv[1]:NULL)){
        printf("  "RED"[✗]"RST" Không tìm thấy interface UP\n");
        printf("  Chạy: "CYN"sudo ./setup.bash\n\n"RST);return 1;
    }
    printf("  "GRN"[✓]"RST" Interface: "BOLD CYN"%s\n"RST,g_iface);

    printf("\n"BOLD"  Bước 2: Mở AF_PACKET socket\n"RST);sep();
    if(!open_sock()){printf("  "RED"[✗]"RST" Cần sudo\n");return 1;}
    printf("  "GRN"[✓]"RST" MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           g_src_mac[0],g_src_mac[1],g_src_mac[2],g_src_mac[3],g_src_mac[4],g_src_mac[5]);
    printf("  "GRN"[✓]"RST" AES key : ");
    for(int i=0;i<16;i++) printf("%02x",AES_KEY[i]);
    printf(" (128-bit)\n");
    printf("  "GRN"[✓]"RST" HMAC key: ");
    for(int i=0;i<16;i++) printf("%02x",HMAC_KEY[i]);
    printf(" (16 bytes)\n");

    printf("\n"BOLD"  Bước 3: Gửi packets\n"RST);sep();

    demo_arp();
    if(g_running){sleep(1);demo_icmp_enc(5);}
    if(g_running){sleep(1);demo_tcp_enc(5);}
    if(g_running){sleep(1);demo_dns_enc(3);}
    if(g_running){sleep(1);demo_tampered();}

    printf("\n");sep2();
    printf("  "BOLD"  KẾT QUẢ\n"RST);sep2();
    printf("  Tổng gói   : "BOLD"%d\n"RST,g_total);
    printf("  Thành công : "GRN BOLD"%d ✓\n"RST,g_ok);
    if(g_fail) printf("  Thất bại   : "RED BOLD"%d ✗\n"RST,g_fail);
    sep2();
    printf("\n  "BOLD"Xem security events:\n"RST);
    printf("  "CYN"sudo dmesg | grep -E 'HMAC|SECURITY|tamper' | tail -20\n\n"RST);

    if(g_sock>=0)close(g_sock);
    return g_fail>0?1:0;
}
