/*
 * demo.c — AIC Semi USB Network Driver Demo
 *
 * Gửi raw Ethernet frame qua interface aic0 (USB hardware thật).
 * Mỗi gói → kernel gọi ndo_start_xmit() trong driver → log dmesg.
 *
 * Luồng:
 *   demo.c → socket(AF_PACKET) → sendto()
 *   → kernel dev_queue_xmit()
 *   → aicsemi_net_xmit() [trong usb.ko — chạy trên USB hardware]
 *   → log ra dmesg với thông tin chi tiết
 *
 * Build:  gcc -Wall -O2 -o demo demo.c
 * Chạy:   sudo ./demo [tên_interface]
 * Log:    sudo dmesg -w | grep --color aicsemi
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define SRC_IP  "192.168.99.1"
#define DST_IP  "192.168.99.2"
#define DNS_SRV "8.8.8.8"

static char          g_iface[IFNAMSIZ];
static int           g_sock    = -1;
static int           g_ifindex = 0;
static unsigned char g_src_mac[6];
static unsigned char g_bcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
static int           g_total = 0, g_ok = 0, g_fail = 0;
static volatile int  g_running = 1;

static void on_sig(int s) { (void)s; g_running = 0; }

static uint16_t cksum(const void *data, size_t len)
{
    const uint16_t *p = data; uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    sum = (sum >> 16) + (sum & 0xffff); sum += (sum >> 16);
    return (uint16_t)~sum;
}

static void sep(void)  { printf(DIM "  ─────────────────────────────────────────────────\n" RST); }
static void sep2(void) { printf(BOLD CYN "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" RST); }

/* Tìm interface aic0/aic1 đang UP */
static int find_iface(const char *hint)
{
    const char *cand[] = {"aic0","aic1","aic2","usb0","usb1",NULL};
    struct ifreq ifr; int s = socket(AF_INET,SOCK_DGRAM,0); if(s<0)return 0;
    if (hint && hint[0]) {
        memset(&ifr,0,sizeof(ifr)); snprintf(ifr.ifr_name,IFNAMSIZ,"%s",hint);
        if (ioctl(s,SIOCGIFINDEX,&ifr)==0) {
            ioctl(s,SIOCGIFFLAGS,&ifr);
            if (ifr.ifr_flags & IFF_UP) { snprintf(g_iface,IFNAMSIZ,"%s",hint); close(s); return 1; }
            printf("  " YLW "[⚠]" RST " '%s' chưa UP → sudo ip link set %s up\n",hint,hint);
        } else printf("  " RED "[✗]" RST " '%s' không tồn tại\n",hint);
        close(s); return 0;
    }
    for(int i=0;cand[i];i++){
        memset(&ifr,0,sizeof(ifr)); snprintf(ifr.ifr_name,IFNAMSIZ,"%s",cand[i]);
        if(ioctl(s,SIOCGIFINDEX,&ifr)<0) continue;
        ioctl(s,SIOCGIFFLAGS,&ifr);
        if(ifr.ifr_flags & IFF_UP){snprintf(g_iface,IFNAMSIZ,"%s",cand[i]);close(s);return 1;}
        printf("  " YLW "[⚠]" RST " '%s' chưa UP\n",cand[i]);
    }
    close(s); return 0;
}

/* Mở raw socket, lấy ifindex và MAC — 2 ifr riêng tránh union overwrite */
static int open_sock(void)
{
    struct ifreq a, b;
    g_sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(g_sock<0){printf("  " RED "[✗]" RST " socket: %s → cần sudo!\n",strerror(errno));return 0;}
    memset(&a,0,sizeof(a)); snprintf(a.ifr_name,IFNAMSIZ,"%s",g_iface);
    if(ioctl(g_sock,SIOCGIFINDEX,&a)<0){printf("  " RED "[✗]" RST " SIOCGIFINDEX: %s\n",strerror(errno));return 0;}
    g_ifindex = a.ifr_ifindex;
    memset(&b,0,sizeof(b)); snprintf(b.ifr_name,IFNAMSIZ,"%s",g_iface);
    if(ioctl(g_sock,SIOCGIFHWADDR,&b)<0){printf("  " RED "[✗]" RST " SIOCGIFHWADDR: %s\n",strerror(errno));return 0;}
    memcpy(g_src_mac,b.ifr_hwaddr.sa_data,6); return 1;
}

static ssize_t tx(const void *buf, size_t len, const unsigned char *dst)
{
    struct sockaddr_ll sa={0};
    sa.sll_family=AF_PACKET; sa.sll_ifindex=g_ifindex;
    sa.sll_halen=ETH_ALEN; memcpy(sa.sll_addr,dst,ETH_ALEN);
    return sendto(g_sock,buf,len,0,(struct sockaddr*)&sa,sizeof(sa));
}

static void pkt(int ok, const char *type, const char *det)
{
    g_total++;
    if(ok){printf("  " GRN "[✓]" RST " #%-4d " CYN "%-14s" RST " %s\n",g_total,type,det);g_ok++;}
    else  {printf("  " RED "[✗]" RST " #%-4d %-14s %s → %s\n",g_total,type,det,strerror(errno));g_fail++;}
}

/* ── ARP ── */
static void demo_arp(void)
{
    struct { struct ethhdr e; struct arphdr a;
             unsigned char sha[6],spa[4],tha[6],tpa[4]; } __attribute__((packed)) f;
    printf("\n" BOLD "  [1] ARP Request" RST " — broadcast qua USB hardware\n"); sep();
    memset(&f,0,sizeof(f));
    memcpy(f.e.h_source,g_src_mac,6); memcpy(f.e.h_dest,g_bcast,6);
    f.e.h_proto=htons(ETH_P_ARP);
    f.a.ar_hrd=htons(ARPHRD_ETHER); f.a.ar_pro=htons(ETH_P_IP);
    f.a.ar_hln=6; f.a.ar_pln=4; f.a.ar_op=htons(ARPOP_REQUEST);
    memcpy(f.sha,g_src_mac,6);
    inet_pton(AF_INET,SRC_IP,f.spa); inet_pton(AF_INET,DST_IP,f.tpa);
    pkt(tx(&f,sizeof(f),g_bcast)>0,"ARP","Who has 192.168.99.2? (broadcast)");
    usleep(400000);
}

/* ── ICMP ── */
static void demo_icmp(int n)
{
    struct { struct ethhdr e; struct iphdr ip; struct icmphdr ic; char pl[48]; } __attribute__((packed)) f;
    printf("\n" BOLD "  [2] ICMP Echo" RST " — ping qua USB ×%d\n",n); sep();
    printf("  " DIM "(Tương đương ping -c %d 192.168.99.2 ở tầng Ethernet)\n" RST,n); sep();
    for(int i=0;i<n&&g_running;i++){
        memset(&f,0,sizeof(f));
        memcpy(f.e.h_source,g_src_mac,6); memcpy(f.e.h_dest,g_bcast,6);
        f.e.h_proto=htons(ETH_P_IP);
        f.ip.version=4;f.ip.ihl=5;f.ip.ttl=64;f.ip.protocol=IPPROTO_ICMP;
        f.ip.tot_len=htons(sizeof(f)-sizeof(f.e));
        inet_pton(AF_INET,SRC_IP,&f.ip.saddr); inet_pton(AF_INET,DST_IP,&f.ip.daddr);
        f.ip.check=cksum(&f.ip,sizeof(f.ip));
        f.ic.type=ICMP_ECHO; f.ic.un.echo.id=htons(0xA1C0); f.ic.un.echo.sequence=htons(i+1);
        snprintf(f.pl,sizeof(f.pl),"AIC-Semi-USB-Ping-%03d",i+1);
        f.ic.checksum=cksum(&f.ic,sizeof(f.ic)+sizeof(f.pl));
        char d[72]; snprintf(d,sizeof(d),"%s → %s  seq=%d  ttl=64  %zuB",SRC_IP,DST_IP,i+1,sizeof(f));
        pkt(tx(&f,sizeof(f),g_bcast)>0,"ICMP Echo",d); usleep(350000);
    }
}

/* ── TCP SYN ── */
static void demo_tcp(int n)
{
    struct { struct ethhdr e; struct iphdr ip; struct tcphdr tcp; } __attribute__((packed)) f;
    struct { uint32_t s,d; uint8_t z,p; uint16_t l; } ph;
    uint8_t cs[sizeof(ph)+sizeof(f.tcp)];
    uint16_t dp[]={80,443,22,8080,3000};
    const char *sv[]={"HTTP","HTTPS","SSH","HTTP-alt","App"};
    printf("\n" BOLD "  [3] TCP SYN" RST " — connection init qua USB ×%d\n",n); sep();
    printf("  " DIM "(Mô phỏng kết nối HTTP/HTTPS/SSH qua USB adapter)\n" RST); sep();
    for(int i=0;i<n&&g_running;i++){
        uint16_t sp=50000+i,d=dp[i%5];
        memset(&f,0,sizeof(f));
        memcpy(f.e.h_source,g_src_mac,6); memcpy(f.e.h_dest,g_bcast,6);
        f.e.h_proto=htons(ETH_P_IP);
        f.ip.version=4;f.ip.ihl=5;f.ip.ttl=64;f.ip.protocol=IPPROTO_TCP;
        f.ip.tot_len=htons(sizeof(f)-sizeof(f.e));
        inet_pton(AF_INET,SRC_IP,&f.ip.saddr); inet_pton(AF_INET,DST_IP,&f.ip.daddr);
        f.ip.check=cksum(&f.ip,sizeof(f.ip));
        f.tcp.source=htons(sp);f.tcp.dest=htons(d);f.tcp.seq=htonl(0xA1C00000+i);
        f.tcp.doff=5;f.tcp.syn=1;f.tcp.window=htons(65535);
        memset(&ph,0,sizeof(ph)); ph.s=f.ip.saddr;ph.d=f.ip.daddr;ph.p=IPPROTO_TCP;ph.l=htons(sizeof(f.tcp));
        memcpy(cs,&ph,sizeof(ph)); memcpy(cs+sizeof(ph),&f.tcp,sizeof(f.tcp));
        f.tcp.check=cksum(cs,sizeof(cs));
        char det[80]; snprintf(det,sizeof(det),"%s:%u → %s:%u (%s) [SYN]",SRC_IP,sp,DST_IP,d,sv[i%5]);
        pkt(tx(&f,sizeof(f),g_bcast)>0,"TCP SYN",det); usleep(300000);
    }
}

/* ── DNS/UDP ── */
static void demo_dns(int n)
{
    static const uint8_t Q[]={
        0xA1,0xC0,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
        0x07,'a','i','c','s','e','m','i',0x05,'l','o','c','a','l',0x00,
        0x00,0x01,0x00,0x01
    };
    struct { struct ethhdr e; struct iphdr ip; struct udphdr udp; uint8_t dns[sizeof(Q)]; } __attribute__((packed)) f;
    struct { uint32_t s,d; uint8_t z,p; uint16_t l; } ph;
    uint8_t cs[sizeof(ph)+sizeof(f.udp)+sizeof(Q)];
    printf("\n" BOLD "  [4] UDP DNS Query" RST " — truy vấn 'aicsemi.local' qua USB ×%d\n",n); sep();
    printf("  " DIM "(Gói UDP hợp lệ, query DNS cho hostname của driver)\n" RST); sep();
    for(int i=0;i<n&&g_running;i++){
        memset(&f,0,sizeof(f)); memcpy(f.dns,Q,sizeof(Q));
        f.dns[0]=(uint8_t)((0xA1C0+i)>>8); f.dns[1]=(uint8_t)((0xA1C0+i)&0xff);
        memcpy(f.e.h_source,g_src_mac,6); memcpy(f.e.h_dest,g_bcast,6);
        f.e.h_proto=htons(ETH_P_IP);
        f.ip.version=4;f.ip.ihl=5;f.ip.ttl=64;f.ip.protocol=IPPROTO_UDP;
        f.ip.tot_len=htons(sizeof(f)-sizeof(f.e));
        inet_pton(AF_INET,SRC_IP,&f.ip.saddr); inet_pton(AF_INET,DNS_SRV,&f.ip.daddr);
        f.ip.check=cksum(&f.ip,sizeof(f.ip));
        f.udp.source=htons(40000+i);f.udp.dest=htons(53);
        f.udp.len=htons(sizeof(f.udp)+sizeof(Q));
        memset(&ph,0,sizeof(ph)); ph.s=f.ip.saddr;ph.d=f.ip.daddr;ph.p=IPPROTO_UDP;ph.l=f.udp.len;
        memcpy(cs,&ph,sizeof(ph)); memcpy(cs+sizeof(ph),&f.udp,sizeof(f.udp));
        memcpy(cs+sizeof(ph)+sizeof(f.udp),Q,sizeof(Q));
        f.udp.check=cksum(cs,sizeof(cs));
        char det[64]; snprintf(det,sizeof(det),"%s → %s:53 (aicsemi.local A?)",SRC_IP,DNS_SRV);
        pkt(tx(&f,sizeof(f),g_bcast)>0,"DNS Query",det); usleep(450000);
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT,on_sig); signal(SIGTERM,on_sig);

    printf("\n"); sep2();
    printf("  " BOLD CYN "  AIC SEMI USB WIFI — Network Driver Demo\n" RST);
    printf("  " DIM "  Raw packet qua USB hardware → driver log ra dmesg\n" RST);
    sep2();
    printf("\n");
    printf("  " DIM "Luồng: demo.c → AF_PACKET → ndo_start_xmit() → USB chip\n" RST);
    printf("  " BOLD "Terminal khác: " RST CYN "sudo dmesg -w | grep --color aicsemi\n" RST "\n");

    printf(BOLD "  Bước 1: Tìm USB network interface\n" RST); sep();
    if(!find_iface(argc>1?argv[1]:NULL)){
        printf("\n  " RED "[✗]" RST " Không tìm thấy interface UP\n\n");
        printf("  Khắc phục: " CYN "sudo ./setup.bash\n\n" RST); return 1;
    }
    printf("  " GRN "[✓]" RST " Interface : " BOLD CYN "%s" RST " (USB adapter)\n", g_iface);

    printf("\n" BOLD "  Bước 2: Mở AF_PACKET socket\n" RST); sep();
    if(!open_sock()){printf("  " YLW "Cần: " RST CYN "sudo ./demo\n\n" RST);return 1;}
    printf("  " GRN "[✓]" RST " ifindex  : %d\n", g_ifindex);
    printf("  " GRN "[✓]" RST " MAC      : %02x:%02x:%02x:%02x:%02x:%02x  (USB adapter MAC)\n",
           g_src_mac[0],g_src_mac[1],g_src_mac[2],g_src_mac[3],g_src_mac[4],g_src_mac[5]);
    printf("  " GRN "[✓]" RST " Socket AF_PACKET sẵn sàng\n");

    printf("\n" BOLD "  Bước 3: Gửi packets qua USB hardware\n" RST);
    printf("  " DIM "(Xem driver log: sudo dmesg -w | grep aicsemi)\n" RST);

    demo_arp();
    if(g_running){sleep(1); demo_icmp(5);}
    if(g_running){sleep(1); demo_tcp(5);}
    if(g_running){sleep(1); demo_dns(3);}

    printf("\n"); sep2();
    printf("  " BOLD "  KẾT QUẢ DEMO\n" RST); sep2();
    printf("  Tổng gói    : " BOLD "%d\n" RST, g_total);
    printf("  Thành công  : " GRN BOLD "%d ✓\n" RST, g_ok);
    if(g_fail) printf("  Thất bại    : " RED BOLD "%d ✗\n" RST, g_fail);
    sep2();
    printf("\n");
    printf("  " BOLD "Xem log driver:\n" RST);
    printf("  " CYN "sudo dmesg | grep '\\[aicsemi\\]' | grep TX | tail -20\n" RST);
    printf("\n");
    printf("  " BOLD "Xem thống kê:\n" RST);
    printf("  " CYN "cat /proc/aicsemi_usbnet/monitor\n\n" RST);

    if(g_sock>=0) close(g_sock);
    return g_fail>0?1:0;
}
