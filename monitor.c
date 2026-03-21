/*
 * monitor.c — AIC Semi USB Packet Monitor v4.0
 *
 * Cách gọi ioctl đúng với ndo_siocdevprivate:
 *   Kernel nhận: ioctl(fd, cmd, &ifr)
 *   Trong đó ifr.ifr_data = pointer tới data buffer
 *   Driver nhận được: data = ifr->ifr_data (đã được kernel chuyển sang kernel ptr)
 *
 * Build: gcc -Wall -O2 -o monitor monitor.c -lncurses
 * Run:   sudo ./monitor [interface]
 * Keys:  q=quit  c=clear  a=all  t=TCP  u=UDP  i=ICMP
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ncurses.h>

/* ── Phải khớp với usb.c ── */
#define MON_RING_SIZE    1024
#define MON_RING_MASK    (MON_RING_SIZE - 1)
/*
 * Dùng SIOCDEVPRIVATE range (0x89F0-0x89FF) — kernel mới route
 * đến ndo_siocdevprivate. Nếu dùng _IOR('A',...) → errno=25 (ENOTTY).
 */
#ifndef SIOCDEVPRIVATE
#define SIOCDEVPRIVATE  0x89F0
#endif
#define AICSEMI_IOC_CLEAR    (SIOCDEVPRIVATE + 0)
#define AICSEMI_IOC_GETRING  (SIOCDEVPRIVATE + 1)
#define AICSEMI_IOC_SETFILT  (SIOCDEVPRIVATE + 2)
#define AICSEMI_IOC_GETSTATS (SIOCDEVPRIVATE + 3)

struct pkt_entry {
    unsigned long long ts_ns;
    unsigned int  seq, len;
    unsigned short eth_proto;
    unsigned char  ip_proto, direction;
    unsigned int   saddr, daddr;
    unsigned short sport, dport;
    unsigned char  tcp_flags, icmp_type, pad[2];
};

struct aicsemi_ring_export {
    unsigned int count, head;
    struct pkt_entry entries[MON_RING_SIZE];
};

struct aicsemi_stats_export {
    unsigned long long tx_total, tx_bytes, tx_dropped;
    unsigned long long rx_total, rx_bytes;
    unsigned long long tcp, udp, icmp, arp, ipv6, other;
    unsigned long long uptime_sec;
    char ifname[16], driver_ver[16];
};

static char g_iface[IFNAMSIZ] = "aic0";
static int  g_sock = -1, g_running = 1, g_filter = 0;

static void on_sig(int s) { (void)s; g_running = 0; }

/* ================================================================
 * IOCTL HELPERS
 *
 * Cách đúng với ndo_siocdevprivate:
 *   struct ifreq ifr;
 *   ifr.ifr_name = "aic0";
 *   ifr.ifr_data = (caddr_t)&my_data;
 *   ioctl(sock, AICSEMI_IOC_*, &ifr);
 *
 * Kernel sẽ:
 *   1. Tìm net_device theo ifr.ifr_name
 *   2. Gọi ndo_siocdevprivate(dev, &ifr, ifr.ifr_data, cmd)
 *      (kernel tự copy ifr.ifr_data → userspace ptr → kernel ptr)
 * ================================================================ */
static int do_ioctl(unsigned long cmd, void *data)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", g_iface);
    ifr.ifr_data = (caddr_t)data;
    return ioctl(g_sock, cmd, &ifr);
}

static int get_stats(struct aicsemi_stats_export *st)
{
    return do_ioctl(AICSEMI_IOC_GETSTATS, st);
}

static int get_ring(struct aicsemi_ring_export *exp)
{
    return do_ioctl(AICSEMI_IOC_GETRING, exp);
}

static void do_clear(void)
{
    /* CLEAR không cần data — truyền NULL OK vì driver không dùng */
    do_ioctl(AICSEMI_IOC_CLEAR, NULL);
}

static void do_setfilt(unsigned int f)
{
    g_filter = (int)f;
    do_ioctl(AICSEMI_IOC_SETFILT, &f);
}

/* ── Format helpers ── */
static const char *ip4(unsigned int a, char *b, int sz)
{ struct in_addr x; x.s_addr = a; inet_ntop(AF_INET, &x, b, sz); return b; }

static const char *fmtb(unsigned long long b, char *buf, int sz)
{
    if      (b < 1024ULL)       snprintf(buf, sz, "%llu B",  b);
    else if (b < 1048576ULL)    snprintf(buf, sz, "%.1fK",   b / 1024.0);
    else if (b < 1073741824ULL) snprintf(buf, sz, "%.2fM",   b / 1048576.0);
    else                        snprintf(buf, sz, "%.2fG",   b / 1073741824.0);
    return buf;
}

static const char *fmtup(unsigned long long s, char *b, int sz)
{ snprintf(b, sz, "%02llu:%02llu:%02llu", s/3600, (s%3600)/60, s%60); return b; }

static const char *pname(unsigned char proto, unsigned short dp)
{
    switch (proto) {
    case 6:    return dp==80?"HTTP": dp==443?"HTTPS": dp==22?"SSH": "TCP";
    case 17:   return dp==53?"DNS":  dp==67||dp==68?"DHCP": "UDP";
    case 1:    return "ICMP";
    case 0x86: return "IPv6";
    case 0:    return "ARP";
    default: { static char t[8]; snprintf(t,8,"IP/%d",proto); return t; }
    }
}

static void draw_bar(int y, int x, int w,
                     unsigned long long v, unsigned long long t, int cp)
{
    int n = (t > 0) ? (int)(v * w / t) : 0;
    if (n > w) n = w;
    attron(COLOR_PAIR(cp));
    for (int i = 0; i < n; i++) mvaddch(y, x+i, ACS_BLOCK);
    attroff(COLOR_PAIR(cp));
    for (int i = n; i < w; i++) mvaddch(y, x+i, ACS_HLINE);
}

/* ================================================================
 * DRAW — Vẽ toàn bộ dashboard
 * ================================================================ */
static void redraw(struct aicsemi_stats_export *s,
                   struct aicsemi_ring_export  *r,
                   int ioctl_ok)
{
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    char b1[24], b2[24], i1[20], i2[20];
    int bw = cols > 90 ? 32 : 22;

    /* Header */
    attron(COLOR_PAIR(1) | A_BOLD);
    mvprintw(0, 0, "%-*s", cols,
        "  AIC Semi USB Network Driver — Packet Monitor v4.0"
        "  [q]Quit [c]Clear [a]All [t]TCP [u]UDP [i]ICMP");
    attroff(COLOR_PAIR(1) | A_BOLD);

    /* Status */
    attron(COLOR_PAIR(2));
    mvprintw(1, 0, "%-*s", cols, "");
    if (ioctl_ok) {
        mvprintw(1, 1, " iface:%-6s  ver:%-8s  uptime:%s  filter:%-5s  ring:%u/%d",
            s->ifname[0] ? s->ifname : g_iface,
            s->driver_ver,
            fmtup(s->uptime_sec, b1, sizeof(b1)),
            g_filter==0?"ALL" : g_filter==6?"TCP" :
            g_filter==17?"UDP": "ICMP",
            r->count, MON_RING_SIZE);
    } else {
        mvprintw(1, 1, " iface:%-6s  [!] ioctl thất bại — kiểm tra driver đã load chưa",
            g_iface);
    }
    attroff(COLOR_PAIR(2));

    if (!ioctl_ok) {
        attron(COLOR_PAIR(4) | A_BOLD);
        mvprintw(4, 2, "Driver chưa load hoặc interface chưa UP.");
        mvprintw(5, 2, "Chạy: sudo ./setup.bash");
        mvprintw(6, 2, "Sau đó: sudo ip link set aic0 up");
        attroff(COLOR_PAIR(4) | A_BOLD);
        refresh();
        return;
    }

    /* TX/RX counters */
    mvprintw(3, 2, "TX: ");
    attron(COLOR_PAIR(5) | A_BOLD);
    printw("%llu pkts  %s", s->tx_total, fmtb(s->tx_bytes, b1, sizeof(b1)));
    attroff(COLOR_PAIR(5) | A_BOLD);
    if (s->tx_dropped) {
        attron(COLOR_PAIR(4));
        printw("  drop:%llu", s->tx_dropped);
        attroff(COLOR_PAIR(4));
    }

    mvprintw(4, 2, "RX: ");
    attron(COLOR_PAIR(3) | A_BOLD);
    printw("%llu pkts  %s", s->rx_total, fmtb(s->rx_bytes, b2, sizeof(b2)));
    attroff(COLOR_PAIR(3) | A_BOLD);

    /* Protocol breakdown */
    mvprintw(6, 2, "Protocol breakdown (TX):");
    attron(A_DIM);
    mvprintw(7, 2, "%-7s %6s %4s%%  %-*s", "Proto","Pkts","Pct", bw, "Bar");
    attroff(A_DIM);

    unsigned long long tot = s->tx_total > 0 ? s->tx_total : 1;
    struct { const char *n; unsigned long long v; int cp; } ps[] = {
        {"TCP",  s->tcp,   5}, {"UDP",   s->udp,  6},
        {"ICMP", s->icmp,  7}, {"ARP",   s->arp,  8},
        {"IPv6", s->ipv6,  9}, {"Other", s->other, 2},
    };
    for (int i = 0; i < 6; i++) {
        int pct = (int)(ps[i].v * 100 / tot);
        mvprintw(8+i, 2, "%-7s %6llu %3d%%  ", ps[i].n, ps[i].v, pct);
        draw_bar(8+i, 22, bw, ps[i].v, tot, ps[i].cp);
    }

    /* Separator */
    attron(A_DIM);
    mvhline(15, 0, ACS_HLINE, cols);
    attroff(A_DIM);

    /* Recent packets từ ring buffer */
    attron(A_BOLD);
    mvprintw(16, 2, "Recent packets — ring buffer (%u entries):", r->count);
    attroff(A_BOLD);

    attron(A_DIM);
    mvprintw(17, 2, "%-3s %-6s %-22s %-22s %5s %s",
             "Dir","Proto","Source","Destination","Bytes","Flags");
    attroff(A_DIM);

    int cnt  = (int)r->count;
    int head = (int)r->head;
    int show = cnt < 13 ? cnt : 13;
    int row  = 18;

    for (int i = show - 1; i >= 0 && row < rows - 2; i--, row++) {
        int idx = (head - i) & MON_RING_MASK;
        struct pkt_entry *e = &r->entries[idx];
        if (!e->seq && !e->ts_ns) continue;

        char src[24], dst[24];
        if (e->eth_proto == 0x0800) {
            e->sport ? snprintf(src, 24, "%s:%u", ip4(e->saddr,i1,20), e->sport)
                     : snprintf(src, 24, "%s",    ip4(e->saddr,i1,20));
            e->dport ? snprintf(dst, 24, "%s:%u", ip4(e->daddr,i2,20), e->dport)
                     : snprintf(dst, 24, "%s",    ip4(e->daddr,i2,20));
        } else if (e->eth_proto == 0x0806) {
            snprintf(src, 24, "ARP"); snprintf(dst, 24, "broadcast");
        } else {
            snprintf(src, 24, "0x%04x", e->eth_proto);
            snprintf(dst, 24, "-");
        }

        char fl[7] = "      ";
        if (e->ip_proto == 6) {
            if (e->tcp_flags & 0x02) fl[0]='S';
            if (e->tcp_flags & 0x10) fl[1]='A';
            if (e->tcp_flags & 0x01) fl[2]='F';
            if (e->tcp_flags & 0x04) fl[3]='R';
            if (e->tcp_flags & 0x08) fl[4]='P';
        }

        attron(COLOR_PAIR(e->direction=='T' ? 5 : 3));
        mvprintw(row, 2, "[%c]", e->direction);
        attroff(COLOR_PAIR(e->direction=='T' ? 5 : 3));
        mvprintw(row, 6, " %-6s %-22s %-22s %4uB %s",
            pname(e->ip_proto, e->dport), src, dst, e->len, fl);
    }

    /* Help */
    attron(COLOR_PAIR(2));
    mvprintw(rows-1, 0, "%-*s", cols,
        " [q]Thoat  [c]Xoa ring  [a]All  [t]TCP  [u]UDP  [i]ICMP"
        "  Refresh: 1s");
    attroff(COLOR_PAIR(2));

    refresh();
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(int argc, char *argv[])
{
    if (argc > 1) snprintf(g_iface, IFNAMSIZ, "%s", argv[1]);

    signal(SIGINT,  on_sig);
    signal(SIGTERM, on_sig);

    /* Mở socket */
    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sock < 0) {
        fprintf(stderr, "socket: %s — cần sudo!\n", strerror(errno));
        return 1;
    }

    /* Kiểm tra interface tồn tại */
    {
        struct ifreq chk;
        memset(&chk, 0, sizeof(chk));
        snprintf(chk.ifr_name, IFNAMSIZ, "%s", g_iface);
        if (ioctl(g_sock, SIOCGIFINDEX, &chk) < 0) {
            fprintf(stderr, "Interface '%s' không tồn tại: %s\n",
                    g_iface, strerror(errno));
            fprintf(stderr, "Cần: sudo ip link set %s up\n", g_iface);
            close(g_sock);
            return 1;
        }
    }

    /* Alloc ring trên heap (56KB) */
    struct aicsemi_ring_export  *ring = calloc(1, sizeof(*ring));
    struct aicsemi_stats_export  st;
    if (!ring) { perror("calloc"); close(g_sock); return 1; }

    /* Init ncurses */
    initscr();
    cbreak(); noecho();
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    curs_set(0);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_BLACK,   COLOR_CYAN);
        init_pair(2, COLOR_BLACK,   COLOR_WHITE);
        init_pair(3, COLOR_GREEN,   -1);
        init_pair(4, COLOR_RED,     -1);
        init_pair(5, COLOR_CYAN,    -1);
        init_pair(6, COLOR_YELLOW,  -1);
        init_pair(7, COLOR_MAGENTA, -1);
        init_pair(8, COLOR_WHITE,   -1);
        init_pair(9, COLOR_BLUE,    -1);
    }

    while (g_running) {
        /* Lấy data từ driver */
        memset(&st,   0, sizeof(st));
        memset(ring,  0, sizeof(*ring));

        int stats_ok = (get_stats(&st)   == 0);
        int ring_ok  = (get_ring(ring)   == 0);
        int ioctl_ok = stats_ok && ring_ok;

        /* Vẽ */
        clear();
        redraw(&st, ring, ioctl_ok);

        /* Xử lý phím */
        int ch = getch();
        switch (ch) {
        case 'q': case 'Q': g_running = 0;       break;
        case 'c': case 'C': do_clear();           break;
        case 'a': case 'A': do_setfilt(0);        break;
        case 't': case 'T': do_setfilt(6);        break;
        case 'u': case 'U': do_setfilt(17);       break;
        case 'i': case 'I': do_setfilt(1);        break;
        }

        napms(1000);
    }

    endwin();
    free(ring);
    close(g_sock);
    printf("\nMonitor thoát.\n");
    return 0;
}
