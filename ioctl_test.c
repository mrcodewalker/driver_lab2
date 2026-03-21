/*
 * ioctl_test.c — Test ioctl tới driver, in kết quả chi tiết
 * Build: gcc -o ioctl_test ioctl_test.c
 * Run:   sudo ./ioctl_test [interface]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#ifndef SIOCDEVPRIVATE
#define SIOCDEVPRIVATE  0x89F0
#endif
#define AICSEMI_IOC_CLEAR    (SIOCDEVPRIVATE + 0)
#define AICSEMI_IOC_GETRING  (SIOCDEVPRIVATE + 1)
#define AICSEMI_IOC_SETFILT  (SIOCDEVPRIVATE + 2)
#define AICSEMI_IOC_GETSTATS (SIOCDEVPRIVATE + 3)

struct aicsemi_stats_export {
    unsigned long long tx_total, tx_bytes, tx_dropped;
    unsigned long long rx_total, rx_bytes;
    unsigned long long tcp, udp, icmp, arp, ipv6, other;
    unsigned long long uptime_sec;
    char ifname[16], driver_ver[16];
};

int main(int argc, char *argv[])
{
    const char *iface = (argc > 1) ? argv[1] : "aic0";
    struct ifreq ifr;
    struct aicsemi_stats_export st;
    int sock, ret;

    printf("=== AIC Semi ioctl Test ===\n");
    printf("Interface: %s\n\n", iface);

    /* 1. Kiểm tra interface tồn tại */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);
    ret = ioctl(sock, SIOCGIFINDEX, &ifr);
    if (ret < 0) {
        printf("[FAIL] Interface '%s' không tồn tại: %s\n", iface, strerror(errno));
        printf("       Cần: sudo ip link set %s up\n", iface);
        return 1;
    }
    printf("[OK]  Interface '%s' tồn tại (ifindex=%d)\n",
           iface, ifr.ifr_ifindex);

    /* 2. Kiểm tra flags */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);
    ioctl(sock, SIOCGIFFLAGS, &ifr);
    printf("[OK]  Flags: 0x%04x (%s%s)\n",
           ifr.ifr_flags,
           (ifr.ifr_flags & IFF_UP) ? "UP " : "DOWN ",
           (ifr.ifr_flags & IFF_RUNNING) ? "RUNNING" : "");

    if (!(ifr.ifr_flags & IFF_UP)) {
        printf("[WARN] Interface chưa UP — ioctl có thể thất bại\n");
        printf("       Chạy: sudo ip link set %s up\n\n", iface);
    }

    /* 3. Test GETSTATS */
    printf("\n--- Test AICSEMI_IOC_GETSTATS (cmd=0x%08lx) ---\n",
           (unsigned long)AICSEMI_IOC_GETSTATS);
    memset(&ifr, 0, sizeof(ifr));
    memset(&st,  0, sizeof(st));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);
    ifr.ifr_data = (caddr_t)&st;

    ret = ioctl(sock, AICSEMI_IOC_GETSTATS, &ifr);
    if (ret == 0) {
        printf("[OK]  GETSTATS thành công!\n");
        printf("      tx_total=%llu  tx_bytes=%llu\n",
               st.tx_total, st.tx_bytes);
        printf("      rx_total=%llu  uptime=%llus\n",
               st.rx_total, st.uptime_sec);
        printf("      driver_ver='%s'  ifname='%s'\n",
               st.driver_ver, st.ifname);
    } else {
        printf("[FAIL] GETSTATS ret=%d errno=%d (%s)\n",
               ret, errno, strerror(errno));
        printf("\n  Nguyên nhân có thể:\n");
        if (errno == EOPNOTSUPP)
            printf("  → EOPNOTSUPP: driver không có ndo_siocdevprivate\n"
                   "    Cần rebuild usb.ko với code mới nhất\n");
        else if (errno == EPERM)
            printf("  → EPERM: cần sudo\n");
        else if (errno == ENODEV)
            printf("  → ENODEV: interface không tồn tại\n");
        else if (errno == EFAULT)
            printf("  → EFAULT: lỗi copy_to_user — driver bug\n");
        else if (errno == EINVAL)
            printf("  → EINVAL: cmd không hợp lệ\n");
    }

    /* 4. In IOC values để so sánh với kernel */
    printf("\n--- IOC command values (SIOCDEVPRIVATE range) ---\n");
    printf("  SIOCDEVPRIVATE = 0x%04x\n", SIOCDEVPRIVATE);
    printf("  CLEAR    = 0x%04x  (offset 0)\n", AICSEMI_IOC_CLEAR);
    printf("  GETRING  = 0x%04x  (offset 1)\n", AICSEMI_IOC_GETRING);
    printf("  SETFILT  = 0x%04x  (offset 2)\n", AICSEMI_IOC_SETFILT);
    printf("  GETSTATS = 0x%04x  (offset 3)\n", AICSEMI_IOC_GETSTATS);
    printf("\n  driver switch: cmd - SIOCDEVPRIVATE = 0,1,2,3\n");

    close(sock);
    return (ret == 0) ? 0 : 1;
}
