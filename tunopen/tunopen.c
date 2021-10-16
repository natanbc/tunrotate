#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static int check(int v, const char* msg) {
    if(v == -1) {
        fprintf(stderr, "%s: %s\n", msg, strerror(errno));
        fflush(stderr);
        exit(1);
    }
    return v;
}

static void create_tun(int target_pid, const char* name, int* tun, int* mtu) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    size_t name_len = strlen(name);
    if(name_len > sizeof(ifr.ifr_name)) {
        fprintf(stderr, "tun device name (%s) exceeds max name length (%zu)\n", name, sizeof(ifr.ifr_name));
        fflush(stderr);
        exit(1);
    }
    memcpy(ifr.ifr_name, name, name_len);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    char buf[64];
    
    sprintf(buf, "/proc/%d/ns/user", target_pid);
    int userns = check(open(buf, O_RDONLY), "Unable to open target userns");

    sprintf(buf, "/proc/%d/ns/net", target_pid);
    int netns = check(open(buf, O_RDONLY), "Unable to open target netns");

    check(setns(userns, CLONE_NEWUSER), "Unable to enter target userns");
    close(userns);

    check(setns(netns, CLONE_NEWNET), "Unable to enter target netns");
    close(netns);

    *tun = check(open("/dev/net/tun", O_RDWR), "Unable to open /dev/net/tun");
    check(ioctl(*tun, TUNSETIFF, &ifr), "Unable to set ifr");

    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    check(ioctl(sock, SIOCGIFMTU, &ifr), "Unable to get mtu");
    close(sock);
    *mtu = ifr.ifr_mtu;
}

static int connect_parent(const char* socket_path) {
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    size_t path_len = strlen(socket_path);
    if(path_len > sizeof(addr.sun_path)) {
        fprintf(stderr, "unix socket path (%s) exceeds max path length (%zu)\n", socket_path, sizeof(addr.sun_path));
        fflush(stderr);
        exit(1);
    }
    memcpy(addr.sun_path, socket_path, path_len);

    int sock = check(socket(AF_UNIX, SOCK_STREAM, 0), "Unable to create unix socket");
    check(connect(sock, (struct sockaddr*) &addr, sizeof(addr)), "Unable to connect to unix socket");
    return sock;
}

static void send_tun_mtu(int sock, int tun, int mtu) {
    struct iovec iov = {
        .iov_base = &mtu,
        .iov_len = sizeof(mtu),
    };

    union {
        char buf[CMSG_SPACE(sizeof(tun))];
        struct cmsghdr align;
    } u;

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = u.buf,
        .msg_controllen = sizeof(u.buf)
    };

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    *cmsg = (struct cmsghdr) {
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = SCM_RIGHTS,
        .cmsg_len = CMSG_LEN(sizeof(tun))
    };

    memcpy(CMSG_DATA(cmsg), &tun, sizeof(tun));
    check(sendmsg(sock, &msg, 0), "Unable to send fd/mtu pair");
}

int main(int argc, char* argv[]) {
    if(argc != 4) {
        fprintf(stderr, "usage: %s <pid> <tun name> <path to unix socket>\n", argv[0]);
        fflush(stderr);
        return 1;
    }
    int sock = connect_parent(argv[3]);

    int pid = atoi(argv[1]);
    int tun, mtu;
    create_tun(pid, argv[2], &tun, &mtu);
 
    send_tun_mtu(sock, tun, mtu);
    close(sock);
    close(tun);
}
