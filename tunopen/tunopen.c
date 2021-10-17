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

    // doing it with rtentry didn't work because why would it
    sprintf(buf, "ip addr add 10.0.0.2/24 dev %s", name);
    system(buf);
    sprintf(buf, "ip link set %s up", name);
    system(buf);
    sprintf(buf, "ip route add default via 10.0.0.1");
    system(buf);
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

static void do_tun(int pid, const char* name, int socket_fd) {
    int tun, mtu;
    create_tun(pid, name, &tun, &mtu);
 
    send_tun_mtu(socket_fd, tun, mtu);
    close(socket_fd);
    close(tun);
}

static void do_wait(int pipe_fd, char* const* argv) {
    char buf[128];
    int r = read(pipe_fd, buf, sizeof buf);
    close(pipe_fd);
    execvp(argv[0], argv);
}

static void usage(const char* name) {
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "    %s tun  <pid> <tun name> <socket fd>\n", name);
    fprintf(stderr, "    %s wait <pipe fd> <target program> [args]\n", name);
    fflush(stderr);
    exit(1);
}

int main(int argc, char* argv[]) {
    if(argc <= 1) {
        usage(argv[0]);
    }
    if(strcmp(argv[1], "tun") == 0) {
        if(argc != 5) usage(argv[0]);
        do_tun(atoi(argv[2]), argv[3], atoi(argv[4]));
    } else if(strcmp(argv[1], "wait") == 0) {
        if(argc < 4) usage(argv[0]);
        do_wait(atoi(argv[2]), &argv[3]);
    } else {
        usage(argv[0]);
    }
}

