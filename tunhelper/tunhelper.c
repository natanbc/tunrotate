#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
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

static void create_tun(int target_pid, const char* name, int* tun, int* netlink) {
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

    *netlink = check(socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE), "Unable to create netlink socket");
}

static void send_fds(int sock, int tun, int netlink) {
    struct iovec iov = {
        .iov_base = "1",
        .iov_len = 1,
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
        .cmsg_len = CMSG_LEN(sizeof(tun) + sizeof(netlink))
    };

    char* ptr = (char*)CMSG_DATA(cmsg);
    memcpy(ptr, &tun, sizeof(tun));
    ptr += sizeof(tun);
    memcpy(ptr, &netlink, sizeof(netlink));

    check(sendmsg(sock, &msg, 0), "Unable to send fd/mtu pair");
}

static void do_tun(int pid, const char* name, int socket_fd) {
    int tun, netlink;
    create_tun(pid, name, &tun, &netlink);
 
    send_fds(socket_fd, tun, netlink);
    close(socket_fd);
    close(tun);
    close(netlink);
}

static void write_str(int fd, const char* str, const char* err) {
    int len = strlen(str);
    if(check(write(fd, str, len), err) != len) check(-1, err);
}

static void map_id(const char* path, int from, int to) {
    int fd = check(open(path, O_WRONLY), "Failed to open file for mapping ids");

    char buf[128];
    sprintf(buf, "%d %d 1", from, to);
    write_str(fd, buf, "Failed to write id map");

    close(fd);
}

static void setgroups_deny() {
    int fd = check(open("/proc/self/setgroups", O_WRONLY), "Failed to open setgroups");
    write_str(fd, "deny", "Failed to write to setgroups");
    close(fd);
}

static void do_unshare(int unshared_fd, int wait_fd, char* const* argv) {
    uid_t real_euid = geteuid();
    gid_t real_egid = getegid();

    check(unshare(CLONE_NEWUSER | CLONE_NEWNET), "Failed to unshare");

    map_id("/proc/self/uid_map", 0, real_euid);
    setgroups_deny();
    map_id("/proc/self/gid_map", 0, real_egid);

    check(write(unshared_fd, "ok\n", 3), "Failed to write to unshared pipe");
    close(unshared_fd);

    char buf[128];
    int r = check(read(wait_fd, buf, sizeof buf), "Failed to read from wait pipe");
    if(r == 0) {
        fprintf(stderr, "Empty read from wait pipe, assuming setup failed\n");
        exit(1);
    }
    close(wait_fd);

    execvp(argv[0], argv);
}

static void usage(const char* name) {
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "    %s tun     <pid> <tun name> <socket fd>\n", name);
    fprintf(stderr, "    %s unshare <unshare fd> <wait fd> <target program> [args]\n", name);
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
    } else if(strcmp(argv[1], "unshare") == 0) {
        if(argc < 4) usage(argv[0]);
        do_unshare(atoi(argv[2]), atoi(argv[3]), &argv[4]);
    } else {
        usage(argv[0]);
    }
}

