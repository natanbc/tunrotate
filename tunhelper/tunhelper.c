#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <sched.h>
#include <stdalign.h>
#include <stdbool.h>
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

static void enter_namespace(int target_pid) {
    char buf[64];
    
    sprintf(buf, "/proc/%d/ns/user", target_pid);
    int userns = check(open(buf, O_RDONLY), "Unable to open target userns");

    sprintf(buf, "/proc/%d/ns/net", target_pid);
    int netns = check(open(buf, O_RDONLY), "Unable to open target netns");

    check(setns(userns, CLONE_NEWUSER), "Unable to enter target userns");
    close(userns);

    check(setns(netns, CLONE_NEWNET), "Unable to enter target netns");
    close(netns);
}

static int create_tun(const char* name) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    size_t name_len = strlen(name);
    if(name_len > sizeof(ifr.ifr_name)) {
        fprintf(stderr, "tun device name (%s) exceeds max name length (%zu)\n", name, sizeof(ifr.ifr_name));
        fflush(stderr);
        exit(1);
    }
    memcpy(ifr.ifr_name, name, name_len);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

    int tun = check(open("/dev/net/tun", O_RDWR), "Unable to open /dev/net/tun");
    check(ioctl(tun, TUNSETIFF, &ifr), "Unable to set ifr");

    return tun;
}

static void send_fds(int sock, int* tun_fds, int tun_count, int netlink) {
    struct iovec iov = {
        .iov_base = "1",
        .iov_len = 1,
    };

    size_t fd_size = sizeof(int) * (tun_count + 1);
    size_t buf_size = CMSG_SPACE(fd_size);
    char* buf = aligned_alloc(alignof(struct cmsghdr), buf_size);
    if(!buf) check(-1, "Failed to allocate SCM_RIGHTS file descriptor buffer");

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = buf,
        .msg_controllen = buf_size
    };

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    *cmsg = (struct cmsghdr) {
        .cmsg_level = SOL_SOCKET,
        .cmsg_type = SCM_RIGHTS,
        .cmsg_len = CMSG_LEN(fd_size)
    };

    int* ptr = (int*)CMSG_DATA(cmsg);
    memcpy(ptr, tun_fds, sizeof(int) * tun_count);
    ptr[tun_count] = netlink;

    check(sendmsg(sock, &msg, 0), "Unable to send file descriptors");
    free(buf);
}

static void do_tun(int pid, const char* name, int socket_fd, int queues) {
    int* tun_fds = malloc(sizeof(int) * queues);
    if(tun_fds == NULL) check(-1, "Failed to allocate queues");

    enter_namespace(pid);
    for(int i = 0; i < queues; i++) {
        tun_fds[i] = create_tun(name);
    }

    int netlink = check(socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE), "Unable to create netlink socket");
 
    send_fds(socket_fd, tun_fds, queues, netlink);

    close(netlink);
    for(int i = 0; i < queues; i++) close(tun_fds[i]);
    free(tun_fds);
    close(socket_fd);
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

// https://github.com/rootless-containers/slirp4netns/pull/133
static void adjust_rmem() {
    FILE* f = fopen("/proc/sys/net/ipv4/tcp_rmem", "r");
    check(f == NULL ? -1 : 0, "Failed to open tcp_rmem for reading");

    size_t min, def, max;
    if(fscanf(f, "%zu %zu %zu", &min, &def, &max) != 3) {
        check(-1, "Failed to parse tcp_rmem");
    }
    fclose(f);

    if(def <= 87380) return;
    def = 87380;

    f = fopen("/proc/sys/net/ipv4/tcp_rmem", "w");
    check(f == NULL ? -1 : 0, "Failed to open tcp_rmem for writing");

    if(fprintf(f, "%zu %zu %zu\n", min, def, max) < 0) {
        check(-1, "Failed to write to tcp_rmem");
    }
    fclose(f);
}

static void do_unshare(bool same_user, int unshared_fd, int wait_fd, char* const* argv) {
    uid_t real_euid = geteuid();
    gid_t real_egid = getegid();

    check(unshare(CLONE_NEWUSER | CLONE_NEWNET), "Failed to unshare");

    map_id("/proc/self/uid_map", same_user ? real_euid : 0, real_euid);
    setgroups_deny();
    map_id("/proc/self/gid_map", same_user ? real_egid : 0, real_egid);

    check(write(unshared_fd, "ok\n", 3), "Failed to write to unshared pipe");
    close(unshared_fd);

    adjust_rmem();

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
    fprintf(stderr, "    %s tun     <pid> <tun name> <socket fd> <number of queues>\n", name);
    fprintf(stderr, "    %s unshare <same user> <unshare fd> <wait fd> <target program> [args]\n", name);
    fflush(stderr);
    exit(1);
}

int main(int argc, char* argv[]) {
    if(argc <= 1) {
        usage(argv[0]);
    }
    if(strcmp(argv[1], "tun") == 0) {
        if(argc != 6) usage(argv[0]);
        do_tun(atoi(argv[2]), argv[3], atoi(argv[4]), atoi(argv[5]));
    } else if(strcmp(argv[1], "unshare") == 0) {
        if(argc < 5) usage(argv[0]);
        do_unshare(!strcmp(argv[2], "true"), atoi(argv[3]), atoi(argv[4]), &argv[5]);
    } else {
        usage(argv[0]);
    }
}

