#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/kern_event.h>
#include <sys/uio.h>

#include "utun.h"

int utun_close(struct netif_handle_s *tun) {
    int r = 0;

    if (tun == NULL) {
        return 0;
    }

    if (tun->fd > 0) {
        r = close(tun->fd);
    }

    free(tun);
    return r;
}

static inline ssize_t utun_data_len(ssize_t len) {
    if (len > 0) {
        return (len > sizeof(u_int32_t)) ? len - sizeof(u_int32_t) : 0;
    } else {
        return len;
    }
}

ssize_t utun_read(netif_handle tun, void *buf, size_t len) {
    u_int32_t type;
    struct iovec iv[2];

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = buf;
    iv[1].iov_len = len;

    return utun_data_len(readv(tun->fd, iv, 2));
}

ssize_t utun_write(netif_handle tun, const void *buf, size_t len) {
    u_int32_t type;
    struct iovec iv[2];
    struct ip *iph = (struct ip *)buf;

    if (iph->ip_v == 6) {
        type = htonl(AF_INET6);
    } else {
        type = htonl(AF_INET);
    }

    iv[0].iov_base = &type;
    iv[0].iov_len = sizeof(type);
    iv[1].iov_base = (void *)buf;
    iv[1].iov_len = len;

    return utun_data_len(writev(tun->fd, iv, 2));
}

uv_poll_t *utun_uv_poll_init(netif_handle tun, uv_loop_t *loop) {
    uv_poll_t *tun_poll_req = malloc(sizeof(uv_poll_t));
    if (uv_poll_init(loop, tun_poll_req, tun->fd) != 0) {
        return NULL;
    }
    return tun_poll_req;
}

/**
 * open a utun device
 * @param num populated with the unit number of the utun device that was opened
 * @return file descriptor to opened utun
 *
 * set up interface address and routes:
 * - ifconfig utun2 169.254.1.2/32 169.254.1.2
 * - route add -host 2.2.2.2 -interface utun2
 * - route add -host 1.2.3.4 -interface utun2
 */
netif_driver utun_open(char *error, size_t error_len) {
    if (error != NULL) {
        memset(error, 0, error_len * sizeof(char));
    }

    struct netif_handle_s *tun = malloc(sizeof(struct netif_handle_s));
    if (tun == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate utun_ctx_s");
        }
        return NULL;
    }

    struct sockaddr_ctl addr;

    if ((tun->fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) < 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to create control socket: %s", strerror(errno));
        }
        utun_close(tun);
        return NULL;
    }

    struct ctl_info info;
    memset(&info, 0, sizeof (info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, strlen(UTUN_CONTROL_NAME));
    if (ioctl(tun->fd, CTLIOCGINFO, &info) == -1) {
        if (error != NULL) {
            snprintf(error, error_len, "ioctl(CTLIOCGINFO) failed: %s", strerror(errno));
        }
        utun_close(tun);
        return NULL;
    }

    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0; // use first available unit

    if (connect(tun->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to open utun device: %s", strerror(errno));
        }
        utun_close(tun);
        return NULL;
    }

    struct ifreq ifname_req;
    socklen_t ifname_req_size = sizeof(ifname_req);
    if (getsockopt(tun->fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, &ifname_req, &ifname_req_size) == -1) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to get ifname: %s", strerror(errno));
            utun_close(tun);
            return NULL;
        }
    }
    strncpy(tun->name, ifname_req.ifr_name, sizeof(tun->name));

    struct netif_driver_s *dev = malloc(sizeof(struct netif_driver_s));
    if (dev == NULL) {
        if (error != NULL) {
            snprintf(error, error_len, "failed to allocate netif_device_s");
            utun_close(tun);
        }
        return NULL;
    }

    dev->handle       = tun;
    dev->read         = utun_read;
    dev->write        = utun_write;
    dev->uv_poll_init = utun_uv_poll_init;
    dev->close        = utun_close;

    return dev;
}