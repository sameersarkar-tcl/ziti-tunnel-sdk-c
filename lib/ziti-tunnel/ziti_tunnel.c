/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// something wrong with lwip_xxxx byteorder functions
#ifdef _WIN32
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

#ifndef strcasecmp
#define strcasecmp(a,b) stricmp(a,b)
#endif
#endif

#if defined(__mips) || defined(__mips__)
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#endif

#include "lwip/init.h"
#include "lwip/raw.h"
#include "lwip/timeouts.h"
#include "netif_shim.h"
#include "ziti/ziti_tunnel.h"
#include "ziti_tunnel_priv.h"
#include "tunnel_tcp.h"
#include "tunnel_udp.h"
#include "uv.h"
#include "loopback_addr.h"

#include <string.h>

const char *DST_PROTO_KEY = "dst_protocol";
const char *DST_IP_KEY = "dst_ip";
const char *DST_PORT_KEY = "dst_port";
const char *DST_HOST_KEY = "dst_hostname";
const char *SRC_PROTO_KEY = "src_protocol";
const char *SRC_IP_KEY = "src_ip";
const char *SRC_PORT_KEY = "src_port";
const char *SOURCE_IP_KEY = "source_ip";

struct resolve_req {
    ip_addr_t addr;
    u16_t port;
    tunneler_context tnlr_ctx;
};

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx);

STAILQ_HEAD(tlnr_ctx_list_s, tunneler_ctx_s) tnlr_ctx_list_head = STAILQ_HEAD_INITIALIZER(tnlr_ctx_list_head);

tunneler_context ziti_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop) {
    TNL_LOG(INFO, "Ziti Tunneler SDK (%s)", ziti_tunneler_version());

    if (opts == NULL) {
        TNL_LOG(ERR, "invalid tunneler options");
        return NULL;
    }

    struct tunneler_ctx_s *ctx = calloc(1, sizeof(struct tunneler_ctx_s));
    if (ctx == NULL) {
        TNL_LOG(ERR, "failed to allocate tunneler context");
        return NULL;
    }
    ctx->loop = loop;
    memcpy(&ctx->opts, opts, sizeof(ctx->opts));
    LIST_INIT(&ctx->intercepts);
    LIST_INIT(&ctx->client_ips);
    loopback_init();
    run_packet_loop(loop, ctx);

    return ctx;
}

#if _WIN32
#define close_socket(s) closesocket((s))
#define SOCKET_ERRNO WSAGetLastError()
#else
#define SOCKET int
#define SOCKET_ERROR (-1)
#define SOCKET_ERRNO (errno)
#define close_socket(s) close((s))
#endif

struct rawsock_forwarder {
    SOCKET sock;
    uv_poll_t watcher;
    char *ip;
    tunneler_context tnlr;
};

static void free_rawsock_forwarder(struct rawsock_forwarder *fwd) {
    if (fwd == NULL) return;
    if (fwd->sock > 0) { // struct is initialized with 0, which means the protocol/address are not intercepted
        int e = close_socket(fwd->sock);
        if (e == SOCKET_ERROR) {
            TNL_LOG(WARN, "failed to close raw socket for %s: err=%d", fwd->ip, SOCKET_ERRNO);
        }
    }
    uv_poll_stop(&fwd->watcher);
    free(fwd->ip);
    free(fwd);
}

static void forward_packet(uv_poll_t* watcher, int status, int revents) {
    struct rawsock_forwarder *fwd = watcher->data;
    if (status != 0) {
        TNL_LOG(ERR, "error reading from raw socket watcher %s: %d", fwd->ip, status);
        return;
    }

    if (revents & UV_READABLE) {
        char buf[16384]; // todo size to mtu
        TNL_LOG(TRACE, "got readable event on raw socket!");
        ssize_t n = recvfrom(fwd->sock, buf, sizeof(buf), 0, NULL, 0);
        if (n < 0) {
            TNL_LOG(ERR, "error reading from raw socket %s: err=%d", fwd->ip, SOCKET_ERRNO);
            return;
        }
        // todo fix packet checksum
        TNL_LOG(INFO, "calling on_packet");
        on_packet(buf, n, &fwd->tnlr->netif);
    }
}

static struct rawsock_forwarder *create_rawsock_forwarder(tunneler_context tnlr, const char *proto, address_t *local_addr) {
    int proto_id = get_protocol_id(proto);
    SOCKET sock = socket(AF_INET, SOCK_RAW, proto_id);
    if (sock == SOCKET_ERROR) {
        TNL_LOG(ERR, "failed to create raw %s socket for %s: err=%d", proto, local_addr->str, SOCKET_ERRNO);
        return NULL;
    }

    struct sockaddr_in ip = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = ip_addr_get_ip4_u32(&local_addr->ip),
            .sin_port = 0,
    };
#if 0
    // on 0.15 bind fails with EADDRNOTAVAIL unless a very log delay is added here.
    // the netsh output shows that the address is in fact assigned to the interface
    // when the bind fails (this is not surprising, since we waited for the ip notification
    //uv_sleep(5000);
    FILE *p = _popen("netsh interface ipv4 show ipaddresses", "rt");
    if (p != NULL) {
        char b[512];
        while (fgets(b, sizeof(b), p) != NULL) {
            TNL_LOG(INFO, "netsh output: '%s'", b);
        }
        if (feof(p)) {
            TNL_LOG(INFO, "netsh exited %d", _pclose(p));
        } else {
            TNL_LOG(ERR, "netsh failed");
        }
    } else {
        TNL_LOG(ERR, "popen failed");
    }
#endif
    int e = bind(sock, (struct sockaddr *) &ip, sizeof(ip));
    if (e == -1) {
        TNL_LOG(ERR, "failed to bind raw %s socket to %s: err=%d", proto, local_addr->str, SOCKET_ERRNO);
        close_socket(sock);
        return NULL;
    }

    struct rawsock_forwarder *fwd = calloc(1, sizeof(struct rawsock_forwarder));
    if (fwd == NULL) {
        TNL_LOG(ERR, "failed to allocate rawsock_forwarder for %s", local_addr->str);
        close_socket(sock);
        return NULL;
    }

    fwd->sock = sock;
    fwd->tnlr = tnlr;
    fwd->ip = strdup(local_addr->str);

    e = uv_poll_init_socket(tnlr->loop, &fwd->watcher, sock);
    if (e != 0) {
        TNL_LOG(ERR, "up_poll_init_socket failed: err=%d", e);
        close_socket(sock);
        free(fwd);
        return NULL;
    }

    fwd->watcher.data = fwd;
    e = uv_poll_start(&fwd->watcher, UV_READABLE, forward_packet);
    if (e != 0) {
        TNL_LOG(ERR, "failed to start poll watcher for %s: err=%d", local_addr->str, e);
        close_socket(sock);
        free(fwd);
        return NULL;
    }

    return fwd;
}

/** create raw socket forwarders to intercept traffic for any IPs that we are spoofing.
 * returns number of forwarders created, or -1 on error */
int create_rawsock_forwarders(tunneler_context tnlr, const char *ip) {
    // Adding the IP as a local address will supersede the route that sends packets to our tun interface,
    // resulting in the kernel/OS dispatching packets that we want to intercept.
    // Intercept packets to this IP with a raw socket while the local address is assigned.

    address_t *local_addr = parse_address(ip, NULL);
    if (local_addr == NULL) {
        TNL_LOG(ERR, "failed to parse address %s", ip);
        return -1;
    }

    int num_forwarders = 0;
    intercept_ctx_t *intercept;
    LIST_FOREACH(intercept, &tnlr->intercepts, entries) {
        TNL_LOG(INFO, "checking if spoofed ip %s is intercepted for service[%s]", ip, intercept->service_name);
        if (address_match(&local_addr->ip, &intercept->addresses)) {
            TNL_LOG(INFO, "ip %s needs to be intercepted for service[%s]", ip, intercept->service_name);
            protocol_t *proto;
            STAILQ_FOREACH(proto, &intercept->protocols, entries) {
                TNL_LOG(INFO, "creating raw %s socket to intercept spoofed ip %s", proto->protocol, ip);
                if (create_rawsock_forwarder(tnlr, proto->protocol, local_addr) == NULL) {
                    // todo clean up any forwarders that were created. attach forwarders to intercept context?
                    return -1;
                }
                num_forwarders++;
            }
        }
    }

    return num_forwarders;
}

int ziti_tunneler_add_local_address(tunneler_context tnlr_ctx, const char *addr) {
    TNL_LOG(DEBUG, "addr='%s'", addr);
    struct client_ip_entry_s *entry;
    LIST_FOREACH(entry, &tnlr_ctx->client_ips, _next) {
        TNL_LOG(DEBUG, "comparing %s %s", addr, entry->ip);
        if (strcmp(addr, entry->ip) == 0) {
            TNL_LOG(INFO, "incrementing reference count for local address %s", addr);
            entry->count++;
            return 0;
        }
    }
    int s = loopback_add_address(addr);
    if (s != 0) {
        TNL_LOG(ERR, "add_local_address failed: e = %d", s);
        return s;
    }

    /* the tunneler may need to intercept this ip, but packets to it won't be dispatched to the tun
     * device because the ip is now a local address (which is necessary for spoofing).
     * create raw sockets to sniff packets to this ip */
    create_rawsock_forwarders(tnlr_ctx, addr);

    entry = calloc(1, sizeof(struct client_ip_entry_s));
    strncpy(entry->ip, addr, sizeof(entry->ip));
    entry->count = 1;
    LIST_INSERT_HEAD(&tnlr_ctx->client_ips, entry, _next);

    return 0;
}

int ziti_tunneler_delete_local_address(tunneler_context tnlr_ctx, const char *addr) {
    TNL_LOG(DEBUG, "addr='%s'", addr);
    struct client_ip_entry_s *entry;
    LIST_FOREACH(entry, &tnlr_ctx->client_ips, _next) {
        TNL_LOG(DEBUG, "comparing %s %s", addr, entry->ip);
        if (strcmp(addr, entry->ip) == 0) {
            TNL_LOG(INFO, "decrementing reference count for local address %s", addr);
            entry->count--;
            break;
        }
    }
    if (entry != NULL && entry->count == 0) {
        return loopback_delete_address(addr);
    }
    return 0;
}

static void tunneler_kill_active(const void *ztx, const char *service_name);

void ziti_tunneler_shutdown(tunneler_context tnlr_ctx) {
    TNL_LOG(DEBUG, "tnlr_ctx %p", tnlr_ctx);

    while (!LIST_EMPTY(&tnlr_ctx->intercepts)) {
        intercept_ctx_t *i = LIST_FIRST(&tnlr_ctx->intercepts);
        tunneler_kill_active(i->ziti_ctx, i->service_name);
        LIST_REMOVE(i, entries);
    }
}

/** called by tunneler application when data has been successfully written to ziti */
void ziti_tunneler_ack(struct write_ctx_s *write_ctx) {
    write_ctx->ack(write_ctx);
}

const char *get_intercepted_address(const struct tunneler_io_ctx_s * tnlr_io) {
    if (tnlr_io == NULL) {
        return NULL;
    }
    return tnlr_io->intercepted;
}

const char *get_client_address(const struct tunneler_io_ctx_s * tnlr_io) {
    if (tnlr_io == NULL) {
        return NULL;
    }
    return tnlr_io->client;
}

void free_tunneler_io_context(tunneler_io_context *tnlr_io_ctx_p) {
    if (tnlr_io_ctx_p == NULL) {
        return;
    }

    if (*tnlr_io_ctx_p != NULL) {
        free((*tnlr_io_ctx_p)->service_name);
        free(*tnlr_io_ctx_p);
        *tnlr_io_ctx_p = NULL;
    }
}

/**
 * called by tunneler application when a service dial has completed
 * - let the client know that we have a connection (e.g. send SYN/ACK)
 */
void ziti_tunneler_dial_completed(struct io_ctx_s *io, bool ok) {
    if (io == NULL) {
        TNL_LOG(ERR, "null io");
        return;
    }
    if (io->ziti_io == NULL || io->tnlr_io == NULL) {
        TNL_LOG(ERR, "null ziti_io or tnlr_io");
    }
    const char *status = ok ? "succeeded" : "failed";
    TNL_LOG(INFO, "ziti dial %s: service=%s, client=%s", status, io->tnlr_io->service_name, io->tnlr_io->client);

    switch (io->tnlr_io->proto) {
        case tun_tcp:
            tunneler_tcp_dial_completed(io, ok);
            break;
        case tun_udp:
            tunneler_udp_dial_completed(io, ok);
            break;
        default:
            TNL_LOG(ERR, "unknown proto %d", io->tnlr_io->proto);
            break;
    }
}

host_ctx_t *ziti_tunneler_host(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, cfg_type_e cfg_type, void *config) {
    host_ctx_t *h = tnlr_ctx->opts.ziti_host((void *) ziti_ctx, tnlr_ctx, tnlr_ctx->loop, service_name, cfg_type, config);
    return h;
}

static void send_dns_resp(uint8_t *resp, size_t resp_len, void *ctx) {
    struct resolve_req *rreq = ctx;

    TNL_LOG(TRACE, "sending DNS resp[%zd] -> %s:%d", resp_len, ipaddr_ntoa(&rreq->addr), rreq->port);
    struct pbuf *rp = pbuf_alloc(PBUF_TRANSPORT, resp_len, PBUF_RAM);
    memcpy(rp->payload, resp, resp_len);

    err_t err = udp_sendto_if_src(rreq->tnlr_ctx->dns_pcb, rp, &rreq->addr, rreq->port,
                                  netif_default, &rreq->tnlr_ctx->dns_pcb->local_ip);
    if (err != ERR_OK) {
        TNL_LOG(WARN, "udp_send() DNS response: %d", err);
    }

    pbuf_free(rp);
    free(rreq);
}

static void on_dns_packet(void *arg, struct udp_pcb *pcb, struct pbuf *p,
    const ip_addr_t *addr, u16_t port) {
    tunneler_context tnlr_ctx = arg;

    struct resolve_req *rr = calloc(1,sizeof(struct resolve_req));
    rr->addr = *addr;
    rr->port = port;
    rr->tnlr_ctx = tnlr_ctx;

    int rc = tnlr_ctx->dns->query(tnlr_ctx->dns, p->payload, p->len, send_dns_resp, rr);
    if (rc != 0) {
        TNL_LOG(WARN, "DNS resolve error: %d", rc);
        free(rr);
    }
    pbuf_free(p);
}

void ziti_tunneler_set_dns(tunneler_context tnlr_ctx, dns_manager *dns) {
    tnlr_ctx->dns = dns;
    if (dns->internal_dns) {
        tnlr_ctx->dns_pcb = udp_new();
        ip_addr_t dns_addr = {
                .type = IPADDR_TYPE_V4,
                .u_addr.ip4.addr = dns->dns_ip,
        };
        udp_bind(tnlr_ctx->dns_pcb, &dns_addr, dns->dns_port);
        udp_recv(tnlr_ctx->dns_pcb, on_dns_packet, tnlr_ctx);
    }
}

int get_protocol_id(const char *protocol) {
    if (strcasecmp(protocol, "tcp") == 0) {
        return IPPROTO_TCP;
    } else if (strcasecmp(protocol, "udp") == 0) {
        return IPPROTO_UDP;
    }
    return -1;
}

const char *get_protocol_str(int protocol_id) {
    switch (protocol_id) {
        case IPPROTO_TCP:
            return "tcp";
        case IPPROTO_UDP:
            return "udp";
        default:
            return "NUL";
    }
}

void intercept_ctx_add_protocol(intercept_ctx_t *ctx, const char *protocol) {
    protocol_t *proto = calloc(1, sizeof(protocol_t));
    proto->protocol = strdup(protocol);
    STAILQ_INSERT_TAIL(&ctx->protocols, proto, entries);
}

address_t *parse_address(const char *hn_or_ip_or_cidr, dns_manager *dns) {
    address_t *addr = calloc(1, sizeof(address_t));
    strncpy(addr->str, hn_or_ip_or_cidr, sizeof(addr->str));
    addr->is_hostname = false;
    char *prefix_sep = strchr(addr->str, '/');

    if (prefix_sep != NULL) {
        *prefix_sep = '\0';
        addr->prefix_len = (int)strtol(prefix_sep + 1, NULL, 10);
    }

    if (ipaddr_aton(addr->str, &addr->ip) == 0) {
        // does not parse as IP address; assume hostname and try to get IP from the dns manager
        if (dns) {
            const char *resolved_ip_str = assign_ip(addr->str);
            if (dns->apply(dns, addr->str, resolved_ip_str) != 0) {
                TNL_LOG(ERR, "failed to apply DNS mapping %s => %s", addr->str, resolved_ip_str);
                free(addr);
                return NULL;
            } else {
                TNL_LOG(DEBUG, "intercept hostname %s is not an ip", addr->str);
                if (ipaddr_aton(resolved_ip_str, &addr->ip) == 0) {
                    TNL_LOG(ERR, "dns manager provided unparsable ip address '%s'", resolved_ip_str);
                    free(addr);
                    return NULL;
                } else {
                    addr->is_hostname = true;
                }
            }
        }
    }

    uint8_t addr_bits = IP_IS_V4(&addr->ip) ? 32 : 128;
    uint8_t net_bits = addr_bits - addr->prefix_len;

    if (prefix_sep != NULL) {
        // update ip (and str) with masked address - host bits zeroed
        if (addr->ip.type == IPADDR_TYPE_V4) {
            ip_addr_set_ip4_u32(&addr->_netmask, PP_HTONL(IPADDR_BROADCAST >> net_bits << net_bits));
            ip_addr_set_ip4_u32(&addr->ip, ip_2_ip4(&addr->ip)->addr & ip_2_ip4(&addr->_netmask)->addr);
        } else if (addr->ip.type == IPADDR_TYPE_V6) {
            TNL_LOG(ERR, "IPv6 CIDR intercept is not currently supported");
        }
        snprintf(addr->str, sizeof(addr->str), "%s/%d", ipaddr_ntoa(&addr->ip), addr->prefix_len);
    } else {
        // use full ip
        addr->prefix_len = addr_bits;
    }

    return addr;
}

address_t *intercept_ctx_add_address(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx, const char *address) {
    address_t *addr = parse_address(address, tnlr_ctx->dns);

    if (addr == NULL) {
        TNL_LOG(ERR, "failed to parse address '%s' service[%s]", address, i_ctx->service_name);
        return NULL;
    }

    STAILQ_INSERT_TAIL(&i_ctx->addresses, addr, entries);
    return addr;
}

port_range_t *parse_port_range(uint16_t low, uint16_t high) {
    port_range_t *pr = calloc(1, sizeof(port_range_t));
    if (low <= high) {
        pr->low = low;
        pr->high = high;
    } else {
        pr->low = high;
        pr->high = low;
    }

    if (low == high) {
        snprintf(pr->str, sizeof(pr->str), "%d", low);
    } else {
        snprintf(pr->str, sizeof(pr->str), "[%d-%d]", low, high);
    }
    return pr;
}

port_range_t *intercept_ctx_add_port_range(intercept_ctx_t *i_ctx, uint16_t low, uint16_t high) {
    port_range_t *pr = parse_port_range(low, high);
    STAILQ_INSERT_TAIL(&i_ctx->port_ranges, pr, entries);
    return pr;
}

/** intercept a service as described by the intercept_ctx */
int ziti_tunneler_intercept(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx) {
    if (tnlr_ctx == NULL) {
        TNL_LOG(ERR, "null tnlr_ctx");
        return -1;
    }

    address_t *address;
    STAILQ_FOREACH(address, &i_ctx->addresses, entries) {
        protocol_t *proto;
        STAILQ_FOREACH(proto, &i_ctx->protocols, entries) {
            port_range_t *pr;
            STAILQ_FOREACH(pr, &i_ctx->port_ranges, entries) {
                // todo find conflicts with services
                // intercept_ctx_t *match;
                // match = lookup_intercept_by_address(tnlr_ctx, proto->protocol, &address->ip, pr->low, pr->high);
                TNL_LOG(DEBUG, "intercepting address[%s:%s:%s] service[%s]",
                        proto->protocol, address->str, pr->str, i_ctx->service_name);
            }
        }
    }

    STAILQ_FOREACH(address, &i_ctx->addresses, entries) {
         add_route(tnlr_ctx->opts.netif_driver, address);
    }

    LIST_INSERT_HEAD(&tnlr_ctx->intercepts, (struct intercept_ctx_s *)i_ctx, entries);

    return 0;
}

static void tunneler_kill_active(const void *ztx, const char *service_name) {
    struct io_ctx_list_s *l;
    ziti_sdk_close_cb zclose;

    l = tunneler_tcp_active(ztx, service_name);
    while (!SLIST_EMPTY(l)) {
        struct io_ctx_list_entry_s *n = SLIST_FIRST(l);
        TNL_LOG(DEBUG, "service[%s] client[%s] killing active connection", service_name, n->io->tnlr_io->client);
        // close the ziti connection, which also closes the underlay
        zclose = n->io->tnlr_io->tnlr_ctx->opts.ziti_close;
        if (zclose) zclose(n->io->ziti_io);
        SLIST_REMOVE_HEAD(l, entries);
        free(n);
    }
    free(l);

    // todo be selective about protocols when merging newer config types
    l = tunneler_udp_active(ztx, service_name);
    while (!SLIST_EMPTY(l)) {
        struct io_ctx_list_entry_s *n = SLIST_FIRST(l);
        TNL_LOG(DEBUG, "service[%s] client[%s] killing active connection", service_name, n->io->tnlr_io->client);
        // close the ziti connection, which also closes the underlay
        zclose = n->io->tnlr_io->tnlr_ctx->opts.ziti_close;
        if (zclose) zclose(n->io->ziti_io);
        SLIST_REMOVE_HEAD(l, entries);
        free(n);
    }
    free(l);
}

intercept_ctx_t * ziti_tunnel_find_intercept(tunneler_context tnlr_ctx, void *ziti_ctx, const char *service_name) {
    struct intercept_ctx_s *intercept;
    if (tnlr_ctx == NULL) {
        TNL_LOG(WARN, "null tnlr_ctx");
        return NULL;
    }

    LIST_FOREACH(intercept, &tnlr_ctx->intercepts, entries) {
        if (strcmp(intercept->service_name, service_name) == 0 &&
            intercept->ziti_ctx == ziti_ctx) {
            return intercept;
        }
    }

    return NULL;
}


// when called due to service unavailable we want to remove from tnlr_ctx.
// when called due to conflict we want to mark as disabled
void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, void *ziti_ctx, const char *service_name) {
    TNL_LOG(DEBUG, "removing intercept for service %s", service_name);
    struct intercept_ctx_s *intercept = ziti_tunnel_find_intercept(tnlr_ctx, ziti_ctx, service_name);

    if (intercept != NULL) {
        tunneler_kill_active(ziti_ctx, service_name);

        LIST_REMOVE(intercept, entries);
        free_intercept(intercept);
    }
}

/** called by tunneler application when data is read from a ziti connection */
ssize_t ziti_tunneler_write(tunneler_io_context tnlr_io_ctx, const void *data, size_t len) {
    if (tnlr_io_ctx == NULL) {
        TNL_LOG(WARN, "null tunneler io context");
        return -1;
    }

    ssize_t r;
    switch (tnlr_io_ctx->proto) {
        case tun_tcp:
            r = tunneler_tcp_write(tnlr_io_ctx->tcp, data, len);
            break;
        case tun_udp:
            r = tunneler_udp_write(tnlr_io_ctx->udp.pcb, data, len);
            break;
    }

    return r;
}

/** called by tunneler application when a ziti connection closes */
int ziti_tunneler_close(tunneler_io_context tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL) {
        TNL_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    TNL_LOG(INFO, "closing connection: service=%s, client=%s",
            tnlr_io_ctx->service_name, tnlr_io_ctx->client);
    switch (tnlr_io_ctx->proto) {
        case tun_tcp:
            tunneler_tcp_close(tnlr_io_ctx->tcp);
            tnlr_io_ctx->tcp = NULL;
            break;
        case tun_udp:
            tunneler_udp_close(tnlr_io_ctx->udp.pcb);
            tnlr_io_ctx->udp.pcb = NULL;
            break;
        default:
            TNL_LOG(ERR, "unknown proto %d", tnlr_io_ctx->proto);
            break;
    }

    free(tnlr_io_ctx);
    return 0;
}

/** called by tunneler application when an EOF is received from ziti */
int ziti_tunneler_close_write(tunneler_io_context tnlr_io_ctx) {
    if (tnlr_io_ctx == NULL) {
        TNL_LOG(INFO, "null tnlr_io_ctx");
        return 0;
    }
    TNL_LOG(INFO, "closing write connection: service=%s, client=%s",
            tnlr_io_ctx->service_name, tnlr_io_ctx->client);
    switch (tnlr_io_ctx->proto) {
        case tun_tcp:
            tunneler_tcp_close_write(tnlr_io_ctx->tcp);
            break;
        default:
            TNL_LOG(DEBUG, "not sending FIN on %d connection", tnlr_io_ctx->proto);
            break;
    }
    return 0;
}

static void on_tun_data(uv_poll_t * req, int status, int events) {
    if (status != 0) {
        TNL_LOG(WARN, "not sure why status is %d", status);
        return;
    }

    if (events & UV_READABLE) {
        netif_shim_input(netif_default);
    }
}

static void check_lwip_timeouts(uv_timer_t * handle) {
    sys_check_timeouts();
}

/**
 * set up a protocol handler. lwip will call recv_fn with arg for each
 * packet that matches the protocol.
 */
static struct raw_pcb * init_protocol_handler(u8_t proto, raw_recv_fn recv_fn, void *arg) {
    struct raw_pcb *pcb;
    err_t err;

    if ((pcb = raw_new_ip_type(IPADDR_TYPE_ANY, proto)) == NULL) {
        TNL_LOG(ERR, "failed to allocate raw pcb for protocol %d", proto);
        return NULL;
    }

    if ((err = raw_bind(pcb, IP_ANY_TYPE)) != ERR_OK) {
        TNL_LOG(ERR, "failed to bind for protocol %d: error %d", proto, err);
        raw_remove(pcb);
        return NULL;
    }

    raw_bind_netif(pcb, netif_default);
    raw_recv(pcb, recv_fn, arg);

    return pcb;
}

static void run_packet_loop(uv_loop_t *loop, tunneler_context tnlr_ctx) {
    tunneler_sdk_options opts = tnlr_ctx->opts;
    if (opts.ziti_close == NULL || opts.ziti_close_write == NULL ||  opts.ziti_write == NULL ||
        opts.ziti_dial == NULL || opts.ziti_host == NULL) {
        TNL_LOG(ERR, "ziti_sdk_* callback options cannot be null");
        exit(1);
    }

    lwip_init();

    netif_driver netif_driver = opts.netif_driver;
    if (netif_add_noaddr(&tnlr_ctx->netif, netif_driver, netif_shim_init, ip_input) == NULL) {
        TNL_LOG(ERR, "netif_add failed");
        exit(1);
    }

    netif_set_default(&tnlr_ctx->netif);
    netif_set_link_up(&tnlr_ctx->netif);
    netif_set_up(&tnlr_ctx->netif);

    if (netif_driver->setup) {
        netif_driver->setup(netif_driver->handle, loop, on_packet, netif_default);
    } else if (netif_driver->uv_poll_init) {
        netif_driver->uv_poll_init(netif_driver->handle, loop, &tnlr_ctx->netif_poll_req);
        if (uv_poll_start(&tnlr_ctx->netif_poll_req, UV_READABLE, on_tun_data) != 0) {
            TNL_LOG(ERR, "failed to start tun poll handle");
            exit(1);
        }
    } else {
        TNL_LOG(WARN, "no method to initiate tunnel reader, maybe it's ok");
    }

    if ((tnlr_ctx->tcp = init_protocol_handler(IP_PROTO_TCP, recv_tcp, tnlr_ctx)) == NULL) {
        TNL_LOG(ERR, "tcp setup failed");
        exit(1);
    }
    if ((tnlr_ctx->udp = init_protocol_handler(IP_PROTO_UDP, recv_udp, tnlr_ctx)) == NULL) {
        TNL_LOG(ERR, "udp setup failed");
        exit(1);
    }

    uv_timer_init(loop, &tnlr_ctx->lwip_timer_req);
    uv_timer_start(&tnlr_ctx->lwip_timer_req, check_lwip_timeouts, 0, 10);
}

#define _str(x) #x
#define str(x) _str(x)
const char* ziti_tunneler_version() {
    return str(GIT_VERSION);
}