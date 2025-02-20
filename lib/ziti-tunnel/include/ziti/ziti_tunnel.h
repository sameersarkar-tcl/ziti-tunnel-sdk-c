/*
 Copyright 2021 NetFoundry Inc.

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

/**
 * @file ziti_tunneler.h
 * @brief Defines the macros, functions, typedefs and constants required to implement a Ziti
 * tunneler application.
 */

#ifndef ZITI_TUNNELER_SDK_ZITI_TUNNEL_H
#define ZITI_TUNNELER_SDK_ZITI_TUNNEL_H

#include <stdbool.h>
#include "uv.h"
#include "sys/queue.h"
#include "ziti/netif_driver.h"
#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

/** keys used in app_data model map */
extern const char *DST_PROTO_KEY; // "dst_protocol"
extern const char *DST_IP_KEY;    // "dst_ip"
extern const char *DST_PORT_KEY;  // "dst_port"
extern const char *DST_HOST_KEY;  // "dst_hostname"
extern const char *SRC_PROTO_KEY; // "src_protocol"
extern const char *SRC_IP_KEY;    // "src_ip"
extern const char *SRC_PORT_KEY;  // "src_port"
extern const char *SOURCE_IP_KEY; // "source_ip"

typedef struct tunneler_ctx_s *tunneler_context;
typedef struct tunneler_io_ctx_s *tunneler_io_context;
const char * get_intercepted_address(const struct tunneler_io_ctx_s * tnlr_io);
const char * get_client_address(const struct tunneler_io_ctx_s * tnlr_io);
typedef struct hosted_io_ctx_s *hosted_io_context;
typedef struct hosted_service_ctx_s host_ctx_t;
typedef struct io_ctx_s io_ctx_t;

typedef void (*tunnel_logger_f)(int level, const char *module, const char *file, unsigned int line, const char *func, const char *fmt, ...);

typedef enum {
    CLIENT_CFG_V1,    // ziti-tunnel-client.v1
    SERVER_CFG_V1,    // ziti-tunnel-server.v1
    INTERCEPT_CFG_V1, // intercept.v1
    HOST_CFG_V1       // host.v1
} cfg_type_e;

typedef struct protocol_s {
    char *protocol;
    STAILQ_ENTRY(protocol_s) entries;
} protocol_t;
typedef STAILQ_HEAD(protocol_list_s, protocol_s) protocol_list_t;

// xxx.xxx.xxx.xxx/xx
#define MAX_IP_OR_CIDR 20

typedef struct address_s {
    char       str[MAX_IP_OR_CIDR]; // ip || ip/prefix
    ip_addr_t  ip;
    ip_addr_t  _netmask;
    uint8_t    prefix_len;
#ifdef OPENWRT
    bool       is_hostname;
#endif    
    STAILQ_ENTRY(address_s) entries;
} address_t;
typedef STAILQ_HEAD(address_list_s, address_s) address_list_t;

typedef struct port_range_s {
    int low;
    int high;
    char str[16]; // [123456-123456]
    STAILQ_ENTRY(port_range_s) entries;
} port_range_t;
typedef STAILQ_HEAD(port_range_list_s, port_range_s) port_range_list_t;

/**
 * called when a client connection is intercepted.
 * implementations are expected to dial the service and return
 * context that will be passed to ziti_read/ziti_write */
typedef void * (*ziti_sdk_dial_cb)(const void *app_intercept_ctx, io_ctx_t *io);
typedef int (*ziti_sdk_close_cb)(void *ziti_io_ctx);
typedef ssize_t (*ziti_sdk_write_cb)(const void *ziti_io_ctx, void *write_ctx, const void *data, size_t len);
typedef host_ctx_t * (*ziti_sdk_host_cb)(void *ziti_ctx, uv_loop_t *loop, const char *service_name, cfg_type_e cfg_type, const void *cfg);

/** data needed to intercept packets and dial the associated ziti service */
typedef struct intercept_ctx_s  intercept_ctx_t;
typedef bool (*intercept_match_addr_fn)(ip_addr_t *addr, void *app_intercept_ctx);

extern intercept_ctx_t* intercept_ctx_new(tunneler_context tnlt_ctx, const char *app_id, void *app_intercept_ctx);
/** parse address string as hostname|ip|cidr and add result to list of intercepted addresses */
#ifdef OPENWRT
extern address_t *intercept_ctx_add_address(intercept_ctx_t *i_ctx, const char *address, const char *intercept_name);
#else
extern address_t *intercept_ctx_add_address(intercept_ctx_t *i_ctx, const char *address);
#endif
extern void intercept_ctx_set_match_addr(intercept_ctx_t *intercept, intercept_match_addr_fn pred);
extern void intercept_ctx_add_protocol(intercept_ctx_t *ctx, const char *protocol);
extern port_range_t *intercept_ctx_add_port_range(intercept_ctx_t *i_ctx, uint16_t low, uint16_t high);
extern void intercept_ctx_override_cbs(intercept_ctx_t *i_ctx, ziti_sdk_dial_cb dial, ziti_sdk_write_cb write, ziti_sdk_close_cb close_write, ziti_sdk_close_cb close);

struct io_ctx_s {
    tunneler_io_context   tnlr_io;
    void *                ziti_io; // context specific to ziti SDK being used by the app.
    const void *          ziti_ctx;
    ziti_sdk_write_cb     write_fn;
    ziti_sdk_close_cb     close_write_fn;
    ziti_sdk_close_cb     close_fn;
};

struct io_ctx_list_entry_s {
    struct io_ctx_s *io;
    SLIST_ENTRY(io_ctx_list_entry_s) entries;
};
SLIST_HEAD(io_ctx_list_s, io_ctx_list_entry_s);




typedef struct tunneler_sdk_options_s {
    netif_driver   netif_driver;
    ziti_sdk_dial_cb    ziti_dial;
    ziti_sdk_close_cb   ziti_close;
    ziti_sdk_close_cb   ziti_close_write;
    ziti_sdk_write_cb   ziti_write;
    ziti_sdk_host_cb    ziti_host;
} tunneler_sdk_options;

#ifdef OPENWRT

typedef struct dns_manager_s dns_manager;

typedef int (*dns_fallback_cb)(const char *name, void *ctx, struct in_addr* addr);

typedef void (*dns_answer_cb)(uint8_t *a_packet, size_t a_len, void *ctx);
typedef int (*dns_query)(dns_manager *dns, const uint8_t *q_packet, size_t q_len, dns_answer_cb cb, void *ctx);

struct dns_manager_s {
    bool internal_dns;
    uint32_t dns_ip;
    uint16_t dns_port;

    int (*apply)(dns_manager *dns, const char *host, const char *ip);
    int (*remove)(dns_manager *dns, const char *host);
    dns_query query;

    uv_loop_t *loop;
    dns_fallback_cb fb_cb;
    void *fb_ctx;
    void *data;
};

// fallback will be called on the worker thread to avoid blocking event loop
extern dns_manager *get_tunneler_dns(uv_loop_t *l, uint32_t dns_ip, dns_fallback_cb cb, void *ctx);

#endif

#ifdef OPENWRT
    extern address_t *parse_address(const char *hn_or_ip_or_cidr, const char *intercept_name, dns_manager *dns);
    extern void ziti_remove_dnsmasq_iproute(struct tunneler_ctx_s *tnlr, const char *intercept_name, const char *ipaddr);
#else
    extern address_t *parse_address(const char *ip_or_cidr);
#endif

extern port_range_t *parse_port_range(uint16_t low, uint16_t high);

extern bool protocol_match(const char *protocol, const protocol_list_t *protocols);
extern bool address_match(const ip_addr_t *addr, const address_list_t *addresses);
extern bool port_match(int port, const port_range_list_t *port_ranges);

extern tunneler_context ziti_tunneler_init(tunneler_sdk_options *opts, uv_loop_t *loop);
extern tunneler_context ziti_tunneler_init_host_only(tunneler_sdk_options *opts, uv_loop_t *loop);

extern void ziti_tunneler_exclude_route(tunneler_context tnlr_ctx, const char* dst);

/** called by tunneler application when it is done with a tunneler_context.
 * calls `stop_intercepting` for each intercepted service. */
extern void ziti_tunneler_shutdown(tunneler_context tnlr_ctx);

extern int ziti_tunneler_intercept(tunneler_context tnlr_ctx, intercept_ctx_t *i_ctx);

extern host_ctx_t * ziti_tunneler_host(tunneler_context tnlr_ctx, const void *ziti_ctx, const char *service_name, cfg_type_e cfg_type, void *cfg);

extern void ziti_tunneler_stop_intercepting(tunneler_context tnlr_ctx, void *zi_ctx);

extern intercept_ctx_t * ziti_tunnel_find_intercept(tunneler_context tnlr_ctx, void *zi_ctx);

extern void ziti_tunneler_set_idle_timeout(struct io_ctx_s *io_context, unsigned int timeout);

extern void ziti_tunneler_dial_completed(struct io_ctx_s *io_context, bool ok);

extern ssize_t ziti_tunneler_write(tunneler_io_context tnlr_io_ctx, const void *data, size_t len);

struct write_ctx_s;
extern void ziti_tunneler_ack(struct write_ctx_s *write_ctx);

extern int ziti_tunneler_close(tunneler_io_context tnlr_io_ctx);

extern int ziti_tunneler_close_write(tunneler_io_context tnlr_io_ctx);

extern const char* ziti_tunneler_version();

extern const char* ziti_tunneler_build_date();

#ifdef OPENWRT
extern void ziti_tunneler_init_dns(uint32_t mask, int bits);
extern void ziti_tunneler_set_dns(tunneler_context tnlr_ctx, dns_manager *dns);
#endif

extern void ziti_tunnel_set_logger(tunnel_logger_f logger);
extern void ziti_tunnel_set_log_level(int lvl);

typedef void (*ziti_tunnel_async_fn)(uv_loop_t *loop, void *ctx);
extern void ziti_tunnel_async_send(tunneler_context tctx, ziti_tunnel_async_fn f, void *arg);

#ifdef __cplusplus
}
#endif

#endif /* ZITI_TUNNELER_SDK_ZITI_TUNNEL_H */