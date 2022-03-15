#include "loopback_addr.h"

#define LOCAL_ADDRESS_LIFETIME 30
#define LOCAL_ADDRESS_REFRESH (LOCAL_ADDRESS_LIFETIME - (LOCAL_ADDRESS_LIFETIME/10))

#ifdef _WIN32
#include <windows.h>
#include "uv.h"

struct addr_add_ctx_s {
    HANDLE notify_event;
    HANDLE complete_event;
    SOCKADDR_INET addr;
};

// called when IP addresses are changed on the local system
static void CALLBACK on_address_change(PVOID callerContext, PMIB_UNICASTIPADDRESS_ROW row, MIB_NOTIFICATION_TYPE notificationType) {
    ZITI_LOG(VERBOSE, "notificationType %d", notificationType);

    if (row == NULL) {
        ZITI_LOG(VERBOSE, "null row");
        return;
    }

    if (callerContext == NULL) {
        ZITI_LOG(VERBOSE, "null caller context");
        return;
    }
    struct addr_add_ctx_s *ctx = callerContext;

    if (notificationType == MibAddInstance) {
        // check that address matches the one that was added
        if (row->Address.si_family == AF_INET &&
            row->Address.Ipv4.sin_addr.S_un.S_addr == ctx->addr.Ipv4.sin_addr.S_un.S_addr) {
            ZITI_LOG(DEBUG, "added address matches");
            SetEvent(ctx->complete_event);
        }
        if (row->Address.si_family == AF_INET6) {
            ZITI_LOG(VERBOSE, "ipv6 not handled");
        }
    }
}

static void refresh_local_addresses(uv_timer_t *timer);
static uv_timer local_address_timer;

void loopback_init(void) {
    uv_timer_init(uv_default_loop(), &local_address_timer);
    local_address_timer.data = tun;
    uv_unref((uv_handle_t *) &local_address_timer);
    uv_timer_start(&local_address_timer, refresh_local_addresses,
                   LOCAL_ADDRESS_REFRESH*1000, LOCAL_ADDRESS_REFRESH*1000);
}

int loopback_add_address(netif_handle tun, const char *addr) {
    PMIB_IPINTERFACE_TABLE ip_table = NULL;
    PMIB_UNICASTIPADDRESS_ROW addr_row = NULL;
    NET_LUID loopback_luid;

    unsigned long status = GetIpInterfaceTable( AF_INET, &ip_table );
    if (status != NO_ERROR) {
        ZITI_LOG(ERROR, "unable to find loopback device: GetIpInterfaceTable returned error %ld", status);
        return 1;
    }
    loopback_luid = ip_table->Table[0].InterfaceLuid;
    FreeMibTable(ip_table);
    ip_table = NULL;

    address_t *a = parse_address(addr);
    if (a == NULL) {
        ZITI_LOG(ERROR, "failed to parse address %s", addr);
        return 1;
    }

    addr_row = calloc(1, sizeof(MIB_UNICASTIPADDRESS_ROW));
    InitializeUnicastIpAddressEntry(addr_row);
    addr_row->InterfaceLuid = loopback_luid;
    addr_row->ValidLifetime = LOCAL_ADDRESS_LIFETIME;
    addr_row->PreferredLifetime = LOCAL_ADDRESS_LIFETIME;

    if (IP_IS_V4(&a->ip)) {
        addr_row->Address.Ipv4.sin_family = AF_INET;
        addr_row->Address.Ipv4.sin_addr.S_un.S_addr = ip_addr_get_ip4_u32(&a->ip);
        addr_row->OnLinkPrefixLength = a->prefix_len;
#if 0
    } else if (IP_IS_V6(&a->ip)) {
        addr_row->Address.Ipv6.sin6_family = AF_INET6;
        addr_row->Address.Ipv6.sin6_addr.u.Word = a->ip.u_addr.ip6.addr;
#endif
    } else {
        ZITI_LOG(ERROR, "unexpected IP address type %d", IP_GET_TYPE(&a->ip));
        free(a);
        free(addr_row);
        return 1;
    }
    free(a);

    struct addr_add_ctx_s *ctx = calloc(1, sizeof(struct addr_add_ctx_s));
    ctx->complete_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ctx->complete_event == NULL) {
        ZITI_LOG(ERROR, "CreateEvent failed: %s", GetLastError());
        free(ctx);
        return 1;
    }
    memcpy(&ctx->addr, &addr_row->Address, sizeof(ctx->addr));

    NotifyUnicastIpAddressChange(AF_INET, &on_address_change, ctx, FALSE, &ctx->notify_event);

    status = CreateUnicastIpAddressEntry(addr_row);
    ZITI_LOG(INFO, "CreateUnicastIpAddress e=%d", status);
    if (status != NO_ERROR && status != ERROR_OBJECT_ALREADY_EXISTS) {
        ZITI_LOG(ERROR, "failed to create local address %s: %d", addr, status);
        CancelMibChangeNotify2(ctx->notify_event);
        free(ctx);
        return 1;
    }

    // wait for address to be added.
    ZITI_LOG(DEBUG, "waiting for ip add to complete");
    status = WaitForSingleObject(ctx->complete_event, 3000);
    ZITI_LOG(DEBUG, "wait status=%d", status);
    CancelMibChangeNotify2(ctx->notify_event);
    CloseHandle(ctx->complete_event);
    free(ctx);

    if (status == WAIT_OBJECT_0) {
        ZITI_LOG(DEBUG, "successfully added %s to loopback interface", addr);
    } else {
        ZITI_LOG(ERROR, "wait for address %s failed: %d", addr, status);
        return 1;
    }

    model_map_set(&tun->local_addresses, addr, addr_row);
    return 0;
}

int loopback_del_address(netif_handle tun, const char *addr) {
    ZITI_LOG(DEBUG, "removing local address %s", addr);
    PMIB_UNICASTIPADDRESS_ROW addr_row = model_map_remove(&tun->local_addresses, addr);
    if (addr_row == NULL) {
        ZITI_LOG(VERBOSE, "no map entry existed for local address %s", addr);
        return 0;
    }

    unsigned long s = DeleteUnicastIpAddressEntry(addr_row);
    free(addr_row);
    if (s != NO_ERROR) {
        ZITI_LOG(ERROR, "failed to remove local address %s: %d", addr, s);
        return 1;
    }

    return 0;
}

void refresh_local_addresses(uv_timer_t *timer) {
    ZITI_LOG(DEBUG, "refreshing local addresses");
    struct netif_handle_s *tun = timer->data;
    const char *addr;
    MIB_UNICASTIPADDRESS_ROW *addr_row;
    MODEL_MAP_FOREACH(addr, addr_row, &tun->local_addresses) {
        ZITI_LOG(DEBUG, "refreshing local address %s", addr);
        unsigned long s = SetUnicastIpAddressEntry(addr_row);
        if (s != NO_ERROR) {
            ZITI_LOG(ERROR, "failed to reset local address %s: %d", addr, s);
        }
    }
}

#elif __linux__
#include <stdio.h>
#include <stdlib.h>

void loopback_init(void) {
}

int loopback_add_address(const char *addr) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ip address add %s/32 dev lo valid_lft forever preferred_lft forever", addr);
    int s = system(cmd);
    return s;
}

int loopback_delete_address(const char *addr) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ip address del %s/32 dev lo", addr);
    return -1;
}
#elif __MACH__ && __APPLE__
#include <stdio.h>
#include <stdlib.h>

void loopback_init(void) {
}

int loopback_add_address(const char *addr) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ifconfig %s alias %s/32", "lo0", addr);
    int s = system(cmd);
    return s;
}

int loopback_delete_address(const char *addr) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ifconfig %s -alias %s", "lo0", addr);
    return -1;
}
#endif