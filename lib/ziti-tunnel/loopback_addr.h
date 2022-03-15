#ifndef ZITI_TUNNEL_SDK_C_LOCAL_ADDR_H
#define ZITI_TUNNEL_SDK_C_LOCAL_ADDR_H

extern void loopback_init(void);
extern int loopback_add_address(const char *addr);
extern int loopback_delete_address(const char *addr);

#endif //ZITI_TUNNEL_SDK_C_LOCAL_ADDR_H
