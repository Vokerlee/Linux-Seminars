#ifndef SSH_CLIENT_H_
#define SSH_CLIENT_H_

#include "ipv4_net.h"
#include <syslog.h>
#include <signal.h>

#define SSH_SERVER_PORT 16161
#define SSH_BROADCAST_PORT 11199

#define SSH_SECONDS_TIMEOUT_BROADCAST  1
#define SSH_USECONDS_TIMEOUT_BROADCAST 0

int vssh_handle_arguments(int argc, char *argv[]);
int vssh_send_message    (in_addr_t dest_ip, const char *message, size_t len, int connection_type);
int vssh_send_broadcast  (in_addr_t dest_ip);

#endif // !SSH_CLIENT_H_
