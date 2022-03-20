#ifndef SSH_CLIENT_H_
#define SSH_CLIENT_H_

#include "ipv4_net.h"
#include "ipv4_net_config.h"
#include "udt_api.h"
#include <syslog.h>
#include <signal.h>

#define SSH_SERVER_PORT 16161

int vssh_handle_arguments(int argc, char *argv[]);
int vssh_send_message(in_addr_t dest_ip, const char *message, size_t len, int connection_type);

#endif // !SSH_CLIENT_H_
