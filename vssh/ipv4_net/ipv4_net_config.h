#ifndef IPV4_NET_CONFIG_H_
#define IPV4_NET_CONFIG_H_

#define _GNU_SOURCE
#include <stdio.h>

// Log defines
#define _UDT_LOG_
#define _IPV4_UDT_LOG_
#define _IPV4_TCP_LOG_
#define _IPV4_LOG_

// UDT version
#define UDT_VERSION_MAJOR 0
#define UDT_VERSION_MINOR 2
#define UDT_VERSION       5

// UDT connection parameters (handshake)
#define UDT_N_MAX_ATTEMPTS_CONN   6 // attempts to connnect to server
#define UDT_SECONDS_TIMEOUT_CONN  2
#define UDT_USECONDS_TIMEOUT_CONN 0

// UDT server connection parameters (already connected)
// The maximum possible amount of time being unactive in connection -> disconnection
#define UDT_SECONDS_TIMEOUT_SERVER  180
#define UDT_USECONDS_TIMEOUT_SERVER 0

// UDT client connection parameters (already connected)
// The maximum possible amount of time being unactive in connection -> disconnection
#define UDT_SECONDS_TIMEOUT_CLIENT  180
#define UDT_USECONDS_TIMEOUT_CLIENT 0

// UDT send parameters (already connected)
// The maximum possible amount of time being unactive while sending -> disconnection
#define UDT_SECONDS_TIMEOUT_SEND  50
#define UDT_USECONDS_TIMEOUT_SEND 0
#define UDT_N_MAX_ATTEMPTS_SEND   3

// UDT read parameters (activate after first received packet)
// The maximum possible amount of time being unactive while receiving -> disconnection
#define UDT_SECONDS_TIMEOUT_READ  UDT_SECONDS_TIMEOUT_SEND  * UDT_N_MAX_ATTEMPTS_SEND
#define UDT_USECONDS_TIMEOUT_READ UDT_USECONDS_TIMEOUT_SEND * UDT_N_MAX_ATTEMPTS_SEND

// TCP parameters
#define TCP_N_MAX_PENDING_CONNECTIONS 1024

// General parameters
#define PACKET_DATA_SIZE BUFSIZ
#define N_MAX_FILENAME_LEN 1024

#endif // !IPV4_NET_CONFIG_H_
