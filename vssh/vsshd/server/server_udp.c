#include "server.h"

void *udt_server_handler(void *connection_socket)
{
    int socket_fd = (int) connection_socket;
    
    ipv4_ctl_message ctl_message = {0};
    char message[PACKET_DATA_SIZE + 1] = {0};

    ipv4_udt_syslog(LOG_INFO, "is ready to work");

    while(1)
    {
        ssize_t recv_bytes = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ipv4_ctl_message), SOCK_STREAM_UDT);
        if (recv_bytes != -1 && recv_bytes != 0)
        {
            switch (ctl_message.message_type)
            {
                case IPV4_MSG_HEADER_TYPE:
                {
                    recv_bytes = ipv4_receive_message(socket_fd, message, ctl_message.message_length, SOCK_STREAM_UDT);
                    if (recv_bytes == -1 || recv_bytes == 0)
                        ipv4_udt_syslog(LOG_ERR, "couldn't receive message after getting msg header");

                    ipv4_udt_syslog(LOG_INFO, "get message:\n%s", message);

                    break;
                }
                    
                default:
                    break;
            }

            memset(message, 0, sizeof(message));
        }
    }

    void *retval = 0;
    pthread_exit(retval);
}

int launch_vssh_udp_server(in_addr_t ip)
{
    int socket_fd = ipv4_socket(SOCK_DGRAM, SO_REUSEADDR);
    if (socket_fd == -1)
    {
        ipv4_udt_syslog(LOG_ERR, "error while getting socket: %s", strerror(errno));
        ipv4_udt_syslog(LOG_ERR, "exit because of error");
        exit(EXIT_FAILURE);
    }

    int bind_state = ipv4_bind(socket_fd, ip, htons(SSH_SERVER_PORT), SOCK_STREAM_UDT, udt_server_handler);
    if (bind_state == -1)
    {
        ipv4_udt_syslog(LOG_ERR, "error while binding to socket");
        close(socket_fd);
        ipv4_udt_syslog(LOG_ERR, "exit because of error");
        exit(EXIT_FAILURE);
    }

    return -1; // unreachable
}
