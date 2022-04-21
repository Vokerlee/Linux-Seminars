#include "server.h"

void *tcp_server_handler(void *connection_socket)
{
    int socket_fd = (int) connection_socket;

    ipv4_ctl_message ctl_message = {0};
    char message[PACKET_DATA_SIZE + 1] = {0};

    ipv4_tcp_syslog(LOG_INFO, "new thread is ready to work");

    while(1)
    {
        ssize_t recv_bytes = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ipv4_ctl_message), SOCK_STREAM);
        if (recv_bytes != -1 && recv_bytes != 0)
        {
            switch (ctl_message.message_type)
            {
                case IPV4_SHUTDOWN_TYPE: // only in TCP
                {
                    ipv4_tcp_syslog(LOG_NOTICE, "successfully finish job and exit");

                    void *retval = 0;
                    pthread_exit(retval);
                }
                    
                case IPV4_MSG_HEADER_TYPE:
                {
                    recv_bytes = ipv4_receive_message(socket_fd, message, ctl_message.message_length, SOCK_STREAM);
                    if (recv_bytes == -1 || recv_bytes == 0)
                        ipv4_tcp_syslog(LOG_ERR, "couldn't receive message after getting msg header");

                    ipv4_tcp_syslog(LOG_INFO, "get message:\n%s", message);

                    break;
                }

                case IPV4_SHELL_REQUEST_TYPE:
                {
                    ipv4_tcp_syslog(LOG_INFO, "get shell request");
                    handle_terminal_request(socket_fd, SOCK_STREAM);

                    break;
                }

                case IPV4_USERS_LIST_REQUEST_TYPE:
                {
                    ipv4_tcp_syslog(LOG_INFO, "get users list request");
                    handle_users_list_request(socket_fd, SOCK_STREAM);
                    
                    break;
                }
                    
                default:
                    break;
            }

            memset(message, 0, sizeof(message));
        }
        else
            ipv4_tcp_syslog(LOG_ERR, "error while receiving requests");
    }

    void *retval = 0;
    pthread_exit(retval);
}

int launch_vssh_tcp_server(in_addr_t ip)
{
    int socket_fd = ipv4_socket(SOCK_STREAM, SO_REUSEADDR);
    if (socket_fd == -1)
    {
        ipv4_tcp_syslog(LOG_ERR, "error while getting socket: %s", strerror(errno));
        ipv4_tcp_syslog(LOG_ERR, "exit because of error");
        exit(EXIT_FAILURE);
    }
        
    int bind_state = ipv4_bind(socket_fd, ip, htons(SSH_SERVER_PORT), SOCK_STREAM, NULL);
    if (bind_state == -1)
    {
        ipv4_tcp_syslog(LOG_ERR, "error while binding to socket: %s", strerror(errno));
        close(socket_fd);
        ipv4_tcp_syslog(LOG_ERR, "exit because of error");
        exit(EXIT_FAILURE);
    }

    // Listening on
    int listen_state = ipv4_listen(socket_fd);
    if (listen_state == -1)
    {
        ipv4_tcp_syslog(LOG_ERR, "error while listening to socket: %s", strerror(errno));
        close(socket_fd);
        ipv4_tcp_syslog(LOG_ERR, "exit because of error");
        exit(EXIT_FAILURE);
    }

    // Accept connections
    while(1)
    {
        struct sockaddr_in accept_addr = {0};
        socklen_t length = sizeof(struct sockaddr_in);

        int accepted_socket_fd = ipv4_accept(socket_fd, (struct sockaddr *) &accept_addr, &length);
        if (accepted_socket_fd == -1)
        {
            ipv4_tcp_syslog(LOG_ERR, "error in accept(): %s", strerror(errno));
            continue;
        }

        ipv4_tcp_syslog(LOG_NOTICE, "new connection: IP = %s, port = %d!\n", 
                        inet_ntoa(accept_addr.sin_addr), (int) ntohs(accept_addr.sin_port));

        pthread_t new_thread = {0};
        int pthread_error = pthread_create(&new_thread, NULL, tcp_server_handler, (void *) accepted_socket_fd);
        if (pthread_error == -1)
        {
            ipv4_tcp_syslog(LOG_ERR, "error in pthread_create(): %s", strerror(errno));
            ipv4_tcp_syslog(LOG_ERR, "cannot connnect with client because of pthread_create() error");
            continue;
        }

        pthread_error = pthread_detach(new_thread);
        if (pthread_error == -1)
            ipv4_tcp_syslog(LOG_WARNING, "error in pthread_detach(): %s", strerror(errno));
    }	

    return 0;
}
