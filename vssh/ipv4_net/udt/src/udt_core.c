#include "udt_core.h"
#include "udt_packet.h"
#include "udt_buffer.h"
#include "udt_utils.h"

#define _GNU_SOURCE
#include <unistd.h>

udt_conn_t connection = {0};

pthread_mutex_t handshake_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  handshake_cond  = PTHREAD_COND_INITIALIZER;

extern udt_buffer_t RECV_BUFFER;
extern udt_buffer_t SEND_BUFFER;

int udt_startup()
{
    return udt_send_buffer_init() || udt_recv_buffer_init();
}

void udt_handshake_init()
{
    udt_packet_t packet;
    size_t n_attempts_to_connect = UDT_N_MAX_ATTEMPTS_CONN;

    while (connection.is_connected == 0 && n_attempts_to_connect > 0)
    {
        pthread_mutex_lock(&handshake_mutex);

        udt_packet_new_handshake(&packet);
        udt_send_packet_buffer_write(&packet);

        pthread_cond_wait(&handshake_cond, &handshake_mutex);
        pthread_mutex_unlock(&handshake_mutex);

        pthread_mutex_init(&handshake_mutex, NULL);
        pthread_cond_init (&handshake_cond,  NULL);

        n_attempts_to_connect--;
    }
}

void udt_handshake_terminate()
{
    connection.is_connected = 1;
}

void udt_connection_close()
{
    udt_packet_t packet;

    packet_clear_header(packet);
    packet_set_ctrl    (packet);
    packet_set_type    (packet, PACKET_TYPE_SHUTDOWN);

    udt_packet_new(&packet, NULL, 0);
    udt_send_packet_buffer_write(&packet);
}

void udt_prepare_to_fork()
{
    if (connection.is_main_server != 1)
        return;

    pthread_mutex_init(&handshake_mutex, NULL);
    pthread_cond_init (&handshake_cond,  NULL);

    pthread_cond_signal(&SEND_BUFFER.cond);
    pthread_mutex_init(&SEND_BUFFER.mutex, NULL);
    pthread_cond_init (&SEND_BUFFER.cond,  NULL);
}

void udt_child_after_fork()
{
    if (connection.is_main_server != 1)
        return;

    connection.is_main_server = 0;
    memset(&connection.last_addr, 0, sizeof(connection.last_addr));
    connection.last_packet_number = 0;

    close(connection.socket_fd);

    connection.recv_thread = pthread_self();
    pthread_create(&connection.send_thread, NULL, udt_sender_start, (void *) &connection);

    pthread_t server_thread;
    pthread_create(&server_thread, NULL, connection.server_handler, (void *) &connection.socket_fd);
}

void *udt_sender_start(void *arg)
{
    int old_type = 0;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);

    udt_syslog(LOG_INFO, "sender-thread is ready to send packets");

    udt_packet_t packet;

    while (udt_send_packet_buffer_read(&packet))
    {
        ssize_t n_sent_bytes = sendto(connection.socket_fd, &packet, sizeof(udt_packet_t), 0,
                                      (struct sockaddr *) &(connection.addr), sizeof(struct sockaddr));
        if (n_sent_bytes == -1)
            udt_syslog(LOG_ERR, "sendto() error: %s", strerror(errno));

        memset(&packet, 0, sizeof(udt_packet_t));
    }

    void *retval = 0;
    pthread_exit(retval);
}

void *udt_receiver_start(void *arg)
{
    int old_type = 0;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);

    udt_syslog(LOG_INFO, "receiver-thread is ready to receive packets");

    udt_packet_t packet;
    memset(&packet, 0, sizeof(udt_packet_t));

    while (1)
    {
        int recv_error = recvfrom(connection.socket_fd, &packet, sizeof(udt_packet_t), 0,
                                  (struct sockaddr *) &(connection.last_addr), &(connection.addrlen));

        if (recv_error == -1 && errno == EAGAIN)
        {
            if (connection.is_in_wait == 1) // send packet
            {
                connection.no_ack = 1;
                connection.is_in_wait = 0;
            }
            else if (connection.is_connected == 1) // already connected
            {
                connection.is_connected = 0;
                connection.is_in_wait   = 0;
                connection.addr.sin_addr.s_addr = 0;
                udt_syslog(LOG_NOTICE, "disconnection has occured from client: IP = %s, port = %d", 
                           inet_ntoa(connection.addr.sin_addr), (int) ntohs(connection.addr.sin_port));

                pthread_cond_signal(&(RECV_BUFFER.cond));

                struct timeval tv = {.tv_sec = 0, .tv_usec = 0};    
                setsockopt(connection.socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));

                if (connection.is_client == 0)
                {
                    udt_syslog(LOG_NOTICE, "exit because of disconnection");
                    exit(EXIT_FAILURE);
                }
            }
            else // process of connection (client)
                pthread_cond_signal(&handshake_cond);

            errno = 0;
            continue;
        }
        else if (recv_error == -1)
        {
            udt_syslog(LOG_ERR, "recvfrom() error: %s", strerror(errno));
            continue;
        }

        udt_syslog(LOG_INFO, "message from IP = %s, port = %d\n", inet_ntoa(connection.last_addr.sin_addr), (int) ntohs(connection.last_addr.sin_port));

        if (connection.is_connected == 0)
            connection.addr = connection.last_addr;
        else if (connection.last_addr.sin_addr.s_addr != connection.addr.sin_addr.s_addr || connection.last_addr.sin_port != connection.addr.sin_port)
        {
            udt_syslog(LOG_ERR, "message from unknown source");
            continue;
        }

        if (udt_handle_request_packet(&packet) != 0)
            continue;

        udt_packet_parse(packet);
    }

    void *retval = 0;
    pthread_exit(retval);
}
