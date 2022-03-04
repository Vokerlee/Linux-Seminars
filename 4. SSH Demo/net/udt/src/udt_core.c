#include "udt_core.h"
#include "udt_packet.h"
#include "udt_buffer.h"

udt_conn_t connection = {0};

pthread_mutex_t handshake_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  handshake_cond  = PTHREAD_COND_INITIALIZER;

extern udt_buffer_t RECV_BUFFER;
extern udt_buffer_t SEND_BUFFER;

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

void *udt_sender_start(void *arg)
{
    int old_type = 0;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);

    udt_conn_t *conn = (udt_conn_t *) arg;
    udt_packet_t packet;

    while (udt_send_packet_buffer_read(&packet))
    {
        if (sendto(conn->socket_fd, &packet, sizeof(udt_packet_t), 0,
                    (struct sockaddr *) &(conn->addr), sizeof(struct sockaddr)) == -1)
            exit(errno);

        memset(&packet, 0, sizeof(udt_packet_t));
    }

    void *retval = 0;
	pthread_exit(retval);
}

void *udt_receiver_start(void *arg)
{
    int old_type = 0;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old_type);

    udt_conn_t *conn = (udt_conn_t *) arg;
    udt_packet_t packet;

    memset(&packet, 0, sizeof(udt_packet_t));

    while (1)
    {
        int recv_error = recvfrom(conn->socket_fd, &packet, sizeof(udt_packet_t), 0,
                                  (struct sockaddr *) &(conn->last_addr), &(conn->addrlen));

        if (recv_error == -1 && errno == EAGAIN)
        {
            if (conn->is_in_wait == 1) // send packet
            {
                conn->no_ack = 1;
                conn->is_in_wait = 0;
            }
            else if (conn->is_connected == 1) // already connected
            {
                conn->is_connected = 0;
                conn->is_in_wait   = 0;
                conn->addr.sin_addr.s_addr = 0;
                printf("DISCONNECTION!\n");

                pthread_cond_signal(&(RECV_BUFFER.cond));

                struct timeval tv = {.tv_sec = 0, .tv_usec = 0};    
                setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));
            }
            else // process of connection
            {
                pthread_cond_signal(&handshake_cond);
            }

            memset(&packet, 0, sizeof(udt_packet_t));
            errno = 0;
            continue;
        }
        else if (recv_error == -1)
        {
            memset(&packet, 0, sizeof(udt_packet_t));
            continue;
        }

        printf("MSG from ip = %s, port = %d\n", inet_ntoa(conn->last_addr.sin_addr), (int) ntohs(conn->last_addr.sin_port));

        if (conn->is_connected == 0)
            conn->addr = conn->last_addr;
        else if (conn->last_addr.sin_addr.s_addr != conn->addr.sin_addr.s_addr || conn->last_addr.sin_port != conn->addr.sin_port)
        {
            printf("ALIEN!!!\n"); // now we just skeep aliens, but in future they will be handled by other subservers
            memset(&packet, 0, sizeof(udt_packet_t));
            continue;
        }
        
        udt_packet_parse(packet);
        memset(&packet, 0, sizeof(udt_packet_t));
    }

    void *retval = 0;
	pthread_exit(retval);
}
