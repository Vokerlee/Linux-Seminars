#ifndef UDT_BUFFER_H_
#define UDT_BUFFER_H_

#include <pthread.h>
#include "udt_packet.h"

typedef struct _udt_block udt_block_t;
struct _udt_block
{
    char *data;
    ssize_t len;
    int last;
    udt_block_t *next;
};

typedef struct _udt_packet_block udt_packet_block_t;
struct _udt_packet_block
{
    udt_packet_t packet;
    ssize_t len;
    udt_packet_block_t *next;
};

typedef struct _udt_buffer udt_buffer_t;
struct _udt_buffer
{
    void *first;
    void *last;
    ssize_t size;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

int udt_buffer_init(udt_buffer_t *buffer);
int udt_send_buffer_init();
int udt_recv_buffer_init();

ssize_t udt_buffer_write(udt_buffer_t *buffer, char *data, ssize_t len);
ssize_t udt_buffer_read (udt_buffer_t *buffer, char *data, ssize_t len);
int udt_buffer_write_packet(udt_buffer_t *buffer, udt_packet_t *packet);
int udt_buffer_read_packet (udt_buffer_t *buffer, udt_packet_t *packet);

ssize_t udt_recv_buffer_write(char *data, ssize_t len);
ssize_t udt_recv_buffer_read (char *data, ssize_t len);

ssize_t udt_send_buffer_write(const char *data, ssize_t len);
int udt_send_packet_buffer_write(udt_packet_t *packet);
int udt_send_packet_buffer_read (udt_packet_t *packet);

ssize_t udt_recv_file_buffer_read (int fd, off_t *offset, ssize_t size);
ssize_t udt_send_file_buffer_write(int fd, off_t  offset, ssize_t size);

#endif // !UDT_BUFFER_H_
