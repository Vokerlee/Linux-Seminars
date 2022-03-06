#ifndef UDT_API_H_
#define UDT_API_H_

#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>

int udt_startup();

int udt_bind   (int socket_fd, const struct sockaddr *addr, socklen_t len);
int udt_connect(int socket_fd, const struct sockaddr *addr, socklen_t len);

ssize_t udt_recv(               char *buffer, size_t len);
ssize_t udt_send(int socket_fd, char *buffer, size_t len);

int udt_close(int socket_fd);

ssize_t udt_recvfile(               int fd, off_t *offset, ssize_t filesize);
ssize_t udt_sendfile(int socket_fd, int fd, off_t  offset, ssize_t filesize);

void udt_set_server_handler(void *(*server_handler)(void *));

#endif // !UDT_API_H_
