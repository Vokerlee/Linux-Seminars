#include "net.h"
#define MY_PERSONAL_PORT 14888

int main()
{
    // Creating own socket
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0); // UDP
    if (socket_fd == -1)
    {
        perror("socket()");
        errx(EX_OSERR, "socket() error");
    }

    int optval = 1;
    int error = setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
    if (error == -1)
    {
        perror("setsockopt()");
        close(socket_fd);
        errx(EX_OSERR, "setsockopt() error");
    }

    error = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (error == -1)
    {
        perror("setsockopt()");
        close(socket_fd);
        errx(EX_OSERR, "setsockopt() error");
    }

    // Binding to own socket
    struct sockaddr_in sender_addr = {0};

    sender_addr.sin_family = AF_INET;
    sender_addr.sin_port = htons(MY_PERSONAL_PORT);
    sender_addr.sin_addr.s_addr = INADDR_ANY;

    int error_bind_server = bind(socket_fd, (struct sockaddr *) &sender_addr, sizeof(struct sockaddr_in));
    if (error_bind_server == -1)
    {
        perror("bind()");
        close(socket_fd);
        errx(EX_OSERR, "bind() error");
    }

    // To send broadcast
    struct sockaddr_in broadcast_addr = {0};
    socklen_t length = sizeof(struct sockaddr_in);

    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(BROADCAST_PORT);
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

    // Sending broadcast
    const char msg[N_MAX_MSG_LEN] = "If you are here, tell me!";

    ssize_t sent_bytes = sendto(socket_fd, msg, sizeof(msg), 0, (struct sockaddr *) &broadcast_addr, length);
    if (sent_bytes == -1 || sent_bytes != sizeof(msg))
    {
        perror("sendto()");
        errx(EX_OSERR, "send() error");
    }

    // Receive responses
    char received_msg[N_MAX_MSG_LEN] = {0};
    struct sockaddr_in accept_addr = {0};

    struct timeval tv = {0};
    tv.tv_sec = 1; // 1 second

    error = setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &tv, sizeof(struct timeval));
    if (error == -1)
    {
        perror("setsockopt()");
        close(socket_fd);
        errx(EX_OSERR, "setsockopt() error");
    }

    while(1)
    {
        memset(received_msg, 0, sizeof(received_msg));

        ssize_t n_received_bytes = recvfrom(socket_fd, received_msg, sizeof(received_msg), 0, (struct sockaddr *) &accept_addr, &length);
        if (n_received_bytes == -1 && errno != EWOULDBLOCK && errno != EAGAIN)
        {
            perror("recvfrom()");
            close(socket_fd);
            exit(EXIT_FAILURE);
        }
        else if (n_received_bytes == -1)
            break;

        printf("There is a response!\n");
        printf("From IP = %s, port = %d!\n\n", inet_ntoa(accept_addr.sin_addr), (int) ntohs(accept_addr.sin_port));

        printf("Message:\n%s\n", received_msg);
        printf("==================================================\n");
    }

    close(socket_fd);

    return 0;
}
