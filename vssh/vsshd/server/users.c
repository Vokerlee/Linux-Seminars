#include "server.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

int handle_users_list_request(int socket_fd, int connection_type)
{
    char buffer[BUFSIZ + 1] = {0};
    char *cur_pos = buffer;
    ssize_t n_max_bytes_to_write = BUFSIZ;
    ssize_t n_written_bytes = -1;

    while (1)
    {
        errno = 0;
        struct passwd* entry = getpwent();
        if (entry == NULL)
        {
            if (errno)
            {
                ipv4_syslog(LOG_ERR, "[USERS]: \"getpwent()\" error: %s", strerror(errno));
                return -1;
            }

            break;
        }

        n_written_bytes = snprintf(cur_pos, n_max_bytes_to_write, "\t%s\n", entry->pw_name);
        n_max_bytes_to_write -= n_written_bytes;
        cur_pos += n_written_bytes;
    }

    endpwent();

    return ipv4_send_message(socket_fd, buffer, BUFSIZ, connection_type);
}
