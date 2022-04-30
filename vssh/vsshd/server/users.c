#include "server.h"

#include <stdlib.h>
#include <termios.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

extern int login_into_user(char *username);
extern int handle_terminal_commands(int socket_fd, int master_fd, int connection_type);

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

int handle_file(int socket_fd, int connection_type, size_t file_size, char *username, char *dest_file_path)
{
    int master_fd = posix_openpt(O_RDWR | O_NOCTTY);
	if (master_fd == -1)
    {
        ipv4_syslog(LOG_ERR, "[TERMINAL]: error while using posix_openpt(): %s", strerror(errno));
		return -1;
	}

    #define CLOSE_MASTER_AND_LOG(master_fd, corrupted_function)                                             \
    do {                                                                                                    \
        int saved_errno = errno;                                                                            \
        close(master_fd);                                                                                   \
        errno = saved_errno;                                                                                \
                                                                                                            \
        ipv4_syslog(LOG_ERR, "[TERMINAL]: error while using " #corrupted_function ": %s", strerror(errno)); \
                                                                                                            \
    } while(0)

    if (grantpt(master_fd) == -1)
    {
        CLOSE_MASTER_AND_LOG(master_fd, grantpt());
        return -1;
    }

    if (unlockpt(master_fd) == -1)
    {
        CLOSE_MASTER_AND_LOG(master_fd, unlockpt());
        return -1;
    }

    struct termios term;
	if (tcgetattr(master_fd, &term) == -1)
    {
		CLOSE_MASTER_AND_LOG(master_fd, tcgetattr());
		return -1;
	}

	cfmakeraw(&term);

	if (tcsetattr(master_fd, TCSANOW, &term) == -1)
    {
		CLOSE_MASTER_AND_LOG(master_fd, tcsetattr());
		return -1;
	}

    char *slave_pty_name = ptsname(master_fd);
    if (slave_pty_name == NULL)
    {
        CLOSE_MASTER_AND_LOG(master_fd, ptsname());
        return -1;
    }

    pid_t child_pid = fork();
    if (child_pid == -1)
    {
        CLOSE_MASTER_AND_LOG(master_fd, fork());
        return -1;
    }

    #undef CLOSE_MASTER_AND_LOG

    if (child_pid == 0)
    {
        if (setsid() == -1)
        {
            ipv4_syslog(LOG_ERR, "[TERMINAL]: error while using setsid(): %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
            
        close(master_fd);

        int slave_fd = open(slave_pty_name, O_RDWR);
        if (slave_fd == -1)
        {
            ipv4_syslog(LOG_ERR, "[TERMINAL]: error while using open(): %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

    #ifdef TIOCSCTTY // Acquire controlling tty on BSD
        if (ioctl(slaveFd, TIOCSCTTY, 0) == -1)
            errx(EX_OSERR, "ioctl() error: %s", strerror(errno));
    #endif

        if (dup2(slave_fd, STDIN_FILENO) != STDIN_FILENO)
        {
            ipv4_syslog(LOG_ERR, "[TERMINAL]: error while using dup2() for STDIN_FILENO: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (dup2(slave_fd, STDOUT_FILENO) != STDOUT_FILENO)
        {
            ipv4_syslog(LOG_ERR, "[TERMINAL]: error while using dup2() for STDOUT_FILENO: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (dup2(slave_fd, STDERR_FILENO) != STDERR_FILENO)
        {
            ipv4_syslog(LOG_ERR, "[TERMINAL]: error while using dup2() for STDERR_FILENO: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        int login_state = login_into_user(username);

        ipv4_syslog(LOG_ERR, "[FILE TRANSFER] login state: %d", login_state);
        close(slave_fd);

        if (login_state == 0)
            exit(EXIT_SUCCESS);
        else
            exit(EXIT_FAILURE);
    }

    ipv4_ctl_message ctl_message = {0};
    char password[BUFSIZ + 1]    = {0};
    char file_message[PACKET_DATA_SIZE + 1] = {0};

    ssize_t recv_bytes_ctl = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ipv4_ctl_message), connection_type);
    if (recv_bytes_ctl == -1)
    {
        ipv4_syslog(LOG_ERR, "[TERMINAL]: error during ipv4_receive_message(): %s", strerror(errno));
        return -1;
    }
    if (connection_type == SOCK_STREAM && recv_bytes_ctl == 0)
    {
        ipv4_syslog(LOG_ERR, "[TERMINAL]: error during ipv4_receive_message(): %s", strerror(errno));
        return -1;
    }
        
    ssize_t recv_bytes = ipv4_receive_message(socket_fd, password, ctl_message.message_length, connection_type);
    if (recv_bytes == -1)
    {
        ipv4_syslog(LOG_ERR, "[TERMINAL]: error during ipv4_receive_message(): %s", strerror(errno));
        return -1;
    }
    if (connection_type == SOCK_STREAM && recv_bytes_ctl == 0)
    {
        ipv4_syslog(LOG_ERR, "[TERMINAL]: error during ipv4_receive_message(): %s", strerror(errno));
        return -1;
    }

    ipv4_syslog(LOG_NOTICE, "[FILE TRANSFER] password[%zu]: %s", strlen(password), password);

    write(master_fd, password, ctl_message.message_length);

    int exit_state = 0;
    waitpid(child_pid, &exit_state, 0);
    close(master_fd);

    char *buffer = NULL;
    int fd = -1;

    if (exit_state == 0) // right password
    {
        snprintf(file_message, 2, "%c", 0x19);

        struct passwd *user_info = getpwnam(username);
        if (user_info == NULL)
        {
            ipv4_syslog(LOG_NOTICE, "[FILE TRANSFER] getpwnam() returned NULL: %s", strerror(errno));
            snprintf(file_message, 2, "%c", 0x17);
            exit_state = 1;
        }

        seteuid(user_info->pw_uid);
        setegid(user_info->pw_gid);

        buffer = malloc(file_size + 1);
        if (buffer == NULL)
        {
            ipv4_syslog(LOG_INFO, "[FILE TRANSFER]: malloc() error");
            seteuid(getuid());
            setegid(getgid());
            snprintf(file_message, 2, "%c", 0x17);
            exit_state = 1;
        }

        fd = open(dest_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd == -1)
        {
            ipv4_syslog(LOG_INFO, "[FILE TRANSFER]: open() error: %s", strerror(errno));
            seteuid(getuid());
            setegid(getgid());
            snprintf(file_message, 2, "%c", 0x17);
            free(buffer);
            exit_state = 1;
        }
    }
    else // invalid password
    {
        snprintf(file_message, 2, "%c", 0x18);
    }

    ssize_t sent_bytes = ipv4_send_message(socket_fd, file_message, PACKET_DATA_SIZE, connection_type);
    if (sent_bytes == -1 || sent_bytes == 0)
    {
        ipv4_syslog(LOG_ERR, "[FILE TRANSFER] ipv4_send_message() couldn't sent message\n");
        free(buffer);
        close(fd);
        seteuid(getuid());
        setegid(getgid());
        return -1;
    }

    if (exit_state != 0)
    {
        seteuid(getuid());
        setegid(getgid());
        return -1;
    }

    recv_bytes_ctl = ipv4_receive_message(socket_fd, &ctl_message, sizeof(ipv4_ctl_message), connection_type);
    if (recv_bytes_ctl == -1)
    {
        ipv4_syslog(LOG_ERR, "[FILE TRANSFER] ipv4_receive_message() couldn't receive message\n");
        free(buffer);
        close(fd);
        seteuid(getuid());
        setegid(getgid());
        return -1;
    }

    if (ctl_message.message_type == IPV4_FILE_HEADER_TYPE)
    {
        ipv4_syslog(LOG_INFO, "[FILE TRANSFER] begin to receive file (size = %zu)", file_size);

        ssize_t recv_bytes = ipv4_receive_buffer(socket_fd, buffer, file_size, connection_type);
        if (recv_bytes == -1)
        {
            ipv4_syslog(LOG_ERR, "[FILE TRANSFER] ipv4_receive_buffer() error\n");
            free(buffer);
            close(fd);
            return -1;
        }

        write(fd, buffer, file_size);
    }

    ipv4_syslog(LOG_NOTICE, "[FILE TRANSFER] successfully finish job and exit");

    seteuid(getuid());
    setegid(getgid());

    free(buffer);
    close(fd);

    return 0;
}
