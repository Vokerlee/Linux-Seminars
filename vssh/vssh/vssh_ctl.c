#include "vssh.h"

static const int INFO_INDENT = 40;
static const char *VSSHD_PID_FILE_NAME = "/var/run/vsshd.pid";

#define MAX_PID_NAME_LENGTH 64

int vssh_handle_arguments(int argc, char *argv[])
{
    int indent = 0;

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
    {
        fprintf(stderr, "\033[0;34m"); // green
        fprintf(stderr, "Usage: vssh [OPTION]\n"
                "Options:\n");

        fprintf(stderr, "\t-h, --help%n", &indent);
        fprintf(stderr, "%*sPrint help information (you are here now)\n", INFO_INDENT - indent, " ");
    }
    else if (strcmp(argv[1], "--msg") == 0 || strcmp(argv[1], "-m") == 0)
    {
        if (argc == 2)
            errx(EX_USAGE, "Error: too few arguments\n"
                           "See --help option");

        if (strcmp(argv[2], "--tcp") == 0)
            return vssh_send_message(inet_addr(argv[3]), argv[4], strlen(argv[4]), SOCK_STREAM);
        else if (strcmp(argv[2], "--udp") == 0)
            return vssh_send_message(inet_addr(argv[3]), argv[4], strlen(argv[4]), SOCK_STREAM_UDT);
        else
            return vssh_send_message(inet_addr(argv[2]), argv[3], strlen(argv[3]), SOCK_STREAM);
    }
    else if (strcmp(argv[1], "--terminate") == 0 || strcmp(argv[1], "-t") == 0)
    {
        int fd = open(VSSHD_PID_FILE_NAME, O_RDONLY);
        if (errno == EACCES)
        {
            fprintf(stderr, "vsshd is not launched yet or you have no rights to know it\n");
            exit(EXIT_FAILURE);
        }
        else if (fd == -1)
        {
            perror("PID file of vsshd cannot be opened");
            exit(EXIT_FAILURE);
        }

        char buffer[MAX_PID_NAME_LENGTH + 1] = {0};

        int read_state = read(fd, buffer, MAX_PID_NAME_LENGTH);
        if (read_state == -1)
        {
            perror("cannot read PID file of vsshd");
            exit(EXIT_FAILURE);
        }

        close(fd);

        pid_t vsshd_pid = atoi(buffer);

        int state = kill(vsshd_pid, 0); // exist daemon now or not
        if (state == -1)
        {
            fprintf(stderr, "vsshd is not launched yet\n");
            exit(EXIT_FAILURE);
        }

        return kill(vsshd_pid, SIGTERM);
    }
    else if (strcmp(argv[1], "--broadcast") == 0 || strcmp(argv[1], "-br") == 0)
    {
        if (argc == 2)
            errx(EX_USAGE, "Error: too few arguments\n"
                           "See --help option");

        int broadcast_state = vssh_send_broadcast(inet_addr(argv[2]));
        if (broadcast_state == -1)
        {
            fprintf(stderr, "broadcast error\n");
            exit(EXIT_FAILURE);
        }
    }   
    else
        return -1;

    return 0;
}
