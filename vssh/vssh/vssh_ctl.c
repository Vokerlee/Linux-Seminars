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
        int broadcast_state = vssh_send_broadcast_request();
        if (broadcast_state == -1)
        {
            fprintf(stderr, "broadcast error\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        if (argc < 3)
            errx(EX_USAGE, "Error: too few arguments\n"
                           "See --help option");

        int connection_type = 0;

        if (strcmp(argv[2], "--tcp") == 0)
            connection_type = SOCK_STREAM;
        else if (strcmp(argv[2], "--udp") == 0)
            connection_type = SOCK_STREAM_UDT;
        else
        {
            fprintf(stderr, "Error: no --tcp or --udp\n"
                            "See --help option");
            return -1;
        }

        in_addr_t ip_addr_dest = inet_addr(argv[3]);
        if (ip_addr_dest == 0)
        {
            fprintf(stderr, "Error: invalid destination IP address, check it\n"
                            "See --help option");
            return -1;
        }

        if (strcmp(argv[1], "--msg") == 0 || strcmp(argv[1], "-m") == 0)
        {
            if (argc < 5)
                errx(EX_USAGE, "Error: too few arguments\n"
                               "See --help option");

            return vssh_send_message(ip_addr_dest, argv[4], strlen(argv[4]), connection_type);
        }   
        else if (strcmp(argv[1], "--shell") == 0 || strcmp(argv[1], "-sh") == 0)
            return vssh_shell_request(ip_addr_dest, connection_type);
        else
            return -1;
    }

    return 0;
}
