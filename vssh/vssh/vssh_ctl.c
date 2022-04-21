#include "vssh.h"

static const int INFO_INDENT = 50;
static const char *VSSHD_PID_FILE_NAME = "/var/run/vsshd.pid";

#define MAX_PID_NAME_LENGTH 64

int vssh_handle_arguments(int argc, char *argv[])
{
    int indent = 0;

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
    {
        if (argc > 2)
        {
            fprintf(stderr, "\033[0;36m"); // yellow
            fprintf(stderr, "All parameters after \"%s\" were ignored\n", argv[1]);
        }
        
        fprintf(stderr, "\033[0;34m"); // green
        fprintf(stderr, "Usage: vssh [OPTION] ...\n");

        fprintf(stderr, "Possible parameters:\n"
                        "\t[IPv4Type] = [--udp] || [--tcp]\n"
                        "\t[IP] = [x.x.x.x]\n\n"
                        "Options:\n");

        fprintf(stderr, "\t--[h]elp%n", &indent);
        fprintf(stderr, "%*sPrint help information (you are here now)\n", INFO_INDENT - indent, " ");
        indent = 0;

        fprintf(stderr, "\t--[t]erminate%n", &indent);
        fprintf(stderr, "%*sTerminate VSSH daemon on local device\n", INFO_INDENT - indent, " ");
        indent = 0;

        fprintf(stderr, "\t--[br]oadcast%n", &indent);
        fprintf(stderr, "%*sGet list of all avaiable VSSH servers\n", INFO_INDENT - indent, " ");
        fprintf(stderr, "\t%*sExample: vssh -br\n\n",                 INFO_INDENT - 1, " ");
        indent = 0;

        fprintf(stderr, "\t--[m]essage [IPv4Type] [IP] [Message]%n", &indent);
        fprintf(stderr, "%*sSend message to VSSH server (can be found in logs)\n", INFO_INDENT - indent, " ");
        fprintf(stderr, "\t%*sExample: vssh -m --tcp 127.0.0.1 \"Hello!!\"\n\n",   INFO_INDENT - 1, " ");
        indent = 0;

        fprintf(stderr, "\t--[u]sers [IPv4Type] [IP]%n", &indent);
        fprintf(stderr, "%*sRequest the full list of server users\n",                     INFO_INDENT - indent, " ");
        fprintf(stderr, "\t%*sExample: vssh -u --tcp 127.0.0.1\n\n",                      INFO_INDENT - 1, " ");
        indent = 0;

        fprintf(stderr, "\t--[sh]ell [IPv4Type] [IP] [UserName] %n", &indent);
        fprintf(stderr, "%*sRequest shell regime: opens shell on server\n",                INFO_INDENT - indent, " ");
        fprintf(stderr, "\t%*sExample: vssh -sh --tcp 127.0.0.1\n",                        INFO_INDENT - 1, " ");
        fprintf(stderr, "\t%*sTo close the regime you are to write \"exit\" command\n",    INFO_INDENT - 1, " ");
        fprintf(stderr, "\t%*sTo get the list of possible users see \"--users\" option\n", INFO_INDENT - 1, " ");
        indent = 0;

        fprintf(stderr, "\t--[l]og [IPv4Type] [IP]%n", &indent);
        fprintf(stderr, "%*sPrint log information to stdout\n",                           INFO_INDENT - indent, " ");
        fprintf(stderr, "\t%*sExample: vssh -l --tcp 127.0.0.1\n\n",                      INFO_INDENT - 1, " ");
        indent = 0;

    }
    else if (strcmp(argv[1], "--terminate") == 0 || strcmp(argv[1], "-t") == 0)
    {
        if (argc > 2)
        {
            fprintf(stderr, "\033[0;36m"); // yellow
            fprintf(stderr, "All parameters after \"%s\" were ignored\n", argv[1]);
            fprintf(stderr, "\033[0;31m"); // green
        }

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
        if (argc > 2)
        {
            fprintf(stderr, "\033[0;36m"); // yellow
            fprintf(stderr, "All parameters after \"%s\" were ignored\n", argv[1]);
        }

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
                           "See --help option\n");

        int connection_type = 0;

        if (strcmp(argv[2], "--tcp") == 0)
            connection_type = SOCK_STREAM;
        else if (strcmp(argv[2], "--udp") == 0)
            connection_type = SOCK_STREAM_UDT;
        else
        {
            fprintf(stderr, "Error: no --tcp or --udp\n"
                            "See --help option\n");
            return -1;
        }

        in_addr_t ip_addr_dest = inet_addr(argv[3]);
        if (ip_addr_dest == 0)
        {
            fprintf(stderr, "Error: invalid destination IP address, check it\n"
                            "See --help option\n");
            return -1;
        }

        if (strcmp(argv[1], "--msg") == 0 || strcmp(argv[1], "-m") == 0)
        {
            if (argc < 5)
                errx(EX_USAGE, "Error: too few arguments\n"
                               "See --help option\n");

            return vssh_send_message(ip_addr_dest, argv[4], strlen(argv[4]), connection_type);
        }   
        else if (strcmp(argv[1], "--shell") == 0 || strcmp(argv[1], "-sh") == 0)
        {
            if (argv[4] == NULL)
            {
                fprintf(stderr, "Error: invalid username\n"
                                "See --help option\n");
                return -1;
            }

             return vssh_shell_request(ip_addr_dest, connection_type, argv[4]);
        }
           
        else if (strcmp(argv[1], "--users") == 0 || strcmp(argv[1], "-u") == 0)
            return vssh_users_list_request(ip_addr_dest, connection_type);
        else
            return -1;
    }

    return 0;
}
