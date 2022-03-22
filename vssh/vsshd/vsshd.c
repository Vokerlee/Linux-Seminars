#include "server.h"
#include "daemon.h"

static const char *VSSHD_PID_FILE_NAME = "/var/run/vsshd.pid";

int main(int argc, char *argv[])
{
    if (argc != 2)
        errx(EX_USAGE, "Error: invalid amount of arguments");

    int is_daemon = become_daemon(0); // become daemon
    if (is_daemon == -1)
    {
        fprintf(stderr, "Error while becoming a daemon\n");
        exit(EXIT_FAILURE);
    }

    openlog("vsshd", LOG_PID, LOG_USER | LOG_LOCAL0); // open logs

    int pid_file_fd = create_unique_pid_file(argv[0], VSSHD_PID_FILE_NAME, 0); // check if there is already existing daemon
    if (pid_file_fd == -1)
        exit(EXIT_FAILURE);

    syslog(LOG_INFO, "Unique PID file \"%s\" is created", VSSHD_PID_FILE_NAME);

    int connection_type = SOCK_STREAM;
    if (strcmp(argv[1], "--udp") == 0)
        connection_type = SOCK_DGRAM;
    else if (strcmp(argv[1], "--tcp") != 0)
    {
        syslog(LOG_ERR, "Error: invalid argument \"%s\"", argv[1]);
        return EXIT_FAILURE;
    }
        
    // Launch server
    if (connection_type == SOCK_STREAM)
        return launch_vssh_tcp_server(INADDR_ANY);
    else if (connection_type == SOCK_DGRAM)
        return launch_vssh_udp_server(INADDR_ANY);
}
