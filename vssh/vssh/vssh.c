#include "vssh.h"

#include <termios.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    fprintf(stderr, "\033[0;31m"); // red color
    closelog();

    if (argc < 2)
        errx(EX_USAGE, "Error: too few arguments\n"
                       "See --help option");

    int return_value = vssh_handle_arguments(argc, argv);

    struct termios term;
	if (tcgetattr(STDIN_FILENO, &term) == -1)
    {
		perror("tcgetattr()");
		return EXIT_FAILURE;
	}

	term.c_cc[VINTR]  = 3;
    term.c_cc[VQUIT]  = 34;
    term.c_cc[VSUSP]  = 32;
    term.c_cc[VSTOP]  = 23;
    term.c_cc[VSTART] = 21;

	if (tcsetattr(STDIN_FILENO, TCSANOW, &term) == -1)
    {
		perror("tcsetattr()");
		return EXIT_FAILURE;
	}

    return return_value;
}
