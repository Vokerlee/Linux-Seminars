#include "vssh.h"

#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include "utils.h"

int main(int argc, char *argv[])
{
    fprintf(stderr, "\033[0;31m"); // red color
    closelog();

    struct termios term;
	if (tcgetattr(STDIN_FILENO, &term) == -1)
    {
		perror("tcgetattr()");
		return EXIT_FAILURE;
	}

    if (argc < 2)
        errx(EX_USAGE, "Error: too few arguments\n"
                       "See --help option");

    int return_value = vssh_handle_arguments(argc, argv);

	if (tcsetattr(STDIN_FILENO, TCSANOW, &term) == -1)
    {
		perror("tcsetattr()");
		return EXIT_FAILURE;
	}

    return return_value;
}
