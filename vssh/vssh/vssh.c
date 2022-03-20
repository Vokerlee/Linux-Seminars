#include "vssh.h"

int main(int argc, char *argv[])
{
    fprintf(stderr, "\033[0;31m"); // red color
    closelog();

    if (argc < 2)
        errx(EX_USAGE, "Error: too few arguments\n"
                       "See --help option");

    return vssh_handle_arguments(argc, argv);
}
