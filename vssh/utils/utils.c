#include "utils.h"

off_t get_file_size(int file_fd)
{
    int saved_errno = errno;

    off_t curr_pos = lseek(file_fd, 0, SEEK_CUR);
    if (curr_pos == -1)
    {
        perror("lseek()");
		return -1;
    }

    off_t file_size = lseek(file_fd, 0, SEEK_END);
	off_t start_pos = lseek(file_fd, curr_pos, SEEK_SET);
    if (file_size == -1 || start_pos == -1)
	{
		perror("lseek()");
		return -1;
	}

    errno = saved_errno;
	
    return file_size;
}