#ifndef NET_UTILS_H_
#define NET_UTILS_H_

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sysexits.h>
#include <err.h>

off_t get_file_size(int file_fd);

#endif // !NET_UTILS_H_
