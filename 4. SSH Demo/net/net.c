#include "utils.h"
#include "net.h"

int ipv4_connect(int socket_fd, in_addr_t dest_ip, in_port_t dest_port)
{
    int saved_errno = errno;

	struct sockaddr_in dest_addr = {0};
	socklen_t length = sizeof(struct sockaddr_in);

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = dest_port;
	dest_addr.sin_addr.s_addr = dest_ip;

	// Connection
	int connect_error = connect(socket_fd, (struct sockaddr *) &dest_addr, length);
	if (connect_error == -1)
	{
		perror("connect()");
		return -1;
	}

	errno = saved_errno;

	return 0;
}

int ipv4_sock_connect(int type, in_addr_t dest_ip, in_port_t dest_port)
{
	int saved_errno = errno;

	int socket_fd = socket(AF_INET, type, 0);
	if (socket_fd == -1)
	{
		perror("socket()");
		return -1;
	}

	int connect_error = ipv4_connect(socket_fd, dest_ip, dest_port);
	if (connect_error == -1)
	{
		close(socket_fd);
		return -1;
	}

    errno = saved_errno;

    return socket_fd;
}

int ipv4_bind(int socket_fd, in_addr_t ip, in_port_t port)
{
	int saved_errno = errno;

	int optval = 1;
	int setsockopt_error = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (setsockopt_error == -1)
	{
		perror("setsockopt()");
		return -1;
	}

	struct sockaddr_in addr = {0};

	addr.sin_family = AF_INET;
	addr.sin_port = port;
	addr.sin_addr.s_addr = ip;

	int error_bind_server = bind(socket_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in));
	if (error_bind_server == -1)
	{
		perror("bind()");
		return -1;
	}

	errno = saved_errno;

	return 0;
}

int ipv4_sock_bind(int type, in_addr_t ip, in_port_t port)
{
	int saved_errno = errno;

	int socket_fd = socket(AF_INET, type, 0);
	if (socket_fd == -1)
	{
		perror("socket()");
		return -1;
	}

	int bind_error = ipv4_bind(socket_fd, ip, port);
	if (bind_error == -1)
	{
		close(socket_fd);
		return -1;
	}
		
	errno = saved_errno;

	return socket_fd;
}

ssize_t ipv4_send_file(int type, int socket_fd, int file_fd, const char* file_name)
{
    if (type == SOCK_STREAM)
        return ipv4_send_file_tcp(socket_fd, file_fd, file_name);
    else if (type == SOCK_DGRAM)
        return ipv4_send_file_udp(socket_fd, file_fd, file_name);
    else
        return -1;
}

ssize_t ipv4_receive_file(int type, int socket_fd, pthread_mutex_t *sync_mutex)
{
    if (type == SOCK_STREAM)
        return ipv4_receive_file_tcp(socket_fd, sync_mutex);
    else if (type == SOCK_DGRAM)
        return ipv4_receive_file_udp(socket_fd, sync_mutex);
    else
        return -1;
}

ssize_t ipv4_send_file_tcp(int socket_fd, int file_fd, const char* file_name)
{   
    int saved_errno = errno;

    off_t file_size = get_file_size(file_fd);
    if (file_size == -1)
        return -1;

	size_t n_iters = file_size / PACKET_DATA_SIZE; // iterations to send the whole file
	if (file_size % PACKET_DATA_SIZE != 0)
		n_iters++;

	char message[PACKET_DATA_SIZE] = {0};

	*((size_t *) message)     = file_size;
	*((size_t *) message + 1) = n_iters;
	*((size_t *) message + 2) = strlen(file_name);
	strncpy((char *)((size_t *) message + 3), file_name, N_MAX_FILENAME_LEN);

    ssize_t sent_hdr_bytes = write(socket_fd, message, HDR_MSG_LEN);
	if (sent_hdr_bytes == -1 || sent_hdr_bytes != HDR_MSG_LEN)
	{
		perror("write()");
		return -1;
	}

    // Sending the file

	for (size_t i = 0; i < n_iters - 1; i++)
	{
		int read_error = read(file_fd, message, PACKET_DATA_SIZE);
		if (read_error == -1)
		{
			perror("read()");
			return -1;
		}

		ssize_t sent_bytes = write(socket_fd, message, PACKET_DATA_SIZE);
		if (sent_bytes == -1 || sent_bytes != PACKET_DATA_SIZE)
		{
			perror("write()");
			return -1;
		}
	}

	memset(message, 0, sizeof(message));

	int read_error = read(file_fd, message, file_size % PACKET_DATA_SIZE);
	if (read_error == -1)
	{
		perror("read()");
		return -1;
	}

	ssize_t sent_bytes = write(socket_fd, message, file_size % PACKET_DATA_SIZE);
	if (sent_bytes == -1 || sent_bytes != file_size % PACKET_DATA_SIZE)
	{
		perror("write()");
		close(socket_fd);
		errx(EX_OSERR, "write() error");
	}

    errno = saved_errno;

    return sent_hdr_bytes + n_iters * PACKET_DATA_SIZE;
}

ssize_t ipv4_send_file_udp(int socket_fd, int file_fd, const char* file_name)
{
    
}

ssize_t ipv4_receive_file_tcp(int socket_fd, pthread_mutex_t *sync_mutex)
{
    char message[PACKET_DATA_SIZE] = {0};
	char file_name[N_MAX_FILENAME_LEN] = {0};

	if (read(socket_fd, message, HDR_MSG_LEN) == -1)
	{
		perror("read()");
		return -1;
	}

	size_t file_size     = *((size_t *) message);
	size_t n_iters       = *((size_t *) message + 1);
	size_t filename_size = *((size_t *) message + 2);
	strncpy(file_name, (char *)((size_t *) message + 3), N_MAX_FILENAME_LEN);

	if (sync_mutex)
	{
		int mutex_error = pthread_mutex_lock(sync_mutex);
		if (mutex_error != -1)
		{
			printf("File information:\n");
			printf("\tsize       = %zu\n", file_size);
			printf("\titerations = %zu\n", n_iters);
			printf("\tname size  = %zu\n", filename_size);
			printf("\tname       = %s\n",  file_name);
			printf("==================================================\n");

			pthread_mutex_unlock(sync_mutex);
		}
		else
			perror("pthread_mutex_unlock()");
	}

	int file_fd = open(file_name, O_WRONLY | O_CREAT, 0666);
	if (file_fd == -1)
	{
		perror("open()");
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0; i < n_iters - 1; i++)
	{
		int read_error = read(socket_fd, message, PACKET_DATA_SIZE);
		if (read_error == -1)
		{
			perror("read()");
			close(file_fd);
			return -1;
		}

		ssize_t written_bytes = write(file_fd, message, PACKET_DATA_SIZE);
		if (written_bytes == -1 || written_bytes != PACKET_DATA_SIZE)
		{
			perror("write()");
			close(file_fd);
			return -1;
		}
	}

	memset(message, 0, sizeof(message));

	int read_error = read(socket_fd, message, file_size % PACKET_DATA_SIZE);
	if (read_error == -1)
	{
		perror("read()");
		close(file_fd);
		return -1;
	}

	ssize_t sent_bytes = write(file_fd, message, file_size % PACKET_DATA_SIZE);
	if (sent_bytes == -1 || sent_bytes != file_size % PACKET_DATA_SIZE)
	{
		perror("write()");
		close(file_fd);
		return -1;
	}

	close(file_fd);

	return HDR_MSG_LEN + n_iters * PACKET_DATA_SIZE;
}

ssize_t ipv4_receive_file_udp(int socket_fd, pthread_mutex_t *sync_mutex)
{
    
}




