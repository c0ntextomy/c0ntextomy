#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define log_info(fmt, ...) 	fprintf(stderr, "[*] " fmt "\n", ##__VA_ARGS__);
#define log_error(fmt, ...) fprintf(stderr, "[!] " fmt "\n", ##__VA_ARGS__);

int drop_to_lldb(int fd)
{
	char *argv[4];

	log_info("Dropping to lldb");
	asprintf(&argv[2], "process connect -p gdb-remote fd://%u", fd);
	if (argv[2] == NULL) {
		log_error("asprintf() failed");
		return -1;
	}

	argv[0] = "lldb";
	argv[1] = "--one-line";
	argv[3] = NULL;

	log_info("Executing lldb");
	if (execvp(argv[0], argv) < 0) {
		log_error("Failed to execute lldb");
		return -1;
	}

	free(argv[2]);
	return 0;
}

char *read_tlv_packet(int fd)
{
	uint64_t size = 0;
	char *buffer = NULL;
	ssize_t ret = 0;

	ret = recv(fd, &size, sizeof(uint64_t), MSG_WAITALL);
	if (ret < 0) {
		log_error("Failed to read tlv size: %s", strerror(errno));
		return NULL;
	}

	if (size <= 0 || size > 1024) {
		log_error("Invalid tlv size");
		return NULL;
	}

	if ((buffer = malloc(size * sizeof(char))) == NULL) {
		log_error("Failed to allocate memory for tlv payload");
		return NULL;
	}

	ret = recv(fd, buffer, size, MSG_WAITALL);
	if (ret < 0) {
		free(buffer);
		log_error("Failed to read tlv payload: %s", strerror(errno));
		return NULL;
	}

	return buffer;
}

int get_hijacked_session(const char *address, int port)
{
	char *hijacked_address = NULL;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int server 	= -1,
		client 	= -1,
		yes 	= 1;

	log_info("Listening for hijacked session at %s:%d", address, port);

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(address);
	server_addr.sin_port = htons(port);

	if ((server = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_error("Failed to create socket: %s", strerror(errno));
		goto cleanup_and_exit;
	}

	setsockopt(server, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	if (bind(server, (const struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
		log_error("Failed to bind socket: %s", strerror(errno));
		goto cleanup_and_exit;
	}

	if (listen(server, 1) != 0) {
		log_error("Failed to listen on socket: %s", strerror(errno));
		goto cleanup_and_exit;
	}

	if ((client = accept(server, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
		log_error("Failed to accept client: %s", strerror(errno));
		goto cleanup_and_exit;
	}

	setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));
	setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));

	log_info(
		"Got connection from: %s:%d",
		inet_ntoa(client_addr.sin_addr),
		ntohs(client_addr.sin_port)
	);

	if ((hijacked_address = read_tlv_packet(client)) == NULL) {
		log_error("Failed to read hijacked address");
		close(client);
		client = -1;
		goto cleanup_and_exit;
	}

	log_info("Hijacked session: %s", hijacked_address)
	free(hijacked_address);

cleanup_and_exit:
	if (server >= 0)
		close(server);
	return client;
}

char *get_ipv4_for_iface(const char *iface)
{
	FILE *fp = NULL;
	char 	*cmd 		= NULL,
			*buff 		= NULL,
			*buff_p 	= NULL,
			*inet_p 	= NULL,
			*inet_ep 	= NULL,
			*inet 		= NULL;
	size_t 	size 		= 0,
			size_left 	= 0,
			ret 		= 0;

	asprintf(&cmd, "ifconfig %s", iface);
	if (cmd == NULL) {
		log_error("asprintf() failed");
		return NULL;
	}

	fp = popen(cmd, "r");
	free(cmd);
	
	if (fp == NULL) {
		log_error("Failed to execute ifconfig");
		return NULL;
	}

	do {
		size_left -= ret;
		buff_p += ret;

		if (buff == NULL) {
			if ((buff = buff_p = malloc(1024 * sizeof(char))) == NULL) {
				log_error("Failed to allocate memory");
				return NULL;
			}
			size = size_left = 1024;
		} else if (size_left == 0) {
			if ((buff = realloc(buff, (size + 1024) * sizeof(char))) == NULL) {
				log_error("Failed to realloc memory");
				return NULL;
			}

			buff_p = buff + (size - size_left);
			size += 1024;
			size_left += 1024;
		}
	} while ((ret = fread(buff_p, sizeof(char), size_left, fp)) > 0);

	size = size - size_left;
	buff[size] = 0;

	if ((inet_p = strstr(buff, "\tinet ")) == NULL)
		goto fail;

	inet_p += sizeof("\tinet");
	if ((inet_ep = strchr(inet_p, ' ')) == NULL)
		goto fail;
	
	*inet_ep = 0;
	inet = strdup(inet_p);
	free(buff);

	return inet_p;
fail:
	log_error("Failed to parse ifconfig");

	if (buff)
		free(buff);
	return NULL;
}

void print_header()
{
	fprintf(stderr, "          __      _           _\n");
	fprintf(stderr, "      __ /  \\ _ _| |_ _____ _| |_ ___ _ __ _  _\n");
	fprintf(stderr, "     / _| () | ' \\  _/ -_) \\ /  _/ _ \\ '  \\ || |\n");
	fprintf(stderr, "     \\__|\\__/|_||_\\__\\___/_\\_\\\\__\\___/_|_|_\\_, |\n");
	fprintf(stderr, "       (c) 2019-2020 @danyl931 @pimskeks   |__/\n\n");
	fprintf(stderr, "\tA simple tool to listen to a single hijacked lldb\n");
	fprintf(stderr, "\tconnection and drop to an interactive lldb session.\n\n");
	fprintf(stderr, "\tTo properly exit without corrupting the original\n");
	fprintf(stderr, "\tsession please detach using the `detach` command.\n\n");
}

int main(int argc, char *argv[])
{
	char *address = NULL;
	int fd = -1;

	print_header();

	if (argc != 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		fprintf(stderr, "Usage: %s [-h | --help] interface\n", *argv);
		return -1;
	}

	if ((address = get_ipv4_for_iface(argv[1])) == NULL)
		return -1;

	if ((fd = get_hijacked_session(address, 4141)) < 0)
		return -1;

	return drop_to_lldb(fd);
}