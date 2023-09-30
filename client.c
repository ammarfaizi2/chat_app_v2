// SPDX-License-Identifier: GPL-2.0-only
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "func.h"

static const char server_addr[] = "127.0.0.1";
static uint16_t server_port = 8787;

static int create_socket(void)
{
	struct sockaddr_in addr;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, server_addr, &addr.sin_addr);
	addr.sin_port = htons(server_port);

	printf("Connecting to server %s:%hu...\n", server_addr, server_port);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		close(fd);
		return -1;
	}

	printf("Successfully connected to the server!\n");
	return fd;
}

static int get_input_user(struct data *d)
{
	size_t len;

	printf("Enter your message: ");
	if (!fgets(d->data, MAX_DATA_LEN, stdin)) {
		printf("EOF!\n");
		return -1;
	}

	len = strlen(d->data);
	if (d->data[len - 1] == '\n') {
		d->data[len - 1] = '\0';
		len--;
	}

	d->len = len + 1;
	return 0;
}

static int get_messages_from_server(int tcp_fd)
{
	struct data_srv *d;
	ssize_t ret;

	printf("[ Getting messages from the server... ]\n");
	d = malloc(sizeof(*d) + MAX_DATA_LEN);
	if (!d)
		return -1;

	while (1) {
		ret = recv(tcp_fd, d, sizeof(*d) + MAX_DATA_LEN, MSG_DONTWAIT);
		if (ret < 0) {

			ret = errno;
			free(d);
			if (ret == EAGAIN || ret == EINTR)
				return 0;

			return -1;
		}

		while (ret > 0) {
			size_t cur_struct_len;
			uint16_t len;

			printf("%s said: %s\n", d->sender, d->data.data);

			/*
			 * If we received more than cur_struct_len, then we
			 * probably got more than one message. Move it to
			 * the front and print it.
			 */
			len = ntohs(d->data.len);
			cur_struct_len = sizeof(*d) + len;
			ret -= cur_struct_len;
			memmove(d, d->data.data + len, ret);
		}
	}

	free(d);
	return 0;
}

static int send_message_to_server(int tcp_fd, struct data *d)
{
	uint16_t len = d->len;
	ssize_t ret;

	d->len = htons(d->len);
	ret = send(tcp_fd, d, sizeof(*d) + len, 0);
	if (ret < 0) {
		perror("send");
		return -1;
	}

	return 0;
}

static int process_input_user(int tcp_fd, struct data *d)
{
	if (!strcmp(d->data, "exit"))
		return -1;

	if (!strcmp(d->data, "get_msg"))
		return get_messages_from_server(tcp_fd);

	return send_message_to_server(tcp_fd, d);
}

static void start_event_loop(int tcp_fd)
{
	struct data *d;

	d = malloc(sizeof(*d) + MAX_DATA_LEN);
	if (!d)
		return;

	while (1) {
		if (get_input_user(d) < 0)
			break;

		if (process_input_user(tcp_fd, d) < 0)
			break;
	}
	free(d);
}

int main(void)
{
	int tcp_fd;

	tcp_fd = create_socket();
	if (tcp_fd < 0)
		return 1;

	start_event_loop(tcp_fd);
	close(tcp_fd);
	return 0;
}