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

static int create_socket(void)
{
	uint16_t server_port = 8787;
	char *server_addr, *tmp;
	struct sockaddr_in addr;
	int fd;

	server_addr = getenv("CHAT_SERVER_ADDR");
	if (!server_addr) {
		printf("Missing CHAT_SERVER_ADDR var!\n");
		return -1;
	}

	tmp = getenv("CHAT_SERVER_PORT");
	if (tmp)
		server_port = (uint16_t)atoi(tmp);

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

	putchar('\r');
	d = malloc(sizeof(*d) + MAX_DATA_LEN);
	if (!d)
		return -1;

	while (1) {
		ret = recv(tcp_fd, d, sizeof(*d) + MAX_DATA_LEN, MSG_DONTWAIT);
		if (ret < 0) {

			ret = errno;
			if (ret == EAGAIN || ret == EINTR)
				break;

			free(d);
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

	printf("Enter your message: ");
	fflush(stdout);
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

	if (!strcmp(d->data, "clear")) {
		printf("\ec");
		return 0;
	}

	return send_message_to_server(tcp_fd, d);
}

static void start_event_loop(int tcp_fd)
{
	struct pollfd fds[2];
	struct data *d;
	int ret;

	d = malloc(sizeof(*d) + MAX_DATA_LEN);
	if (!d)
		return;

	fds[0].fd = STDIN_FILENO;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	fds[1].fd = tcp_fd;
	fds[1].events = POLLIN;
	fds[1].revents = 0;

	printf("Enter your message: ");
	fflush(stdout);
	while (1) {
		ret = poll(fds, 2, -1);
		if (ret < 0) {
			perror("poll");
			break;
		}

		if (fds[0].revents & POLLIN) {
			if (get_input_user(d) < 0)
				break;
			if (d->len == 1) {
				printf("Enter your message: ");
				fflush(stdout);
				continue;
			}
			if (process_input_user(tcp_fd, d) < 0)
				break;
		}

		if (fds[1].events & POLLIN) {
			ret = get_messages_from_server(tcp_fd);
			if (ret < 0)
				break;
		}
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
