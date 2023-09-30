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

static const char bind_addr[] = "0.0.0.0";
static uint16_t bind_port = 8787;

#define MAX_CLIENTS 10

struct client_state {
	int			fd;
	struct sockaddr_in	addr;
	struct data		*data;
};

struct server_context {
	int			tcp_fd;
	uint16_t		nr_clients;
	struct pollfd		fds[MAX_CLIENTS + 1];
	struct client_state	clients[MAX_CLIENTS];
};

static int create_socket(void)
{
	struct sockaddr_in addr;
	int fd;

	/*
	 * The purpose of SOCK_NONBLOCK is to avoid sleeping in
	 * the accept() syscall.
	 */
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, bind_addr, &addr.sin_addr);
	addr.sin_port = htons(bind_port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(fd);
		return -1;
	}

	if (listen(fd, 10) < 0) {
		perror("listen");
		close(fd);
		return -1;
	}

	printf("Listening on %s:%hu...\n", bind_addr, bind_port);
	return fd;
}

static int plug_client_in(struct server_context *ctx, int fd,
			  struct sockaddr_in *addr)
{
	struct client_state *cl = NULL;
	int i;

	for (i = 0; i < MAX_CLIENTS; i++) {
		if (ctx->clients[i].fd < 0) {
			cl = &ctx->clients[i];
			break;
		}
	}

	if (!cl)
		return -EAGAIN;

	cl->fd = fd;
	cl->addr = *addr;
	ctx->fds[i + 1].fd = fd;
	ctx->fds[i + 1].events = POLLIN;
	ctx->fds[i + 1].revents = 0;
	return 0;
}

static int accept_connection(struct server_context *ctx)
{
	char addr_str[INET_ADDRSTRLEN];
	struct sockaddr_in addr;
	socklen_t addr_len;
	uint16_t port;
	int client_fd;
	int err;

	addr_len = sizeof(addr);
	client_fd = accept(ctx->tcp_fd, (struct sockaddr *)&addr, &addr_len);
	if (client_fd < 0) {

		err = errno;
		if (err == EAGAIN || err == EINTR)
			return 0;

		perror("accept");
		return -1;
	}

	inet_ntop(AF_INET, &addr.sin_addr, addr_str, sizeof(addr_str));
	port = ntohs(addr.sin_port);
	printf("Accepted a new connection from %s:%hu\n", addr_str, port);

	err = plug_client_in(ctx, client_fd, &addr);
	if (err < 0) {
		printf("The client slot is full, dropping a new connection!\n");
		close(client_fd);
		return 0;
	}

	return 0;
}

static void close_client(struct server_context *ctx, int i)
{
	struct client_state *cl = &ctx->clients[i];

	close(cl->fd);
	cl->fd = -1;
	memset(&cl->addr, 0, sizeof(cl->addr));

	ctx->fds[i + 1].fd = -1;
	ctx->fds[i + 1].events = 0;
	ctx->fds[i + 1].revents = 0;
}

static const char *stringify_addr4(struct sockaddr_in *addr)
{
	static char buf[INET_ADDRSTRLEN + sizeof(":65535")];

	inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
	sprintf(buf + strlen(buf), ":%hu", ntohs(addr->sin_port));
	return buf;
}

static int broadcast_message_from(struct server_context *ctx, int idx,
				  uint16_t len)
{
	struct client_state *from = &ctx->clients[idx];
	struct client_state *cl;
	struct data_srv *d;
	size_t send_len;
	ssize_t ret;
	int i;

	send_len = sizeof(*d) + len;
	d = malloc(send_len);
	if (!d)
		return -1;

	inet_ntop(AF_INET, &from->addr.sin_addr, d->sender, sizeof(d->sender));
	sprintf(d->sender + strlen(d->sender), ":%hu", ntohs(from->addr.sin_port));
	memcpy(&d->data, from->data, sizeof(*from->data) + len);

	for (i = 0; i < MAX_CLIENTS; i++) {
		cl = &ctx->clients[i];

		/*
		 * Do not broadcast to itself and other inactive clients.
		 */
		if (cl == from || cl->fd < 0)
			continue;

		ret = send(cl->fd, d, send_len, 0);
		if (ret <= 0)
			close_client(ctx, i);
	}

	free(d);
	return 0;
}

static int process_client_data(struct server_context *ctx,
			       struct client_state *cl, int idx)
{
	uint16_t len = ntohs(cl->data->len);
	cl->data->data[len - 1] = '\0';

	printf("%s said: %s\n", stringify_addr4(&cl->addr), cl->data->data);
	return broadcast_message_from(ctx, idx, len);
}

static int handle_client_event(struct server_context *ctx, int i)
{
	struct client_state *cl = &ctx->clients[i];
	ssize_t ret;

	ret = recv(cl->fd, cl->data, sizeof(*cl->data) + MAX_DATA_LEN, 0);
	if (ret < 0) {
		perror("recv");
		close_client(ctx, i);
		return 0;
	}

	if (ret == 0) {
		printf("Client disconnected!\n");
		close_client(ctx, i);
		return 0;
	}

	return process_client_data(ctx, cl, i);
}

static void start_event_loop(int tcp_fd)
{
	struct server_context ctx;
	int ret;
	int i;

	memset(&ctx, 0, sizeof(ctx));

	for (i = 0; i < MAX_CLIENTS; i++)
		ctx.clients[i].fd = -1;

	for (i = 0; i < MAX_CLIENTS; i++) {
		struct data *d = malloc(sizeof(*ctx.clients[i].data) + MAX_DATA_LEN);
		if (!d)
			goto out_free;

		ctx.clients[i].data = d;
	}

	/*
	 * Reminder:
	 * The number of elements in ctx.fds is +1 of the number of elements
	 * in ctx.clients because the first index is used to store the main
	 * TCP fd that we use to accept a new connection.
	 */
	ctx.tcp_fd = tcp_fd;
	ctx.fds[0].fd = tcp_fd;
	ctx.fds[0].events = POLLIN;
	ctx.fds[0].revents = 0;
	for (i = 1; i <= MAX_CLIENTS; i++) {
		ctx.fds[i].fd = -1;
		ctx.fds[i].events = 0;
		ctx.fds[i].revents = 0;
	}

	while (1) {
		int nr_ready;

		nr_ready = poll(ctx.fds, MAX_CLIENTS + 1, -1);
		if (nr_ready < 0) {
			perror("poll");
			break;
		}

		/*
		 * First, let's check the main TCP fd. If it has a POLLIN
		 * bit set in revents, then there is a client that connects
		 * to the server.
		 */
		if (ctx.fds[0].revents & POLLIN) {
			ret = accept_connection(&ctx);
			if (ret < 0)
				break;

			nr_ready--;
		}

		if (nr_ready == 0)
			continue;

		for (i = 1; i <= MAX_CLIENTS; i++) {

			if (ctx.fds[i].revents & POLLIN) {
				ret = handle_client_event(&ctx, i - 1);
				if (ret < 0)
					goto out_free;
				nr_ready--;
			}

			if (nr_ready == 0)
				break;
		}
	}

out_free:
	for (i = 0; i < 10; i++) {
		if (ctx.clients[i].data)
			free(ctx.clients[i].data);
		if (ctx.clients[i].fd > 0)
			close(ctx.clients[i].fd);
	}
}

int main(void)
{
	int tcp_fd;

	tcp_fd = create_socket();
	if (tcp_fd < 0)
		return -1;

	start_event_loop(tcp_fd);
	close(tcp_fd);
	return 0;
}
