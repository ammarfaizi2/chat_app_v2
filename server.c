// SPDX-License-Identifier: GPL-2.0-only

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>
#include <poll.h>

#include "packet.h"

#define NR_CLIENTS 512

struct client_state {
	int			fd;
	struct sockaddr_in	addr;
	size_t			recv_len;
	struct packet		pkt;
};

struct server_ctx {
	FILE			*db;
	int			tcp_fd;
	uint32_t		nr_clients;
	struct client_state	*clients;
	struct pollfd		*fds;
};

static const char db_file_name[] = "chat_history.bin";
static const char default_bind_addr[] = "0.0.0.0";
static uint16_t default_bind_port = 8787;

static int create_socket(void)
{
	const char *tmp, *bind_addr;
	struct sockaddr_in addr;
	uint16_t bind_port;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int));

	bind_addr = getenv("CHAT_APP_BIND_ADDR");
	if (!bind_addr)
		bind_addr = default_bind_addr;

	tmp = getenv("CHAT_APP_BIND_PORT");
	if (tmp)
		bind_port = (uint16_t)atoi(tmp);
	else
		bind_port = default_bind_port;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
		printf("Invalid bind address: %s\n", bind_addr);
		close(fd);
		return -1;
	}
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

static int init_server_ctx(struct server_ctx *ctx)
{
	uint32_t i;

	ctx->db = fopen(db_file_name, "rb+");
	if (!ctx->db) {
		ctx->db = fopen(db_file_name, "wb+");
		if (!ctx->db) {
			perror("fopen");
			return -1;
		}

		printf("Created database file: %s\n", db_file_name);
	} else {
		printf("Loaded database file: %s\n", db_file_name);
	}

	ctx->tcp_fd = create_socket();
	if (ctx->tcp_fd < 0) {
		fclose(ctx->db);
		return -1;
	}

	ctx->fds = calloc(NR_CLIENTS + 1, sizeof(*ctx->fds));
	if (!ctx->fds) {
		perror("calloc");
		fclose(ctx->db);
		close(ctx->tcp_fd);
		return -1;
	}

	ctx->clients = calloc(NR_CLIENTS, sizeof(*ctx->clients));
	if (!ctx->clients) {
		perror("calloc");
		fclose(ctx->db);
		close(ctx->tcp_fd);
		free(ctx->fds);
		return -1;
	}

	ctx->fds[0].fd = ctx->tcp_fd;
	ctx->fds[0].events = POLLIN;
	ctx->nr_clients = NR_CLIENTS;

	for (i = 0; i < ctx->nr_clients; i++)
		ctx->clients[i].fd = -1;

	for (i = 1; i <= ctx->nr_clients; i++)
		ctx->fds[i].fd = -1;

	return 0;
}

static void destroy_server_ctx(struct server_ctx *ctx)
{
	if (ctx->db)
		fclose(ctx->db);

	if (ctx->tcp_fd >= 0)
		close(ctx->tcp_fd);

	if (ctx->fds)
		free(ctx->fds);

	if (ctx->clients)
		free(ctx->clients);
}

static int poll_for_events(struct server_ctx *ctx)
{
	int ret;

	ret = poll(ctx->fds, ctx->nr_clients + 1, -1);
	if (ret < 0) {
		ret = errno;
		if (ret == EINTR)
			return 0;

		perror("poll");
		return -1;
	}

	return ret;
}

static int plug_client_in(struct server_ctx *ctx, int fd, struct sockaddr_in *addr)
{
	struct client_state *cs = NULL;
	char addr_str[INET_ADDRSTRLEN];
	uint16_t port;
	uint32_t i;

	for (i = 0; i < ctx->nr_clients; i++) {
		if (ctx->clients[i].fd < 0) {
			cs = &ctx->clients[i];
			break;
		}
	}

	/*
	 * The client slot is full!
	 */
	if (!cs)
		return -EAGAIN;

	cs->fd = fd;
	cs->addr = *addr;
	cs->recv_len = 0;
	ctx->fds[i + 1].fd = fd;
	ctx->fds[i + 1].events = POLLIN;

	inet_ntop(AF_INET, &cs->addr.sin_addr, addr_str, sizeof(addr_str));
	port = ntohs(cs->addr.sin_port);
	printf("Accepted a new connection from %s:%hu\n", addr_str, port);
	return 0;
}

static int accept_new_connection(struct server_ctx *ctx)
{
	struct sockaddr_in addr;
	socklen_t addr_len;
	int fd, ret;

	addr_len = sizeof(addr);
	fd = accept(ctx->tcp_fd, (struct sockaddr *)&addr, &addr_len);
	if (fd < 0) {
		ret = errno;
		if (ret == EINTR || ret == EAGAIN)
			return 0;

		perror("accept");
		return -1;
	}

	ret = plug_client_in(ctx, fd, &addr);
	if (ret < 0) {
		printf("Client slot is full, dropping a new connection...\n");
		close(fd);
		return 0;
	}

	return 0;
}

static const char *stringify_ip4(struct sockaddr_in *addr)
{
	static char buf[INET_ADDRSTRLEN + sizeof(":65535")];

	inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
	sprintf(buf + strlen(buf), ":%hu", ntohs(addr->sin_port));
	return buf;
}

static void close_client(struct server_ctx *ctx, uint32_t idx)
{
	close(ctx->clients[idx].fd);
	ctx->clients[idx].fd = -1;

	ctx->fds[idx + 1].fd = -1;
	ctx->fds[idx + 1].events = 0;
	ctx->fds[idx + 1].revents = 0;
}

static int handle_event(struct server_ctx *ctx, uint32_t idx)
{
	struct client_state *cs = &ctx->clients[idx];
	ssize_t ret;
	size_t len;
	char *buf;

	buf = (char *)&cs->pkt + cs->recv_len;
	len = sizeof(cs->pkt) - cs->recv_len;
	ret = recv(cs->fd, buf, len, MSG_DONTWAIT);
	if (ret < 0) {

		ret = errno;
		if (ret == EAGAIN || ret == EINTR)
			return 0;

		printf("Client %s error: %s\n", stringify_ip4(&cs->addr), strerror(ret));
		close_client(ctx, idx);
		return 0;
	}

	if (ret == 0) {
		printf("Client %s disconnected\n", stringify_ip4(&cs->addr));
		close_client(ctx, idx);
		return 0;
	}

	return 0;
}

static int handle_events(struct server_ctx *ctx, int nr_events)
{
	int ret = 0;
	uint32_t i;

	if (ctx->fds[0].revents & POLLIN) {
		ret = accept_new_connection(ctx);
		if (ret < 0)
			return ret;

		nr_events--;
	}

	for (i = 1; i <= ctx->nr_clients; i++) {
		if (nr_events == 0)
			break;

		if (ctx->fds[i].revents & POLLIN) {
			ret = handle_event(ctx, i - 1);
			if (ret < 0)
				break;

			nr_events--;
		}
	}

	return ret;
}

static void start_event_loop(struct server_ctx *ctx)
{
	int ret;

	while (1) {
		ret = poll_for_events(ctx);
		if (ret < 0)
			break;

		ret = handle_events(ctx, ret);
		if (ret < 0)
			break;
	}
}

int main(void)
{
	struct server_ctx ctx;
	int ret;
	
	memset(&ctx, 0, sizeof(ctx));
	ctx.tcp_fd = -1;
	ret = init_server_ctx(&ctx);
	if (ret < 0)
		return 1;

	start_event_loop(&ctx);

	destroy_server_ctx(&ctx);
	return 0;
}
