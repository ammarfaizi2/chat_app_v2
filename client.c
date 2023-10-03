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

static const char default_server_addr[] = "127.0.0.1";
static uint16_t default_server_port = 8787;

struct client_ctx {
	int		tcp_fd;
	struct pollfd	fds[2];
	struct packet	pkt;
	size_t		recv_ret;
	char		msg[MAX_MSG_LEN];
};

static int create_socket(void)
{
	const char *tmp, *server_addr;
	struct sockaddr_in addr;
	uint16_t server_port;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	server_addr = getenv("CHAT_APP_SERVER_ADDR");
	if (!server_addr)
		server_addr = default_server_addr;

	tmp = getenv("CHAT_APP_SERVER_PORT");
	if (tmp)
		server_port = (uint16_t)atoi(tmp);
	else
		server_port = default_server_port;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (inet_pton(AF_INET, server_addr, &addr.sin_addr) != 1) {
		printf("Invalid server address: %s\n", server_addr);
		close(fd);
		return -1;
	}
	addr.sin_port = htons(server_port);

	printf("Connecting to %s:%hu...\n", server_addr, server_port);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		close(fd);
		return -1;
	}

	printf("Successfully connected to the server!\n");
	return fd;
}

static int init_client_ctx(struct client_ctx *ctx)
{
	ctx->tcp_fd = create_socket();
	if (ctx->tcp_fd < 0)
		return -1;

	ctx->fds[0].fd = ctx->tcp_fd;
	ctx->fds[0].events = POLLIN;

	ctx->fds[1].fd = STDIN_FILENO;
	ctx->fds[1].events = POLLIN;
	return 0;
}

static void destroy_client_ctx(struct client_ctx *ctx)
{
	if (ctx->tcp_fd >= 0)
		close(ctx->tcp_fd);
}

static int poll_for_events(struct client_ctx *ctx)
{
	int ret;

	ret = poll(ctx->fds, 2, -1);
	if (ret < 0) {
		ret = errno;
		if (ret == EINTR)
			return 0;

		perror("poll");
		return -1;
	}

	return ret;
}

static int handle_server_packet(struct client_ctx *ctx)
{
	return 0;
}

static int send_message_to_server(struct client_ctx *ctx, size_t len)
{
	struct packet *pkt = &ctx->pkt;
	size_t send_len;
	ssize_t ret;

	send_len = prep_cl_pkt_msg(pkt, ctx->msg, len);
	ret = send(ctx->tcp_fd, pkt, send_len, 0);
	if (ret < 0) {
		perror("send");
		return -1;
	}

	if (ret == 0) {
		printf("Server disconnected!\n");
		return -1;
	}

	return 0;
}

static int process_user_input(struct client_ctx *ctx, size_t len)
{
	if (!strcmp(ctx->msg, "exit"))
		return -1;
	
	if (!strcmp(ctx->msg, "clear")) {
		printf("\ec");
		fflush(stdout);
		return 0;
	}

	return send_message_to_server(ctx, len);
}

static int handle_user_input(struct client_ctx *ctx)
{
	size_t len;
	int ret;

	if (!fgets(ctx->msg, sizeof(ctx->msg), stdin)) {
		printf("EOF!\n");
		return -1;
	}

	/*
	 * Cut the ending LF if it ends with an LF.
	 */
	len = strlen(ctx->msg);
	if (ctx->msg[len - 1] == '\n') {
		ctx->msg[len - 1] = '\0';
		len--;
	}

	/*
	 * Pass len + 1 to process_user_input() to account the null byte.
	 */
	ret = process_user_input(ctx, len + 1);
	if (ret < 0)
		return -1;

	printf("Enter your message: ");
	fflush(stdout);
	return 0;
}

static int handle_events(struct client_ctx *ctx)
{
	int ret = 0;

	if (ctx->fds[0].revents & POLLIN) {
		ret = handle_server_packet(ctx);
		if (ret < 0)
			return -1;
	}

	if (ctx->fds[1].revents & POLLIN) {
		ret = handle_user_input(ctx);
	}

	return ret;
}

static void start_event_loop(struct client_ctx *ctx)
{
	int ret;

	printf("Enter your message: ");
	fflush(stdout);
	while (1) {
		ret = poll_for_events(ctx);
		if (ret < 0)
			break;

		ret = handle_events(ctx);
		if (ret < 0)
			break;
	}
}

int main(void)
{
	struct client_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.tcp_fd = -1;
	ret = init_client_ctx(&ctx);
	if (ret < 0)
		return 1;

	start_event_loop(&ctx);
	destroy_client_ctx(&ctx);
	return 0;
}
