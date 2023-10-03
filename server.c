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

static const char *stringify_ip4(struct sockaddr_in *addr)
{
	static char buf[INET_ADDRSTRLEN + sizeof(":65535")];

	inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
	sprintf(buf + strlen(buf), ":%hu", ntohs(addr->sin_port));
	return buf;
}

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

__attribute__((__noreturn__))
static void abort_db_corruption(size_t len, size_t exp_len, const char *desc)
{
	printf("The database is corrupted! (len != exp_len) %zu != %zu (%s)\n", len, exp_len, desc);
	abort();
}

static int sync_client_chat_history(struct server_ctx *ctx, struct client_state *cs)
{
	static const size_t meta_len = offsetof(struct packet_msg_id, msg.msg);
	struct packet *pkt;

	pkt = malloc(sizeof(*pkt));
	if (!pkt) {
		perror("malloc");
		return -1;
	}

	rewind(ctx->db);
	pkt->type = SR_PKT_MSG_ID;
	pkt->__pad = 0;
	while (1) {
		uint16_t msg_len_he;
		size_t body_len;
		size_t send_len;
		ssize_t ret;
		size_t len;

		len = fread(&pkt->msg_id, 1, meta_len, ctx->db);
		if (!len)
			break;
		if (len != meta_len)
			abort_db_corruption(len, meta_len, "fread(&pkt->msg_id)");

		msg_len_he = ntohs(pkt->msg_id.msg.len);
		if (msg_len_he > MAX_MSG_LEN)
			abort_db_corruption(msg_len_he, MAX_MSG_LEN, "msg_len_he");

		len = fread(pkt->msg_id.msg.msg, 1, msg_len_he, ctx->db);
		if (len != msg_len_he)
			abort_db_corruption(len, msg_len_he, "fread(pkt->msg_id.msg.msg)");

		body_len = sizeof(pkt->msg_id) + msg_len_he;
		pkt->len = htons(body_len);
		send_len = PKT_HDR_LEN + body_len;
		ret = send(cs->fd, pkt, send_len, 0);
		if (ret < 0) {
			perror("send");
			free(pkt);
			return -1;
		}
	}

	free(pkt);
	return 0;
}

static void close_client(struct server_ctx *ctx, uint32_t idx);

static int broadcast_leave_notification(struct server_ctx *ctx, struct client_state *from)
{
	struct client_state *to;
	struct packet *pkt;
	size_t send_len;
	ssize_t ret;
	uint32_t i;

	pkt = malloc(sizeof(*pkt));
	if (!pkt) {
		perror("malloc");
		return -1;
	}

	send_len = prep_sr_pkt_leave(pkt, stringify_ip4(&from->addr));
	for (i = 0; i < ctx->nr_clients; i++) {
		to = &ctx->clients[i];

		/*
		 * Do not broadcast to sender or inactive client.
		 */
		if (from == to || to->fd < 0)
			continue;

		ret = send(to->fd, pkt, send_len, 0);
		if (ret < 0) {
			printf("Client %s disconnected!\n", stringify_ip4(&to->addr));
			close_client(ctx, i);
		}
	}

	free(pkt);
	return 0;
}

static void close_client(struct server_ctx *ctx, uint32_t idx)
{
	close(ctx->clients[idx].fd);
	ctx->clients[idx].fd = -1;
	broadcast_leave_notification(ctx, &ctx->clients[idx]);

	ctx->fds[idx + 1].fd = -1;
	ctx->fds[idx + 1].events = 0;
	ctx->fds[idx + 1].revents = 0;
}

static int broadcast_join_notification(struct server_ctx *ctx, struct client_state *from)
{
	struct client_state *to;
	struct packet *pkt;
	size_t send_len;
	ssize_t ret;
	uint32_t i;

	pkt = malloc(sizeof(*pkt));
	if (!pkt) {
		perror("malloc");
		return -1;
	}

	send_len = prep_sr_pkt_join(pkt, stringify_ip4(&from->addr));
	for (i = 0; i < ctx->nr_clients; i++) {
		to = &ctx->clients[i];

		/*
		 * Do not broadcast to sender or inactive client.
		 */
		if (from == to || to->fd < 0)
			continue;

		ret = send(to->fd, pkt, send_len, 0);
		if (ret < 0) {
			printf("Client %s disconnected!\n", stringify_ip4(&to->addr));
			close_client(ctx, i);
		}
	}

	free(pkt);
	return 0;
}

static int plug_client_in(struct server_ctx *ctx, int fd, struct sockaddr_in *addr)
{
	struct client_state *cs = NULL;
	char addr_str[INET_ADDRSTRLEN];
	uint16_t port;
	uint32_t i;
	int ret;

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

	ret = sync_client_chat_history(ctx, cs);
	if (ret < 0) {
		close_client(ctx, i);
		return 0;
	}

	broadcast_join_notification(ctx, cs);
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

static int save_cl_pkt_msg_to_db(struct server_ctx *ctx,
				 struct packet_msg_id *msg_id, size_t write_len)
{
	clearerr(ctx->db);
	fseek(ctx->db, 0, SEEK_END);
	fwrite(msg_id, write_len, 1, ctx->db);

	if (ferror(ctx->db)) {
		perror("fwrite");
		return -1;
	}

	fflush(ctx->db);
	return 0;
}

static int broadcast_message(struct server_ctx *ctx, struct client_state *from,
			     struct packet_msg_id *msg_id, size_t msg_len_he)
{
	struct client_state *to;
	struct packet *pkt;
	size_t send_len;
	ssize_t ret;
	uint32_t i;

	pkt = malloc(sizeof(*pkt) + msg_len_he);
	if (!pkt) {
		perror("malloc");
		return -1;
	}

	send_len = prep_sr_pkt_msg_id(pkt, msg_id->identity, msg_id->msg.msg, msg_len_he);
	for (i = 0; i < ctx->nr_clients; i++) {
		to = &ctx->clients[i];

		/*
		 * Do not broadcast to sender or inactive client.
		 */
		if (from == to || to->fd < 0)
			continue;

		ret = send(to->fd, pkt, send_len, 0);
		if (ret < 0) {
			printf("Client %s disconnected!\n", stringify_ip4(&to->addr));
			close_client(ctx, i);
		}
	}

	free(pkt);
	return 0;
}

static int handle_cl_pkt_msg(struct server_ctx *ctx, struct client_state *cs)
{
	size_t msg_len_he = ntohs(cs->pkt.msg.len);
	struct packet_msg_id *msg_id;
	const char *id;
	size_t wr_len;
	int ret;

	if (msg_len_he > MAX_MSG_LEN) {
		printf("Client %s sent too long message (%zu bytes)\n", stringify_ip4(&cs->addr), msg_len_he);
		return -1;
	}

	msg_id = malloc(sizeof(*msg_id) + msg_len_he);
	if (!msg_id) {
		perror("malloc");
		return -1;
	}

	id = stringify_ip4(&cs->addr);
	strncpy(msg_id->identity, id, sizeof(msg_id->identity));
	msg_id->msg.len = cs->pkt.msg.len;
	memcpy(msg_id->msg.msg, cs->pkt.msg.msg, msg_len_he);
	wr_len = sizeof(*msg_id) + msg_len_he;

	msg_id->msg.msg[msg_len_he - 1] = '\0';
	ret = save_cl_pkt_msg_to_db(ctx, msg_id, wr_len);
	if (ret < 0) {
		free(msg_id);
		return -1;
	}

	printf("%s said: %s\n", id, msg_id->msg.msg);
	broadcast_message(ctx, cs, msg_id, msg_len_he);
	free(msg_id);
	return 0;
}

static int process_client_packet(struct server_ctx *ctx, struct client_state *cs)
{
	size_t expected_len;
	int ret = 0;

try_again:
	/*
	 * If we have not received the packet header yet, we can't
	 * read the packet type, pad, and len. Keep receiving...
	 */
	if (cs->recv_len < PKT_HDR_LEN)
		return 0;

	/*
	 * If we have not received the packet body yet, keep
	 * receiving. The packet body length is available in
	 * cs->pkt.len stored in network endian byte order.
	 */
	expected_len = PKT_HDR_LEN + ntohs(cs->pkt.len);
	if (cs->recv_len < expected_len)
		return 0;

	switch (cs->pkt.type) {
	case CL_PKT_MSG:
		ret = handle_cl_pkt_msg(ctx, cs);
		break;
	default:
		printf("Client %s sent an invalid packet type: %hhu\n", stringify_ip4(&cs->addr), cs->pkt.type);
		return -1;
	}

	cs->recv_len -= expected_len;
	if (cs->recv_len > 0) {
		char *dst = (char *)&cs->pkt;
		char *src = dst + expected_len;
		size_t cp_len = cs->recv_len;

		memmove(dst, src, cp_len);
		goto try_again;
	}

	return ret;
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

	cs->recv_len += (size_t)ret;
	ret = process_client_packet(ctx, cs);
	if (ret < 0) {
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
