// SPDX-License-Identifier: GPL-2.0-only
#ifndef PACKET_H
#define PACKET_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_MSG_LEN 4096

struct packet_msg {
	uint16_t	len;
	char		msg[];
} __packed;

struct packet_join {
	char		identity[INET_ADDRSTRLEN + sizeof(":65535")];
} __packed;

struct packet_leave {
	char		identity[INET_ADDRSTRLEN + sizeof(":65535")];
} __packed;

struct packet_msg_id {
	char			identity[INET_ADDRSTRLEN + sizeof(":65535")];
	struct packet_msg	msg;
} __packed;

enum {
	CL_PKT_MSG    = 10,

	SR_PKT_MSG_ID = 20,
	SR_PKT_JOIN   = 21,
	SR_PKT_LEAVE  = 22,
};

#define PKT_HDR_LEN 4

struct packet {
	uint8_t		type;
	uint8_t		__pad;
	uint16_t	len;
	union {
		struct packet_msg	msg;
		struct packet_join	join;
		struct packet_leave	leave;
		struct packet_msg_id	msg_id;
		char			__raw_buf[4096 + MAX_MSG_LEN];
	};
};

static inline size_t prep_sr_pkt_msg_id(struct packet *pkt, const char *id,
					const char *msg, size_t len)
{
	size_t body_len = sizeof(pkt->msg_id) + len;

	if (len > MAX_MSG_LEN)
		len = MAX_MSG_LEN;

	pkt->type = SR_PKT_MSG_ID;
	pkt->__pad = 0;
	pkt->len = htons(body_len);

	strncpy(pkt->msg_id.identity, id, sizeof(pkt->msg_id.identity));
	pkt->msg_id.msg.len = htons(len);
	memcpy(pkt->msg_id.msg.msg, msg, len);
	return PKT_HDR_LEN + body_len;
}

static inline size_t prep_cl_pkt_msg(struct packet *pkt, const char *msg, size_t len)
{
	size_t body_len = sizeof(pkt->msg) + len;

	if (len > MAX_MSG_LEN)
		len = MAX_MSG_LEN;

	pkt->type = CL_PKT_MSG;
	pkt->__pad = 0;
	pkt->len = htons(body_len);

	pkt->msg.len = htons(len);
	memcpy(pkt->msg.msg, msg, len);
	return PKT_HDR_LEN + body_len;
}

#endif /* #ifndef PACKET_H */
