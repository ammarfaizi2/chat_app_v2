// SPDX-License-Identifier: GPL-2.0-only

#ifndef FUNC_H
#define FUNC_H

#include <stdint.h>

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

struct data {
	uint16_t	len;
	char		data[];
} __packed;

struct data_srv {
	char		sender[INET_ADDRSTRLEN + sizeof(":65535")];
	struct data	data;
} __packed;

#define MAX_DATA_LEN 65535

#endif
