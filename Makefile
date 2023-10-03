# SPDX-License-Identifier: GPL-2.0-only
CFLAGS = -Wall -Wextra -O2 -ggdb3
LDFLAGS = -O2 -ggdb3

all: server client

server.o: server.c packet.h
client.o: client.c packet.h

server: server.o
client: client.o

clean:
	rm -vf *.o server client

.PHONY: all clean
