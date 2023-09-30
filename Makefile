# SPDX-License-Identifier: GPL-2.0-only
CFLAGS = -Wall -Wextra -O2 -ggdb3

all: server client

server.o: server.c
client.o: client.c
func.o: func.h
server: server.o
client: client.o

clean:
	rm -f server client

.PHONY: all clean
