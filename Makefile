CC=gcc
CFLAGS=-O2 -Wall -std=c99
CFLAGS_BASE=$(CFLAGS)
LDFLAGS=
LDFLAGS_BASE=$(LDFLAGS)
COMP=$(CC) -c $(CFLAGS_BASE) -o
LINK=$(CC) $(LDFLAGS_BASE) -o

.PHONY: all

all: udppunchhole

main.o : main.c
	$(COMP) $@ $<

udppunchhole: main.o
	$(LINK) $@ $^
