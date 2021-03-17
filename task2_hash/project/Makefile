CC = gcc
CFLAGS = -g
LDFLAGS = -lcrypto

all: hash
run: hash
	python test.py
hash: main.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)