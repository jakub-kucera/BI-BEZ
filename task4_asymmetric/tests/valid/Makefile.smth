CC = gcc
CFLAGS = -std=c11 -Wall -pedantic -Wno-long-long -g
LDFLAGS = -lcrypto

all: hash
run: all
	python test.py
clean:
	rm -f *.o hash
hash: main.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)