CC = gcc
CFLAGS = -Wall -pedantic -Wno-long-long -g
LDFLAGS = -lcrypto

all: hash
run: hash
	python test.py
clean:
	rm -f *.o hash
hash: main.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)