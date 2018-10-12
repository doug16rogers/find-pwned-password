TARGETS = pwned2bin find-pwned-password-hash

CC = gcc
CFLAGS = -Wall -Werror -std=c99

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

all: $(TARGETS)

pwned2bin: pwned2bin.o
	gcc -o $@ $^

find-pwned-password-hash: find-pwned-password-hash.o sha1.o
	gcc -o $@ $^

.PHONY: clean
clean:
	rm -rf *~ *.o $(TARGETS)

