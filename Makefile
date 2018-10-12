TARGETS = pwned2bin find-pwned

CC = gcc
CFLAGS = -Wall -Werror -std=c99

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

all: $(TARGETS)

pwned2bin: pwned2bin.o
	gcc -o $@ $^

find-pwned: find-pwned.o sha1.o
	gcc -o $@ $^

.PHONY: clean
clean:
	rm -rf *~ *.o $(TARGETS)

