# (c) 2018-2019 Doug Rogers under Zero Clause BSD License. See LICENSE.txt.
# You are free to do whatever you want with this software. Have at it!

TARGETS = pwned2bin find-pwned

CC = gcc
CFLAGS = -Wall -Werror -std=c99

%.o: %.c
	$(CC) -o $@ $(CFLAGS) -c $<

all: $(TARGETS)

pwned2bin: pwned2bin.o
	gcc -o $@ $^

find-pwned: find-pwned.o bsd_0_clause_license.o sha1.o
	gcc -o $@ $^

.PHONY: clean
clean:
	rm -rf *~ *.o $(TARGETS)

