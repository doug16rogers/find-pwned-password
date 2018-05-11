
all: pwned2bin find-pwned-password-hash

pwned2bin: pwned2bin.c
	gcc -o $@ $^

find-pwned-password-hash: find-pwned-password-hash.c sha1.c
	gcc -o $@ $^

.PHONY: clean
clean:
	rm -rf *~ *.o pwned2bin find-pwned-password-hash
