/* This software is in the public domain. */

/*
 * Read lines in pwned-password format from stdin and write them in binary to
 * stdout.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

struct {
    unsigned char sha[20];
    uint32_t count;
} line = {0};

int hex_val(char c) {
    if (('0' <= c) && (c <= '9'))
        return c - '0';
    if (('A' <= c) && (c <= 'F'))
        return 10 + c - 'A';
    if (('a' <= c) && (c <= 'f'))
        return 10 + c - 'a';
    return -1;
}

int get_hex_byte(unsigned char* b) {
    int b1 = hex_val(getchar());
    int b0 = hex_val(getchar());
    if ((b1 < 0) || (b0 < 0))
        return 0;
    *b = 16 * b1 + b0;
    return 1;
}

int copy_line(void) {
    for (int k = 0; k < 20; ++k) {
        if (!get_hex_byte(&line.sha[k])) {
            return 0;
        }
    }
    if (getchar() != ':')
        return 0;
    unsigned int count = 0;
    if (1 != fscanf(stdin, "%u", &count)) {
        return 0;
    }
    line.count = (uint32_t) count;
    write(1, &line, sizeof(line));
    while (getchar() == ' ')
        ;
    getchar();
    return 1;
}

int main(int argc, char* argv[]) {
    assert(sizeof(line) == 24);
    while (copy_line())
        ;
    return 0;
}
