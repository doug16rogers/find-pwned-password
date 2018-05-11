/* Copyright (c) 2016 Doug Rogers under the terms of the MIT License. */
/* See http://www.opensource.org/licenses/mit-license.html.. */
/* $Id$ */

#include "sha1.h"

/**
 * Rotate @a _x to the left by @a _c bits.
 */
#define ROTATE_LEFT(_x,_c) ((((uint32_t) _x) << (_c)) | (((uint32_t) _x) >> (0x20 - (_c))))

/**
 * Constant initialized sha1 state.
 */
const sha1_t sha1_initialized = SHA1_INIT();

/* ------------------------------------------------------------------------- */
sha1_t* sha1_init(sha1_t* sha1) {
    return sha1_init_flags(sha1, SHA1_FLAGS_DEFAULT);
}   /* sha1_init() */

/* ------------------------------------------------------------------------- */
sha1_t* sha1_init_flags(sha1_t* sha1, uint32_t flags) {
    if (NULL != sha1) {
        *sha1 = sha1_initialized;
        sha1->flags = flags;
    }
    return sha1;
}   /* sha1_init_flags() */

/* ------------------------------------------------------------------------- */
static void sha1_hash_block(uint32_t* restrict h, const uint8_t* restrict block_data) {
    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    uint32_t f;
    uint32_t w[0x50];
    uint32_t k;
    uint32_t temp;
    uint32_t i = 0;
/* printf("\n"); */
/* printf("SHA-1 block of data:\n"); */
/* hex_dump(block_data, SHA1_BLOCK_BYTES); */
    for (i = 0; i < 0x10; ++i) {
        w[i] = (((uint32_t) block_data[(4*i)+0]) << 0x18) +
               (((uint32_t) block_data[(4*i)+1]) << 0x10) +
               (((uint32_t) block_data[(4*i)+2]) << 0x08) +
               (((uint32_t) block_data[(4*i)+3]) << 0x00);
    }
    for (i = 0x10; i < 0x50; ++i) {
        k = w[i-0x03] ^ w[i-0x08] ^ w[i-0x0E] ^ w[i-0x10];
        w[i] = ROTATE_LEFT(k, 1);
    }
/* printf("w[0x00..0x50 x 0x20 bits]:\n"); */
/* hex_dump(w, sizeof(w)); */
/* printf("h[0..4] before:\n"); */
/* hex_dump(h, SHA1_BINARY_BYTES); */
    for (i = 0; i < 0x50; i++) {
        if (i < 0x14) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 0x28) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 0x3C) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        // @todo(dr) Remove temp and do the operation at the bottom with a.
        temp = ROTATE_LEFT(a, 5);
        temp += f + e + k + w[i];
        e = d;
        d = c;
        c = ROTATE_LEFT(b, 30);
        b = a;
        a = temp;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
/* printf("h[0..4] after:\n"); */
/* hex_dump(h, SHA1_BINARY_BYTES); */
}   /* sha1_hash_block() */

/* ------------------------------------------------------------------------- */
sha1_t* sha1_update(sha1_t* restrict sha1, const void* restrict data, size_t size) {
    const uint8_t* b = data;
    size_t bytes_used_in_block = 0;
    size_t bytes_free_in_block = 0;

    if ((NULL == sha1) || (NULL == data) || (0 == size)) {
        return sha1;
    }

    /*
     * Check for fewer than enough to fill a block.
     */
    bytes_used_in_block = sha1->bytes % SHA1_BLOCK_BYTES;
    bytes_free_in_block = SHA1_BLOCK_BYTES - bytes_used_in_block;

    if (size < bytes_free_in_block) {
        memcpy(&sha1->block[bytes_used_in_block], b, size);
        sha1->bytes += size;
        return sha1;
    }

    /*
     * Fill the first block and hash it.
     */
    memcpy(&sha1->block[bytes_used_in_block], b, bytes_free_in_block);
    b           += bytes_free_in_block;
    sha1->bytes += bytes_free_in_block;
    size        -= bytes_free_in_block;
    sha1_hash_block(sha1->h, sha1->block);
    ++sha1->blocks;

    /*
     * Repeat for each full block.
     */
    while (size >= SHA1_BLOCK_BYTES) {
        memcpy(&sha1->block[0], b, SHA1_BLOCK_BYTES);
        b           += SHA1_BLOCK_BYTES;
        sha1->bytes += SHA1_BLOCK_BYTES;
        size        -= SHA1_BLOCK_BYTES;
        sha1_hash_block(sha1->h, sha1->block);
        ++sha1->blocks;
    }

    /*
     * Pour the remainder into the block.
     */
    if (size > 0) {
        memcpy(&sha1->block[0], b, size);
        sha1->bytes += size;
    }

    return sha1;
}   /* sha1_update() */

/* ------------------------------------------------------------------------- */
sha1_t* sha1_end(sha1_t* sha1) {
    size_t bytes_used_in_block = 0;
    uint64_t bits = 0;

    if (NULL == sha1) {
        return sha1;
    }

    /*
     * The algorithm calls for writing a single bit=1 after the last data bit
     * has been written, followed by as many 0 bits as are necessary to pad
     * to the location at then end of the block that is used to hold the
     * 64-bit bit count, written little-endian (figures). If any of this
     * doesn't fit, then the block is zeroed to the end and a new block is
     * used for the bit count (still at the end of the block).
     */
    bytes_used_in_block = sha1->bytes % SHA1_BLOCK_BYTES;
    sha1->block[bytes_used_in_block++] = 0x80;   /* Append a single 1 bit (MSB first). */

    /*
     * If there's not enough room to store the bit length in the current
     * block, fill it out with zeroes, hash it, then carry on.
     */
    if (bytes_used_in_block > (SHA1_BLOCK_BYTES - 8)) {
        memset(&sha1->block[bytes_used_in_block], 0, SHA1_BLOCK_BYTES - bytes_used_in_block);
        sha1_hash_block(sha1->h, sha1->block);
        ++sha1->blocks;
        bytes_used_in_block = 0;
    }

    /*
     * Write zeroes out to the end - except leave room for the 64-bit bit count.
     *
     * NOTE: This depends on little-endian architecture!
     */
    memset(&sha1->block[bytes_used_in_block], 0, (SHA1_BLOCK_BYTES - 8) - bytes_used_in_block);
    bits = 8 * sha1->bytes;
#if 1
    sha1->block[SHA1_BLOCK_BYTES - 8] = (bits >> 0x38) & 0xFF;  /* SHA-1 writes the size big-endian. */
    sha1->block[SHA1_BLOCK_BYTES - 7] = (bits >> 0x30) & 0xFF;
    sha1->block[SHA1_BLOCK_BYTES - 6] = (bits >> 0x28) & 0xFF;
    sha1->block[SHA1_BLOCK_BYTES - 5] = (bits >> 0x20) & 0xFF;
    sha1->block[SHA1_BLOCK_BYTES - 4] = (bits >> 0x18) & 0xFF;
    sha1->block[SHA1_BLOCK_BYTES - 3] = (bits >> 0x10) & 0xFF;
    sha1->block[SHA1_BLOCK_BYTES - 2] = (bits >> 0x08) & 0xFF;
    sha1->block[SHA1_BLOCK_BYTES - 1] = (bits >> 0x00) & 0xFF;
#else
    memcpy(&sha1->block[SHA1_BLOCK_BYTES - 8], &bits, 8);       /* Little-endian only. */
#endif
    sha1_hash_block(sha1->h, sha1->block);
    ++sha1->blocks;
    return sha1;
}   /* sha1_end() */

/* ------------------------------------------------------------------------- */
char*  sha1_text(const sha1_t* restrict sha1, char* restrict text) {
    static char shared_text[SHA1_TEXT_BYTES] = "";
    const uint8_t* hash = (const uint8_t*) &sha1->h[0];
    size_t i = 0;
    const char* tohex = (sha1->flags & SHA1_FLAG_UPPER_CASE) ? "0123456789ABCDEF" : "0123456789abcdef";
    text = (NULL != text) ? text : shared_text;
    if (NULL != sha1) {
        text[0] = 0;
        for (i = 0; i < SHA1_BINARY_BYTES; ++i) {
            text[2*i+0] = tohex[(hash[i^3] >> 4) & 0x0F];
            text[2*i+1] = tohex[(hash[i^3] >> 0) & 0x0F];
        }
    }
    text[2*i] = 0;
    return text;
}   /* sha1_text() */

/* ------------------------------------------------------------------------- */
char* sha1_buffer(const void* restrict data, size_t size, char* restrict text) {
    return sha1_buffer_flags(data, size, text, SHA1_FLAGS_DEFAULT);
}   /* sha1_buffer() */

/* ------------------------------------------------------------------------- */
char* sha1_buffer_flags(const void* restrict data, size_t size, char* restrict text, uint32_t flags) {
    sha1_t sha1;
    return sha1_text(sha1_end(sha1_update(sha1_init_flags(&sha1, flags), data, size)), text);
}   /* sha1_buffer_flags() */

