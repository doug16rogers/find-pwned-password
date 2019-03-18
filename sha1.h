/* (c) 2018 Doug Rogers under Zero Clause BSD License. See LICENSE.txt. */
/* You are free to do whatever you want with this software. Have at it! */

#ifndef __sha1_h__
#define __sha1_h__

#include <string.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA1_BINARY_BYTES   0x14
#define SHA1_BINARY_WORDS   (SHA1_BINARY_BYTES / sizeof(uint32_t))
#define SHA1_TEXT_BYTES     ((SHA1_BINARY_BYTES * 2) + 1)

#define SHA1_BLOCK_BYTES    0x40

#define SHA1_COUNT_BLOCKS_HASHED 0

#define SHA1_FLAG_UPPER_CASE    0x0001  /**< Use upper case hexadecimal. */

#define SHA1_FLAGS_DEFAULT      0

/**
 * SHA1 state tracker object.
 */
typedef struct {
    uint32_t h[SHA1_BINARY_WORDS];      /**< Current hash state. */
    uint8_t  block[SHA1_BLOCK_BYTES];   /**< Holding area for input block. */
    uint64_t bytes;                     /**< Bytes hashed; should probably be bits. */
    uint32_t blocks;                    /**< Number of blocks hashed. */
    uint32_t flags;                     /**< Bitwise OR of SHA1_FLAG_xxx. */
} sha1_t;

#define SHA1_INIT_FLAGS(_flags)  \
    { { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 },   \
        {0}, 0, 0, _flags }

#define SHA1_INIT()    SHA1_INIT_FLAGS(SHA1_FLAGS_DEFAULT)

extern const sha1_t sha1_initialized;     /* Global set to SHA1_INIT(). */

sha1_t* sha1_init(sha1_t* sha1);                        /* Same as *sha1 = SHA1_INIT(); */
sha1_t* sha1_init_flags(sha1_t* sha1, uint32_t flags);  /* Same as *sha1 = SHA1_INIT_FLAGS(flags); */
sha1_t* sha1_update(sha1_t* restrict sha1, const void* restrict data, size_t size);
sha1_t* sha1_end(sha1_t* sha1);
char*  sha1_text(const sha1_t* restrict sha1, char* restrict text);
char*  sha1_buffer(const void* restrict data, size_t size, char* restrict text);
char*  sha1_buffer_flags(const void* restrict data, size_t size, char* restrict text, uint32_t flags);
uint8_t* sha1_buffer_bin(const void* restrict data, size_t size, uint8_t* restrict bin);

#ifdef __cplusplus
}
#endif

#endif
