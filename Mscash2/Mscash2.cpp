/* Domain Cached Credentials 2 (MSCash2) example
 * written by S3nf <thes3nf at googlemail.com> in 2010
 * a slow but working implementation
 *
 * Generating Domain Cached Credentials for modern Windows operating systems, supporting:
 *     - Windows Vista
 *     - Windows 7
 *     - Windows Server 2008
 *
 * This software is based on:
 *     - the MSCASH patch for john written by Alain Espinosa <alainesp at gmail.com> in 2007
 *     - RFC 1320 - The MD4 Message-Digest Algorithm
 *     - RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
 *     - RFC 3174 - US Secure Hash Algorithm 1 (SHA1)
 *     - the HMAC-SHA1 implementation of the PolarSSL open source cryptagraphic library (http://polarssl.org/)
 *
 * This software was written by S3nf in 2010. No copyright is claimed, and the software is hereby placed in
 * the public domain. In case this attempt to disclaim copyright and place the software in the public domain
 * is deemed null and void, then the software is Copyright (c) 2010 S3nf and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mscash2_fmt_plug.h"

#define ITERATIONS                  10240

#define INIT_MD4_A                  0x67452301
#define INIT_MD4_B                  0xefcdab89
#define INIT_MD4_C                  0x98badcfe
#define INIT_MD4_D                  0x10325476

#define SQRT_2                      0x5a827999
#define SQRT_3                      0x6ed9eba1

#define SHA1_DIGEST_LENGTH          20

#define INIT_SHA1_A                 0x67452301
#define INIT_SHA1_B                 0xEFCDAB89
#define INIT_SHA1_C                 0x98BADCFE
#define INIT_SHA1_D                 0x10325476
#define INIT_SHA1_E                 0xC3D2E1F0

#ifndef GET_WORD_32_BE
#define GET_WORD_32_BE(n,b,i)                           \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_WORD_32_BE
#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

#define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

#define R(t)                                            \
(                                                       \
    temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^     \
           W[(t - 14) & 0x0F] ^ W[ t      & 0x0F],      \
    ( W[t & 0x0F] = S(temp,1) )                         \
)

#define P(a,b,c,d,e,x)                                  \
{                                                       \
    e += S(a,5) + F(b,c,d) + K + x; b = S(b,30);        \
}


 /*
  * byte2hexstring
  * convert byte array to hex string
  */
unsigned char* byte2hexstring(unsigned char* byte, unsigned int len) {
    unsigned int i;
    unsigned char* hexstring;

    hexstring = (unsigned char*)malloc(len * 2 + 1);
    memset(hexstring, 0, 2 * len + 1);

    for (i = 0; i < len; i++)
        sprintf((char*) & hexstring[2 * i], "%02x", byte[i]);

    return hexstring;
}


/*
 * hmac_sha1
 * based on RFC 2104, RFC 3174 and the HMAC-SHA1 implementation of the PolarSSL
 * open source cryptographic library (http://www.polarssl.org)
 */
static void hmac_sha1(const unsigned char* key, unsigned int keylen, const unsigned char* input, unsigned int inputlen, unsigned char* output)
{
    unsigned int i, temp, W[16];
    unsigned int A, B, C, D, E, state[5];
    unsigned char buf[64];
    unsigned char ipad[64];
    unsigned char opad[64];

    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);
    memset(buf, 0, 64);

    // step 1: append zeros to the end of K to create a B Byte string
    memcpy(buf, input, inputlen);
    buf[inputlen] = 0x80;
    PUT_WORD_32_BE((64 + inputlen) << 3, buf, 60);

    // step 2: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with ipad
    // step 5: XOR (bitwise exclusive-OR) the B byte string computed in step 1 with opad    
    for (i = 0; i < keylen; i++)
    {
        ipad[i] = ipad[i] ^ key[i];
        opad[i] = opad[i] ^ key[i];
    }

    // step 3: append the stream of data 'text' to the B byte sting resulting from step 2
    // first part of stream (64 bytes) is ipad, second part of stream (64 bytes) is buf

    // step 4: apply H to the stream (ipad & buf) generated in step 3
    GET_WORD_32_BE(W[0], ipad, 0);
    GET_WORD_32_BE(W[1], ipad, 4);
    GET_WORD_32_BE(W[2], ipad, 8);
    GET_WORD_32_BE(W[3], ipad, 12);
    GET_WORD_32_BE(W[4], ipad, 16);
    GET_WORD_32_BE(W[5], ipad, 20);
    GET_WORD_32_BE(W[6], ipad, 24);
    GET_WORD_32_BE(W[7], ipad, 28);
    GET_WORD_32_BE(W[8], ipad, 32);
    GET_WORD_32_BE(W[9], ipad, 36);
    GET_WORD_32_BE(W[10], ipad, 40);
    GET_WORD_32_BE(W[11], ipad, 44);
    GET_WORD_32_BE(W[12], ipad, 48);
    GET_WORD_32_BE(W[13], ipad, 52);
    GET_WORD_32_BE(W[14], ipad, 56);
    GET_WORD_32_BE(W[15], ipad, 60);

    A = INIT_SHA1_A;
    B = INIT_SHA1_B;
    C = INIT_SHA1_C;
    D = INIT_SHA1_D;
    E = INIT_SHA1_E;

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    P(A, B, C, D, E, W[0]);
    P(E, A, B, C, D, W[1]);
    P(D, E, A, B, C, W[2]);
    P(C, D, E, A, B, W[3]);
    P(B, C, D, E, A, W[4]);
    P(A, B, C, D, E, W[5]);
    P(E, A, B, C, D, W[6]);
    P(D, E, A, B, C, W[7]);
    P(C, D, E, A, B, W[8]);
    P(B, C, D, E, A, W[9]);
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));

#undef K
#undef F

    A += INIT_SHA1_A;
    B += INIT_SHA1_B;
    C += INIT_SHA1_C;
    D += INIT_SHA1_D;
    E += INIT_SHA1_E;

    state[0] = A;
    state[1] = B;
    state[2] = C;
    state[3] = D;
    state[4] = E;

    // process buf (2nd part of stream)
    GET_WORD_32_BE(W[0], buf, 0);
    GET_WORD_32_BE(W[1], buf, 4);
    GET_WORD_32_BE(W[2], buf, 8);
    GET_WORD_32_BE(W[3], buf, 12);
    GET_WORD_32_BE(W[4], buf, 16);
    GET_WORD_32_BE(W[5], buf, 20);
    GET_WORD_32_BE(W[6], buf, 24);
    GET_WORD_32_BE(W[7], buf, 28);
    GET_WORD_32_BE(W[8], buf, 32);
    GET_WORD_32_BE(W[9], buf, 36);
    GET_WORD_32_BE(W[10], buf, 40);
    GET_WORD_32_BE(W[11], buf, 44);
    GET_WORD_32_BE(W[12], buf, 48);
    GET_WORD_32_BE(W[13], buf, 52);
    GET_WORD_32_BE(W[14], buf, 56);
    GET_WORD_32_BE(W[15], buf, 60);

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    P(A, B, C, D, E, W[0]);
    P(E, A, B, C, D, W[1]);
    P(D, E, A, B, C, W[2]);
    P(C, D, E, A, B, W[3]);
    P(B, C, D, E, A, W[4]);
    P(A, B, C, D, E, W[5]);
    P(E, A, B, C, D, W[6]);
    P(D, E, A, B, C, W[7]);
    P(C, D, E, A, B, W[8]);
    P(B, C, D, E, A, W[9]);
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));

#undef K
#undef F

    A += state[0];
    B += state[1];
    C += state[2];
    D += state[3];
    E += state[4];

    PUT_WORD_32_BE(A, buf, 0);
    PUT_WORD_32_BE(B, buf, 4);
    PUT_WORD_32_BE(C, buf, 8);
    PUT_WORD_32_BE(D, buf, 12);
    PUT_WORD_32_BE(E, buf, 16);

    buf[20] = 0x80;
    PUT_WORD_32_BE(0x2A0, buf, 60);

    // step 6: append the stream of data 'text' to the B byte sting resulting from step 2
    // first part of stream (64 bytes) is opad, second part of stream (64 bytes) is the H result from step 4

    // step 7: apply H to the stream (opad & buf) generated in step 6 and output the result
    GET_WORD_32_BE(W[0], opad, 0);
    GET_WORD_32_BE(W[1], opad, 4);
    GET_WORD_32_BE(W[2], opad, 8);
    GET_WORD_32_BE(W[3], opad, 12);
    GET_WORD_32_BE(W[4], opad, 16);
    GET_WORD_32_BE(W[5], opad, 20);
    GET_WORD_32_BE(W[6], opad, 24);
    GET_WORD_32_BE(W[7], opad, 28);
    GET_WORD_32_BE(W[8], opad, 32);
    GET_WORD_32_BE(W[9], opad, 36);
    GET_WORD_32_BE(W[10], opad, 40);
    GET_WORD_32_BE(W[11], opad, 44);
    GET_WORD_32_BE(W[12], opad, 48);
    GET_WORD_32_BE(W[13], opad, 52);
    GET_WORD_32_BE(W[14], opad, 56);
    GET_WORD_32_BE(W[15], opad, 60);

    A = INIT_SHA1_A;
    B = INIT_SHA1_B;
    C = INIT_SHA1_C;
    D = INIT_SHA1_D;
    E = INIT_SHA1_E;

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    P(A, B, C, D, E, W[0]);
    P(E, A, B, C, D, W[1]);
    P(D, E, A, B, C, W[2]);
    P(C, D, E, A, B, W[3]);
    P(B, C, D, E, A, W[4]);
    P(A, B, C, D, E, W[5]);
    P(E, A, B, C, D, W[6]);
    P(D, E, A, B, C, W[7]);
    P(C, D, E, A, B, W[8]);
    P(B, C, D, E, A, W[9]);
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));

#undef K
#undef F

    A += INIT_SHA1_A;
    B += INIT_SHA1_B;
    C += INIT_SHA1_C;
    D += INIT_SHA1_D;
    E += INIT_SHA1_E;

    // store state for 2nd part
    state[0] = A;
    state[1] = B;
    state[2] = C;
    state[3] = D;
    state[4] = E;

    GET_WORD_32_BE(W[0], buf, 0);
    GET_WORD_32_BE(W[1], buf, 4);
    GET_WORD_32_BE(W[2], buf, 8);
    GET_WORD_32_BE(W[3], buf, 12);
    GET_WORD_32_BE(W[4], buf, 16);
    GET_WORD_32_BE(W[5], buf, 20);
    GET_WORD_32_BE(W[6], buf, 24);
    GET_WORD_32_BE(W[7], buf, 28);
    GET_WORD_32_BE(W[8], buf, 32);
    GET_WORD_32_BE(W[9], buf, 36);
    GET_WORD_32_BE(W[10], buf, 40);
    GET_WORD_32_BE(W[11], buf, 44);
    GET_WORD_32_BE(W[12], buf, 48);
    GET_WORD_32_BE(W[13], buf, 52);
    GET_WORD_32_BE(W[14], buf, 56);
    GET_WORD_32_BE(W[15], buf, 60);

#define F(x,y,z) (z ^ (x & (y ^ z)))
#define K 0x5A827999

    P(A, B, C, D, E, W[0]);
    P(E, A, B, C, D, W[1]);
    P(D, E, A, B, C, W[2]);
    P(C, D, E, A, B, W[3]);
    P(B, C, D, E, A, W[4]);
    P(A, B, C, D, E, W[5]);
    P(E, A, B, C, D, W[6]);
    P(D, E, A, B, C, W[7]);
    P(C, D, E, A, B, W[8]);
    P(B, C, D, E, A, W[9]);
    P(A, B, C, D, E, W[10]);
    P(E, A, B, C, D, W[11]);
    P(D, E, A, B, C, W[12]);
    P(C, D, E, A, B, W[13]);
    P(B, C, D, E, A, W[14]);
    P(A, B, C, D, E, W[15]);
    P(E, A, B, C, D, R(16));
    P(D, E, A, B, C, R(17));
    P(C, D, E, A, B, R(18));
    P(B, C, D, E, A, R(19));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0x6ED9EBA1

    P(A, B, C, D, E, R(20));
    P(E, A, B, C, D, R(21));
    P(D, E, A, B, C, R(22));
    P(C, D, E, A, B, R(23));
    P(B, C, D, E, A, R(24));
    P(A, B, C, D, E, R(25));
    P(E, A, B, C, D, R(26));
    P(D, E, A, B, C, R(27));
    P(C, D, E, A, B, R(28));
    P(B, C, D, E, A, R(29));
    P(A, B, C, D, E, R(30));
    P(E, A, B, C, D, R(31));
    P(D, E, A, B, C, R(32));
    P(C, D, E, A, B, R(33));
    P(B, C, D, E, A, R(34));
    P(A, B, C, D, E, R(35));
    P(E, A, B, C, D, R(36));
    P(D, E, A, B, C, R(37));
    P(C, D, E, A, B, R(38));
    P(B, C, D, E, A, R(39));

#undef K
#undef F

#define F(x,y,z) ((x & y) | (z & (x | y)))
#define K 0x8F1BBCDC

    P(A, B, C, D, E, R(40));
    P(E, A, B, C, D, R(41));
    P(D, E, A, B, C, R(42));
    P(C, D, E, A, B, R(43));
    P(B, C, D, E, A, R(44));
    P(A, B, C, D, E, R(45));
    P(E, A, B, C, D, R(46));
    P(D, E, A, B, C, R(47));
    P(C, D, E, A, B, R(48));
    P(B, C, D, E, A, R(49));
    P(A, B, C, D, E, R(50));
    P(E, A, B, C, D, R(51));
    P(D, E, A, B, C, R(52));
    P(C, D, E, A, B, R(53));
    P(B, C, D, E, A, R(54));
    P(A, B, C, D, E, R(55));
    P(E, A, B, C, D, R(56));
    P(D, E, A, B, C, R(57));
    P(C, D, E, A, B, R(58));
    P(B, C, D, E, A, R(59));

#undef K
#undef F

#define F(x,y,z) (x ^ y ^ z)
#define K 0xCA62C1D6

    P(A, B, C, D, E, R(60));
    P(E, A, B, C, D, R(61));
    P(D, E, A, B, C, R(62));
    P(C, D, E, A, B, R(63));
    P(B, C, D, E, A, R(64));
    P(A, B, C, D, E, R(65));
    P(E, A, B, C, D, R(66));
    P(D, E, A, B, C, R(67));
    P(C, D, E, A, B, R(68));
    P(B, C, D, E, A, R(69));
    P(A, B, C, D, E, R(70));
    P(E, A, B, C, D, R(71));
    P(D, E, A, B, C, R(72));
    P(C, D, E, A, B, R(73));
    P(B, C, D, E, A, R(74));
    P(A, B, C, D, E, R(75));
    P(E, A, B, C, D, R(76));
    P(D, E, A, B, C, R(77));
    P(C, D, E, A, B, R(78));
    P(B, C, D, E, A, R(79));

#undef K
#undef F

    A += state[0];
    B += state[1];
    C += state[2];
    D += state[3];
    E += state[4];

    PUT_WORD_32_BE(A, output, 0);
    PUT_WORD_32_BE(B, output, 4);
    PUT_WORD_32_BE(C, output, 8);
    PUT_WORD_32_BE(D, output, 12);
    PUT_WORD_32_BE(E, output, 16);
}


/* PBKDF2
 * stripped-down implementation
 * based on the source code written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL Project 1999
 */
static void PBKDF2_DCC2(const unsigned char* pass, const unsigned char* salt, int saltlen, unsigned char* out)
{
    unsigned char temp[SHA1_DIGEST_LENGTH];
    unsigned char buf[48];
    unsigned int i;

    memset(buf, 0, 48);
    memcpy(buf, salt, saltlen);
    buf[saltlen + 3] = 0x01;

    hmac_sha1(pass, 16, buf, saltlen + 4, temp);

    memcpy(out, temp, 16);

    for (i = 0; i <= ITERATIONS; i++)
    {
        hmac_sha1(pass, 16, temp, SHA1_DIGEST_LENGTH, temp);

        out[0] ^= temp[0];
        out[1] ^= temp[1];
        out[2] ^= temp[2];
        out[3] ^= temp[3];
        out[4] ^= temp[4];
        out[5] ^= temp[5];
        out[6] ^= temp[6];
        out[7] ^= temp[7];
        out[8] ^= temp[8];
        out[9] ^= temp[9];
        out[10] ^= temp[10];
        out[11] ^= temp[11];
        out[12] ^= temp[12];
        out[13] ^= temp[13];
        out[14] ^= temp[14];
        out[15] ^= temp[15];
        // out[16] ^= temp[16]; // - was a bug?


        if (i >= 10230)
        {
            printf("DCC2 aka M$ Cache 2: %s\n", byte2hexstring((unsigned char*)out, 16));
        }
    }
}



// MD4 compression function
void md4_crypt(unsigned int* buffer, unsigned int* hash)
{
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int d;

    // round 1
    a = 0xFFFFFFFF + buffer[0]; a = (a << 3) | (a >> 29);
    d = INIT_MD4_D + (INIT_MD4_C ^ (a & 0x77777777)) + buffer[1]; d = (d << 7) | (d >> 25);
    c = INIT_MD4_C + (INIT_MD4_B ^ (d & (a ^ INIT_MD4_B))) + buffer[2]; c = (c << 11) | (c >> 21);
    b = INIT_MD4_B + (a ^ (c & (d ^ a))) + buffer[3]; b = (b << 19) | (b >> 13);

    a += (d ^ (b & (c ^ d))) + buffer[4];  a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))) + buffer[5];  d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))) + buffer[6];  c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))) + buffer[7];  b = (b << 19) | (b >> 13);

    a += (d ^ (b & (c ^ d))) + buffer[8];  a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))) + buffer[9];  d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))) + buffer[10];  c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))) + buffer[11];  b = (b << 19) | (b >> 13);

    a += (d ^ (b & (c ^ d))) + buffer[12]; a = (a << 3) | (a >> 29);
    d += (c ^ (a & (b ^ c))) + buffer[13]; d = (d << 7) | (d >> 25);
    c += (b ^ (d & (a ^ b))) + buffer[14]; c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a))) + buffer[15]; b = (b << 19) | (b >> 13);

    // round 2
    a += ((b & (c | d)) | (c & d)) + buffer[0] + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + buffer[4] + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + buffer[8] + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + buffer[12] + SQRT_2; b = (b << 13) | (b >> 19);

    a += ((b & (c | d)) | (c & d)) + buffer[1] + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + buffer[5] + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + buffer[9] + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + buffer[13] + SQRT_2; b = (b << 13) | (b >> 19);

    a += ((b & (c | d)) | (c & d)) + buffer[2] + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + buffer[6] + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + buffer[10] + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + buffer[14] + SQRT_2; b = (b << 13) | (b >> 19);

    a += ((b & (c | d)) | (c & d)) + buffer[3] + SQRT_2; a = (a << 3) | (a >> 29);
    d += ((a & (b | c)) | (b & c)) + buffer[7] + SQRT_2; d = (d << 5) | (d >> 27);
    c += ((d & (a | b)) | (a & b)) + buffer[11] + SQRT_2; c = (c << 9) | (c >> 23);
    b += ((c & (d | a)) | (d & a)) + buffer[15] + SQRT_2; b = (b << 13) | (b >> 19);

    // round 3
    a += (d ^ c ^ b) + buffer[0] + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + buffer[8] + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + buffer[4] + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + buffer[12] + SQRT_3; b = (b << 15) | (b >> 17);

    a += (d ^ c ^ b) + buffer[2] + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + buffer[10] + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + buffer[6] + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + buffer[14] + SQRT_3; b = (b << 15) | (b >> 17);

    a += (d ^ c ^ b) + buffer[1] + SQRT_3; a = (a << 3) | (a >> 29);
    d += (c ^ b ^ a) + buffer[9] + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + buffer[5] + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + buffer[13] + SQRT_3; b = (b << 15) | (b >> 17);

    a += (d ^ c ^ b) + buffer[3] + SQRT_3; a = (a << 3) | (a >> 29);

    d += (c ^ b ^ a) + buffer[11] + SQRT_3; d = (d << 9) | (d >> 23);
    c += (b ^ a ^ d) + buffer[7] + SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + buffer[15] + SQRT_3; b = (b << 15) | (b >> 17);

    hash[0] = a + INIT_MD4_A;
    hash[1] = b + INIT_MD4_B;
    hash[2] = c + INIT_MD4_C;
    hash[3] = d + INIT_MD4_D;
}

// main
int main(int argc, char* argv[])
{
    dcc2_tst(argc, argv);

    unsigned int i;
    unsigned int buffer[16];
    unsigned int nt_hash[16];
    unsigned int dcc_hash[16];
    unsigned int dcc2_hash[16];
    unsigned char salt[44];
    unsigned char username[] = "shimingming";
    unsigned char password[] = "Admin@123";
    unsigned int username_len = strlen((const char *)username);
    unsigned int password_len = strlen((const char*)password);

    memset(nt_hash, 0, 64);
    memset(buffer, 0, 64);
    memset(salt, 0, 44);

    // convert ASCII username to Unicode (WideChar)
    for (i = 0; i < (username_len >> 1) + 1; i++)
        ((unsigned int*)salt)[i] = username[2 * i] | (username[2 * i + 1] << 16);

    // convert ASCII password to Unicode

    for (i = 0; i < password_len >> 1; i++)
        buffer[i] = password[2 * i] | (password[2 * i + 1] << 16);

    // MD4 padding
    if (password_len % 2 == 1)
        buffer[i] = password[password_len - 1] | 0x800000;
    else
        buffer[i] = 0x80;

    // put password length at end of buffer
    buffer[14] = password_len << 4;

    // generate MD4 hash of the password (NT hash)
    md4_crypt(buffer, nt_hash);

    // concatenate NT hash and the username (salt)
    memcpy((unsigned char*)nt_hash + 16, salt, username_len << 1);

    i = username_len + 8;

    // MD4 padding
    if (username_len % 2 == 1)
        nt_hash[i >> 1] = username[username_len - 1] | 0x800000;
    else
        nt_hash[i >> 1] = 0x80;

    // put length at end of buffer
    nt_hash[14] = i << 4;

    md4_crypt(nt_hash, dcc_hash);


    // stripped-down PBKDF2 for DCC2
    PBKDF2_DCC2((unsigned char*)dcc_hash, salt, username_len << 1, (unsigned char*)dcc2_hash);

    ARCH_WORD_32  hash[1024] = {0};
    PBKDF2_DCC2_plug((const unsigned char*)dcc_hash, username, username_len << 1, (ARCH_WORD_32*)hash, 1);

    // the even slower OpenSSL PBKDF2 implementation (compile with -lssl)   
    // PKCS5_PBKDF2_HMAC_SHA1((unsigned char*)dcc_hash, 16, salt, username_len << 1, ITERATIONS, 16, (unsigned char*)dcc2_hash);

    // user credentials and DCC and DCC2 hash values
    printf("username           : %s\n", username);
    printf("password           : %s\n", password);
    printf("DCC  aka M$ Cache  : %s\n", byte2hexstring((unsigned char*)dcc_hash, 16));
    printf("DCC2 aka M$ Cache 2: %s\n", byte2hexstring((unsigned char*)dcc2_hash, 16));
    printf("PBKDF2_DCC2_plug aka M$ Cache 2: %s\n", byte2hexstring((unsigned char*)hash, 16));

    return 0;
}