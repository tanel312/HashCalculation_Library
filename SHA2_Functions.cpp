/* HashCalculation_Library : Defines the functions for the static library.

This file contains the sha2 computation functions and is part of HashCalculation_Library which is a free software : you can redistribute it
and /or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of
the License, or any later version.

HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/

#include "pch.h"

void SHA224_256_Functions(uint8_t* Input, uint32_t* Hash, uint8_t Type)
{
    uint32_t tmp1;
    uint32_t tmp2;
    uint32_t j;
    data32Struct word[64];
    uint32_t h[8];

    memcpy(h, Hash, sizeof(h));
    // initialization of first 16 words
    for (int j = 0; j < 16; j++) // break  into sixteen 32-bit big-endian words
    {
        for (tmp1 = 0; tmp1 < 4; tmp1++)
            word[j].b[tmp1] = Input[(j * 4) + (3 - tmp1)]; // put in big endian form
    }
    // initialization of remaining words
    for (j = 16; j < 64; j++) // extend the sixteen 32-bit words into sixty four 32-bit words
    {
        word[j].w32 = // w(x) = w(x-16) + ROTR(x-15,7) ⊕ ROTR(x-15,18) ⊕ SHR(x-15,3) + w(x-7) + ROTR(x-2,17) ⊕ ROTR(x-2,19) ⊕ SHR(x-2,10)
            word[j - 16].w32 +
            (((word[j - 15].w32 >> 7) | (word[j - 15].w32 << (32 - 7))) ^ ((word[j - 15].w32 >> 18) | (word[j - 15].w32 << (32 - 18))) ^ (word[j - 15].w32 >> 3)) +
            word[j - 7].w32 +
            (((word[j - 2].w32 >> 17) | (word[j - 2].w32 << (32 - 17))) ^ ((word[j - 2].w32 >> 19) | (word[j - 2].w32 << (32 - 19))) ^ (word[j - 2].w32 >> 10));
    }
    // calculate hash
    for (j = 0; j < 64; j++)
    {
        tmp1 = // E(x) = (x+3) + ROTR(x, 6) ⊕ ROTR(x, 11) ⊕ ROTR(x, 25) +  ((x & y) ⊕ (~x & z)) + k(x)
            h[7] +
            (((h[4] >> 6) | (h[4] << (32 - 6))) ^ ((h[4] >> 11) | (h[4] << (32 - 11))) ^ ((h[4] >> 25) | (h[4] << (32 - 25)))) +
            ((h[4] & h[5]) ^ ((~h[4]) & h[6])) +
            k224_256[j] +
            word[j].w32;
        tmp2 = // E(x) = ROTR(x,2) ⊕ ROTR(x,13) ⊕ ROTR(x,22) + ((x & y) ⊕ (x & z) ⊕ (x & z))
            (((h[0] >> 2) | (h[0] << (32 - 2))) ^ ((h[0] >> 13) | (h[0] << (32 - 13))) ^ ((h[0] >> 22) | (h[0] << (32 - 22)))) +
            ((h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]));
        memcpy(&h[1], &h[0], 7 * sizeof(h[0]));
        h[0] = tmp1 + tmp2;
        h[4] += tmp1;
    }
    for (j = 0; j < 8; j++) // add to result
    {
        Hash[j] += h[j];
    }
    return;
}

void SHA384_512_Functions(uint8_t* Input, uint64_t* Hash, uint8_t Type)
{
    uint32_t tmp;
    uint64_t tmp1, tmp2;
    uint32_t j;
    data64Struct word[80];
    uint64_t h[8];
    memcpy(h, Hash, sizeof(h));
    // initialization of first 16 words
    for (j = 0; j < 16; j++)  // break  into sixteen 64-bit big-endian words
    {
        for (tmp = 0; tmp < 8; tmp++)
            word[j].b[tmp] = Input[(j * 8) + (7 - tmp)]; // put in big endian form
    }
    // initialization of remaining words
    for (j = 16; j < 80; j++) // extend the sixteen 64-bit words into eighty 64-bit words
    { 
        word[j].w64 = // w(x) = w(x-16) + ROTR(x-15,1) ⊕ ROTR(x-15,8) ⊕ SHR(x-15,7) + w(x-7) + ROTR(x-2,19) ⊕ ROTR(x-2,61) ⊕ SHR(x-2,6)
            word[j - 16].w64 +
            (((word[j - 15].w64 >> 1) | (word[j - 15].w64 << 63)) ^ ((word[j - 15].w64 >> 8) | (word[j - 15].w64 << 56)) ^ (word[j - 15].w64 >> 7)) +
            word[j - 7].w64 +
            (((word[j - 2].w64 >> 19) | (word[j - 2].w64 << 45)) ^ ((word[j - 2].w64 >> 61) | (word[j - 2].w64 << 3)) ^ (word[j - 2].w64 >> 6));
    }
    memcpy(h, Hash, sizeof(h));
    // calculate hash
    for (j = 0; j < 80; j++)
    {
        tmp1 =  // E(x) = (x+3) + ROTR(x, 14) ⊕ ROTR(x, 18) ⊕ ROTR(x, 41) +  ((x & y) ⊕ (~x & z)) + k(x) + w(x)
            h[7] +
            (((h[4] >> 14) | (h[4] << 50)) ^ ((h[4] >> 18) | (h[4] << 46)) ^ ((h[4] >> 41) | (h[4] << 23))) +
            ((h[4] & h[5]) ^ (~h[4] & h[6])) +
            k384_512[j] + word[j].w64;

        tmp2 = // E(x) = ROTR(x,28) ⊕ ROTR(x,34) ⊕ ROTR(x,39) + ((x & y) ⊕ (x & z) ⊕ (x & z))
            (((h[0] >> 28) | (h[0] << 36)) ^ ((h[0] >> 34) | (h[0] << 30)) ^ ((h[0] >> 39) | (h[0] << 25))) +
            ((h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]));
        memcpy(&h[1], &h[0], 7 * sizeof(h[0]));
        h[0] = tmp1 + tmp2;
        h[4] += tmp1;
    }
    for (j = 0; j < 8; j++) // add to result
    {
        Hash[j] += h[j];
    }
    return;
}
