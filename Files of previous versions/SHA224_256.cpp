/* HashCalculation_Library : Defines the functions for the static library.

This file is part of HashCalculation_Library which is a free software : you can redistribute itand /or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.
HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/
#include "pch.h"

// although Length is unsigned 64_bit, the code below processes upto unsigned 32bit. But 64-bit length is used in padding
bool SHA224_256_Compute(uint8_t* Inp, uint64_t Length, uint8_t* Hash, uint8_t Type)
{
    if (Length > UINT32_MAX)
        return false;
    uint32_t h[2][8] = {// initial values
        {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4},
        {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} };
    uint32_t tmp1;
    uint32_t tmp2;
    uint32_t i, j;
    uint8_t* buffer;
    data32Struct word[64];
    uint32_t block;
    data64Struct length;
    data32Struct hash[8];
    const uint8_t size[] = { 7,8 };
    // Preprocessing; size adjusment, padding and storing original length
    tmp1 = (uint32_t)Length;
    i = Length % 64; // 512-bit = 64 bytes
    if (i < 57) // 64 bytes - 8 bytes original length + 1 byte padding mark
        j = (64 - i) + tmp1;
    else
        j = (64 - i) + tmp1 + 64;
    buffer = (uint8_t*)malloc(j);
    if (buffer == NULL)
        return false;
    memset(buffer, 0, j);
    memcpy(buffer, Inp, tmp1);
    buffer[tmp1] = 0x80;
    length.w64 = Length * 8;
    i = 7;
    do
    {
        buffer[j - 1 - i] = length.bytes.b[i];
    } while (i--);
    block = j / 64; // 512-bit = 64 bytes
    memcpy(hash, h[Type], sizeof(h) / 2);
    for (i = 0; i < block; i++) // process message in blocks of 512 bits
    {
        for (int j = 0; j < 16; j++) // initialization of first 16 words
        {
            for (tmp1 = 0; tmp1 < 4; tmp1++)
                word[j].bytes.b[tmp1] = buffer[(i * 64) + (j * 4) + (3 - tmp1)]; // put in big endian form
        }
        for (j = 16; j < 64; j++) // initialization of remaining words
        {
            word[j].w32 =
                word[j - 16].w32 +
                (((word[j - 15].w32 >> 7) | (word[j - 15].w32 << (32 - 7))) ^ ((word[j - 15].w32 >> 18) | (word[j - 15].w32 << (32 - 18))) ^ (word[j - 15].w32 >> 3)) +
                word[j - 7].w32 +
                (((word[j - 2].w32 >> 17) | (word[j - 2].w32 << (32 - 17))) ^ ((word[j - 2].w32 >> 19) | (word[j - 2].w32 << (32 - 19))) ^ (word[j - 2].w32 >> 10));
        }
        memcpy(h[Type], hash, sizeof(h) / 2);
        for (j = 0; j < 64; j++) // calculation hash
        {
            tmp1 =
                h[Type][7] +
                (((h[Type][4] >> 6) | (h[Type][4] << (32 - 6))) ^ ((h[Type][4] >> 11) | (h[Type][4] << (32 - 11))) ^ ((h[Type][4] >> 25) | (h[Type][4] << (32 - 25)))) +
                ((h[Type][4] & h[Type][5]) ^ ((~h[Type][4]) & h[Type][6])) +
                k224_256[j] +
                word[j].w32;
            tmp2 =
                (((h[Type][0] >> 2) | (h[Type][0] << (32 - 2))) ^ ((h[Type][0] >> 13) | (h[Type][0] << (32 - 13))) ^ ((h[Type][0] >> 22) | (h[Type][0] << (32 - 22)))) +
                ((h[Type][0] & h[Type][1]) ^ (h[Type][0] & h[Type][2]) ^ (h[Type][1] & h[Type][2]));

            memcpy(&h[Type][1], &h[Type][0], 7 * sizeof(h[Type][0]));
            h[Type][0] = tmp1 + tmp2;
            h[Type][4] += tmp1;
        }
        for (j = 0; j < 8; j++)
        {
            hash[j].w32 += h[Type][j];
        }
    }
    // conversion from big endian
    for (i = 0; i < size[Type]; i++)
        for (j = 0; j < 4; j++)
            Hash[i * 4 + j] = hash[i].bytes.b[3 - j];
    free(buffer);
    return true;
}
