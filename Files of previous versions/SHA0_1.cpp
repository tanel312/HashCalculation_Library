/* HashCalculation_Library : Defines the functions for the static library.

This file is part of HashCalculation_Library which is a free software : you can redistribute itand /or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.
HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/
#include "pch.h"

// although Length is unsigned 64_bit, the code below processes upto unsigned 32bit. But 64-bit length is used in padding
bool SHA01_Compute(uint8_t* Inp, uint64_t Length, uint8_t* Hash, uint8_t Type)
{
    if (Length > UINT32_MAX)
        return false;
    uint32_t h[] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }; // initial values
    uint32_t f; // functions
    uint32_t tmp;
    uint8_t index;
    uint32_t i, j;
    uint8_t* buffer;
    data32Struct word[80];
    uint32_t block;
    data64Struct length;
    data32Struct hash[5];
    // Preprocessing; size adjusment, padding and storing original length
    tmp = (uint32_t)Length;
    i = Length % 64; // 512-bit = 64 bytes
    if (i < 57) // 64 bytes - 8 bytes original length + 1 byte padding mark
        j = (64 - i) + tmp;
    else
        j = (64 - i) + tmp + 64;
    buffer = (uint8_t*)malloc(j);
    if (buffer == NULL)
        return false;
    memset(buffer, 0, j);
    memcpy(buffer, Inp, tmp);
    buffer[tmp] = 0x80;
    length.w64 = Length * 8;
    i = 7;
    do
    {
        buffer[j - 1 - i] = length.bytes.b[i];
    } while (i--);
    block = j / 64; // 512-bit = 64 bytes
    memcpy(hash, h, sizeof(h));
    for (i = 0; i < block; i++) // process message in blocks of 512 bits
    {
        for (int j = 0; j < 16; j++) // initialization of first 16 words
        {
            for (tmp = 0; tmp < 4; tmp++)
                word[j].bytes.b[tmp] = buffer[(i * 64) + (j * 4) + (3 - tmp)]; // put in big endian form
        }
        for (j = 16; j < 80; j++) // initialization of remaining words
        {
            tmp = (word[j - 3].w32 ^ word[j - 8].w32 ^ word[j - 14].w32 ^ word[j - 16].w32);
            if (Type == SHA1) // Hash 1
                word[j].w32 = ((tmp << 1) | (tmp >> (31)));
            else // Hash 0
                word[j].w32 = tmp;
        }
        memcpy(h, hash, sizeof(h));
        for (j = 0; j < 80; j++) // calculation hash
        {
            index = j / 20;
            switch (index)
            {
            case 0:
                f = h[3] ^ (h[1] & (h[2] ^ h[3]));
                break;
            case 1:
                f = h[1] ^ h[2] ^ h[3];
                break;
            case 2:
                f = (h[1] & h[2]) | (h[1] & h[3]) | (h[2] & h[3]);
                break;
            case 3:
                f = h[1] ^ h[2] ^ h[3];
                break;
            }
            tmp = (((h[0] << 5) | (h[0] >> 27)) + f + h[4] + k0_1[index] + word[j].w32);
            h[4] = h[3];
            h[3] = h[2];
            h[2] = (h[1] << 30) | (h[1] >> 2);
            h[1] = h[0];
            h[0] = tmp;
        }
        for (j = 0; j < 5; j++)
        {
            hash[j].w32 += h[j];
        }
    }
    // conversion from big endian
    for (i = 0; i < 5; i++)
        for (j = 0; j < 4; j++)
            Hash[i * 4 + j] = hash[i].bytes.b[3 - j];
    free(buffer);
    return true;
}
