/* HashCalculation_Library : Defines the functions for the static library.

This file is part of HashCalculation_Library which is a free software : you can redistribute itand /or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.
HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/
#include "pch.h"

// although Length is unsigned 64_bit, the code below processes upto unsigned 32bit. But 64-bit length is used in 128-bit padding
bool SHA384_512_Compute(uint8_t* Inp, uint64_t Length, uint8_t* Hash, uint8_t Type)
{
    if (Length > UINT32_MAX)
        return false;
    uint64_t h[4][8] = { // initial values
        {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
         0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL}, // SHA384
        {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
         0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL}, // SHA512
        {0x8C3D37C819544DA2ULL, 0x73E1996689DCD4D6ULL, 0x1DFAB7AE32FF9C82ULL, 0x679DD514582F9FCFULL,
         0x0F6D2B697BD44DA8ULL, 0x77E36F7304C48942ULL, 0x3F9D85A86A1D36C8ULL, 0x1112E6AD91D692A1ULL}, // SHA512/224
        {0x22312194FC2BF72CULL, 0x9F555FA3C84C64C2ULL, 0x2393B86B6F53B151ULL, 0x963877195940EABDULL,
         0x96283EE2A88EFFE3ULL, 0xBE5E1E2553863992ULL, 0x2B0199FC2C85B8AAULL, 0x0EB72DDC81C52CA2ULL} }; // SHA512/256
    uint32_t tmp;
    uint64_t tmp1, tmp2;
    uint32_t i, j;
    uint8_t* buffer;
    data64Struct word[80];
    uint64_t block;
    data64Struct length;
    data64Struct hash[8];
    const uint8_t size[] = { 6, 8, 3, 4 };
    // Preprocessing; size adjusment, padding and storing original length
    tmp = (uint32_t)Length;
    i = Length % 128; // 1024-bit = 128 bytes
    if (i < 113) // 128 bytes - 16 bytes original length + 1 byte padding mark
        j = (128 - i) + tmp;
    else
        j = (128 - i) + tmp + 128;
    buffer = (uint8_t*)malloc(j);
    if (buffer == NULL)
        return false;
    memset(buffer, 0, j);
    memcpy(buffer, Inp, tmp);
    buffer[tmp] = 0x80;
    // length block is 2 x 64 = 128 bit, upper 64-bit assumed to be always zero
    length.w64 = Length * 8;
    i = 7;
    do
    {
        buffer[j - 1 - i] = length.bytes.b[i];
    } while (i--);
    block = j / 128; // 1024-bit = 128 bytes
    memcpy(hash, h[Type], sizeof(h[Type][0]) * 8);
    for (i = 0; i < block; i++) // process message in blocks of 1024 bits
    {
        for (j = 0; j < 16; j++) // initialization of first 16 words
        {
            for (tmp = 0; tmp < 8; tmp++)
                word[j].bytes.b[tmp] = buffer[(i * 128) + (j * 8) + (7 - tmp)]; // put in big endian form
        }
        for (j = 16; j < 80; j++) // initialization of remaining words
        {
            word[j].w64 = word[j - 16].w64 +
                (((word[j - 15].w64 >> 1) | (word[j - 15].w64 << 63)) ^ ((word[j - 15].w64 >> 8) | (word[j - 15].w64 << 56)) ^ (word[j - 15].w64 >> 7)) +
                word[j - 7].w64 +
                (((word[j - 2].w64 >> 19) | (word[j - 2].w64 << 45)) ^ ((word[j - 2].w64 >> 61) | (word[j - 2].w64 << 3)) ^ (word[j - 2].w64 >> 6));
        }
        memcpy(h[Type], hash, sizeof(h[Type][0]) * 8);
        for (j = 0; j < 80; j++) // calculation hash
        {
            tmp1 = h[Type][7] +
                (((h[Type][4] >> 14) | (h[Type][4] << 50)) ^ ((h[Type][4] >> 18) | (h[Type][4] << 46)) ^ ((h[Type][4] >> 41) | (h[Type][4] << 23))) +
                ((h[Type][4] & h[Type][5]) ^ (~h[Type][4] & h[Type][6])) +
                k384_512[j] + word[j].w64;

            tmp2 = (((h[Type][0] >> 28) | (h[Type][0] << 36)) ^ ((h[Type][0] >> 34) | (h[Type][0] << 30)) ^ ((h[Type][0] >> 39) | (h[Type][0] << 25))) +
                ((h[Type][0] & h[Type][1]) ^ (h[Type][0] & h[Type][2]) ^ (h[Type][1] & h[Type][2]));
            memcpy(&h[Type][1], &h[Type][0], 7 * sizeof(h[Type][0]));
            h[Type][0] = tmp1 + tmp2;
            h[Type][4] += tmp1;
        }
        for (j = 0; j < 8; j++)
        {
            hash[j].w64 += h[Type][j];
        }
    }
    // conversion from big endian
    for (i = 0; i < size[Type]; i++)
        for (j = 0; j < 8; j++)
            Hash[i * 8 + j] = hash[i].bytes.b[7 - j];
    if (Type == SHA512_224)
        for (j = 0; j < 8; j++)
            Hash[i * 8 + j] = hash[i].bytes.b[7 - j];
    free(buffer);
    return true;
}
