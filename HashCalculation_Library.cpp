/* HashCalculation_Library : Defines the functions for the static library.

This file is part of HashCalculation_Library which is a free software : you can redistribute itand /or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.
HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/

#include "pch.h"

// compute a SHA hash
void SHA01_Compute(const uint8_t* Input, uint64_t Length, uint8_t* SHA, uint8_t Type)
{
    int i, j;
    uint32_t h[] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }; // initial values
    data32Struct hash[5];
    data512bit buff; // 512bit buffer
    data64Struct length;
    int remain, block;
    memset(&buff.b[0], 0, 64); // clear block of 512bits
    remain = (int)Length % BLOCK512;
    block = (int)Length / BLOCK512;
    for (i = 0; i < block; i++)
    {
        memcpy(&buff.b[0], Input + (i * BLOCK512), BLOCK512);
        SHA01_Functions(buff.b, h, Type);
    }
    // last block
    memset(&buff.b[0], 0, 64); // clear block of 512bits
    memcpy(&buff.b[0], Input + (i * BLOCK512), remain);
    if (remain > 56)
    {
        SHA01_Functions(buff.b, h, Type);
        memset(&buff.b[0], 0, 64); // clear block of 512bits
    }
    length.w64 = Length * 8;
    i = 7;
    do
    {
        buff.b[BLOCK512 - 1 - i] |= length.b[i];
    } while (i--);
    buff.b[remain] |= 0x80; // there is always space for 0x80
    SHA01_Functions(&buff.b[0], h, Type);
    // conversion from big endian
    memcpy(hash, h, sizeof(h));
    for (i = 0; i < 5; i++)
        for (j = 0; j < 4; j++)
            SHA[i * 4 + j] = hash[i].b[3 - j];
    return;
}

void SHA224_256_Compute(const uint8_t* Input, uint64_t Length, uint8_t* SHA, uint8_t Type)
{
    int i, j;
    uint32_t h[2][8] = {// initial values
        {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4},
        {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} };
    data32Struct hash[8];
    const uint8_t size[] = { 7,8 };
    data512bit buff; // 512bit buffer
    data64Struct length;
    int remain, block;
    memset(&buff.b[0], 0, BLOCK512); // clear block of 512bits
    remain = (int)Length % BLOCK512;
    block = (int)Length / BLOCK512;
    for (i = 0; i < block; i++)
    {
        memcpy(&buff.b[0], Input + (i * BLOCK512), BLOCK512);
        SHA224_256_Functions(buff.b, h[Type], Type);
    }
    // last block
    memset(&buff.b[0], 0, BLOCK512); // clear block of 512bits
    memcpy(&buff.b[0], Input + (i * BLOCK512), remain);
    if (remain > 56) // reserve 8 bytes to store original message length (64 - 8)
    {
        SHA224_256_Functions(buff.b, h[Type], Type);
        memset(&buff.b[0], 0, BLOCK512); // clear block of 512bits
    }
// append original message length in bits, as a 64-bit big-endian integer
    length.w64 = Length * 8;
    i = 7;
    do
    {
        buff.b[BLOCK512 - 1 - i] |= length.b[i];
    } while (i--);
    buff.b[remain] |= 0x80; // append bit '1' to message
    SHA224_256_Functions(&buff.b[0], h[Type], Type);
    // conversion from big endian
    memcpy(hash, h[Type], sizeof(h)/2);
    for (i = 0; i < size[Type]; i++)
        for (j = 0; j < 4; j++)
            SHA[i * 4 + j] = hash[i].b[3 - j];
    return;
}


void SHA384_512_Compute(const uint8_t* Input, uint64_t Length, uint8_t* SHA, uint8_t Type)
{
    int i, j;
    uint64_t h[4][8] = { // initial values
        {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
         0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL}, // SHA384
        {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
         0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL}, // SHA512
        {0x8C3D37C819544DA2ULL, 0x73E1996689DCD4D6ULL, 0x1DFAB7AE32FF9C82ULL, 0x679DD514582F9FCFULL,
         0x0F6D2B697BD44DA8ULL, 0x77E36F7304C48942ULL, 0x3F9D85A86A1D36C8ULL, 0x1112E6AD91D692A1ULL}, // SHA512/224
        {0x22312194FC2BF72CULL, 0x9F555FA3C84C64C2ULL, 0x2393B86B6F53B151ULL, 0x963877195940EABDULL,
         0x96283EE2A88EFFE3ULL, 0xBE5E1E2553863992ULL, 0x2B0199FC2C85B8AAULL, 0x0EB72DDC81C52CA2ULL} }; // SHA512/256
    data64Struct hash[8];
    const uint8_t size[] = { 6, 8, 3, 4 };
    data1024bit buff; // 1024bit buffer
    data64Struct length;
    int remain, block;
    memset(&buff.b[0], 0, BLOCK1024); // clear block of 512bits
    remain = (int)Length % BLOCK1024;
    block = (int)Length / BLOCK1024;
    for (i = 0; i < block; i++)
    {
        memcpy(&buff.b[0], Input + (i * BLOCK1024), BLOCK1024);
        SHA384_512_Functions(buff.b, h[Type], Type);
    }
    // last block
    memset(&buff.b[0], 0, BLOCK1024); // clear block of 1024bits
    memcpy(&buff.b[0], Input + (i * BLOCK1024), remain);
    if (remain > 114) // reserve 16 bytes to store original message length (128 - 16)
    {
        SHA384_512_Functions(buff.b, h[Type], Type);
        memset(&buff.b[0], 0, BLOCK1024); // clear block of 1024bits
    }
    length.w64 = Length * 8;
    i = 7;
    do
    {
        buff.b[BLOCK1024 - 1 - i] |= length.b[i];
    } while (i--);
    buff.b[remain] |= 0x80; // append bit '1' to message
    SHA384_512_Functions(&buff.b[0], h[Type], Type);
    // conversion from big endian
    memcpy(hash, h[Type], sizeof(h) / 4);
    // conversion from big endian
    for (i = 0; i < size[Type]; i++)
        for (j = 0; j < 8; j++)
            SHA[i * 8 + j] = hash[i].b[7 - j];
    if (Type == VARIANTSHA512_224)
        for (j = 0; j < 8; j++)
            SHA[i * 8 + j] = hash[i].b[7 - j];
    return;
}

// compute a SHA-3 and SHAKE hash
void SHA3_Shake_Compute(const uint8_t* Input, uint64_t Length, uint8_t* SHA, int SHAsize, uint8_t Type)
{
    data1600bit buff;
    int remain, block;
    int rate;
    int i;
    memset(SHA, 0, SHAsize); //clear sha buffer
    memset(&buff.w64[0], 0, BLOCK1600); // clear block of 1600bits
    i = SHAsize;
    if (Type == VARIANTSHAKE128)
        i = 16;
    if (Type == VARIANTSHAKE256)
        i = 32;
    rate = BLOCK1600 - 2 * i; // rate = 1600 - 2 x output size
    remain = Length % rate;
    block = (int)(Length / rate);
    for (i = 0; i < block; i++)
    {
        for (int j = 0; j < rate; j++)
            buff.b[j] ^= Input[(i * rate) + j];
        SHA3_Functions(buff.w64);
    }
    // last block
    for (int i = 0; i < remain; i++)
        buff.b[i] ^= Input[(block * rate) + i];
    if (Type == SHA3)
        buff.b[remain] ^= 0x06; // append bits '110' to message
    else
        buff.b[remain] ^= 0x1F; // append bits '111111' to message
    buff.b[rate - 1] ^= 0x80;
    SHA3_Functions(buff.w64);

    i = SHAsize;
    if (SHAsize > 168 && Type == VARIANTSHAKE128) // for 1600 bit, output is limited to 1344 bit
        i = 168;
    if (SHAsize > 136 && Type == VARIANTSHAKE256) // for 1600 bit, output is limited to 1088 bit
        i = 136;
    memcpy(SHA, &buff.b[0], i * sizeof(buff.b[0]));
    return;
}
