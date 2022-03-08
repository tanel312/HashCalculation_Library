#include "SHA.h"

// although Length is unsigned 64_bit, the code below processes upto unsigned 32bit. But 64-bit length is used in padding
bool SHA224_256_Compute(uint8_t* Inp, uint64_t Length, uint32_t* Hash, uint8_t Type)
{
    if (Length > UINT32_MAX)
        return false;
    uint32_t h[2][8] = {// initial values
        {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4},
        {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}}; 
    uint32_t tmp1;
    uint32_t tmp2;
    uint32_t i, j;
    uint8_t* buffer;
    uint32_t word[64];
    uint32_t block;
    dataStruct length;
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
    length.doubleword = Length * 8;
    i = 7;
    do
    {
        buffer[j - 1 - i] = length.bytes.b[i];
    } while (i--);
    block = j / 64; // 512-bit = 64 bytes
    memcpy(Hash, h[Type], sizeof(h) / 2);
    for (i = 0; i < block; i++) // process message in blocks of 512 bits
    {
        for (int j = 0; j < 16; j++) // initialization of first 16 words
        {
            word[j] = 
                ((uint32_t)(buffer[i * 64 + j * 4 + 3])) |
                ((uint32_t)(buffer[i * 64 + j * 4 + 2]) << 8) |
                ((uint32_t)(buffer[i * 64 + j * 4 + 1]) << 16) |
                ((uint32_t)(buffer[i * 64 + j * 4]) << 24);
        }
        for (j = 16; j < 64; j++) // initialization of remaining words
        {
            word[j] = 
                word[j - 16] + 
                (((word[j - 15] >> 7) | (word[j - 15] << (32 - 7))) ^ ((word[j - 15] >> 18) | (word[j - 15] << (32 - 18))) ^ (word[j - 15] >> 3)) +
                word[j - 7] + 
                (((word[j - 2] >> 17) | (word[j - 2] << (32 - 17))) ^ ((word[j - 2] >> 19) | (word[j - 2] << (32 - 19))) ^ (word[j - 2] >> 10));
        }
        memcpy(h[Type], Hash, sizeof(h) / 2);
        for (j = 0; j < 64; j++) // calculation hash
        {
            tmp1 = 
                h[Type][7] + 
                (((h[Type][4] >> 6) | (h[Type][4] << (32 - 6))) ^ ((h[Type][4] >> 11) | (h[Type][4] << (32 - 11))) ^ ((h[Type][4] >> 25) | (h[Type][4] << (32 - 25)))) +
                ((h[Type][4] & h[Type][5]) ^ ((~h[Type][4]) & h[Type][6])) +
                k224_256[j] + 
                word[j];
            tmp2 = 
                (((h[Type][0] >> 2) | (h[Type][0] << (32 - 2))) ^ ((h[Type][0] >> 13) | (h[Type][0] << (32 - 13))) ^ ((h[Type][0] >> 22) | (h[Type][0] << (32 - 22)))) +
                ((h[Type][0] & h[Type][1]) ^ (h[Type][0] & h[Type][2]) ^ (h[Type][1] & h[Type][2]));

            memcpy(&h[Type][1], &h[Type][0], 7 * sizeof(h[Type][0]));
            h[Type][0] = tmp1 + tmp2;
            h[Type][4] += tmp1;
        }
        for (j = 0; j < 8; j++)
        {
            Hash[j] += h[Type][j];
        }
    }
    free(buffer);
    return true;
}
