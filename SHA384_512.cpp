#include "SHA.h"

// although Length is unsigned 64_bit, the code below processes upto unsigned 32bit. But 64-bit length is used in 128-bit padding
bool SHA384_512_Compute(uint8_t* Inp, uint64_t Length, uint64_t* Hash, uint8_t Type)
{
    if (Length > UINT32_MAX)
        return false;
    uint64_t h[2][8] = { // initial values
        {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
         0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL},
        {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
         0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL} };
    uint32_t tmp;
    uint64_t tmp1, tmp2;
    uint32_t i, j;
    uint8_t* buffer;
    uint64_t word[80];
    uint64_t block;
    dataStruct length;
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
    length.doubleword = Length * 8;
    i = 7;
    do
    {
        buffer[j - 1 - i] = length.bytes.b[i];
    } while (i--);
    block = j / 128; // 1024-bit = 128 bytes
    memcpy(Hash, h[Type], sizeof(h[Type][0]) * 8);
    for (i = 0; i < block; i++) // process message in blocks of 1024 bits
    {
        for (j = 0; j < 16; j++) // initialization of first 16 words
        {
            word[j] = ((uint64_t)(buffer[i * 128 + j * 8 + 7])) |
                ((uint64_t)(buffer[i * 128 + j * 8 + 6]) << 8) |
                ((uint64_t)(buffer[i * 128 + j * 8 + 5]) << 16) |
                ((uint64_t)(buffer[i * 128 + j * 8 + 4]) << 24) |
                ((uint64_t)(buffer[i * 128 + j * 8 + 3]) << 32) |
                ((uint64_t)(buffer[i * 128 + j * 8 + 2]) << 40) |
                ((uint64_t)(buffer[i * 128 + j * 8 + 1]) << 48) |
                ((uint64_t)(buffer[i * 128 + j * 8 + 0]) << 56);
        }
        for (j = 16; j < 80; j++) // initialization of remaining words
        {
            word[j] = word[j - 16] +
                (((word[j - 15] >> 1) | (word[j - 15] << 63)) ^ ((word[j - 15] >> 8) | (word[j - 15] << 56)) ^ (word[j - 15] >> 7)) +
                word[j - 7] +
                (((word[j - 2] >> 19) | (word[j - 2] << 45)) ^ ((word[j - 2] >> 61) | (word[j - 2] << 3)) ^ (word[j - 2] >> 6));
        }
        memcpy(h[Type], Hash, sizeof(h[Type][0]) * 8);
        for (j = 0; j < 80; j++) // calculation hash
        {
            tmp1 = h[Type][7] +
                (((h[Type][4] >> 14) | (h[Type][4] << 50)) ^ ((h[Type][4] >> 18) | (h[Type][4] << 46)) ^ ((h[Type][4] >> 41) | (h[Type][4] << 23))) +
                ((h[Type][4] & h[Type][5]) ^ (~h[Type][4] & h[Type][6])) +
                k384_512[j] + word[j];

            tmp2 = (((h[Type][0] >> 28) | (h[Type][0] << 36)) ^ ((h[Type][0] >> 34) | (h[Type][0] << 30)) ^ ((h[Type][0] >> 39) | (h[Type][0] << 25))) +
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
