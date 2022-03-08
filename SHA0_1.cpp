#include "SHA.h"

// although Length is unsigned 64_bit, the code below processes upto unsigned 32bit. But 64-bit length is used in padding
bool SHA01_Compute(uint8_t* Inp, uint64_t Length, uint32_t* Hash, uint8_t Type)
{
    if (Length > UINT32_MAX)
        return false;
    uint32_t h[] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }; // initial values
    uint32_t f; // functions
    uint32_t tmp;
    uint8_t index;
    uint32_t i, j;
    uint8_t* buffer;
    uint32_t word[80];
    uint32_t block;
    dataStruct length;
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
    length.doubleword = Length * 8;
    i = 7;
    do
    {
        buffer[j - 1 - i] = length.bytes.b[i];
    } while (i--);
    block = j / 64; // 512-bit = 64 bytes
    memcpy(Hash, h, sizeof(h));
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
        for (j = 16; j < 80; j++) // initialization of remaining words
        {
            tmp = (word[j - 3] ^ word[j - 8] ^ word[j - 14] ^ word[j - 16]);
            if (Type == SHA1) // Hash 1
                word[j] = ((tmp << 1) | (tmp >> (31)));
            else // Hash 0
                word[j] = tmp;
        }
        memcpy(h, Hash, sizeof(h));
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
            tmp = (((h[0] << 5) | (h[0] >> 27)) + f + h[4] + k0_1[index] + word[j]);
            h[4] = h[3];
            h[3] = h[2];
            h[2] = (h[1] << 30) | (h[1] >> 2);
            h[1] = h[0];
            h[0] = tmp;
        }
        for (j = 0; j < 5; j++)
        {
            Hash[j] += h[j];
        }
    }
    free(buffer);
    return true;
}

