/* HashCalculation_Library : Defines the functions for the static library.

This file contains the sha0 & 1 computation functions and is part of HashCalculation_Library which is a free software : you can redistribute it
and /or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of
the License, or any later version.

HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/

#include "pch.h"

void SHA01_Functions(uint8_t* Input, uint32_t* Hash, uint8_t Type)
{
    uint32_t f; // functions
    uint32_t tmp;
    uint8_t index;
    uint32_t j;
    uint32_t hash[5];
    data32Struct word[80];

    memcpy(hash, Hash, sizeof(hash));
    // initialization of first 16 words
    for (int j = 0; j < 16; j++) // break  into sixteen 32-bit big-endian words
    {
        for (tmp = 0; tmp < 4; tmp++)
            word[j].b[tmp] = Input[(j * 4) + (3 - tmp)]; // put in big endian form
    }
    // initialization of remaining words
    for (j = 16; j < 80; j++) // extend the sixteen 32-bit words into eighty 32-bit words
    {
        tmp = (word[j - 3].w32 ^ word[j - 8].w32 ^ word[j - 14].w32 ^ word[j - 16].w32); // w[i] = (w[i-3] ⊕ w[i-8] ⊕ w[i-14] ⊕ w[i-16])
        if (Type == SHA1) // Hash 1
            word[j].w32 = ((tmp << 1) | (tmp >> (31))); // ROTL(b,1)
        else // Hash 0
            word[j].w32 = tmp;
    }
    // calculate hash
    for (j = 0; j < 80; j++) 
    {
        index = j / 20;
        switch (index)
        {
        case 0: // Bitwise choice between c and d, controlled by b for 0  ≤ i ≤ 19
            f = hash[3] ^ (hash[1] & (hash[2] ^ hash[3])); // Ch(b,c,d) = d ⊕ (b & (c ⊕ d))
            break;
        case 1: // for 20  ≤ i ≤ 39 // Parity(b,c,d) = b ⊕ c ⊕ d
        case 3: // for 60  ≤ i ≤ 79
            f = hash[1] ^ hash[2] ^ hash[3];
            break;
        case 2: // Bitwise majority function for 40  ≤ i ≤ 59
            f = (hash[1] & hash[2]) | (hash[1] & hash[3]) | (hash[2] & hash[3]); // Maj(b,c,d) = (b & c) | (b & d) | (c & d)
            break;
        }
        tmp = (((hash[0] << 5) | (hash[0] >> 27)) + f + hash[4] + k0_1[index] + word[j].w32); // ROTL(a, 5) + f + e + k + w[i]
        hash[4] = hash[3];
        hash[3] = hash[2];
        hash[2] = (hash[1] << 30) | (hash[1] >> 2); // ROTL(b,30)
        hash[1] = hash[0];
        hash[0] = tmp;
    }
    for (j = 0; j < 5; j++) // add to result
    {
        Hash[j] += hash[j];
    }
    return;
}
