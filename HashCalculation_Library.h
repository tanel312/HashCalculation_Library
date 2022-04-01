/* HashCalculation_Library : Defines the functions for the static library.

This file is part of HashCalculation_Library which is a free software : you can redistribute itand /or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.
HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/
#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <iostream>

// SHA types
#define SHA0 0
#define SHA1 1
#define SHA3 10
#define VARIANTSHA224 0
#define VARIANTSHA256 1
#define VARIANTSHA384 0
#define VARIANTSHA512 1
#define VARIANTSHA512_224 2
#define VARIANTSHA512_256 3
#define VARIANTSHAKE128   1
#define VARIANTSHAKE256   2

#define SHA_SIZE128        16
#define SHA_SIZE160        20
#define SHA_SIZE224        28
#define SHA_SIZE256        32
#define SHA_SIZE384        48
#define SHA_SIZE512        64
#define SHAKE_SIZE128      32
#define SHAKE_SIZE256      64

// computes hash iaw Hash0 or Hash1 algortihm
void SHA01_Compute(
    const uint8_t* Inp,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 2^64 bytes
    uint8_t* Hash, // output; byte (8-bit), array size 20 for SHA0 / 20 for SHA1
    uint8_t Type); // input; 0 for SHA224 or 1 for SHA256
bool SHA01_Compute1(uint8_t* Inp, uint64_t Length, uint8_t* Hash, uint8_t Type);

// computes hash iaw Hash2 224-bit or 256-bit algortihm
void SHA224_256_Compute(
    const uint8_t* Inp,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 2^64 bytes
    uint8_t* Hash, // output; array of byte (8-bit), array size 28 for SHA224 / 32 for SHA256
    uint8_t Type); // input; 0 for SHA224 or 1 for SHA256

// computes hash iaw Hash2 384-bit or 512-bit algortihm
void SHA384_512_Compute(
    const uint8_t* Inp,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 2^64 bytes
    uint8_t* Hash, // output; array of byte (8-bit), array size 48 for SHA384 / 64 for SHA512 / 28 for SHA512-224 / 32 for SHA512-256
    uint8_t Type); // input; 0 for SHA384 or 1 for SHA512 or 2 for SHA512-224 or 3 for SHA512-256

// computes hash iaw Hash3 algorithm for 1600bit block with variants 224-bit, 256-bit, 384-bit, 512-bit, SHAKE128 and SHAKE256,
// SHA output is limited to 1088 bits for SHAKE256 and 1344 bits fo SHAKE128 even if SHAsize value is higher
void SHA3_Shake_Compute(
    const uint8_t* Input,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 2^64 bytes
    uint8_t* SHA, // output; array of byte (8-bit);
    //array size 28 for 224 / 32 for 256 / 48 for 384 / 64 for 512 / 32 to 168 for SHAKE128 / 64 to 136 for SHAKE256
    int SHAsize, // input; size of SHA array in bytes;
    // 28 for 224 / 32 for 256 / 48 for 384 / 64 for 512 / 32 to 168 for SHAKE128 / 64 to 136 for SHAKE256
    uint8_t Type); // input; 1 for SHAKE128 / 2 for SHAKE256, 0x0a for other variants; 224-bit, 256-bit, 384-bit, 512-bit
