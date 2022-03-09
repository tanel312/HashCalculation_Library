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
#define SHA224 0
#define SHA256 1
#define SHA384 0
#define SHA512 1
#define SHA512_224 2
#define SHA512_256 3

// computes hash iaw Hash0 or Hash1 algortihm, returns false if length of input data is over the limit or available memory
bool SHA01_Compute(
    uint8_t* Inp,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 4,294,967,295 bytes
    uint8_t* Hash, // output; byte (8-bit), array size 20 for SHA0 / 20 for SHA1
    uint8_t Type); // input; 0 for SHA224 or 1 for SHA256

// computes hash iaw Hash2 224-bit or 256-bit algortihm, returns false if length of input data is over the limit or available memory
bool SHA224_256_Compute(
    uint8_t* Inp,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 4,294,967,295 bytes
    uint8_t* Hash, // output; array of byte (8-bit), array size 28 for SHA224 / 32 for SHA256
    uint8_t Type); // input; 0 for SHA224 or 1 for SHA256

// computes hash iaw Hash2 384-bit or 512-bit algortihm, returns false if length of input data is over the limit or available memory
bool SHA384_512_Compute(
    uint8_t* Inp,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 4,294,967,295 bytes
    uint8_t* Hash, // output; array of byte (8-bit), array size 48 for SHA384 / 64 for SHA512 / 28 for SHA512-224 / 32 for SHA512-256
    uint8_t Type); // input; 0 for SHA384 or 1 for SHA512 or 2 for SHA512-224 or 3 for SHA512-256
