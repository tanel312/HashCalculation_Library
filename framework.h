/* HashCalculation_Library : Defines the functions for the static library.

This file is part of HashCalculation_Library which is a free software : you can redistribute itand /or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.
HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/
#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <iostream>
#include "SHA_tables.h"
#include "HashCalculation_Library.h"

#define BLOCK512 64 // 512 bits in bytes
#define BLOCK1024 128 // 1024 bits in bytes
#define BLOCK1600 200 // 1600 bits in bytes

typedef union 
{
    uint8_t b[4];
    uint32_t w32;
} data32Struct;
typedef union 
{
    uint8_t b[8];
    uint32_t w32[2];
    uint64_t w64;
} data64Struct;
typedef union
{
    uint8_t b[64];
    uint32_t w32[16];
    uint64_t w64[8];
} data512bit;
typedef union
{
    uint8_t b[128];
    uint32_t w32[32];
    uint64_t w64[16];
} data1024bit;
typedef union
{
    uint8_t b[200];
    uint64_t w64[25];
    uint64_t w[5][5];
} data1600bit;

void SHA01_Functions(uint8_t* Input, uint32_t* Hash, uint8_t Type);
void SHA224_256_Functions(uint8_t* Input, uint32_t* Hash, uint8_t Type);
void SHA384_512_Functions(uint8_t* Input, uint64_t* Hash, uint8_t Type);
void SHA3_Functions(uint64_t* Input);
