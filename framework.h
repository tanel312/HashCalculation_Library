#pragma once
#include <iostream>
#include "SHA_tables.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define SHA0 0
#define SHA1 1
#define SHA224 0
#define SHA256 1
#define SHA384 0
#define SHA512 1

union dataStruct
{
    struct _d
    {
        uint8_t b[8];
    } bytes;
    uint64_t doubleword;
};

// computes hash iaw Hash0 or Hash1 algortihm, returns false if length of input data is over the limit or available memory
bool SHA01_Compute(
    uint8_t* Inp,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 4,294,967,295 bytes
    uint32_t* Hash, // output; array of 32-bit words. array size 5 for SHA0 / 5 for SHA1
    uint8_t Type); // input; 0 for SHA224 or 1 for SHA256

// computes hash iaw Hash2 224-bit or 256-bit algortihm, returns false if length of input data is over the limit or available memory
bool SHA224_256_Compute(
    uint8_t* Inp,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 4,294,967,295 bytes
    uint32_t* Hash, // output; array of 32-bit words. array size 8 for SHA224 / 8 for SHA256
    uint8_t Type); // input; 0 for SHA224 or 1 for SHA256

// computes hash iaw Hash2 384-bit or 512-bit algortihm, returns false if length of input data is over the limit or available memory
bool SHA384_512_Compute(
    uint8_t* Inp,   // input; input data
    uint64_t Length, // input; size of input data in bytes < 4,294,967,295 bytes
    uint64_t* Hash, // output; array of 64-bit words. array size 6 for SHA384 / 8 for SHA512
    uint8_t Type); // input; 0 for SHA384 or 1 for SHA512
