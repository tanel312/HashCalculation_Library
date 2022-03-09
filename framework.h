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

union data32Struct
{
    struct
    {
        uint8_t b[4];
    } bytes;
    uint32_t w32;
};

union data64Struct
{
    struct
    {
        uint8_t b[8];
    } bytes;
    uint64_t w64;
};
