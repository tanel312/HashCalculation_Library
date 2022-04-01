/* HashCalculation_Library : Defines the functions for the static library.

This file contains the sha3 computation functions and is part of HashCalculation_Library which is a free software : you can redistribute it
and /or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of 
the License, or any later version.

HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/
// 
// https://www.researchgate.net/publication/339196556_High_Throughput_Implementation_of_the_Keccak_Hash_Function_Using_the_Nios-II_Processor
// https://crypto.stackexchange.com/questions/59162/implementation-details-of-the-%CF%80-step-of-the-keccak-round-function

#include "pch.h"

// preforms Keccak round functions
// Input/Output; Array of 25 64-bit words (1600bits)
void SHA3_Functions(uint64_t* Array)
{
    int r, offset;
    uint64_t tmp1, tmp2, tmpArray[5];
    int x, y;
    int X, Y;
    data1600bit* array = (data1600bit*)Array;
    for (r = 0; r < 24; r++)
    {
        // Theta step
        // C[x] = A[x, 0]⊕A[x, 1]⊕A[x, 2]⊕A[x, 3]⊕A[x, 4] 0≤x≤4Theta(θ)
        for (x = 0; x < 5; x++)
            tmpArray[x] = array->w[0][x] ^ array->w[1][x] ^ array->w[2][x] ^ array->w[3][x] ^ array->w[4][x];
        for (x = 0; x < 5; x++)
        {
            // D[x] = C[x−1]⊕ROT(C[x + 1], 1) 0≤x≤4
            tmp1 = tmpArray[(x + 4) % 5] ^ (((tmpArray[(x + 1) % 5]) << 1) | ((tmpArray[(x + 1) % 5]) >> 63));
            // A[x, y] = A[x, y]⊕D[x] 0≤x, y≤4
            for (y = 0; y < 5; y++)
                array->w[y][x] ^= tmp1;
        }
        // Rho and Pi steps; Rho (ρ)-Pi(π): B[y, 2x+3y] = ROT(A[x,y],r[x,y]) 0≤x,y≤4
        x = 0; y = 1;
        tmp1 = array->w[x][y];
        for (int t = 0; t < 24; t++)
        {
            Y = x;
            X = (2 * y + 3 * x) % 5;
            tmp2 = array->w[X][Y];
            offset = ((t + 1) * (t + 2) / 2) % 64;
            array->w[X][Y] = ((tmp1 << offset) | (tmp1 >> (64 - offset)));
            tmp1 = tmp2;
            x = X; y = Y;
        }
        //  Chi step; Chi (χ): A[x,y] = B[x,y]⊕((NOTB[x+1, y]) AND(B[x+2, y])) 0≤x,y≤4
        for (x = 0; x < 5; x++)
        {
            memcpy(tmpArray, &array->w[x][0], 5 * sizeof(uint64_t));
            for (y = 0; y < 5; y++)
                array->w[x][y] ^= (~tmpArray[(y + 1) % 5]) & (tmpArray[(y + 2) % 5]);
        }
        //  Iota step; lota (ι): A[0, 0] = A[0, 0]⊕RC
        array->w[0][0] ^= k3[r];
    }
}

