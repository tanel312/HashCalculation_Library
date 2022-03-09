/* HashCalculation_Library : Defines the functions for the static library.

This file is part of HashCalculation_Library which is a free software : you can redistribute itand /or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.
HashCalculation_Library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty

https://github.com/tanel312  www.tanels.com  tanel.utilities@gmail.com
*/
#include "..\pch.h"

#pragma comment (lib, "..\\Debug\\HashCalculation_Library.lib")

void PrintCompare(const char* Label, uint8_t* Result, uint8_t* Test, int Size)
{
    bool check = true;
    char cc[2];
    char* p;
    uint8_t say, i;
    printf("%s: ", Label);
    for (i = 0; i < Size - 1; i += 2)
    {
        memcpy(cc, Test + i, 2);
        say = (uint8_t)strtoll(cc, &p, 16);
        if (say != Result[i / 2])
            check = false;
        printf("%02x", Result[i / 2]);
    }
    if (!check)
        printf("\nHash not verified !!!");
    printf("\n\n");
    return;
}
int main()
{
    uint8_t Input0[] = { "The quick brown fox jumps over the lazy dog" };
    uint8_t TestResult00[] = { "b03b401ba92d77666221e843feebf8c561cea5f7" };
    uint8_t TestResult01[] = { "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" };
    uint8_t TestResult02[] = { "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525" };
    uint8_t TestResult03[] = { "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" };
    uint8_t TestResult04[] = { "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1" };
    uint8_t TestResult05[] = { "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6" };
    uint8_t TestResult06[] = { "944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37" };
    uint8_t TestResult07[] = { "dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d" };
    uint8_t Input1[] = { "" };
    uint8_t TestResult10[] = { "f96cea198ad1dd5617ac084a3d92c6107708c0ef" }; //SHA-0
    uint8_t TestResult11[] = { "da39a3ee5e6b4b0d3255bfef95601890afd80709" }; // SHA-1
    uint8_t TestResult12[] = { "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" }; // SHA224
    uint8_t TestResult13[] = { "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }; // SHA256
    uint8_t TestResult14[] = { "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" };
    uint8_t TestResult15[] = { "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" };
    uint8_t TestResult16[] = { "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4" }; //  SHA512 / 224
    uint8_t TestResult17[] = { "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a" }; //  SHA512 / 256
    uint8_t Hash[64];

    printf("Input Message: %s\n\n", Input1);
    SHA01_Compute(Input1, sizeof(Input1) - 1, Hash, SHA0);
    PrintCompare("SHA-0", Hash, TestResult10, sizeof(TestResult10));
    SHA01_Compute(Input1, sizeof(Input1) - 1, Hash, SHA1);
    PrintCompare("SHA-1", Hash, TestResult11, sizeof(TestResult11));
    SHA224_256_Compute(Input1, sizeof(Input1) - 1, Hash, SHA224);
    PrintCompare("SHA-224", Hash, TestResult12, sizeof(TestResult12));
    SHA224_256_Compute(Input1, sizeof(Input1) - 1, Hash, SHA256);
    PrintCompare("SHA-256", Hash, TestResult13, sizeof(TestResult13));
    SHA384_512_Compute(Input1, sizeof(Input1) - 1, Hash, SHA384);
    PrintCompare("SHA-384", Hash, TestResult14, sizeof(TestResult14));
    SHA384_512_Compute(Input1, sizeof(Input1) - 1, Hash, SHA512);
    PrintCompare("SHA-512", Hash, TestResult15, sizeof(TestResult15));
    SHA384_512_Compute(Input1, sizeof(Input1) - 1, Hash, SHA512_224);
    PrintCompare("SHA-512/224", Hash, TestResult16, sizeof(TestResult16));
    SHA384_512_Compute(Input1, sizeof(Input1) - 1, Hash, SHA512_256);
    PrintCompare("SHA-512/256", Hash, TestResult17, sizeof(TestResult17));

    printf("Input: %s\n\n", Input0);
    SHA01_Compute(Input0, sizeof(Input0) - 1, Hash, SHA0);
    PrintCompare("SHA-0", Hash, TestResult00, sizeof(TestResult00));
    SHA01_Compute(Input0, sizeof(Input0) - 1, Hash, SHA1);
    PrintCompare("SHA-1", Hash, TestResult01, sizeof(TestResult01));
    SHA224_256_Compute(Input0, sizeof(Input0) - 1, Hash, SHA224);
    PrintCompare("SHA-224", Hash, TestResult02, sizeof(TestResult02));
    SHA224_256_Compute(Input0, sizeof(Input0) - 1, Hash, SHA256);
    PrintCompare("SHA-256", Hash, TestResult03, sizeof(TestResult03));
    SHA384_512_Compute(Input0, sizeof(Input0) - 1, Hash, SHA384);
    PrintCompare("SHA-384", Hash, TestResult04, sizeof(TestResult04));
    SHA384_512_Compute(Input0, sizeof(Input0) - 1, Hash, SHA512);
    PrintCompare("SHA-512", Hash, TestResult05, sizeof(TestResult05));
    SHA384_512_Compute(Input0, sizeof(Input0) - 1, Hash, SHA512_224);
    PrintCompare("SHA-512/224", Hash, TestResult06, sizeof(TestResult06));
    SHA384_512_Compute(Input0, sizeof(Input0) - 1, Hash, SHA512_256);
    PrintCompare("SHA-512/256", Hash, TestResult07, sizeof(TestResult07));
    return 0;
}