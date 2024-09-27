#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define LDisASMR (*b >> 4)
#define LDisASMC (*b & 0xF)

static const uint8_t LegacyPrefixes[] = { 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67 };
static const uint8_t Op1ModRM[] = { 0x62, 0x63, 0x69, 0x6B, 0xC0, 0xC1, 0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7, 0xFE, 0xFF };
static const uint8_t Op1Imm8[] = { 0x6A, 0x6B, 0x80, 0x82, 0x83, 0xA8, 0xC0, 0xC1, 0xC6, 0xCD, 0xD4, 0xD5, 0xEB };
static const uint8_t Op1Imm32[] = { 0x68, 0x69, 0x81, 0xA9, 0xC7, 0xE8, 0xE9 };
static const uint8_t Op2ModRM[] = { 0x0D, 0xA3, 0xA4, 0xA5, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };

inline bool FindByte(const uint8_t* Arr, const size_t N, const uint8_t X)
{
    for (size_t I = 0; I < N; I++)
    {
        if (Arr[I] == X)
            return true;
    }

    return false;
}

inline void ParseModRM(uint8_t** B, const bool AddressPrefix)
{
    uint8_t ModRM = *++(*B);
    bool HasSIB = false;

    if (!AddressPrefix || (AddressPrefix && **B >= 0x40))
    {
        if (**B < 0xC0 && (**B & 0b111) == 0b100 && !AddressPrefix)
        {
            HasSIB = true;
            (*B)++;
        }

        if (ModRM >= 0x40 && ModRM <= 0x7F)
            (*B)++;
        else if ((ModRM <= 0x3F && (ModRM & 0b111) == 0b101) || (ModRM >= 0x80 && ModRM <= 0xBF))
            *B += (AddressPrefix) ? 2 : 4;
        else if (HasSIB && (**B & 0b111) == 0b101)
            *B += (ModRM & 0b01000000) ? 1 : 4;
    }
    else if (AddressPrefix && ModRM == 0x26)
        *B += 2;
}

inline size_t LDisASM(const void* const Address, const bool X86_64Mode)
{
    size_t Offset = 0;
    bool OperandPrefix = false, AddressPrefix = false, RexW = false;
    uint8_t* B = (uint8_t*)(Address);

    for (int I = 0; I < 14 && (FindByte(LegacyPrefixes, sizeof(LegacyPrefixes), *B) || (X86_64Mode && LDisASMR == 4)); I++, B++)
    {
        if (*B == 0x66)
            OperandPrefix = true;
        else if (*B == 0x67)
            AddressPrefix = true;
        else if (LDisASMR == 4 && LDisASMC >= 8)
            RexW = true;
    }

    if (*B == 0x0F)
    {
        B++;

        if (*B == 0x38 || *B == 0x3A)
        {
            if (*B++ == 0x3A)
                Offset++;

            ParseModRM(&B, AddressPrefix);
        }
        else 
        {
            if (LDisASMR == 8)
                Offset += 4;
            else if ((LDisASMR == 7 && LDisASMC < 4) || *B == 0xA4 || *B == 0xC2 || (*B > 0xC3 && *B <= 0xC6) || *B == 0xBA || *B == 0xAC)
                Offset++;

            if (FindByte(Op2ModRM, sizeof(Op2ModRM), *B) || (LDisASMR != 3 && LDisASMR > 0 && LDisASMR < 7) || *B >= 0xD0 || (LDisASMR == 7 && LDisASMC != 7) || LDisASMR == 9 || LDisASMR == 0xB || (LDisASMR == 0xC && LDisASMC < 8) || (LDisASMR == 0 && LDisASMC < 4))
                ParseModRM(&B, AddressPrefix);
        }
    }
    else
    {
        if ((LDisASMR == 0xE && LDisASMC < 8) || (LDisASMR == 0xB && LDisASMC < 8) || LDisASMR == 7 || (LDisASMR < 4 && (LDisASMC == 4 || LDisASMC == 0xC)) || (*B == 0xF6 && !(*(B + 1) & 48)) || FindByte(Op1Imm8, sizeof(Op1Imm8), *B))
            Offset++;
        else if (*B == 0xC2 || *B == 0xCA)
            Offset += 2;
        else if (*B == 0xC8)
            Offset += 3;
        else if ((LDisASMR < 4 && (LDisASMC == 5 || LDisASMC == 0xD)) || (LDisASMR == 0xB && LDisASMC >= 8) || (*B == 0xF7 && !(*(B + 1) & 48)) || FindByte(Op1Imm32, sizeof(Op1Imm32), *B))
            Offset += (RexW) ? 8 : (OperandPrefix ? 2 : 4);
        else if (LDisASMR == 0xA && LDisASMC < 4)
            Offset += (RexW) ? 8 : (AddressPrefix ? 2 : 4);
        else if (*B == 0xEA || *B == 0x9A)
            Offset += OperandPrefix ? 4 : 6;

        if (FindByte(Op1ModRM, sizeof(Op1ModRM), *B) || (LDisASMR < 4 && (LDisASMC < 4 || (LDisASMC >= 8 && LDisASMC < 0xC))) || LDisASMR == 8 || (LDisASMR == 0xD && LDisASMC >= 8))
            ParseModRM(&B, AddressPrefix);
    }

    return (size_t)((ptrdiff_t)(++B + Offset) - (ptrdiff_t)(Address));
}