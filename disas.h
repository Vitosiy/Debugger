#pragma once

#include <windows.h>
#include <udis86.h>

void PrintDisasCode(unsigned char *code, unsigned int codeSize);
unsigned int DisasInstruction(unsigned char *instCode, size_t instCodeSize, uint64_t pc, char *asmString, char *hexString);
unsigned int GetInstructionSize(unsigned char *instCode, unsigned int instCodeSize, uint64_t pc);
