#include <string.h>

#include "udis86.h"
#include "disas.h"
#ifdef _WIN64
#define	DISAS_MODE	64
#else
#define DISAS_MODE	32
#endif


void PrintDisasCode(unsigned char *code, unsigned int codeSize) {
	ud_t ud_obj;

	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, DISAS_MODE);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	ud_set_input_buffer(&ud_obj, code, codeSize);

	while (ud_disassemble(&ud_obj)) {
		const char* hex1, *hex2;
		hex1 = ud_insn_hex(&ud_obj);
		hex2 = hex1 + 16;
		printf("%-16.16s %-24s\n", hex1, ud_insn_asm(&ud_obj));
		if (strlen(hex1) > 16) {
			printf("%-16s\n", hex2);
		}
	}

}

unsigned int DisasInstruction(
	unsigned char *instCode,
	size_t instCodeSize,
	uint64_t pc,
	char *asmString,
	char *hexString) {

	ud_t ud_obj;

	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, DISAS_MODE);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	ud_set_pc(&ud_obj, pc);
	ud_set_input_buffer(&ud_obj, instCode, instCodeSize);

	if (ud_disassemble(&ud_obj)) {
		if (asmString) {
			strcpy(asmString, ud_insn_asm(&ud_obj));
		}
		if (hexString) {
			strcpy(hexString, ud_insn_hex(&ud_obj));
		}
		return ud_insn_len(&ud_obj);
	}
	else {
		return 0;
	}
}

unsigned int GetInstructionSize(unsigned char *instCode, unsigned int instCodeSize, uint64_t pc) {
	ud_t ud_obj;

	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, DISAS_MODE);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	ud_set_pc(&ud_obj, pc);

	ud_set_input_buffer(&ud_obj, instCode, instCodeSize);

	if (ud_disassemble(&ud_obj)) {
		return ud_insn_len(&ud_obj);
	}
	else {
		return 0;
	}
}
