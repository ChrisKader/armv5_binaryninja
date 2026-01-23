// gcc -g test.c armv5.c -o test
// ./test e59ff018          # single instruction
// ./test -f btrom.bin      # disassemble file
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "armv5.h"

int test_single(uint32_t insword, uint32_t address)
{
	Instruction instr;
	memset(&instr, 0, sizeof(instr));

	uint32_t rc = armv5_decompose(insword, &instr, address, 0);
	if(rc) {
		printf("ERROR: armv5_decompose() returned %d\n", rc);
		return rc;
	}

	char instxt[4096];
	memset(instxt, 0, sizeof(instxt));
	rc = armv5_disassemble(&instr, instxt, sizeof(instxt));
	if(rc) {
		printf("ERROR: armv5_disassemble() returned %d\n", rc);
		return rc;
	}

	printf("%08X: %s\n", address, instxt);
	return 0;
}

int test_file(const char *filename)
{
	FILE *f = fopen(filename, "rb");
	if (!f) {
		perror("fopen");
		return 1;
	}

	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	fseek(f, 0, SEEK_SET);

	uint8_t *data = malloc(size);
	if (!data) {
		fprintf(stderr, "Failed to allocate %ld bytes\n", size);
		fclose(f);
		return 1;
	}
	size_t bytes_read = fread(data, 1, size, f);
	fclose(f);
	if (bytes_read != (size_t)size) {
		fprintf(stderr, "Warning: only read %zu of %ld bytes\n", bytes_read, size);
	}

	for (long off = 0; off + 4 <= size; off += 4) {
		uint32_t insword = *(uint32_t *)(data + off);
		Instruction instr;
		memset(&instr, 0, sizeof(instr));

		uint32_t rc = armv5_decompose(insword, &instr, (uint32_t)off, 0);
		if (rc) {
			printf("%08lX: %08X  <undefined>\n", off, insword);
		} else {
			char instxt[256];
			memset(instxt, 0, sizeof(instxt));
			armv5_disassemble(&instr, instxt, sizeof(instxt));
			printf("%08lX: %08X  %s\n", off, insword, instxt);
		}
	}

	free(data);
	return 0;
}

int main(int ac, char **av)
{
	if (ac < 2) {
		fprintf(stderr, "Usage: %s <hex> | -f <file>\n", av[0]);
		return 1;
	}

	if (strcmp(av[1], "-f") == 0 && ac >= 3) {
		return test_file(av[2]);
	}

	uint32_t insword = strtoul(av[1], NULL, 16);
	return test_single(insword, 0);
}
