// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023, Ivaylo Ivanov <ivo.ivanov@null.net>
 */

#ifndef MAIN_H
#define MAIN_H

// memory address where emulation starts
#define MEMORY_BASE 0x80000000
#define ADDRESS 0x84000000

#define SDRAM_BASE			(0x80000000)
#define SDRAM_BANK_LEN			(0x20000000)
#define SDRAM_BANK_COUNT		(2)
#define SDIO_BASE_ADDR			(0x30000000)

struct memory_mapping {
	uint64_t base;
	size_t size;
	uint32_t perms;
};

/*
	UC_PROT_NONE = 0
	UC_PROT_READ = 1
	UC_PROT_WRITE = 2
	UC_PROT_EXEC = 4
	UC_PROT_ALL = 7
*/

struct memory_mapping memmap[] = {
	/* PMGR */
	{ 0x3F100000, 0x00100000, UC_PROT_READ },
	/* DRAM */
	{ SDRAM_BASE, (SDRAM_BANK_LEN * SDRAM_BANK_COUNT), UC_PROT_ALL },
	/* End of map */
	{ 0x00000000, 0x00000000, UC_PROT_NONE },
};

#endif // MAIN_H
