// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023, Ivaylo Ivanov <ivo.ivanov@null.net>
 */

#include <unicorn/unicorn.h>
#include <string.h>
#include "main.h"
#include "periph.h"

static uc_err
load_image(uc_engine *uc, const char *file, uint64_t base, uint64_t *last) {
	char buf[1024];
	FILE *f;
	long sz;
	uc_err err;
	uint64_t addr = base;

	if (!(f = fopen(file, "r")))
		return UC_ERR_HANDLE;

	fseek(f, 0L, SEEK_END);
	sz = ftell(f);
	fseek(f, 0L, SEEK_SET);

	while (ftell(f) != sz) {
		size_t n = fread(buf, 1, 1024, f);
		*last = addr;
		if ((err = uc_mem_write(uc, addr, buf, n)) != UC_ERR_OK)
			return err;
		addr += n;
	}

	return err;
}


static uc_err
register_device(uc_engine *uc, struct device *dev)
{
	uc_err err;

	err = uc_mem_map(uc, dev->base, dev->size, UC_PROT_READ | UC_PROT_WRITE);
	if (err != UC_ERR_OK)
		return err;

	if (dev->callback) {
		err = uc_hook_add(uc, &dev->hook,
		    UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
		    dev->callback, dev,
		    dev->base,
		    dev->base + dev->size - 1);
		if (err != UC_ERR_OK)
			return err;
	}

	return err;
}

int main(int argc, char **argv, char **envp) {
	uc_engine *uc;
	uc_err err;
	uc_hook trace1, trace2;

	uint64_t end;

	printf("Setting up the emulator\n");

	// Initialize emulator in ARM mode
	err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
	if (err) {
		printf("Failed on uc_open() with error returned: %u (%s)\n", err,
			   uc_strerror(err));
		return 	0;
	}

	struct memory_mapping map;

	for (int i = 0; memmap[i].perms != UC_PROT_NONE; i++) {
		map = memmap[i];
		if ((err = uc_mem_map(uc, map.base, map.size, map.perms)))
			return err;
	}

	for (int i = 0; devices[i] != NULL; i++)
		if ((err = register_device(uc, devices[i])) != UC_ERR_OK)
			return err;

	if ((err = load_image(uc, argv[1], ADDRESS, &end)) != UC_ERR_OK) {
		printf("load_image: %s\n", uc_strerror(err));
		goto cleanup;
	}

	printf("Booting..\n");
	if ((err = uc_emu_start(uc, ADDRESS, end, 0, 0)) != UC_ERR_OK) {
		printf("\n\n>>>> A6Emu: %s\n", uc_strerror(err));
		//dump_regs(uc);
		goto cleanup;
	}

	// now print out some registers
	printf(">>> Emulation done. Below is the CPU context\n");

	uc_close(uc);

	return 0;

cleanup:
	uc_close(uc);
}
