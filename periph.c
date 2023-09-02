// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023, Ivaylo Ivanov <ivo.ivanov@null.net>
 */

#include <unicorn/unicorn.h>
#include <string.h>
#include "periph.h"

/* UART0, used for debugging */
struct uart_state uart0_state;

struct uart_state {
	uint64_t cache[100];
};

static void uart_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	struct device *uart = (struct device *) user_data;
	struct uart_state *state = (struct uart_state *) uart->state;
	uint64_t offset = address - uart->base;
	uint64_t *cache = &state->cache[offset];
	uint64_t ret;

	if (type == UC_MEM_READ)
		goto read;

	if (type == UC_MEM_WRITE)
		goto write;

	return;

read:
	switch (offset) {
	case 0x10:
		*cache = ~*cache;
		ret = *cache;
		break;
	default:
		*cache = 0;
		ret = *cache;
	};
	uc_mem_write(uc, address, &ret, sizeof(uint64_t));
	return;

write:
	switch (offset) {
	case 0x20:
		printf("%c", (char) value);
		break;
	};
	return;
}

struct device uart0 = {
	.base = UART0_BASE_ADDR,
	.size = 0x00100000,
	.callback = uart_callback,
	.state = &uart0_state
};

struct device uart1 = {
	.base = UART1_BASE_ADDR,
	.size = 0x00100000,
	.callback = uart_callback,
	.state = &uart0_state
};

struct device uart2 = {
	.base = UART2_BASE_ADDR,
	.size = 0x00100000,
	.callback = uart_callback,
	.state = &uart0_state
};

struct device uart3 = {
	.base = UART3_BASE_ADDR,
	.size = 0x00100000,
	.callback = uart_callback,
	.state = &uart0_state
};

struct device uart4 = {
	.base = UART4_BASE_ADDR,
	.size = 0x00100000,
	.callback = uart_callback,
	.state = &uart0_state
};

struct device uart5 = {
	.base = UART5_BASE_ADDR,
	.size = 0x00100000,
	.callback = uart_callback,
	.state = &uart0_state
};

struct device uart6 = {
	.base = UART6_BASE_ADDR,
	.size = 0x00100000,
	.callback = uart_callback,
	.state = &uart0_state
};

/* AIC */
static void aic_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	struct device *uart = (struct device *) user_data;
	uint64_t offset = address - uart->base;
	uint64_t ret;

	if (type == UC_MEM_READ)
		goto read;

	if (type == UC_MEM_WRITE)
		goto write;

	return;

read:
	switch(offset) {
		case 0x20:
			ret = 0x0;
			break;
		default:
			break;
	}

	uc_mem_write(uc, address, &ret, sizeof(uint64_t));
	return;

write:
	printf("\nWriting prompted at offset %lx with %c", offset, (char) value);
	return;
}

struct device aic = {
	.base = AIC_BASE_ADDR,
	.size = 0x00100000,
	.callback = aic_callback,
	.state = NULL
};

struct device *devices[] = {
	&uart0,
	&uart1,
	&uart2,
	&uart3,
	&uart4,
	&uart5,
	&uart6,
	&aic,
	NULL
};
