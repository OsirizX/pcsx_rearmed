// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 OsirizX
 */

#include <malloc.h>
#include <stdbool.h>
#include <sys/memory.h>

#include "../psxhw.h"
#include "../psxmem.h"
#include "../r3000a.h"

#include "mem.h"

#include <sys/process.h>
#include <ps3mapi_ps3_lib.h>

static void* psx_mem;
static void* psx_parallel;
static void* psx_scratch;
static void* psx_bios;

static sys_mem_addr_t base_addr;
static sys_mem_addr_t psx_mem_addr;
static sys_mem_addr_t psx_parallel_addr;
static sys_mem_addr_t psx_scratch_addr;
static sys_mem_addr_t psx_bios_addr;
static sys_mem_id_t psx_mem_id;
static sys_mem_id_t psx_parallel_id;
static sys_mem_id_t psx_scratch_id;
static sys_mem_id_t psx_bios_id;

static uint64_t page_table[2] = {0, 0};

void* code_buffer;

int lightrec_init_mmap(void) {
  u32 psx_mem_size = 0x200000;
  u32 psx_parallel_size = 0x10000;
  u32 psx_scratch_size = 0x10000;
  u32 psx_bios_size = 0x80000;
  u32 padding_size = 0x100000;

  base_addr = 0x0;
  sysMMapperAllocateAddress(0x20000000, 0x40f, 0x10000000, &base_addr);
  sysMMapperAllocateMemory(0x200000, SYS_MEMORY_PAGE_SIZE_1M, &psx_mem_id);
  sysMMapperAllocateMemory(0x100000, SYS_MEMORY_PAGE_SIZE_1M, &psx_parallel_id);
  sysMMapperAllocateMemory(0x100000, SYS_MEMORY_PAGE_SIZE_1M, &psx_scratch_id);
  sysMMapperAllocateMemory(0x100000, SYS_MEMORY_PAGE_SIZE_1M, &psx_bios_id);

  for (int i = 0; i < 4; i++) {
    sysMMapperSearchAndMap(base_addr, psx_mem_id, SYS_MEMORY_PROT_READ_WRITE, &psx_mem_addr);
    if (i == 0) {
      psxM = (void*)psx_mem_addr;
      printf("psxM 0x%llx 0x%llx\n", psxM, psx_mem_addr);
    }
  }

  sysMMapperSearchAndMap(base_addr, psx_parallel_id, SYS_MEMORY_PROT_READ_WRITE, &psx_parallel_addr);
  psxP = (void*)psx_parallel_addr;
  printf("psxP 0x%llx 0x%llx\n", psxP, psx_parallel_addr);

  sysMMapperSearchAndMap(base_addr, psx_scratch_id, SYS_MEMORY_PROT_READ_WRITE, &psx_scratch_addr);
  psxH = (void*)psx_scratch_addr;
  printf("psxH 0x%llx 0x%llx\n", psxH, psx_scratch_addr);

  sysMMapperSearchAndMap(base_addr, psx_bios_id, SYS_MEMORY_PROT_READ_WRITE, &psx_bios_addr);
  psxR = (void*)psx_bios_addr;
  printf("psxR 0x%llx 0x%llx\n", psxR, psx_bios_addr);

  ps3mapi_process_page_allocate(sysProcessGetPid(), CODE_BUFFER_SIZE, PAGE_SIZE_AUTO, 0x2F, 1, page_table);
  code_buffer = (void *)page_table[0];

	return 0;
}

void lightrec_free_mmap(void) {
  sys_mem_id_t ret_id;
  sysMMapperUnmapMemory(psx_mem_addr, &ret_id);
  sysMMapperFreeMemory(ret_id);
  sysMMapperUnmapMemory(psx_parallel_addr, &ret_id);
  sysMMapperFreeMemory(ret_id);
  sysMMapperUnmapMemory(psx_scratch_addr, &ret_id);
  sysMMapperFreeMemory(ret_id);
  sysMMapperUnmapMemory(psx_bios_addr, &ret_id);
  sysMMapperFreeMemory(ret_id);
  sysMMapperFreeAddress(base_addr);
  if (page_table[0] > 0 && page_table[1] > 0)
    ps3mapi_process_page_free(sysProcessGetPid(), 0x2F, page_table);
}

void DCFlushRange(void* startaddr, unsigned int len){
  if(len == 0) return;
  __asm__ volatile (
    "clrlwi.  5, %0, 27\n"
    "beq  1f\n"
    "addi %1, %1, 0x20\n"
    "1:\n"
    "addi %1, %1, 0x1f\n"
    "srwi %1, %1, 5\n"
    "mtctr  %1\n"
    "2:\n"
    "dcbf 0, %0\n"
    "addi %0, %0, 0x20\n"
    "bdnz 2b\n"
    "sync\n"
    : : "b" (startaddr), "b" (len) : "5", "memory" );
}

void ICInvalidateRange(void* startaddr, unsigned int len)  {
  if(len == 0) return;
  __asm__ volatile (
    "clrlwi.  5, %0, 27\n"
    "beq  1f\n"
    "addi %1, %1, 0x20\n"
    "1:\n"
    "addi %1, %1, 0x1f\n"
    "srwi %1, %1, 5\n"
    "mtctr  %1\n"
    "2:\n"
    "icbi 0, %0\n"
    "addi %0, %0, 0x20\n"
    "bdnz 2b\n"
    "sync\n"
    "isync\n"
    : : "b" (startaddr), "b" (len) : "5", "memory" );
}
