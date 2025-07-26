#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cheese_kallsyms_lookup {
  const void* kernel_data;
  size_t kernel_length;
  // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/kernel/kallsyms_internal.h;l=7;drc=64e166099b69bfc09f667253358a15160b86ea43
  const int* kallsyms_offsets;
  uint64_t kallsyms_relative_base;
  unsigned int kallsyms_num_syms;
  const uint8_t* kallsyms_names;
  const char* kallsyms_token_table;
  const uint16_t* kallsyms_token_index;
  char** decompressed_names;
  uint64_t text_base;
};
uint64_t cheese_kallsyms_lookup(struct cheese_kallsyms_lookup* kallsyms_lookup,
                                const char* name);
static void* align_pointer_to_8(void* inptr);
static size_t decompress_string(uint8_t* p, const char* kallsyms_token_table,
                                const uint16_t* kallsyms_token_index,
                                char* output);
static void* memmem_last(const void* big, size_t big_len, const void* little,
                         size_t little_len);
int cheese_create_kallsyms_lookup(
    struct cheese_kallsyms_lookup* kallsyms_lookup, void* kernel_data,
    size_t kernel_length);
uint64_t cheese_kallsyms_lookup(struct cheese_kallsyms_lookup* kallsyms_lookup,
                                const char* name);

// dumped from 51154110092200520's kernel
// dd if=kernel bs=1 skip=42016888 count=72 of=init_cred_start_bytes.bin
extern unsigned char init_cred_start_bytes_bin[];

uint64_t cheese_lookup_init_cred(
    struct cheese_kallsyms_lookup* kallsyms_lookup);

uint64_t cheese_decode_adrp(uint32_t instr, uint64_t pc);

uint64_t cheese_lookup_selinux_state(
    struct cheese_kallsyms_lookup* kallsyms_lookup);

#ifndef KALLSYMS_LOOKUP_INCLUDE
#endif