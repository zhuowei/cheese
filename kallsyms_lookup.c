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

static void* align_pointer_to_8(void* inptr) {
  return (void*)((((uintptr_t)inptr) + 7ull) & ~7ull);
}

static size_t decompress_string(uint8_t* p, const char* kallsyms_token_table,
                                const uint16_t* kallsyms_token_index,
                                char* output) {
  uint8_t count = *p;
  size_t output_length = 0;
  char* s = output;
  for (int i = 0; i < count; i++) {
    const char* token = kallsyms_token_table + kallsyms_token_index[p[i + 1]];
    size_t token_length = strlen(token);
    output_length += token_length;
    if (s) {
      strcpy(s, token);
      s += token_length;
    }
  }
  if (s) {
    *s = 0;
  }
  return output_length;
}

static void* memmem_last(const void* big, size_t big_len, const void* little,
                         size_t little_len) {
  for (const void* p = big + big_len - little_len; p >= big; p--) {
    if (!memcmp(p, little, little_len)) {
      return (void*)p;
    }
  }
  return NULL;
}

int cheese_create_kallsyms_lookup(
    struct cheese_kallsyms_lookup* kallsyms_lookup, void* kernel_data,
    size_t kernel_length) {
  // https://github.com/marin-m/vmlinux-to-elf/tree/master?tab=readme-ov-file#how-does-it-work-really
  // https://github.com/facebookincubator/oculus-linux-kernel/blob/oculus-quest3-kernel-master/scripts/kallsyms.c#L408
  // find the token table first
  static const char token_table1[] = {
      'A', 0, 'B', 0, 'C', 0, 'D', 0, 'E', 0, 'F', 0, 'G', 0, 'H', 0, 'I', 0,
      'J', 0, 'K', 0, 'L', 0, 'M', 0, 'N', 0, 'O', 0, 'P', 0, 'Q', 0, 'R', 0,
      'S', 0, 'T', 0, 'U', 0, 'V', 0, 'W', 0, 'X', 0, 'Y', 0, 'Z', 0};
  void* kallsyms_token_table_letters_ptr =
      memmem(kernel_data, kernel_length, token_table1, sizeof(token_table1));
  if (!kallsyms_token_table_letters_ptr) {
    fprintf(stderr, "can't find kallsyms_token_table: no letters\n");
    return 1;
  }
  void* kallsyms_token_table_ptr = kallsyms_token_table_letters_ptr;
  for (int i = 0; i <= 0x41; i++) {
    char zero = 0;
    kallsyms_token_table_ptr =
        memmem_last(kernel_data, (kallsyms_token_table_ptr - kernel_data),
                    &zero, sizeof(zero));
    if (!kallsyms_token_table_ptr) {
      fprintf(stderr,
              "can't find kallsyms_token_table: can't move backwards\n");
      return 1;
    }
  }
  kallsyms_token_table_ptr += 1;

  void* kallsyms_token_index_ptr;
  {
    void* p = kallsyms_token_table_ptr;
    for (int i = 0; i < 256; i++) {
      p += strlen(p) + 1;
    }
    kallsyms_token_index_ptr = align_pointer_to_8(p);
  }

  void* kallsyms_markers_ptr = kallsyms_token_table_ptr - sizeof(uint32_t);
  if (!*((uint32_t*)kallsyms_markers_ptr)) {
    // alignment padding; skip
    kallsyms_markers_ptr -= sizeof(uint32_t);
  }
  while (*((uint32_t*)kallsyms_markers_ptr)) {
    kallsyms_markers_ptr -= sizeof(uint32_t);
  }

  void* kallsyms_names_end_ptr = kallsyms_markers_ptr - 1;
  while (!*(char*)kallsyms_names_end_ptr) {
    // alignment padding; skip
    kallsyms_names_end_ptr -= 1;
  }
  // not going to try to do the full backwards parse here... just look for the
  // 00000000 padding after num_syms
  uint32_t zeroint = 0;
  void* kallsyms_names_ptr =
      memmem_last(kernel_data, kallsyms_names_end_ptr - kernel_data, &zeroint,
                  sizeof(zeroint)) +
      sizeof(zeroint);

  void* kallsyms_num_syms_ptr = kallsyms_names_ptr - sizeof(uint64_t);
  unsigned int kallsyms_num_syms = *(unsigned int*)kallsyms_num_syms_ptr;
  void* kallsyms_relative_base_ptr = kallsyms_num_syms_ptr - sizeof(uint64_t);
  void* kallsyms_offsets_ptr = kallsyms_relative_base_ptr -
                               (((kallsyms_num_syms * sizeof(int)) + 7) & ~7);
  // fprintf(stderr, "kallsyms_offsets %lx kallsyms_names %lx kallsyms_markers
  // %lx kallsyms_token_table %lx kallsyms_relative_base %lx\n",
  // kallsyms_offsets_ptr - kernel_data, kallsyms_names_ptr - kernel_data,
  // kallsyms_markers_ptr - kernel_data, kallsyms_token_table_ptr - kernel_data,
  // *(uint64_t*)kallsyms_relative_base_ptr);

  kallsyms_lookup->kernel_data = kernel_data;
  kallsyms_lookup->kernel_length = kernel_length;
  kallsyms_lookup->kallsyms_offsets = kallsyms_offsets_ptr;
  kallsyms_lookup->kallsyms_relative_base =
      *(uint64_t*)kallsyms_relative_base_ptr;
  kallsyms_lookup->kallsyms_num_syms = kallsyms_num_syms;
  kallsyms_lookup->kallsyms_names = kallsyms_names_ptr;
  kallsyms_lookup->kallsyms_token_table = kallsyms_token_table_ptr;
  kallsyms_lookup->kallsyms_token_index = kallsyms_token_index_ptr;

  kallsyms_lookup->decompressed_names =
      malloc(kallsyms_num_syms * sizeof(char*));

  {
    uint8_t* p = kallsyms_names_ptr;
    for (int i = 0; i < kallsyms_num_syms; i++) {
      uint8_t entry_token_count = *p;
      size_t length = decompress_string(p, kallsyms_token_table_ptr,
                                        kallsyms_token_index_ptr, NULL);
      char* s = malloc(length + 1);
      decompress_string(p, kallsyms_token_table_ptr, kallsyms_token_index_ptr,
                        s);
      kallsyms_lookup->decompressed_names[i] = s;
      p += entry_token_count + 1;
    }
  }

  uint64_t efi_header_end_addr =
      cheese_kallsyms_lookup(kallsyms_lookup, "efi_header_end");
  if (!efi_header_end_addr) {
    fprintf(stderr, "can't find efi_header_end\n");
    return 1;
  }

  uint64_t text_base = efi_header_end_addr - 0x10000;
  kallsyms_lookup->text_base = text_base;
  return 0;
}

uint64_t cheese_kallsyms_lookup(struct cheese_kallsyms_lookup* kallsyms_lookup,
                                const char* name) {
  for (int i = 0; i < kallsyms_lookup->kallsyms_num_syms; i++) {
    if (strcmp(kallsyms_lookup->decompressed_names[i] + 1, name) == 0) {
      return kallsyms_lookup->kallsyms_relative_base +
             kallsyms_lookup->kallsyms_offsets[i];
    }
  }
  return 0;
}

// dumped from 51154110092200520's kernel
// dd if=kernel bs=1 skip=42016888 count=72 of=init_cred_start_bytes.bin
unsigned char init_cred_start_bytes_bin[] = {
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00};

uint64_t cheese_lookup_init_cred(
    struct cheese_kallsyms_lookup* kallsyms_lookup) {
  void* p =
      memmem_last(kallsyms_lookup->kernel_data, kallsyms_lookup->kernel_length,
                  init_cred_start_bytes_bin, sizeof(init_cred_start_bytes_bin));
  if (!p) {
    return 0;
  }
  return kallsyms_lookup->text_base + (p - kallsyms_lookup->kernel_data);
}

uint64_t cheese_decode_adrp(uint32_t instr, uint64_t pc) {
  uint32_t immhi = (instr >> 5) & ((1 << 19) - 1);  // 19 bits
  uint32_t immlo = (instr >> 29) & 0b11;            // 2 bits
  int64_t extended = ((int32_t)(immhi << 2 | immlo)) << 11 >> 11;
  // fprintf(stderr, "%ld\n", extended);
  int64_t off = extended << 12;
  return (pc & ~((1 << 12) - 1)) + off;
}

uint64_t cheese_lookup_selinux_state(
    struct cheese_kallsyms_lookup* kallsyms_lookup) {
  /*
  https://source.chromium.org/chromiumos/chromiumos/codesearch/+/main:src/third_party/kernel/v5.10/security/selinux/selinuxfs.c;l=459;drc=066314b0b76f61d4d7679f806f19c5c6bcf27441
  ffffffc008799944 t sel_read_policy
  (lldb) x/32i 0x799944
  0x799944: paciasp
  0x799948: str    x30, [x18], #0x8
  0x79994c: stp    x29, x30, [sp, #-0x30]!
  0x799950: stp    x22, x21, [sp, #0x10]
  0x799954: stp    x20, x19, [sp, #0x20]
  0x799958: mov    x29, sp
  0x79995c: mrs    x8, SP_EL0
  0x799960: ldr    x8, [x8, #0x778]
  0x799964: adrp   x9, 5635
  0x799968: ldrsw  x9, [x9, #0xc18]
  0x79996c: ldr    x22, [x0, #0xd8]
  0x799970: ldr    x8, [x8, #0x78]
  0x799974: adrp   x0, 8415
  0x799978: mov    x19, x3
  0x79997c: mov    x20, x2
  0x799980: add    x8, x8, x9
  0x799984: ldr    w8, [x8, #0x4]
  0x799988: mov    x21, x1
  0x79998c: add    x0, x0, #0x990
  0x799990: mov    w2, #0x2 ; =2
  0x799994: mov    w3, #0x1 ; =1
  0x799998: mov    w4, #0x800 ; =2048
  0x79999c: mov    w1, w8
  0x7999a0: mov    x5, xzr
  0x7999a4: bl     0xd41bc
  */
  uint64_t sel_read_policy_addr =
      cheese_kallsyms_lookup(kallsyms_lookup, "sel_read_policy");
  if (!sel_read_policy_addr) {
    return 0;
  }

  uint64_t text_base = kallsyms_lookup->text_base;

  uint64_t sel_read_policy_off = sel_read_policy_addr - text_base;
  const uint32_t* instrs = kallsyms_lookup->kernel_data + sel_read_policy_off;
  uint64_t found_addr = 0;
  for (int i = 0; i < 0x100; i++) {
    uint32_t instr = instrs[i];
#define BL_MASK (0b111111 << 26)
#define BL_INST (0b100101 << 26)
#define ADRP_X0_MASK ((0b10011111 << 24) | (0b11111))
#define ADRP_X0_INST (0b10010000 << 24)
#define ADD_X0_MASK ((0b1111111111 << 22) | (0b1111111111))
#define ADD_X0_INST (0b1001000100 << 22)
    // fprintf(stderr, "%lx %x\n", sel_read_policy_off + i*4, instr);
    if ((instr & BL_MASK) == BL_INST) {  // bl
      return found_addr;
    } else if ((instr & ADRP_X0_MASK) == ADRP_X0_INST) {
      found_addr = cheese_decode_adrp(
          instr, sel_read_policy_addr + i * sizeof(uint32_t));
      // fprintf(stderr, "%lx\n", found_addr);
    } else if ((instr & ADD_X0_MASK) == ADD_X0_INST) {
      uint32_t imm = (instr >> 10) & ((1 << 12) - 1);
      // fprintf(stderr, "add %x\n", imm);
      found_addr += imm;
    }
  }

  return 0;
}

#ifndef KALLSYMS_LOOKUP_INCLUDE

#define PATH "/Volumes/orangehd/docs/oculus/q3/q3_51154110092200520/kernel"
// #define PATH "/Volumes/orangehd/docs/oculus/q3/q3_50473320162100510/kernel"

int main() {
  FILE* f = fopen(PATH, "r");
  fseek(f, 0, SEEK_END);
  off_t file_length = ftell(f);
  fseek(f, 0, SEEK_SET);
  void* kernel_data = malloc(file_length);
  fread(kernel_data, 1, file_length, f);
  fclose(f);
  struct cheese_kallsyms_lookup kallsyms_lookup;
  if (cheese_create_kallsyms_lookup(&kallsyms_lookup, kernel_data,
                                    file_length)) {
    return 1;
  }
  uint64_t addr = cheese_kallsyms_lookup(&kallsyms_lookup, "selinux_state");
  printf("%llx\n", addr);
  uint64_t init_cred_addr = cheese_lookup_init_cred(&kallsyms_lookup);
  printf("%llx\n", init_cred_addr);
  uint64_t selinux_state = cheese_lookup_selinux_state(&kallsyms_lookup);
  printf("%llx\n", selinux_state);
}

#endif
