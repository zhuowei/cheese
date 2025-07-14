#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cheese_kallsyms_lookup {
  // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/kernel/kallsyms_internal.h;l=7;drc=64e166099b69bfc09f667253358a15160b86ea43
  const int* kallsyms_offsets;
  uint64_t kallsyms_relative_base;
  unsigned int kallsyms_num_syms;
  const uint8_t* kallsyms_names;
  const char* kallsyms_token_table;
  const uint16_t* kallsyms_token_index;
  char** decompressed_names;
};

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

int cheese_create_kallsyms_lookup(
    struct cheese_kallsyms_lookup* kallsyms_lookup, void* kernel_data,
    size_t kernel_length) {
  // https://github.com/marin-m/vmlinux-to-elf/tree/master?tab=readme-ov-file#how-does-it-work-really
  // https://github.com/facebookincubator/oculus-linux-kernel/blob/oculus-quest3-kernel-master/scripts/kallsyms.c#L408
  //  simpler heuristics since we know the first 4 entries of the
  //  kallsyms_offsets:
  /*
  ffffffc008000000 T _text
  ffffffc008000000 t _head
  ffffffc008000040 t pe_header
  ffffffc008000044 t coff_header
  */
  const static unsigned int first_offsets[] = {0x0, 0x0, 0x40, 0x44};
  void* kallsyms_offsets_ptr =
      memmem(kernel_data, kernel_length, first_offsets, sizeof(first_offsets));

  void* kallsyms_relative_base_ptr;
  {
    uint64_t* p = kallsyms_offsets_ptr;
    while ((void*)p < (kernel_data + kernel_length)) {
      uint64_t val = *p;
      // kernel base always starts with ffff and aligned to 2MB
      if (val > 0xffff000000000000ull && (val & 0x1fffffull) == 0) {
        kallsyms_relative_base_ptr = (void*)p;
        break;
      }
      p++;
    }
  }
  void* kallsyms_num_syms_ptr = kallsyms_relative_base_ptr + sizeof(uint64_t);
  unsigned int kallsyms_num_syms = *(unsigned int*)kallsyms_num_syms_ptr;
  void* kallsyms_names_ptr = kallsyms_num_syms_ptr + 8;  // 4 bytes + alignment
  unsigned int first_marker = 0;
  void* kallsyms_markers_ptr = align_pointer_to_8(memmem(
      kallsyms_names_ptr, kernel_length - (kallsyms_names_ptr - kernel_data),
      &first_marker, sizeof(first_marker)));
  void* kallsyms_token_table_ptr = align_pointer_to_8(
      kallsyms_markers_ptr +
      ((kallsyms_num_syms + 255) / 256) * sizeof(unsigned int));
  void* kallsyms_token_index_ptr;
  {
    void* p = kallsyms_token_table_ptr;
    for (int i = 0; i < 256; i++) {
      p += strlen(p) + 1;
    }
    kallsyms_token_index_ptr = align_pointer_to_8(p);
  }

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
      if (i < 10) {
        fprintf(stderr, "%s\n", s);
      }
      p += entry_token_count + 1;
    }
  }
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

#ifndef KALLSYMS_LOOKUP_INCLUDE

int main() {
  FILE* f = fopen(
      "/Volumes/orangehd/docs/oculus/q3/q3_51154110092200520/kernel", "r");
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
}

#endif
