//
// Created by hawkes on 4/28/20.
//

#ifndef ADRENALINE_ADRENALINE_H
#define ADRENALINE_ADRENALINE_H

enum kgsl_user_mem_type {
    KGSL_USER_MEM_TYPE_PMEM         = 0x00000000,
    KGSL_USER_MEM_TYPE_ASHMEM       = 0x00000001,
    KGSL_USER_MEM_TYPE_ADDR         = 0x00000002,
    KGSL_USER_MEM_TYPE_ION          = 0x00000003,
    KGSL_USER_MEM_TYPE_DMABUF       = 0x00000003,
    KGSL_USER_MEM_TYPE_MAX          = 0x00000007,
};

struct kgsl_map_user_mem {
    int fd;
    unsigned long gpuaddr;   /*output param */
    size_t len;
    size_t offset;
    unsigned long hostptr;   /*input param */
    enum kgsl_user_mem_type memtype;
    unsigned int flags;
};

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id; /*output param */
};

/* destroy a draw context */
struct kgsl_drawctxt_destroy {
    unsigned int drawctxt_id;
};


struct kgsl_command_object {
    uint64_t offset;
    uint64_t gpuaddr;
    uint64_t size;
    unsigned int flags;
    unsigned int id;
};

struct kgsl_gpu_command {
    uint64_t flags;
    uint64_t __user cmdlist;
    unsigned int cmdsize;
    unsigned int numcmds;
    uint64_t __user objlist;
    unsigned int objsize;
    unsigned int numobjs;
    uint64_t __user synclist;
    unsigned int syncsize;
    unsigned int numsyncs;
    unsigned int context_id;
    unsigned int timestamp;
};

#define KGSL_IOC_TYPE 0x09

#define IOCTL_KGSL_DRAWCTXT_CREATE \
        _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

#define IOCTL_KGSL_DRAWCTXT_DESTROY \
        _IOW(KGSL_IOC_TYPE, 0x14, struct kgsl_drawctxt_destroy)

#define IOCTL_KGSL_MAP_USER_MEM \
        _IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)

#define IOCTL_KGSL_GPU_COMMAND \
        _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)

#define KGSL_CMDLIST_IB             0x00000001U
#define KGSL_MEMFLAGS_USE_CPU_MAP   0x10000000ULL

#define CP_TYPE4_PKT    (4 << 28)
#define CP_TYPE7_PKT    (7 << 28)

#define CP_NOP                  0x10
#define CP_WAIT_FOR_ME          0x13
#define CP_WAIT_FOR_IDLE        0x26
#define CP_WAIT_REG_MEM         0x3c
#define CP_MEM_WRITE            0x3d
#define CP_INDIRECT_BUFFER_PFE  0x3f
#define CP_SET_DRAW_STATE       0x43
#define CP_MEM_TO_MEM           0x73

#define upper_32_bits(n) ((uint32_t)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((uint32_t)(n))

static inline uint cp_gpuaddr(uint *cmds, uint64_t gpuaddr)
{
    uint *start = cmds;

    *cmds++ = lower_32_bits(gpuaddr);
    *cmds++ = upper_32_bits(gpuaddr);

    return cmds - start;
}

static inline uint pm4_calc_odd_parity_bit(uint val) {
    return (0x9669 >> (0xf & ((val) ^
                              ((val) >> 4) ^ ((val) >> 8) ^ ((val) >> 12) ^
                              ((val) >> 16) ^ ((val) >> 20) ^ ((val) >> 24) ^
                              ((val) >> 28)))) & 1;
}

static inline uint cp_type7_packet(uint opcode, uint cnt) {
    return CP_TYPE7_PKT | ((cnt) << 0) |
           (pm4_calc_odd_parity_bit(cnt) << 15) |
           (((opcode) & 0x7F) << 16) |
           ((pm4_calc_odd_parity_bit(opcode) << 23));
}

static inline uint cp_wait_for_me(
        uint *cmds)
{
    uint *start = cmds;

    *cmds++ = cp_type7_packet(CP_WAIT_FOR_ME, 0);

    return cmds - start;
}

static inline uint cp_mem_packet(int opcode, uint size, uint num_mem) {
    return cp_type7_packet(opcode, size + num_mem);
}

static inline uint cp_wait_for_idle(
        uint *cmds)
{
    uint *start = cmds;

    *cmds++ = cp_type7_packet(CP_WAIT_FOR_IDLE, 0);

    return cmds - start;
}

static inline int _adreno_iommu_add_idle_indirect_cmds(
        unsigned int *cmds)
{
    unsigned int *start = cmds;
    cmds += cp_wait_for_me(cmds);
    *cmds++ = cp_mem_packet(CP_INDIRECT_BUFFER_PFE, 2, 1);
    cmds += cp_gpuaddr(cmds, 0xfc000000+1024);
    *cmds++ = 2;
    cmds += cp_wait_for_idle(cmds);
    return cmds - start;
}

static inline uint cp_type4_packet(uint opcode, uint cnt)
{
    return CP_TYPE4_PKT | ((cnt) << 0) |
           (pm4_calc_odd_parity_bit(cnt) << 7) |
           (((opcode) & 0x3FFFF) << 8) |
           ((pm4_calc_odd_parity_bit(opcode) << 27));
}

static inline uint cp_register(
        unsigned int reg, unsigned int size)
{
    return cp_type4_packet(reg, size);
}

static inline uint cp_invalidate_state(
        uint *cmds)
{
    uint *start = cmds;

    *cmds++ = cp_type7_packet(CP_SET_DRAW_STATE, 3);
    *cmds++ = 0x40000;
    *cmds++ = 0;
    *cmds++ = 0;

    return cmds - start;
}

#endif //ADRENALINE_ADRENALINE_H
