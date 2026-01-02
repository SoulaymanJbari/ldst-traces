/*
 * This plugin creates a load store trace in a binary format given by struct
 * LogRecord. It creates per-cpu-logfiles log.txt.[cpu idx]. The tracing is
 * enabled when plugin logs are enabled (qemu monitor command `log plugin`). The
 * tracing is disabled when plugin logs are disabled (qemu monitor command `log
 * none`).
 *
 * Attention: even when the tracing is disabled the plugin slows down the guest
 * significantly. This is because the plugin callbacks are still injected during
 * translation and executed they just do not do anything. One could disable the
 * callback registering completely, but you run the risk of losing some
 * load/stores due to qemu's caching of translation blocks. (I.e. it may still
 * execute cached translation blocks without the plugin callbacks even when the
 * plugin is enabled). If you do not need the plugin do not add it in the qemu
 * command line to avoid slowdowns.
 *
 * The logfiles are closed (and any pending writes flushed) on qemu monitor
 * command `stop`. The logfiles are cleared and reopened on qemu monitor command
 * `continue`.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static int limit;
static bool sys;

typedef struct {
    uint64_t tag;
    bool valid;
} CacheBlock;

typedef struct {
    CacheBlock *blocks;
    uint64_t *lru_priorities;
    uint64_t lru_gen_counter;
} CacheSet;

typedef struct {
    CacheSet *sets;
    int num_sets;
    int cachesize;
    int assoc;
    int blksize_shift;
    uint64_t set_mask;
    uint64_t tag_mask;
    uint64_t accesses;
    uint64_t misses;
} Cache;

typedef struct LogRecord {
  uint64_t logical_clock;
  uint64_t insn_count;
  char cpu;
  char store;
  char access_size;
  uint64_t address;
} LogRecord;

#define MAX_BUFFER_SIZE 50000000

typedef struct CPU {
  uint64_t head;
  uint64_t tail;
  LogRecord logRecord[MAX_BUFFER_SIZE];
} CPU;



static CPU *cpus;
static int cpu_len;

static struct qemu_plugin_scoreboard *insn_count_score;
static qemu_plugin_u64 insn_count_entry;

static Cache **l1_dcaches;

static int pow_of_two(int num)
{
    g_assert((num & (num - 1)) == 0);
    int ret = 0;
    while (num /= 2) {
        ret++;
    }
    return ret;
}

static void lru_priorities_init(Cache *cache)
{
    int i;

    for (i = 0; i < cache->num_sets; i++) {
        cache->sets[i].lru_priorities = g_new0(uint64_t, cache->assoc);
        cache->sets[i].lru_gen_counter = 0;
    }
}

static void lru_update_blk(Cache *cache, int set_idx, int blk_idx)
{
    CacheSet *set = &cache->sets[set_idx];
    set->lru_priorities[blk_idx] = cache->sets[set_idx].lru_gen_counter;
    set->lru_gen_counter++;
}

static int lru_get_lru_block(Cache *cache, int set_idx)
{
    int i, min_idx, min_priority;

    min_priority = cache->sets[set_idx].lru_priorities[0];
    min_idx = 0;

    for (i = 1; i < cache->assoc; i++) {
        if (cache->sets[set_idx].lru_priorities[i] < min_priority) {
            min_priority = cache->sets[set_idx].lru_priorities[i];
            min_idx = i;
        }
    }
    return min_idx;
}

static void lru_priorities_destroy(Cache *cache)
{
    int i;

    for (i = 0; i < cache->num_sets; i++) {
        g_free(cache->sets[i].lru_priorities);
    }
}

static inline uint64_t extract_tag(Cache *cache, uint64_t addr)
{
    return addr & cache->tag_mask;
}

static inline uint64_t extract_set(Cache *cache, uint64_t addr)
{
    return (addr & cache->set_mask) >> cache->blksize_shift;
}

static const char *cache_config_error(int blksize, int assoc, int cachesize)
{
    if (cachesize % blksize != 0) {
        return "cache size must be divisible by block size";
    } else if (cachesize % (blksize * assoc) != 0) {
        return "cache size must be divisible by set size (assoc * block size)";
    } else {
        return NULL;
    }
}

static bool bad_cache_params(int blksize, int assoc, int cachesize)
{
    return (cachesize % blksize) != 0 || (cachesize % (blksize * assoc) != 0);
}

static Cache *cache_init(int blksize, int assoc, int cachesize)
{
    Cache *cache;
    int i;
    uint64_t blk_mask;

    /*
     * This function shall not be called directly, and hence expects suitable
     * parameters.
     */
    g_assert(!bad_cache_params(blksize, assoc, cachesize));

    cache = g_new(Cache, 1);
    cache->assoc = assoc;
    cache->cachesize = cachesize;
    cache->num_sets = cachesize / (blksize * assoc);
    cache->sets = g_new(CacheSet, cache->num_sets);
    cache->blksize_shift = pow_of_two(blksize);
    cache->accesses = 0;
    cache->misses = 0;

    for (i = 0; i < cache->num_sets; i++) {
        cache->sets[i].blocks = g_new0(CacheBlock, assoc);
    }

    blk_mask = blksize - 1;
    cache->set_mask = ((cache->num_sets - 1) << cache->blksize_shift);
    cache->tag_mask = ~(cache->set_mask | blk_mask);

    lru_priorities_init(cache);

    return cache;
}

static Cache **caches_init(int blksize, int assoc, int cachesize)
{
    Cache **caches;
    int i;

    if (bad_cache_params(blksize, assoc, cachesize)) {
        fprintf(stderr,"Bad parameters\n");
        return NULL;
    }

    caches = g_new(Cache *, cpu_len);

    for (i = 0; i < cpu_len; i++) {
        caches[i] = cache_init(blksize, assoc, cachesize);
    }

    return caches;
}

static int get_invalid_block(Cache *cache, uint64_t set)
{
    int i;

    for (i = 0; i < cache->assoc; i++) {
        if (!cache->sets[set].blocks[i].valid) {
            return i;
        }
    }

    return -1;
}


static int in_cache(Cache *cache, uint64_t addr)
{
    int i;
    uint64_t tag, set;

    tag = extract_tag(cache, addr);
    set = extract_set(cache, addr);

    for (i = 0; i < cache->assoc; i++) {
        if (cache->sets[set].blocks[i].tag == tag &&
                cache->sets[set].blocks[i].valid) {
            return i;
        }
    }

    return -1;
}

/**
 * access_cache(): Simulate a cache access
 * @cache: The cache under simulation
 * @addr: The address of the requested memory location
 *
 * Returns true if the requested data is hit in the cache and false when missed.
 * The cache is updated on miss for the next access.
 */
static bool access_cache(Cache *cache, uint64_t addr)
{
    int hit_blk, replaced_blk;
    uint64_t tag, set;

    tag = extract_tag(cache, addr);
    set = extract_set(cache, addr);

    hit_blk = in_cache(cache, addr);
    if (hit_blk != -1) {
        lru_update_blk(cache, set, hit_blk);
        return true;
    }

    replaced_blk = get_invalid_block(cache, set);

    if (replaced_blk == -1) {
        replaced_blk = lru_get_lru_block(cache, set);
    }

    lru_update_blk(cache, set, replaced_blk);

    cache->sets[set].blocks[replaced_blk].tag = tag;
    cache->sets[set].blocks[replaced_blk].valid = true;

    return false;
}


static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata) {
  if (!qemu_plugin_log_is_enabled()) {
    return;
  }
  uint64_t effective_addr;
  int cache_idx;
  bool hit_in_l1;
  struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
  if (qemu_plugin_hwaddr_is_io(hwaddr)) {
    return;
  }
  effective_addr = hwaddr ? qemu_plugin_hwaddr_phys_addr(hwaddr) : vaddr;
  cache_idx = cpu_index % cpu_len;
  hit_in_l1 = access_cache(l1_dcaches[cache_idx], effective_addr);
  if (hit_in_l1){
    return;
  }
  uint64_t index = __atomic_fetch_add(&cpus[cpu_index].head,1,__ATOMIC_SEQ_CST);
  uint64_t real_index = index % MAX_BUFFER_SIZE;
  if (qemu_plugin_mem_is_store(info)) {
    cpus[cpu_index].logRecord[real_index].store = 1;
  } else {
    cpus[cpu_index].logRecord[real_index].store = 0;
  }
  uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
  cpus[cpu_index].logRecord[real_index].address = addr;
  cpus[cpu_index].logRecord[real_index].cpu = cpu_index;
  cpus[cpu_index].logRecord[real_index].access_size = qemu_plugin_mem_size_shift(info);
  cpus[cpu_index].logRecord[real_index].logical_clock = qemu_plugin_u64_sum(insn_count_entry);
  uint64_t *val = qemu_plugin_scoreboard_find(insn_count_score, cpu_index);
  cpus[cpu_index].logRecord[real_index].insn_count = *val;
}


static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  struct qemu_plugin_insn *insn;
  size_t n_insns = qemu_plugin_tb_n_insns(tb);

  for (size_t i = 0; i < n_insns; i++) {
    insn = qemu_plugin_tb_get_insn(tb, i);
    qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem, QEMU_PLUGIN_CB_NO_REGS,
                                     QEMU_PLUGIN_MEM_RW, NULL);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn,
      QEMU_PLUGIN_INLINE_ADD_U64,insn_count_entry,1);
  }
}

static void cache_free(Cache *cache)
{
    for (int i = 0; i < cache->num_sets; i++) {
        g_free(cache->sets[i].blocks);
    }

    lru_priorities_destroy(cache);

    g_free(cache->sets);
    g_free(cache);
}

static void caches_free(Cache **caches)
{
    int i;

    for (i = 0; i < cpu_len; i++) {
        cache_free(caches[i]);
    }
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {

}

static void plugin_exit(qemu_plugin_id_t id, void *p) { 
  qemu_plugin_scoreboard_free(insn_count_score);
  caches_free(l1_dcaches);
  munmap(cpus, cpu_len * sizeof(CPU));
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
  int l1_dassoc, l1_dblksize, l1_dcachesize;

  limit = 32;
  sys = info->system_emulation;

  l1_dassoc = 8;
  l1_dblksize = 64;
  l1_dcachesize = l1_dblksize * l1_dassoc * 32;
  cpu_len = info->system.max_vcpus;
  l1_dcaches = caches_init(l1_dblksize, l1_dassoc, l1_dcachesize);
  if (!l1_dcaches) {
      const char *err = cache_config_error(l1_dblksize, l1_dassoc, l1_dcachesize);
      fprintf(stderr, "dcache cannot be constructed from given parameters\n");
      if (err) {
          fprintf(stderr, "%s\n", err);
      }
      return -1;
  }
  uint64_t total_size = cpu_len * sizeof(CPU);
  int fd = shm_open("/qemu_trace", O_CREAT | O_RDWR | O_TRUNC, 0666);
  if (ftruncate(fd, total_size) == -1) {
    perror("ftruncate");
    close(fd);
    return -1; 
  }
  cpus = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  memset(cpus, 0, total_size);
  insn_count_score = qemu_plugin_scoreboard_new(sizeof(uint64_t));
  insn_count_entry = qemu_plugin_scoreboard_u64(insn_count_score);

  /* Register init, translation block and exit callbacks */
  qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
  qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
  qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

  return 0;
}