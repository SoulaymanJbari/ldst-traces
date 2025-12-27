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

#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <qemu-plugin.h>

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

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static CPU *cpus;
static int cpu_len;

static struct qemu_plugin_scoreboard *insn_count_score;
static qemu_plugin_u64 insn_count_entry;


static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata) {
  if (!qemu_plugin_log_is_enabled()) {
    return;
  }
  struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
  if (qemu_plugin_hwaddr_is_io(hwaddr)) {
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

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {

}

static void plugin_exit(qemu_plugin_id_t id, void *p) { 
  qemu_plugin_scoreboard_free(insn_count_score);
  munmap(cpus, cpu_len * sizeof(CPU));
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
  cpu_len = info->system.max_vcpus;
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
