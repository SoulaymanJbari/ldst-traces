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

#include <qemu-plugin.h>

typedef struct LogRecord {
  uint64_t logical_clock;
  uint64_t insn_count;
  char cpu;
  char store;
  char access_size;
  uint64_t address;
} LogRecord;

typedef struct CPU {
  FILE *logfile;
  LogRecord record;
} CPU;

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static CPU *cpus;
static int cpu_len;

static uint64_t logical_clock;
static uint64_t *insn_count;

static inline void log_write(LogRecord *value, int cpu) {
  fwrite(value, sizeof(LogRecord), 1, cpus[cpu].logfile);
}

static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata) {
  if (!qemu_plugin_log_is_enabled()) {
    return;
  }
  LogRecord record;

  if (qemu_plugin_mem_is_store(info)) {
    record.store = 1;
  } else {
    record.store = 0;
  }
  struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
  if (qemu_plugin_hwaddr_is_io(hwaddr)) {
    return;
  }
  uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
  record.address = addr;
  record.cpu = cpu_index;
  record.access_size = qemu_plugin_mem_size_shift(info);
  record.logical_clock = __atomic_load_n(&logical_clock, __ATOMIC_SEQ_CST);
  record.insn_count = insn_count[cpu_index];
  log_write(&record, cpu_index);
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
  if (!qemu_plugin_log_is_enabled()) {
    return;
  }
  ++insn_count[cpu_index];
  __atomic_fetch_add(&logical_clock, 1, __ATOMIC_SEQ_CST);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  struct qemu_plugin_insn *insn;

  size_t n_insns = qemu_plugin_tb_n_insns(tb);
  for (size_t i = 0; i < n_insns; i++) {
    insn = qemu_plugin_tb_get_insn(tb, i);
    qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem, QEMU_PLUGIN_CB_NO_REGS,
                                     QEMU_PLUGIN_MEM_RW, NULL);
    qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                           QEMU_PLUGIN_CB_NO_REGS, NULL);
  }
}

QEMU_PLUGIN_EXPORT void close_logfiles(void) {
  for (int i = 0; i < cpu_len; ++i) {
    fclose(cpus[i].logfile);
  }
}

QEMU_PLUGIN_EXPORT void open_logfiles(void) {
  char filename[32];
  for (int i = 0; i < cpu_len; ++i) {
    snprintf(filename, 32, "log.txt.%d", i);
    cpus[i].logfile = fopen(filename, "wb");
  }
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
  char filename[32];
  snprintf(filename, 32, "log.txt.%d", vcpu_index);
  cpus[vcpu_index].logfile = fopen(filename, "wb");
}

static void plugin_exit(qemu_plugin_id_t id, void *p) { close_logfiles(); }

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv) {
  cpu_len = info->system.max_vcpus;
  cpus = malloc(cpu_len * sizeof(CPU));
  insn_count = calloc(cpu_len, sizeof(uint64_t));

  /* Register init, translation block and exit callbacks */
  qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
  qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
  qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

  return 0;
}
