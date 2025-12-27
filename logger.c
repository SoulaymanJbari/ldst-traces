#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <stdbool.h>

typedef struct LogRecord {
  uint64_t logical_clock;
  uint64_t insn_count;
  char cpu;
  char store;
  char access_size;
  uint64_t address;
} LogRecord;

#define MAX_BUFFER_SIZE 50000000
#define CHUNK_TRESHOLD  10000000

typedef struct CPU {
  uint64_t head;
  uint64_t tail;
  LogRecord logRecord[MAX_BUFFER_SIZE];
} CPU;


int * logfds;

static CPU *cpus;
static int cpu_len;

volatile bool stopping = false;

void handle_signals(int sig) {
    if (sig == SIGINT) stopping = true;
}

int main(int argc, char** argv){
    int nb_error = 0;
    if (argc != 2){
        printf("Il faut préciser le nombre de cpus qui tournent");
        return -1;
    }
    signal(SIGINT, handle_signals);
    cpu_len = atoi(argv[1]);
    logfds = malloc(cpu_len * sizeof(int*));
    char filename[32];
    for (int i=0; i<cpu_len; i++){
        snprintf(filename, 32, "log.txt.%d",i);
        logfds[i] = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    }
    
    uint64_t total_size = cpu_len * sizeof(CPU);
    int fd = shm_open("/qemu_trace", O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        perror("ERREUR shm_open");
        exit(1);
    }
    cpus = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (cpus == MAP_FAILED) {
        perror("ERREUR mmap");
        exit(1);
    }
    while (!stopping){
        for (int i=0; i< cpu_len; i++){
            uint64_t current_head = __atomic_load_n(&cpus[i].head, __ATOMIC_RELAXED);
            uint64_t current_tail = __atomic_load_n(&cpus[i].tail, __ATOMIC_RELAXED);
            uint64_t size = current_head - current_tail;
            if (size > MAX_BUFFER_SIZE){
                printf("Erreur dans l'écriture, écrasement de données\n");
                nb_error++;
                __atomic_store_n(&cpus[i].tail, current_head -1, __ATOMIC_RELEASE);
                continue;
            }
            if (size > CHUNK_TRESHOLD){
                uint64_t real_head = current_head % MAX_BUFFER_SIZE;
                uint64_t real_tail = current_tail % MAX_BUFFER_SIZE;
                if (real_tail < real_head){
                    write(logfds[i], &cpus[i].logRecord[real_tail], sizeof(LogRecord) * size);
                } else {
                    write(logfds[i], &cpus[i].logRecord[real_tail], sizeof(LogRecord) * (MAX_BUFFER_SIZE - real_tail));
                    write(logfds[i], &cpus[i].logRecord[0], sizeof(LogRecord) * (size - (MAX_BUFFER_SIZE - real_tail)));
                }

                __atomic_fetch_add(&cpus[i].tail, size, __ATOMIC_SEQ_CST);
            }
        }

    }
    for (int i=0; i< cpu_len; i++){
        uint64_t current_head = __atomic_load_n(&cpus[i].head, __ATOMIC_RELAXED);
        uint64_t current_tail = __atomic_load_n(&cpus[i].tail, __ATOMIC_RELAXED);
        uint64_t size = current_head - current_tail;
        if (current_head - current_tail != 0){
            uint64_t real_head = current_head % MAX_BUFFER_SIZE;
            uint64_t real_tail = current_tail % MAX_BUFFER_SIZE;
            if (real_tail < real_head){
                write(logfds[i], &cpus[i].logRecord[real_tail], sizeof(LogRecord) * size);
            } else {
                write(logfds[i], &cpus[i].logRecord[real_tail], sizeof(LogRecord) * (MAX_BUFFER_SIZE - real_tail));
                write(logfds[i], &cpus[i].logRecord[0], sizeof(LogRecord) * (size - (MAX_BUFFER_SIZE - real_tail)));
            }
        }
        close(logfds[i]);
    }
    free(logfds);
    munmap(cpus, total_size);
    close(fd);
    printf("Il y a eu %d erreurs\n",nb_error);
    return 0;
}