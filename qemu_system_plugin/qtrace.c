/*
 * QEMU-SYSTEM BASED TRACER
 * ------------------------
 * This plugin supports tracing a target process running within a full QEMU
 * system instance. To identify execution of the target process among other
 * processes running in the system, this plugin supports a simple virtual memory
 * matching test.
 *
 * When launching the plugin, specify one or more <addr>=<data> arguments for
 * the plugin, where <addr> is the hex virtual memory address and <data> are the
 * base64 encoded bytes to check.
 *
 * Before attempting to perform QEMU system based tracing, make sure to apply
 * the patch that accompanies this plugin, which adds support for reading memory
 *
 * - Apply patches in qemu-patches to QEMU v5.2.0
 * - Build this plugin
 * - When launching QEMU, add plugin and plugin arguments as follows:
 *   -plugin file=$PWD/libqtrace.so,arg="<addr>=<data>"
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <qemu-plugin.h>

#define TRACE_MAX_BB_ADDRS  0x1000
#define TRACE_FD            255

#define DEBUG 0

/*
 * Enable for version of memory-read API implementation which works on unpatched
 * QEMU. This is dangerous, however...
 */
#define NO_PATCH_HACK 0

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum reason {
    trace_full = 0,
    trace_syscall_start = 1,
    trace_syscall_end = 2,
};

struct trace_info {
    int64_t syscall_num;
    union {
        struct {
            uint64_t syscall_a1;
            uint64_t syscall_a2;
            uint64_t syscall_a3;
            uint64_t syscall_a4;
            uint64_t syscall_a5;
            uint64_t syscall_a6;
            uint64_t syscall_a7;
            uint64_t syscall_a8;
        };
        int64_t syscall_ret;
    };
};
#define EMPTY_INFO (const struct trace_info) { 0 }

struct {
    struct {
        enum reason reason;
        uint64_t num_addrs;
        struct trace_info info;
    } header;
    uint64_t bb_addrs[TRACE_MAX_BB_ADDRS];
} trace;

static inline void trace_flush(enum reason reason, struct trace_info info) {
    size_t size;
    uint64_t response;

    trace.header.reason = reason;
    trace.header.info = info;

    size = sizeof(trace.header) + (trace.header.num_addrs * sizeof(uint64_t));
    assert(write(TRACE_FD, &trace, size) == size);
#if !DEBUG
    assert(read(TRACE_FD, &response, sizeof(response)) == sizeof(response));
#endif

#if DEBUG
    fprintf(stderr, "syscall(%ld)\n", trace.header.info.syscall_num);
#endif

    trace.header.reason = 0;
    trace.header.num_addrs = 0;
    trace.header.info = EMPTY_INFO;
}

static inline void trace_add_bb_addr(uint64_t addr)
{
    trace.bb_addrs[trace.header.num_addrs++] = addr;
    if (trace.header.num_addrs == TRACE_MAX_BB_ADDRS)
        trace_flush(trace_full, EMPTY_INFO);
}

/*
 * Rudimentary test to check if target process is currently running: "Memory
 * Check" structure, which specifies a simple virtual memory byte-match test to
 * determine whether a particular callback should occur or not.
 */
struct mem_check {
    uint64_t addr;
    gsize len;
    const guchar *data;
};
static struct mem_check *mem_checks;
static size_t num_mem_checks;
static char *mem_check_buf;
static int mem_check_buf_size = 0;

#if NO_PATCH_HACK
typedef uint32_t target_ulong; // Target-dependent! Same size as virtual address
void *qemu_get_cpu(int index);
int cpu_memory_rw_debug(void *cpu, target_ulong addr, void *ptr, target_ulong len, bool is_write);
bool qemu_plugin_mem_read__hack(unsigned int vcpu_index, uint64_t vaddr, uint64_t len, void *data) {
    return cpu_memory_rw_debug(qemu_get_cpu(vcpu_index), vaddr, data, len, false) >= 0;
}
#define qemu_plugin_mem_read qemu_plugin_mem_read__hack
#endif

/*
 * Decode one of the plugin command line arguments specifying a mem check
 */
static void decode_mem_check(char *s)
{
    struct mem_check c;

    /* Decode check argument */
    if (sscanf(s, "%lx=", &c.addr) != 1) return;
    char *data_b64 = strchr(s, '=') + 1;
    if (!*data_b64) return;
    c.data = g_base64_decode(data_b64, &c.len);
    if (c.len == 0) return;

    num_mem_checks++;

    /* Reallocate temporary check buffer to maximum check length */
    if (c.len > mem_check_buf_size) {
        mem_check_buf = realloc(mem_check_buf, c.len);
        assert(mem_check_buf != NULL);
    }

    /* Add check */
    mem_checks = reallocarray(mem_checks, num_mem_checks, sizeof(c));
    mem_checks[num_mem_checks-1] = c;
}

/*
 * Determine if this particular callback (TB translate, exec) should execute
 * based on whether the target process is loaded or not.
 */
static bool should_instrument(void)
{
    for (size_t i = 0; i < num_mem_checks; i++) {
        struct mem_check *c = &mem_checks[i];
        if (!qemu_plugin_mem_read(0, c->addr, c->len, mem_check_buf))
            return false; /* Failed to read */
        if (memcmp(c->data, mem_check_buf, c->len))
            return false; /* Mismatch */
    }

    return true;
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    if (!should_instrument()) return;

    uint64_t addr = (uint64_t) udata;

#if DEBUG
    fprintf(stderr, "exec(0x%lx)\n", addr);
#endif

    trace_add_bb_addr(addr);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    if (!should_instrument()) return;

    uint64_t addr = qemu_plugin_tb_vaddr(tb);

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *) addr);
}

static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_index,
                         int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8)
{
    if (!should_instrument()) return;

    struct trace_info info;
    info.syscall_num = num;
    info.syscall_a1 = a1;
    info.syscall_a2 = a2;
    info.syscall_a3 = a3;
    info.syscall_a4 = a4;
    info.syscall_a5 = a5;
    info.syscall_a6 = a6;
    info.syscall_a7 = a7;
    info.syscall_a8 = a8;

    trace_flush(trace_syscall_start, info);
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_index,
                             int64_t num, int64_t ret)
{
    if (!should_instrument()) return;

    struct trace_info info;
    info.syscall_num = num;
    info.syscall_ret = ret;

    trace_flush(trace_syscall_end, info);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    int server_fd;
    int client_fd;
    struct sockaddr_in server_addr;

    for (int i = 0; i < argc; i++) {
        decode_mem_check(argv[i]);
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &(int){1}, sizeof(int));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(4242);
    bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    listen(server_fd, 1);
    client_fd = accept(server_fd, NULL, NULL);

    assert(dup2(client_fd, TRACE_FD) != -1);
    assert(close(client_fd) != -1);
    assert(close(server_fd) != -1);

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);

    return 0;
}
