#ifndef QTRACE_H
#define QTRACE_H

#define TRACE_MAX_BB_ADDRS  0x1000
#define TRACE_FD            255

enum reason {
    trace_full = 0,
    trace_syscall_start = 1,
    trace_syscall_end = 2,
    trace_async = 3,
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

struct trace {
    struct {
        enum reason reason;
        uint64_t num_addrs;
        struct trace_info info;
    } header;
    uint64_t bb_addrs[TRACE_MAX_BB_ADDRS];
};

#define RESPONSE_ACK 0
#define RESPONSE_FLUSH 1

#endif
