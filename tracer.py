import os
import sys
import fcntl
import select
import termios
import array
import struct
import enum
import ctypes
import subprocess

import syscalls

QEMU_PATH = "/usr/local/bin/qemu-x86_64"
TRACE_MAX_BB_ADDRS = 0x1000


class TRACE_REASON(enum.Enum):
    trace_full = 0
    trace_syscall_start = 1
    trace_syscall_end = 2


class SYSCALL_START_DATA(ctypes.Structure):
    _fields_ = [
        ("syscall_a1", ctypes.c_uint64),
        ("syscall_a2", ctypes.c_uint64),
        ("syscall_a3", ctypes.c_uint64),
        ("syscall_a4", ctypes.c_uint64),
        ("syscall_a5", ctypes.c_uint64),
        ("syscall_a6", ctypes.c_uint64),
        ("syscall_a7", ctypes.c_uint64),
        ("syscall_a8", ctypes.c_uint64),
    ]

    def __getitem__(self, key):
        return getattr(self, self._fields_[key][0])


class SYSCALL_DATA(ctypes.Union):
    _fields_ = [
        ("syscall_start_data", SYSCALL_START_DATA),
        ("syscall_ret", ctypes.c_int64),
    ]


class TRACE_INFO(ctypes.Structure):
    _fields_ = [("syscall_num", ctypes.c_int64), ("syscall_data", SYSCALL_DATA)]


class TRACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("reason", ctypes.c_uint),
        ("num_addrs", ctypes.c_uint64),
        ("info", TRACE_INFO),
    ]


class TRACE(ctypes.Structure):
    _fields_ = [
        ("header", TRACE_HEADER),
        ("bb_addrs", ctypes.c_uint64 * TRACE_MAX_BB_ADDRS),
    ]


def main():
    target = sys.argv[1]

    trace_pipe_read_path = "/tmp/read"
    trace_pipe_write_path = "/tmp/write"

    os.mkfifo(trace_pipe_read_path)
    os.mkfifo(trace_pipe_write_path)

    process = subprocess.Popen(
        [
            QEMU_PATH,
            "-plugin",
            f"./plugin/libtracer.so,arg={trace_pipe_write_path},arg={trace_pipe_read_path}",
            target,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    trace_pipe_read = open(trace_pipe_read_path, "rb")
    trace_pipe_write = open(trace_pipe_write_path, "wb")

    r_list = [process.stdout, process.stderr, trace_pipe_read]
    w_list = []
    x_list = []
    num_bytes = array.array("i", [0])
    while r_list:
        r_available, w_available, x_available = select.select(r_list, w_list, x_list)

        for r in r_available:
            if r == trace_pipe_read:
                data = os.read(r.fileno(), ctypes.sizeof(TRACE_HEADER))
                if data:
                    trace_header = TRACE_HEADER.from_buffer_copy(data)
                    bb_addr_type = dict(TRACE._fields_)["bb_addrs"]._type_
                    bb_addrs_size = trace_header.num_addrs * ctypes.sizeof(bb_addr_type)
                    trace_data = os.read(r.fileno(), bb_addrs_size)
                    trace_addrs = (
                        trace_header.num_addrs * bb_addr_type
                    ).from_buffer_copy(trace_data)

                    reason = TRACE_REASON(trace_header.reason)

                    if reason == TRACE_REASON.trace_full:
                        pass

                    elif reason == TRACE_REASON.trace_syscall_start:
                        syscall_definition = syscalls.x86_64[
                            trace_header.info.syscall_num
                        ]
                        syscall_definition_name = syscall_definition[1]
                        syscall_definition_args = syscall_definition[2:]

                        args = trace_header.info.syscall_data.syscall_start_data

                        def syscall_arg_fmt(arg):
                            if arg <= 0x100:
                                return str(arg)
                            elif (1 << 32) - 0x100 <= arg < (1 << 32):
                                return str(arg | (-(arg & 0x80000000)))
                            else:
                                return hex(arg)

                        description_inner = ", ".join(
                            syscall_arg_fmt(args[i])
                            for i in range(len(syscall_definition_args))
                        )
                        description = f"{syscall_definition_name}({description_inner})"

                        print(description, end=" ")

                    elif reason == TRACE_REASON.trace_syscall_end:
                        print("=", hex(trace_header.info.syscall_data.syscall_ret))

                    os.write(trace_pipe_write.fileno(), b"\x00" * 8)

            elif r == process.stdout:
                fcntl.ioctl(r.fileno(), termios.FIONREAD, num_bytes)
                data = os.read(r.fileno(), num_bytes[0])
                if data:
                    sys.stdout.buffer.write(data)
                # else:
                #     sys.stdout.buffer.close()

            elif r == process.stderr:
                fcntl.ioctl(r.fileno(), termios.FIONREAD, num_bytes)
                data = os.read(r.fileno(), num_bytes[0])
                if data:
                    sys.stderr.buffer.write(data)
                # else:
                #     sys.stderr.buffer.close()

            if not data:
                r_list.remove(r)


if __name__ == "__main__":
    main()
