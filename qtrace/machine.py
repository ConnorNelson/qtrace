import os
import sys
import fcntl
import select
import termios
import array
import enum
import ctypes
import subprocess
import pathlib

from . import syscalls

DEPS_PATH = pathlib.Path(__file__).parent / "deps"
LD_PATH = DEPS_PATH / "lib64" / "ld-linux-x86-64.so.2"
LIBS_PATH = DEPS_PATH / "lib" / "x86_64-linux-gnu"
QEMU_PATH = DEPS_PATH / "usr" / "local" / "bin" / "qemu-x86_64"
QTRACE_PATH = DEPS_PATH / "libqtrace.so"
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


class TraceMachine:
    def __init__(self, argv):
        self.argv = argv
        self.trace = []

    def run(self):
        trace_pipe_read_path = "/tmp/read"
        trace_pipe_write_path = "/tmp/write"

        def create_pipe(path):
            if os.path.exists(path):
                os.unlink(path)
            os.mkfifo(path)

        create_pipe(trace_pipe_read_path)
        create_pipe(trace_pipe_write_path)

        process = subprocess.Popen(
            [
                LD_PATH,
                "--library-path",
                LIBS_PATH,
                QEMU_PATH,
                "-plugin",
                f"{QTRACE_PATH},arg={trace_pipe_write_path},arg={trace_pipe_read_path}",
                *self.argv,
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
            r_available, w_available, x_available = select.select(
                r_list, w_list, x_list
            )

            for r in r_available:
                if r == trace_pipe_read:
                    data = os.read(r.fileno(), ctypes.sizeof(TRACE_HEADER))
                    if data:
                        trace_header = TRACE_HEADER.from_buffer_copy(data)
                        bb_addr_type = dict(TRACE._fields_)["bb_addrs"]._type_
                        bb_addrs_size = trace_header.num_addrs * ctypes.sizeof(
                            bb_addr_type
                        )
                        trace_data = os.read(r.fileno(), bb_addrs_size)
                        trace_addrs = (
                            trace_header.num_addrs * bb_addr_type
                        ).from_buffer_copy(trace_data)

                        reason = TRACE_REASON(trace_header.reason)

                        for address in trace_addrs:
                            self.on_basic_block(address)

                        if reason == TRACE_REASON.trace_full:
                            pass

                        elif reason == TRACE_REASON.trace_syscall_start:
                            syscall_nr = trace_header.info.syscall_num
                            syscall_definition = syscalls["x86_64"][syscall_nr]
                            syscall_args = syscall_definition[2:]
                            args = list(
                                trace_header.info.syscall_data.syscall_start_data
                            )[: len(syscall_args)]
                            self.on_syscall_start(syscall_nr, *args)

                        elif reason == TRACE_REASON.trace_syscall_end:
                            syscall_nr = trace_header.info.syscall_num
                            ret = trace_header.info.syscall_data.syscall_ret
                            self.on_syscall_end(syscall_nr, ret)

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

    def on_basic_block(self, address):
        self.trace.append(("bb", address))

    def on_syscall_start(self, syscall_nr, *args):
        self.current_syscall = syscall_nr
        self.current_syscall_args = args

    def on_syscall_end(self, syscall_nr, ret):
        assert syscall_nr == self.current_syscall
        self.trace.append(("syscall", syscall_nr, self.current_syscall_args, ret))
        del self.current_syscall
        del self.current_syscall_args


class LogTraceMachine(TraceMachine):
    def syscall_int_fmt(self, arg):
        if arg <= 0x100:
            return str(arg)
        elif (1 << 32) - 0x100 <= arg < (1 << 32):
            return str(arg | (-(arg & 0x80000000)))
        else:
            return hex(arg)

    def on_syscall_start(self, syscall_nr, *args):
        super().on_syscall_start(syscall_nr, *args)

        syscall_definition = syscalls["x86_64"][syscall_nr]
        syscall_name = syscall_definition[1]

        if syscall_name.startswith("sys_"):
            syscall_name = syscall_name[len("sys_") :]

        description_inner = ", ".join(self.syscall_int_fmt(arg) for arg in args)
        description = f"{syscall_name}({description_inner})"
        print(description, end=" ")

    def on_syscall_end(self, syscall_nr, ret):
        super().on_syscall_end(syscall_nr, ret)

        print("=", self.syscall_int_fmt(ret))
