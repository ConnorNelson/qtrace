import os
import sys
import fcntl
import select
import termios
import array
import struct
import subprocess

QEMU_PATH = "/usr/local/bin/qemu-x86_64"


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
    trace_pipe_read.read(8)

    trace_pipe_write = open(trace_pipe_write_path, "wb")
    os.write(trace_pipe_write.fileno(), b"\x00" * 8)

    r_list = [process.stdout, process.stderr, trace_pipe_read]
    w_list = []
    x_list = []
    num_bytes = array.array("i", [0])
    while r_list:
        r_available, w_available, x_available = select.select(r_list, w_list, x_list)

        for r in r_available:
            fcntl.ioctl(r.fileno(), termios.FIONREAD, num_bytes)
            data = os.read(r.fileno(), num_bytes[0])

            if r == trace_pipe_read:
                if data:
                    reason, num_addrs = struct.unpack("qq", data[:16])
                    if reason != -1 and num_addrs:
                        print(f"SYSCALL {reason}")
                    os.write(trace_pipe_write.fileno(), b"\x00" * 8)

            elif r == process.stdout:
                if data:
                    sys.stdout.buffer.write(data)
                # else:
                #     sys.stdout.buffer.close()

            elif r == process.stderr:
                if data:
                    sys.stderr.buffer.write(data)
                # else:
                #     sys.stderr.buffer.close()

            if not data:
                r_list.remove(r)


if __name__ == "__main__":
    main()
