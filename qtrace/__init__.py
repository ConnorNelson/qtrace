import pathlib

DEPS_PATH = pathlib.Path(__file__).parent / "deps"
LD_PATH = DEPS_PATH / "lib64" / "ld-linux-x86-64.so.2"
LIBS_PATH = DEPS_PATH / "lib" / "x86_64-linux-gnu"
QEMU_PATH = DEPS_PATH / "usr" / "local" / "bin" / "qemu-x86_64"
QTRACE_PATH = DEPS_PATH / "libqtrace.so"

from .syscalls import syscalls
from .machine import TraceMachine, LogTraceMachine
