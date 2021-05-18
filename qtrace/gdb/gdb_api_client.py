#!/usr/bin/env python

from threading import Event
from subprocess import Popen, PIPE, DEVNULL
from time import sleep
from tempfile import mkdtemp
from pathlib import Path

from rpyc import BgServingThread
from rpyc.utils.factory import unix_connect


class Breakpoint:
    """Mirror of ``gdb.Breakpoint`` class.
    See https://sourceware.org/gdb/onlinedocs/gdb/Breakpoints-In-Python.html
    for more information.
    """

    def __init__(self, conn, *args, **kwargs):
        """Do not create instances of this class directly.
        Use ``pwnlib.gdb.Gdb.Breakpoint`` instead.
        """
        # Creates a real breakpoint and connects it with this mirror
        self.conn = conn
        self.server_breakpoint = conn.root.set_breakpoint(
            self, hasattr(self, "stop"), *args, **kwargs
        )

    def __getattr__(self, item):
        """Return attributes of the real breakpoint."""
        if item in (
            "____id_pack__",
            "__name__",
            "____conn__",
            "stop",
        ):
            # Ignore RPyC netref attributes.
            # Also, if stop() is not defined, hasattr() call in our
            # __init__() will bring us here. Don't contact the
            # server in this case either.
            raise AttributeError()
        return getattr(self.server_breakpoint, item)

    def exposed_stop(self):
        # Handle stop() call from the server.
        return self.stop()


class GDB:
    """Mirror of ``gdb`` module.
    See https://sourceware.org/gdb/onlinedocs/gdb/Basic-Python.html for more
    information.
    """

    def __init__(self, conn, *, extra=None):
        """Do not create instances of this class directly.
        Use :func:`attach` or :func:`debug` with ``api=True`` instead.
        """
        if extra is None:
            extra = []
        self.conn = conn
        self.extra = extra

        registers = set()
        for line in self.execute("info registers").strip().split("\n"):
            register = line.split()[0]
            registers.add(register)
        self.registers = registers

        self.memory = Memory(self)

        class _Breakpoint(Breakpoint):
            def __init__(self, *args, **kwargs):
                super().__init__(conn, *args, **kwargs)

        self.Breakpoint = _Breakpoint
        self.stopped = Event()

        def stop_handler(event):
            self.stopped.set()

        self.events.stop.connect(stop_handler)

    def __getattr__(self, item):
        """Provide access to the attributes of `gdb` module."""
        if item in self.extra:
            return getattr(self.conn.root, item)
        if item in self.registers:
            return self.read_register(item)
        return getattr(self.conn.root.gdb, item)

    def execute(self, command):
        return self.conn.root.gdb.execute(command, to_string=True)

    def read_register(self, register, cast=True):
        result = self.selected_frame().read_register(register)
        if cast:
            result = int(result)
        return result

    def wait(self):
        """Wait until the program stops."""
        self.stopped.wait()
        self.stopped.clear()

    def interrupt_and_wait(self):
        """Interrupt the program and wait until it stops."""
        self.execute("interrupt")
        self.wait()

    def continue_nowait(self):
        """Continue the program. Do not wait until it stops again."""
        self.execute("continue &")

    def continue_and_wait(self):
        """Continue the program and wait until it stops again."""
        self.continue_nowait()
        self.wait()

    def quit(self):
        """Terminate GDB."""
        self.conn.root.quit()


class Memory:
    def __init__(self, gdb):
        self.gdb = gdb

    def __getitem__(self, key):
        if isinstance(key, slice):
            address = key.start
            length = key.stop - key.start
            return self.gdb.selected_inferior().read_memory(address, length).tobytes()
        raise KeyError()


def gdb_api_client(address, machine, *, gdb_args=None, expose_extra=None):
    raise Exception("This is currently broken")

    if gdb_args is None:
        gdb_args = []
    if expose_extra is None:
        expose_extra = []

    socket_dir_path = Path(mkdtemp())
    socket_path = socket_dir_path / "socket"
    gdb_api_bridge_path = Path(__file__).parent / "gdb_api_bridge.py"
    host, port = address

    args = [
        "gdb",
        *("-ex", f"python socket_path = {repr(str(socket_path))}"),
        *("-ex", f"python expose_extra = {str(expose_extra)}"),
        *("-ex", f"source {gdb_api_bridge_path}"),
        *("-ex", f"target remote {host}:{port}"),
        *gdb_args,
        machine.argv[0],
    ]
    process = Popen(args, stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)

    for _ in range(100):
        if socket_path.exists():
            break
        sleep(0.1)

    conn = unix_connect(str(socket_path))
    socket_path.unlink()
    socket_dir_path.rmdir()

    BgServingThread(conn, callback=lambda: None)

    return GDB(conn, extra=expose_extra)
