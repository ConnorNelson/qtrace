from .gdb_minimal_client import gdb_minimal_client


def breakpoint(address):
    address += 0x4000000000

    def wrapper(func):
        func.gdb_breakpoint_address = address
        return func

    return wrapper
