import subprocess
import pathlib

import qtrace


programs_dir = pathlib.Path(__file__).parent / "programs"


def symbol_address(program_path, symbol):
    symbols = subprocess.check_output(["nm", "--defined-only", program_path])
    for line in symbols.decode().split("\n"):
        address, _, current_symbol = line.split(" ", 2)
        if current_symbol == symbol:
            return int(address, 16)
    else:
        raise Exception("Failed to find symbol")


def test_machine():
    factorial_path = programs_dir / "factorial"
    factorial_address = symbol_address(factorial_path, "factorial")

    class TestMachine(qtrace.TraceMachine):
        @qtrace.breakpoint(factorial_address)
        def on_factorial(self):
            results = {
                "rax": self.gdb.rax,
                "rbx": self.gdb.rbx,
                "rcx": self.gdb.rcx,
                "rdx": self.gdb.rdx,
                "rdi": self.gdb.rdi,
                "rsi": self.gdb.rsi,
                "rsp": self.gdb.rsp,
                "rip": self.gdb.rip,
                "instructions": self.gdb.memory[self.gdb.rip : self.gdb.rip + 8],
                "stack": self.gdb.memory[self.gdb.rsp : self.gdb.rsp + 8],
            }
            self.trace.append(("test", results))

    machine = TestMachine([factorial_path, str(7)])
    machine.run()

    factorial_args = [e[1]["rdi"] for e in machine.filtered_trace("test")]
    assert factorial_args == [7, 6, 5, 4, 3, 2, 1, 0]
