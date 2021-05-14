import pathlib

import qtrace


programs_dir = pathlib.Path(__file__).parent / "programs"


def test_machine():
    class TestMachine(qtrace.TraceMachine):
        @qtrace.breakpoint("factorial")
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

    machine = TestMachine([programs_dir / "factorial", str(7)])
    machine.run()

    factorial_args = [e[1]["rdi"] for e in machine.filtered_trace("test")]
    assert factorial_args == [7, 6, 5, 4, 3, 2, 1, 0]
