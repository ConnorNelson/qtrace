import qtrace


def test_gdb():
    class TestMachine(qtrace.TraceMachine):
        @qtrace.breakpoint(0x400180D103)
        def on_D103(self):
            self.results = {
                "rax": self.gdb.rax,
                "rbx": self.gdb.rbx,
                "rcx": self.gdb.rcx,
                "rdx": self.gdb.rdx,
                "rsp": self.gdb.rsp,
                "rip": self.gdb.rip,
                "instructions": self.gdb.memory[self.gdb.rip : self.gdb.rip + 8],
                "stack": self.gdb.memory[self.gdb.rsp : self.gdb.rsp + 8],
            }

    machine = TestMachine(["/bin/false"])
    machine.run()

    assert machine.results == {
        "rax": 0x0,
        "rbx": 0x0,
        "rcx": 0x0,
        "rdx": 0x0,
        "rsp": 0x400180BD70,
        "rip": 0x400180D103,
        "instructions": b"\xe8\xe8\x0c\x00\x00I\x89\xc4",
        "stack": b"\x01\x00\x00\x00\x00\x00\x00\x00",
    }
