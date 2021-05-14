import subprocess


def test_cli():
    output = subprocess.check_output(["qtrace", "false"])
    output_lines = set(output.decode().split("\n"))
    traced_lines = set(line for line in output_lines if line.startswith("Traced "))

    assert any("basic blocks" in line for line in traced_lines)
    assert any("syscalls" in line for line in traced_lines)
    assert any("outputs" in line for line in traced_lines)
