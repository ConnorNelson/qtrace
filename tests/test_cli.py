import subprocess


def test_cli():
    output = subprocess.check_output(["qtrace", "false"])
    output_lines = set(output.decode().split("\n"))

    stats = set(
        (
            "Traced 20921 basic blocks (1632 unique)",
            "Traced 31 syscalls (30 unique)",
            "Traced 2 outputs (2 unique)",
        )
    )

    assert stats.issubset(output_lines)
