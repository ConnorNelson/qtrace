import pathlib

import qtrace


programs_dir = pathlib.Path(__file__).parent / "programs"


def test_loop():
    loop_path = programs_dir / "loop"
    machine = qtrace.TraceMachine([loop_path])
    machine.run()
