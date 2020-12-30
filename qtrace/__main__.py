import sys
import os
import time

from . import LogTraceMachine


def resolve(path):
    if os.path.isfile(path):
        return path
    os_path = os.getenv("PATH")
    if os_path and not path.startswith("/"):
        for path_dir in os_path.split(":"):
            current_path = path_dir + "/" + path
            if os.path.isfile(current_path):
                return current_path


def main():
    args = sys.argv[1:]
    if not args:
        print("Must specify program to trace!", file=sys.stderr)
        exit(1)
    arg_0 = resolve(args[0])
    if not arg_0:
        print(f"No such file: {args[0]}", file=sys.stderr)
        exit(1)
    args[0] = arg_0

    start_time = time.time()

    machine = LogTraceMachine(args)
    machine.run()

    def total(filter_):
        return len(list(machine.filtered_trace(filter_)))

    def unique(filter_):
        return len(set(machine.filtered_trace(filter_)))

    print("\n\n")
    for filter_, description in [
        ("bb", "basic blocks"),
        ("syscall_start", "syscalls"),
        ("output", "outputs"),
    ]:
        print(f"Traced {total(filter_)} {description} ({unique(filter_)} unique)")

    total_time = round(time.time() - start_time, 4)
    print(f"Took {total_time}s")


if __name__ == "__main__":
    main()
