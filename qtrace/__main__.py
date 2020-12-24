import sys
import os

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

    machine = LogTraceMachine(args)
    machine.run()

    total_bb_addrs = sum(1 for event in machine.trace if event[0] == "bb")
    unique_bb_addrs = len(set(event[1] for event in machine.trace if event[0] == "bb"))
    print(f"\n\nTraced {total_bb_addrs} basic blocks ({unique_bb_addrs} unique)")


if __name__ == "__main__":
    main()
