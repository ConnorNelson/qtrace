import sys

from . import LogTraceMachine


def main():
    machine = LogTraceMachine(sys.argv[1:])
    machine.run()

    total_bb_addrs = sum(1 for event in machine.trace if event[0] == "bb")
    unique_bb_addrs = len(set(event[1] for event in machine.trace if event[0] == "bb"))
    print(f"\n\nTraced {total_bb_addrs} basic blocks ({unique_bb_addrs} unique)")


if __name__ == "__main__":
    main()
