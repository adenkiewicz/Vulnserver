#!/usr/bin/env python
from boofuzz import *


def main():
    session = Session(
            target=Target(connection=SocketConnection("192.168.0.101", 9999, proto='tcp')),
            )

    s_initialize(name="Request")
    # s_group("Command", ["STATS", "RTIME", "LTIME", "SRUN", "TRUN", "GMON", "GDOG", "KSTET", "GTER", "HTER", "LTER", "KSTAN"])
    s_static("HTER")
    with s_block("arg"):
        s_delim(" ", fuzzable=False, name='space-1')
        s_string("1")
    s_repeat("arg", min_reps=1, max_reps=5)
    s_static("\n")

    session.connect(s_get("Request"))

    session.fuzz()


if __name__ == "__main__":
    main()
