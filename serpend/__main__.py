#!/usr/bin/env python3
# -*- coding utf-8 -*-
"""
A module for reading and analysing systemd logs
"""
from serpend import Syslog

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser(description="A systemd log mapped memory parser")
    parser.add_argument("logfile")

    args = parser.parse_args()

    with Syslog(args.logfile) as logfile:
        for entry in logfile.entries():

            # print(*entry.items(), sep="\n")
            try:
                print("[%s] [%5d] %s" % (entry['__REALTIME_TIMESTAMP'], entry["_PID"], entry['MESSAGE']))
            except KeyError:
                print("[%s] [xxxxx] %s" % (entry['__REALTIME_TIMESTAMP'], entry['MESSAGE']))

            # break
            # print(entry.get('MESSAGE', 'No message in this entry'))
