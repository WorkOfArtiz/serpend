from serpend import Syslog

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser(description="A systemd log mapped memory parser")
    parser.add_argument("logfile")

    args = parser.parse_args()

    with Syslog(args.logfile) as logfile:
        for entry in logfile.entries():
            print("[%s] %s" % (entry['REALTIME'].strftime("%s.%f"), entry['MESSAGE']))
            # print(entry.get('MESSAGE', 'No message in this entry'))
