# serpend

Python 3 module for parsing systemd logs

## Usage

```
import serpend

with serpend.Syslog('/path/to/logfile') as syslog:
    for entry in syslog.entries():
        print(entry['MESSAGE'])
```