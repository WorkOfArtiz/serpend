# serpend

Python 3 module for parsing systemd logs

## Usage

```
Example

python3 -m serpend --rule-file rules/kernel.serpend /run/log/journal/*/system.journal
```

Or for full usage tips, run with the help flag:

```
python3 -m serpend --help

Output:
usage: __main__.py [-h] [-r [rule [rule ...]]] [-f [rulefile [rulefile ...]]]
                   logfile [logfile ...]

A systemd log rule based analyser

positional arguments:
  logfile               A standard journald logfile

optional arguments:
  -h, --help            show this help message and exit
  -r [rule [rule ...]], --rule [rule [rule ...]]
                        A standalone rule, see the help below for examples
  -f [rulefile [rulefile ...]], --rule-file [rulefile [rulefile ...]]
                        A rule file, see the help below for examples

Supported syntax for matching

       pid   uid  gid    msg    custom specifiers
alert <pat> <pat> <pat> <msg> ( <attr> : <pat>; ... )

attr, attributes are identifiers for the fields. For a writeup on supported fields see:
https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html

pat, a pattern the field should follow
    supported patterns:
        simple patterns
            *        ignore this field, matches regardless of field value or availability
            ?        this field should be available
            !        this field shouldn't be available

        numeric patterns
            <nr>     the field should be that specific number
            != <nr>  the field should not be that specifc number
            >  <nr>  the field should be larger than a number
            <  <nr>  the field should be smaller than a number
            >= <nr>  the field should be larger than a number
            <= <nr>  the field should be smaller than a number

        string pattern
            "string" the field should be exactly that string
            'string' the field should be exactly that string

        complex patterns
            /regex/  the field matches the regex

    Example of rule
        alert * * * "Example rule finding panic messages, message: $MESSAGE" (MESSAGE:/panic/)
```