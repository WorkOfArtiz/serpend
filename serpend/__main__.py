#!/usr/bin/env python3
# -*- coding utf-8 -*-
"""
A module for reading and analysing systemd logs
"""
from serpend import Syslog, SysRule

help_section = """
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
"""

if __name__ == '__main__':
    from argparse import ArgumentParser, RawTextHelpFormatter

    parser = ArgumentParser(description="A systemd log rule based analyser", epilog=help_section, formatter_class=RawTextHelpFormatter)
    parser.add_argument("-r", "--rule",      nargs="*", metavar="rule",     help="A standalone rule, see the help below for examples")
    parser.add_argument("-f", "--rule-file", nargs="*", metavar="rulefile", help="A rule file, see the help below for examples")
    parser.add_argument("logfiles",          nargs="+", metavar="logfile",  help="A standard journald logfile")
    args = parser.parse_args()

    sysrules = [SysRule(rule) for rule in args.rule]

    for rulefile in args.rule_file:
        sysrules.extend(SysRule.rules_from_file(rulefile))

    if not sysrules:
        print("[!] No rules selected, closing")
        exit()

    for logfile in args.logfiles:
        with Syslog(logfile) as syslog:
            for entry in syslog.entries():
                for sysrule in sysrules:
                    sysrule.run_entry(entry)