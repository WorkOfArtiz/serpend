#!/usr/bin/env python3
# -*- coding utf-8 -*-
"""
Analysis tool for systemd logs

It is rule based with rules, example:
alert 0 * * "[$REALTIME] $MESSAGE" (JOURNAL_PATH="/run/log/journal";)

Format:
<rule>        ::= <rule>
<alert>       ::= 'alert' <pid> <uid> <gid> [ <interpolated alert format> ] (' [ <selector>  ';' ]+ ')'
<pid>         ::= <nr> | '*'
<uid>         ::= <nr> | '*'
<gid>         ::= <nr> | '*'
<selector>    ::= <identifier>:<string literal>                            # TODO expand this later

Not part of grammar yet but nice to have:
====================================

FIELD NOT AVAILABLE OP, matches if the entry doesn't have a certain field
----------------------------
<*id>         ::= <nr> | '*' | '!'
<selector>    ::= <identifier> ':' '!'


FUTURE INTERPOLATION OPTIONS
----------------------------
"${command}"                                           # For instance ${MESSAGE[2:4]}

Although we'd need to look at possible commands


FUTURE SELECTOR OPTIONS FOR MORE POWER
--------------------------------------
<selector>    ::= <identifier> like <wildcard>         # aka MESSAGE like "*Crash*"
<selector>    ::= <identifier> matches <regex>         # perl regex like  "/abc/i" or maybe even /abc/mi

"""
from serpend import Syslog
import pyparsing as pp
import re

# standard string format (used if no format is explicitely given)
STANDARD_STRING_FORMAT = "[$__REALTIME_TIMESTAMP] $MESSAGE"

interp_val = re.compile(r'\$([A-Za-z_][A-Za-z0-9_]*)')
def print_entry(fmt, entry):
    """
    Prints an entry according to the fmt string
    :param   fmt: Format string, may contain string interpolated values like "$_PID $REALTIME $MESSAGE"
    :param entry: An entry (from the serpend entries function)
    """
    print(interp_val.sub(r'{\1!s}', fmt.replace("{", "{{").replace("}", "}}")).format(**entry))

"""
GRAMMAR OF THE RULE FILES
"""
hexadecimal = pp.Suppress('0x') + pp.Word(pp.hexnums)
hexadecimal.setParseAction(lambda x: int(x[0], 16))

octogonal = '0' + pp.Optional(pp.Word("01234567"))
octogonal.setParseAction(lambda x: int("".join(x), 8))

decimal = pp.Word(pp.nums)
decimal.setParseAction(lambda x: int(x[0], 10))

number = hexadecimal | octogonal | decimal

string = pp.QuotedString('"', escChar='\\', unquoteResults=True) | pp.QuotedString("'", escChar='\\', unquoteResults=True)

star = pp.Word('*', max=1)
star.setParseAction(lambda x: [None])

pid = number | star
# pid.setParseAction(lambda token:('PID', token[0]))
pid.setParseAction(lambda token: None if token[0] == None else lambda entry: entry.get('_PID', None) == token[0])

uid = number | star
# uid.setParseAction(lambda token:('UID', token[0]))
uid.setParseAction(lambda token: None if token[0] == None else lambda entry: entry.get('_UID', None) == token[0])

gid = number | star
# gid.setParseAction(lambda token:('GID', token[0]))
gid.setParseAction(lambda token: None if token[0] == None else lambda entry: entry.get('_GID', None) == token[0])

interpolated_str_fmt = pp.Optional(string, default=STANDARD_STRING_FORMAT)
# interpolated_str_fmt.setParseAction(lambda fmt:fmt[0])
interpolated_str_fmt.setParseAction(lambda fmt: lambda entry: print_entry(fmt[0], entry))

# Trivial syntax rules, needs to be expanded later
selector = pp.Word(pp.alphas + '_') + pp.Suppress(":") + (string | number)
# selector.setParseAction(lambda sel:(sel[0], sel[1]))
selector.setParseAction(lambda sel: lambda entry: entry[sel[0]] == sel[1])

selectorList = pp.Optional(selector) + pp.ZeroOrMore(pp.Suppress(';') + selector) + pp.Optional(pp.Suppress(';'))
alert = pp.Suppress('alert') + pid + uid + gid + interpolated_str_fmt + pp.Suppress('(') + selectorList + pp.Suppress(')')

rule = alert
rule.setParseAction(lambda x:[x])
rulefile = pp.ZeroOrMore(rule)
rulefile.setParseAction(lambda x:list(x))

class SysRule:
    def __init__(self, rule):
        # if it's a string, we'll have to parse it ourselves, otherwise assume it's already parsed
        if isinstance(rule, str):
            rule = alert.parseString(rule, parseAll=True)

        # from the format we have that
        # pid, uid and gid are either filter functions or None (we dont care)
        # interpolated_string = print_function
        # rest = one or more filter functions
        pid, uid, gid, print_func, *rest = rule

        self.filterfuncs = rest
        self.filterfuncs.extend([x for x in (pid, uid, gid) if x != None])
        self.print_func = print_func

    @staticmethod
    def rules_from_file(filename):
        # Through this little hack, pythonic-comments are easily allowed
        with open(filename, 'r') as f:
            rules = "\n".join(line.split('#', 1)[0] for line in f)

        print(rules)
        rules = rulefile.parseString(rules, parseAll=True)
        # rules = [SysRule(rule) for rule in rules]
        return rules

    def run_entry(self, entry):
        if all(f(entry) for f in self.filterfuncs):
            self.print_func(entry)


if __name__ == '__main__':
    sysrules = SysRule.rules_from_file('../rules/kernel.serpend')

    print(sysrules)
    # sysrule = SysRule('alert 0 * * "[$__REALTIME_TIMESTAMP] $MESSAGE" (JOURNAL_PATH:"/run/log/journal";REALTIME:123123123)')
    # sysrule.run_entry({'_PID':0, '_UID': 1, '_GID':2, 'REALTIME': 123123123, 'MESSAGE':'u got h8xored', "JOURNAL_PATH":"/run/log/journal"})
