#!/usr/bin/env python3
# -*- coding utf-8 -*-
"""
Analysis tool for systemd logs

It is rule based with rules, example:
alert 0 * * "[$REALTIME] $MESSAGE" (JOURNAL_PATH="/run/log/journal";)

Format:
<rule>        ::= <rule>
<alert>       ::= 'alert' <pid> <uid> <gid> [ <interpolated alert format> ] (' [ <selector>  ';' ]+ ')'
<pid>         ::= <pat>
<uid>         ::= <pat>
<gid>         ::= <pat>
<selector>    ::= <identifier>:<pat>
<pat>         ::= <nr>          - a number will be literally matched
                  != <nr>       - negative literal number match
                  >  <nr>       - a number should be larger than another number
                  <  <nr>       - a number should be smaller than another number
                  >= <nr>       - a number should be larger than or equal to another number
                  <= <nr>       - a number should be smaller than or equal to another number
                  "string"      - matches a string literal with double quotes, escaped with \
                  'string'      - matches a string literal with single quotes, escaped with \
                  !             - matches if an entry does not have the attribute
                  *             - always matches, even when the entry doesn't have the attribute
                  ?             - matches if the entry has the attribute, doesn't look at value
                  /regex/       - matches if the value matches the regex


Not part of grammar yet but nice to have:
====================================

FUTURE INTERPOLATION OPTIONS
----------------------------
"${command}"                                           # For instance ${MESSAGE[2:4]}

Although we'd need to look at possible commands

FUTURE SELECTOR OPTIONS FOR EASE OF USE
--------------------------------------
<selector>    ::= <identifier> like <wildcard>         # aka MESSAGE like "*Crash*"
"""
from serpend import Syslog
import pyparsing as pp
import sys, re

# standard string format (used if no format is explicitely given)
STANDARD_STRING_FORMAT = "[$__REALTIME_TIMESTAMP] $MESSAGE"

"""
GRAMMAR
"""
# types of patterns, annotated
PAT_NR, PAT_NE, PAT_LT, PAT_ST, PAT_LE, PAT_SE, PAT_STR, PAT_STAR, PAT_AVAIL, PAT_NEG, PAT_REG = ['PAT_%s' % s for s in
                                                                                                  'NR NR_NE NR_LT NR_ST NR_LE NR_SE STR STAR AVAIL NEG REG'.split()]

# Basic types
hexadecimal = (pp.Suppress('0x') + pp.Word(pp.hexnums)).setParseAction(lambda x: int(x[0], 16))
octogonal = ('0' + pp.Optional(pp.Word("01234567"))).setParseAction(lambda x: int("".join(x), 8))
decimal = pp.Word(pp.nums).setParseAction(lambda x: int(x[0], 10))
string = pp.QuotedString('"', escChar='\\', unquoteResults=True) | pp.QuotedString("'", escChar='\\',
                                                                                   unquoteResults=True)

# Pattern types
pat_number = (hexadecimal | octogonal | decimal).setParseAction(lambda x: (PAT_NR, x[0]))
pat_ne = (pp.Suppress('!=') + (hexadecimal | octogonal | decimal)).setParseAction(lambda x: (PAT_NE, x[0]))
pat_lt = (pp.Suppress('>') + (hexadecimal | octogonal | decimal)).setParseAction(lambda x: (PAT_LT, x[0]))
pat_st = (pp.Suppress('<') + (hexadecimal | octogonal | decimal)).setParseAction(lambda x: (PAT_ST, x[0]))
pat_le = (pp.Suppress('>=') + (hexadecimal | octogonal | decimal)).setParseAction(lambda x: (PAT_LE, x[0]))
pat_se = (pp.Suppress('<=') + (hexadecimal | octogonal | decimal)).setParseAction(lambda x: (PAT_SE, x[0]))
pat_string = string.copy().setParseAction(lambda x: (PAT_STR, x[0]))
pat_star = pp.Literal('*').setParseAction(lambda x: (PAT_STAR, '*'))
pat_neg = pp.Literal('!').setParseAction(lambda x: (PAT_NEG, '!'))
pat_avail = pp.Literal('?').setParseAction(lambda x: (PAT_AVAIL, '?'))
pat_regex = pp.Combine(pp.QuotedString('/', escChar='\\', unquoteResults=True) + pp.Optional(pp.Word(pp.alphas),default=''), joinString=':').setParseAction(lambda x: (PAT_REG, x[0].rsplit(':')))

pat = (
pat_number | pat_ne | pat_le | pat_se | pat_lt | pat_st | pat_string | pat_star | pat_avail | pat_neg | pat_regex).setParseAction(
    lambda x: x[0])

pid = pat.copy()
pid.setParseAction(lambda token: ('_PID', token[0]))

uid = pat.copy()
uid.setParseAction(lambda token: ('_UID', token[0]))

gid = pat.copy()
gid.setParseAction(lambda token: ('_GID', token[0]))

interpolated_str_fmt = pp.Optional(string, default=STANDARD_STRING_FORMAT)
interpolated_str_fmt.setParseAction(lambda fmt: fmt[0])

selector = pp.Word(pp.alphas + '_') + pp.Suppress(":") + pat
selector.setParseAction(lambda sel: (sel[0], sel[1]))

# Selector list is a variable length list with ';' in between and an optional ';' and the end. because thats how
# seperators should work damn it.
selector_list = (pp.delimitedList(selector, ';') + pp.Optional(';') | pp.Empty())

# This is the grand total, the alert rule
alert = pp.Suppress('alert') + pid + uid + gid + interpolated_str_fmt + pp.Suppress('(') + selector_list + pp.Suppress(
    ')')

# So far we only have alert rules
rule = alert.setParseAction(lambda x: [x])

# A rulefile then consists of multiples of these
# rulefile = pp.Forward()
# rulefile << (rule + rulefile | pp.Empty())
rulefile = pp.ZeroOrMore(rule)
rulefile.setParseAction(lambda x: list(x))


class SysRule:
    def __init__(self, rule):
        # if it's a string, we'll have to parse it ourselves, otherwise assume it's already parsed
        if isinstance(rule, str):
            rule = alert.parseString(rule, parseAll=True)[0]

        # Our parsing function parses the rule into
        # pat, pat, pat, print_string, pat, pat, ...
        #
        # This is then internally compiled into quick matches and easy to use parse strings
        pid, uid, gid, print_fmt, *rest = rule
        filters = [pid, uid, gid]
        filters.extend(rest)
        filters = [(attr, (pat_type, pat_val)) for (attr, (pat_type, pat_val)) in filters if pat_type != PAT_STAR]

        # Make a copy of the representation, compiled is gonna look different
        self.representation = 'ALERT "%s" %s' % (
        print_fmt, " ".join("%s(entry, %s, %s)" % (pat_type, attr, pat_val) for (attr, (pat_type, pat_val)) in filters))
        self.user_fmt = print_fmt

        ##########################################
        # Compile time motherfuckers :D          #
        ##########################################

        # print format is compiled to python's string format
        interp_val = re.compile(r'\$([A-Za-z_][A-Za-z0-9_]*)')  # to translate $VAR to {VAR!s}
        self.print_fmt = interp_val.sub(r'{\1!s}', print_fmt.replace("{", "{{").replace("}", "}}"))

        # Filters are compiled into lambdas
        self.filters = [SysRule._compile_filter(f) for f in filters]

    @staticmethod
    def _compile_filter(filter):
        """
        This function returns functions which check if an entry match the pattern in token

        :param filter:
            Consists of
                - attribute, the part of the entry to select based on
                - pattern type, the sort of pattern that is used
                - pattern value, the pattern itself. (for instance a number, a regex or whatever)
        :return
            A filter function With the following shape:  f -> Entry -> Boolean
             with Entry being a dictionairy-like object

        Sorts of patterns
            type      possible patterns:
            PAT_AVAIL ?            matches if the field is an attribute of the entry
            PAT_NEG   !            matches if field is not an attribute of the entry
            PAT_STAR  *            always matches, even if non-existent. (this is useful for the pid, gid and uid which are
                                      always in the alert construction)
            PAT_NR    <number>     matches if the field
                                     1) can be converted to an decimal
                                     2) matches number

            PAT_NE    <number>     matches if the field is not equal / larger than / smaller than / larger equal to /
            PAT_LT    <number>     smaller equal to a number
            PAT_ST    <number>
            PAT_LE    <number>
            PAT_SE    <number>

            PAT_STR   <string>     matches if the field has the exact value of the quoted string. Note both ' and " accepted
                                        examples: "/usr/bin/env", 'If you\'re so "mentally challenged", please visit a doctor'
            PAT_REG   <regex>      matches if the field matches the regex. perl-like syntax
                                        example: /^[a-z]+$/ism
        """
        # print("Compiling filter: %s" % str(filter))
        attribute, (pat_type, pat_val) = filter

        def try_int(val, default=None):
            try:
                return int(val)
            except (ValueError, TypeError):
                return default

        if pat_type == PAT_STAR:
            return lambda entry: True
        if pat_type == PAT_AVAIL:
            return lambda entry: entry.get(attribute, None) != None
        elif pat_type == PAT_NEG:
            return lambda entry: entry.get(attribute, None) == None
        elif pat_type == PAT_STR:
            return lambda entry: entry.get(attribute, None) == pat_val
        elif pat_type == PAT_NR:
            return lambda entry: try_int(entry.get(attribute, None), None) == pat_val
        elif pat_type == PAT_NE:
            return lambda entry: try_int(entry.get(attribute, None), None) not in (None, pat_val)
        elif pat_type == PAT_LT:
            def _larger_than(entry):
                val = try_int(entry.get(attribute, None), None)
                return val != None and val > pat_val

            return _larger_than
        elif pat_type == PAT_ST:
            def _smaller_than(entry):
                val = try_int(entry.get(attribute, None), None)
                return val != None and val < pat_val

            return _smaller_than
        elif pat_type == PAT_LE:
            def _larger_than(entry):
                val = try_int(entry.get(attribute, None), None)
                return val != None and val >= pat_val

            return _larger_than
        elif pat_type == PAT_SE:
            def _smaller_than(entry):
                val = try_int(entry.get(attribute, None), None)
                return val != None and val <= pat_val

            return _smaller_than
        elif pat_type == PAT_REG:
            regex, rflags = pat_val
            flags = 0
            flag_trans = { 'I':re.I, 'M':re.M, 'S':re.S }

            for rflag in rflags.upper():
                flags |= flag_trans.get(rflag, 0)

            compiled = re.compile(regex, flags=flags)

            def _reg_match(entry):
                field = entry.get(attribute, None)
                return field != None and compiled.search(field) != None

            return _reg_match

        raise NotImplementedError("Only PAT_STAR PAT_NEG PAT_STR PAT_NR PAT_REG are supported as patterns currently")

    @staticmethod
    def rules_from_file(filename):
        # Through this little hack, pythonic-comments are easily allowed
        with open(filename, 'r') as f:
            rules = "\n".join(line.split('#', 1)[0] for line in f)
        try:
            rules = rulefile.parseString(rules, parseAll=True)
        except pp.ParseBaseException as ps:
            print("ParseException: %s" % str(ps))
            exit()

        return [SysRule(rule) for rule in rules]

    @staticmethod
    def rules_from_string(rules):
        try:
            rules = "\n".join(line.split('#', 1)[0] for line in rules.split('\n'))
            rules = rulefile.parseString(rules, parseAll=True)
        except pp.ParseBaseException as ps:
            print("ParseException: %s" % str(ps))
            exit()

        return [SysRule(rule) for rule in rules]

    def run_entry(self, entry):
        """
        Runs a rule over an entry and prints the message iff the entry matches
        :param entry: a dictionairy like Systemd EntryObject
        :return: self
        """
        if all(f(entry) for f in self.filters):
            try:
                print(self.print_fmt.format(**entry))
            except BaseException as ke:
                print('Needed to print "%s", but variable %s was not present' % (self.user_fmt, str(ke)), file=sys.stderr)
                print("DUMP {%s}" % ", ".join("%s : %s" % (k, v) for k,v in entry.items()))
        return self

    def matches(self, entry):
        """
        For the sake of extensibility, you can use this function to do different things when the function matches.


        :param entry: a dictionairy like Systemd EntryObject
        :return: true or false depending on whether all patterns matched or not
        """

        return all(f(entry) for f in self.filters)

    def __repr__(self):
        return self.representation

    def __str__(self):
        return self.representation


if __name__ == '__main__':
    rules = """
    # Rule 1, any log PID = 0, no GID, and attributes A being "abc" and attribute B matching regex /[a-z]+/
    alert 0 * ! "[$__REALTIME_TIMESTAMP] RULE 1                 : $MESSAGE" (A:"abc"; B:/[a-z]+/)

    # Rule 2, any log PID = 2, UID = 3, GID = 4
    alert 2 3 4 "[$__REALTIME_TIMESTAMP] RULE 2                 : $MESSAGE" ()

    # Rule 3, any rule with _UID set
    alert * ? * "[$__REALTIME_TIMESTAMP] RULE 3       We has UID=$_UID: $MESSAGE " ()

    # Rule 4, any entry with _UID not set
    alert * ! * "[$__REALTIME_TIMESTAMP] RULE 4 We don't has UID: $MESSAGE" ()

    # Rule 5, any entry with PID != 0
    alert !=0 * * "[$__REALTIME_TIMESTAMP] RULE 5 PID != 0, n.l. $_PID: $MESSAGE" ()
    """.strip()

    test_entries = [
        {'__REALTIME_TIMESTAMP': '123123', 'MESSAGE': 'In a galaxy far away', '_PID': 0, 'A': 'abc', 'B': 'somestring'},
        {'__REALTIME_TIMESTAMP': '123124', 'MESSAGE': 'Star wars you idiot', '_PID': 0, 'A': 'abc',
         'B': 'adifferentstring'},
        {'__REALTIME_TIMESTAMP': '123125', 'MESSAGE': 'And now for something different', '_PID': '2', '_UID': '3',
         '_GID': '4'},
    ]

    print("READING IN RULES FROM STRING ")
    sysrules = SysRule.rules_from_string(rules)
    print("-" * 80)
    print("rules:")
    print(*sysrules, sep='\n')
    print("-" * 80)
    print("Messages #triggered")
    for sysrule in sysrules:
        for entry in test_entries:
            sysrule.run_entry(entry)

    print("\n\n")

    print("READING IN RULES FROM FILE ../rules/kernel.serpend")
    sysrules = SysRule.rules_from_file('../rules/kernel.serpend')
    print("-" * 80)
    print("rules:")
    print(*sysrules, sep='\n')
    print("-" * 80)
    print("Messages #triggered")

    for sysrule in sysrules:
        for entry in test_entries:
            sysrule.run_entry(entry)
