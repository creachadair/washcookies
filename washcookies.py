#!/usr/bin/env python
##
## Name:     washcookies.py
## Purpose:  Clean up Safari and Chrome web cookies.
## Author:   M. J. Fromberger <http://spinning-yarns.org/michael/>
##
## This program edits the stored web cookies for the user who runs it,
## discarding any cookies that are not deemed acceptable by the user.
## Acceptability is determined by a list of rules which come in three flavours:
## Allow, Deny, and Keep.  A rule will either Accept a cookie or Reject it.
## Cookies are rejected if either:
##
## 1. No Keep rule matches the cookie, and either
## 2. Any Deny rule matches the cookie, or
## 3. No Accept rule matches the cookie.
##
## Rules are stored in the file "~/.cookierc".  Each line that is neither blank
## nor a comment specifies one rule.
##
## Rules have the following format:
##
## <f>{<sep><key><op><arg>}+
##
## f    -- "+" for Allow, "-" for Deny, "!" for Keep.
## sep  -- the separator character for criteria.
## key  -- the name of a cookie field.
## op   -- a comparison operator.
## arg  -- an argument for comparison (possibly empty).
##
## Operators:
##  = case-insensitive string equality.
##  ? test for key existence in the cookie.
##  ~ regular expression search (Python regular expressions).
##  @ domain-name string matching.
##
## An operator may be prefixed with '!' to negate the sense of the comparison.
## If the key and operator are omitted, "domain" and "@" are assumed.  The "@"
## operator does case-insensitive string comparison, but if the argument starts
## with a period "." then it matches if the argument is a suffix of the value.
##
## Cookies have the following fields:
##  domain   -- the host or domain for which the cookie is delivered.
##  path     -- the path for which the cookie is delivered.
##  name     -- the name of the cookie.
##  value    -- the content of the cookie.
##  httponly -- the HTTPOnly setting for this cookie.
##
## Examples:
## 1. Accept all cookies from host names ending in banksite.com
##    + .banksite.com
##
## 2. Reject all Google Analytics cookies
##    - name~^__utm[abvz]$
##
## 3. Accept cookies from somehost.com, but not foo.somehost.com
##    + .somehost.com domain!=foo.somehost.com
##
## 4. Reject cookies without an HttpOnly setting
##    - httponly?
##
from __future__ import with_statement, print_function

__version__ = "1.001"

import os, plistlib, pwd, re, sys, tempfile
import cookies

# Regular expression matching a rule in ~/.cookierc
rule_re = re.compile(r'(\w+)(!?[=~@?])(.*)$')


def parse_rule(s):
    """Parse a cookie rule, returning a tuple (f, rs) where

    f is the rule type (+ = accept, - = reject, ! = keep)
    rs is a list of criteria.

    Each criterion is a tuple (op, key, arg) of strings.
    """
    f, sep = s[:2]
    rs = []
    for r in s[2:].split(sep):
        m = rule_re.match(r)
        if m:
            rs.append((m.group(2), m.group(1).lower(), m.group(3)))
        else:
            rs.append(('@', 'domain', r))

    return f, rs


def unparse_rule(r, flag='-', sep=' '):
    """Unparse a cookie rule, returning a string.  The flag is the rule type,
    and sep is the desired criterion separator.
    """
    out = [flag]
    for op, key, val in r:
        if op == '@' and key == 'domain':
            out.append(val)
        else:
            out.append(key + op + val)

    return sep.join(out)


def match_rule(cookie, rule):
    """Returns True if the specified cookie (a dict) matches the given list of
    rule criteria; otherwise False.
    """

    def match_one(op, key, arg):
        neg = op.startswith('!')
        if neg: op = op[1:]

        exists = True
        for k, v in cookie.iteritems():
            if key == k.lower():
                val = v
                break
        else:
            val = ''
            exists = False

        if op == '~':
            res = bool(re.compile(arg).search(val))
        elif op == '@' and arg.startswith('.'):
            # E.g., .foo.com matches "foo.com" or "bar.foo.com"
            vl, al = val.lower(), arg.lower()
            res = (vl == al[1:]) or vl.endswith(al)
        elif op == '?':
            res = exists
        else:
            res = (arg.lower() == val.lower())

        return not res if neg else res

    for op, key, arg in rule:
        if not match_one(op, key, arg):
            return False
    else:
        return True


def load_rules(user=None):
    """Load the list of cookie rules from ".cookierc" in the user's home
    directory.  Returns a tuple of (a, r, k), where a is a list of accept
    rules, r is a list of reject rules, and k is a list of keep rules.

    If no rules are found, the default is to accept all cookies.
    """
    cpath = os.path.expanduser('~%s/.cookierc' % (user or ''))
    try:
        with open(cpath, 'rt') as fp:
            a = []
            r = []
            k = []
            for line in fp:
                if line.isspace() or line.startswith('#'):
                    continue

                f, rs = parse_rule(line.strip())
                if f == '+':
                    a.append(rs)
                elif f == '-':
                    r.append(rs)
                elif f == '!':
                    k.append(rs)

            return a, r, k
    except (OSError, IOError) as e:
        return ([parse_rule('+ .')], [])


def find_bad_cookies(cookies, allow, deny, keep):
    """Return the positions of all the cookies in the list that are not matched
    by any keep rule, and either ARE matched by a deny rule, or NOT matched by
    any allow rule.

    The kill set is a dictionary mapping cookie positions to reasons.  A reason
    is either None, meaning no rule selected this cookie for preservation, or a
    rule, meaning the cookie was rejected by the application of that rule.
    """

    kill = {}
    for pos, cookie in enumerate(cookies):
        for rule in keep:
            if match_rule(cookie, rule):
                break
        else:
            for rule in deny:
                if match_rule(cookie, rule):
                    kill[pos] = rule
                    break
            else:
                for rule in allow:
                    if match_rule(cookie, rule):
                        break
                else:
                    kill[pos] = None

    return kill


def summarize_changes(cookies, icky, path, ofp=sys.stderr):
    """Print a human-readable description of what is going to be deleted to the
    specified file handle.

    cookies -- the list of cookie dictionaries.
    icky    -- dictionary mapping offsets to reasons.
    path    -- the file being edited.
    """
    explain = os.getenv('WC_EXPLAIN', False)

    print("In '%s'" % path, file=ofp)
    if not icky:
        print("No unwanted cookies found.", file=ofp)
        return

    print(
        "Removing %d unwanted cookie%s:" % (len(icky),
                                            "s" if len(icky) != 1 else ""),
        file=ofp)
    for pos in sorted(icky, key=lambda p: cookies[p]['Domain']):
        reason = icky[pos]
        tag = u' \N{black square} ' if reason else u' \N{white square} '
        print(
            tag + u'%-30.30s %s=%-20.20s' %
            (cookies[pos]['Domain'], cookies[pos]['Name'],
             cookies[pos]['Value']),
            file=ofp)
        if explain and reason:
            print('   %s' % \
                  unparse_rule(reason, flag = 'rejected by'), file=ofp)
        elif explain:
            print('   no matching rule', file=ofp)


def process_apple_cookies(allowed, denied, kept):
    """Process old-style (pre-Lion) cookies for Apple Safari."""
    cfpath = cookies.get_apple_cookie_path()
    try:
        cdb = cookies.read_apple_cookies(cfpath)
    except IOError as e:
        return  # No cookies found, skip the rest.

    icky = find_bad_cookies(cdb, allowed, denied, kept)
    summarize_changes(cdb, icky, cfpath)
    for pos in sorted(icky, reverse=True):
        cdb.pop(pos)

    if dry_run:
        print("(skipping write)", file=sys.stderr)
    else:
        if icky:
            cookies.write_apple_cookies(cdb, cfpath)
        print(
            "Kept %d cookie%s." % (len(cdb), "s" if len(cdb) != 1 else ""),
            file=sys.stderr)


def process_binary_cookies(allowed, denied, kept):
    """Process new-style (post-Lion, binary) cookies for Apple Safari."""
    cfpath = cookies.get_apple_bincookie_path()
    try:
        cdb = cookies.read_binary_cookies(cfpath)
    except (IOError, NotImplementedError) as e:
        return  # No cookies found, skip the rest.

    icky = find_bad_cookies(cdb, allowed, denied, kept)
    summarize_changes(cdb, icky, cfpath)
    for pos in sorted(icky, reverse=True):
        cdb.pop(pos)

    if dry_run:
        print("(skipping write)", file=sys.stderr)
    else:
        if icky:
            cookies.write_binary_cookies(cdb, cfpath)
        print(
            "Kept %d cookie%s." % (len(cdb), "s" if len(cdb) != 1 else ""),
            file=sys.stderr)


def process_google_cookies(allowed, denied, kept):
    """Process cookies for Google Chrome."""
    global dry_run
    cfpath = cookies.get_google_cookie_path()
    try:
        cdb = cookies.read_google_cookies(cfpath)
    except IOError:
        return  # No cookies found, skip the rest.

    icky = find_bad_cookies(cdb, allowed, denied, kept)
    kills = list(cdb[p] for p in sorted(icky))
    nkept = len(cdb) - len(kills)
    summarize_changes(cdb, icky, cfpath)

    if dry_run:
        print("(skipping write)", file=sys.stderr)
    else:
        if kills:
            cookies.delete_google_cookies(kills, cfpath)
        print(
            "Kept %d cookie%s." % (nkept, "s" if nkept != 1 else ""),
            file=sys.stderr)


def main(argv):
    """Command-line entry point."""
    global dry_run
    dry_run = os.getenv('WC_DRY_RUN', False)
    allowed, denied, kept = load_rules()
    process_apple_cookies(allowed, denied, kept)
    process_binary_cookies(allowed, denied, kept)
    process_google_cookies(allowed, denied, kept)
    return 0


if __name__ == "__main__":
    res = main(sys.argv[1:])
    sys.exit(res)

__all__ = (
    "parse_rule",
    "match_rule",
    "load_rules",
    "cookie_path",
    "read_cookies",
    "write_cookies",
    "find_bad_cookies",
)

# Here there be dragons
