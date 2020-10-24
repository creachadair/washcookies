washcookies
===========

**Note:** This tool is no longer maintained; I have switched to a new
implementation in https://github.com/creachadair/cookies.

A tool to clean up MacOS browser cookies based on a user-defined file of rules

This program edits the stored web cookies for the user who runs it, discarding
any cookies that are not deemed acceptable by the user.  Acceptability is
determined by a list of rules which come in three flavours: _Allow_, _Deny_,
and _Keep_.  A rule will either Accept a cookie or Reject it.  Cookies are
rejected if either:

1. No Keep rule matches the cookie, and either
2. Any Deny rule matches the cookie, or
3. No Accept rule matches the cookie.

Rules are stored in the file `~/.cookierc`.  Each line that is neither blank
nor a comment specifies one rule.

Rules have the following format:

```
<f>{<sep><key><op><arg>}+

f    -- "+" for Allow, "-" for Deny, "!" for Keep.
sep  -- the separator character for criteria.
key  -- the name of a cookie field.
op   -- a comparison operator.
arg  -- an argument for comparison (possibly empty).
```

Operators:
```
 = case-insensitive string equality.
 ? test for key existence in the cookie.
 ~ regular expression search (Python regular expressions).
 @ domain-name string matching.
```

An operator may be prefixed with `!` to negate the sense of the comparison.  If
the key and operator are omitted, the key `domain` and the operator `@` are
assumed.  The `@` operator does case-insensitive string comparison, but if the
argument starts with a period (`.`) then it matches if the argument is a suffix
of the value.

Cookies have the following fields:
- *domain*:   The host or domain for which the cookie is delivered.
- *path*:     The path for which the cookie is delivered.
- *name*:     The name of the cookie.
- *value*:    The content of the cookie.
- *httponly*: The HTTPOnly setting for this cookie.

Examples:
+ Accept all cookies from `banksite.com`
```
+ .banksite.com
```

+ Reject all Google Analytics cookies
```
- name~^__utm[abvz]$
```

+ Accept cookies from `somehost.com`, but not `foo.somehost.com`
```
+ .somehost.com domain!=foo.somehost.com
```

+ Reject cookies without an HttpOnly setting
```
- httponly?
```

+ Accept cookies from `foobar.com` except those whose names begin with `blah-`
```
+ foobar.com
- foobar.com name~^blah-
```

+ Explicitly keep cookies whose value is `SaveMe` even if other rules say no.
```
! value=SaveMe
```

## Installation ##

The distribution has a `setup.py` that should do the right thing:

    python setup.py install

## Running the Program ##

The program is intended to be run without arguments:

    washcookies.py

Setting the environment variable `WC_EXPLAIN` to non-empty will cause you to
get some extra diagnostic output; setting `WC_DRY_RUN` will have it print out
what would be changed without actually writing the changes back to disk.
