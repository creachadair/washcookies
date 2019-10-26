##
## Name:     bincookies.py
## Purpose:  Parser and serializer for binary cookies files.
## Author:   M. J. Fromberger <http://spinning-yarns.org/michael/>
##

import datetime, struct, time

# With MacOS "Lion", Apple switched from using a plist file to store cookies
# for Safari to a new "binary cookies" file format.  Based on a description of
# the format from E. Miyake, the following parser unpacks it.
#
# URL: http://www.tengu-labs.com/documents/\
#      Miyake%20-%20Safari%20Cookie.binarycookie%20Format%200_2[Draft].pdf
#
# TODO:
# - Figure out the checksum.
# The name of a cookie seems to affect it.
# The value of a cookie, particularly its length, affects it.

# File grammar:
# Off      Size     Description
# 0        4        'cook'
# 4        4        number of pages (n), BE
# 8        4*n      page sizes, BE
# 8+4(n+1) eof-8    page data
# eof-8    4        checksum (BE?)
# eof-4    4        0x07172005 (unknown)
#
# Page grammar:
# 0        4        0x00000100
# 4        4        number of cookies (n), LE
# 8        4*n      cookie offsets, LE
# 8+4*n    4        0x00000000
# 12+4*n   (to eom) cookie data
#
# Cookie grammar:
# 0        4        cookie size, LE
# 4        12       unknown data (padding?)
# 16       4        URL offset, LE
# 20       4        name offset, LE
# 24       4        path offset, LE
# 28       4        value offset, LE
# 32       8        unknown data (padding)?
# 40       8        expiration date, double
# 48       8        created date, double
# 56       (to eom) field data
#
# Sizes are 4-byte unsigned integers.  In the file header they are in network
# byte order; on the cookie pages they are little-endian.


class error(Exception):
    pass


# Apple systems use an "absolute time" based at 01-Jan-2001 00:00:00 UTC.
# This is its offset relative to the Unix epoch, in seconds.
mac_abs_epoch = 978336000

# This is the magic header stored at the beginning of a bincookie file.
FILE_MAGIC = 'cook'

# This is the magic header stored at the beginning of a page.
PAGE_MAGIC = 256


def parse_cookies(data):
    """Parse a binarycookies file and return a list of cookies."""
    (pages, ck), pos = cfile(data, 0)

    result = []
    for pos, size in pages:
        pg, _ = page(data, pos, size)
        result.extend(cookie(data, p, s) for p, s in pg)

    return result


def parse_raw_pages(data):
    """Parse a binarycookies file and return a list of raw page data and a
    checksum.
    """
    (pages, ck), pos = cfile(data, 0)
    return list(data[s:s + n] for s, n in pages), ck


def parse_raw_cookies(data):
    """Parse a binarycookies file and return a list of raw cookie data and a
    checksum.
    """
    (pages, ck), pos = cfile(data, 0)
    result = []
    for pos, size in pages:
        pg, _ = page(data, pos, size)
        result.extend(data[p:p + s] for p, s in pg)

    return result


def cfile(data, pos):
    """Parse a binarycookies file into a list of (start, length) tuples for the
    raw page data.
    """
    magic, pos = bytes(data, pos, 4)
    if magic != FILE_MAGIC:
        raise error("incorrect file magic: %r" % magic)

    vs, pos = head(data, pos)
    for i, n in enumerate(vs):
        vs[i] = pos, n
        pos += n

    ck, pos = bytes(data, pos, 8)
    if pos != len(data):
        raise error("incomplete parse at %d != %d" % (pos, len(data)))

    return (vs, ck), pos


def head(data, pos):
    """Parse the cookie file header, returning a list of page lengths.
    """
    n, pos = bsize(data, pos)
    # Sanity check: There can't be more pages than bytes of data.
    if n > len(data):
        raise error("counter too large: %d" % n)

    vs = [None] * n
    for i in xrange(n):
        vs[i], pos = bsize(data, pos)

    return vs, pos


def page(data, pos, size=0):
    """Parse a page of cookie data of the given size, returning a list of
    (start, length) tuples for the raw cookies.
    """
    base = pos
    magic, pos = bsize(data, pos)
    if magic != PAGE_MAGIC:
        raise error("incorrect page magic number: %s" % magic)

    xs, pos = phead(data, pos)
    xs[-1] = size or len(data)
    xs.sort()

    cs = [None] * (len(xs) - 1)
    for i in xrange(len(cs)):
        size = xs[i + 1] - xs[i]
        cs[i] = xs[i] + base, size

    return cs, pos


def phead(data, pos):
    """Parse a page header, returning a list of cookie offsets."""
    n, pos = lsize(data, pos)

    xs = [0] * (n + 1)
    for i in xrange(len(xs)):
        xs[i], pos = lsize(data, pos)
    if xs[-1] != 0:
        raise error("incorrect page sentinel: %s" % ck)

    return xs, pos


def cookie(data, pos=0, size=0):
    base = pos
    n, pos = lsize(data, pos)
    if n != (size or len(data)):
        raise error("cookie size mismatch: %d != %d" % (n, size))
    _, pos = bytes(data, pos, 12)  # skip padding
    urlpos, pos = lsize(data, pos)
    namepos, pos = lsize(data, pos)
    pathpos, pos = lsize(data, pos)
    valpos, pos = lsize(data, pos)
    _, pos = bytes(data, pos, 8)  # skip padding
    exp, pos = dstamp(data, pos)
    cre, pos = dstamp(data, pos)
    return {
        'Domain': zstr(data, urlpos + base),
        'Name': zstr(data, namepos + base),
        'Path': zstr(data, pathpos + base),
        'Value': zstr(data, valpos + base),
        'Created': cre,
        'Expires': exp,
    }


def u_cookie(ck):
    """Render a cookie dictionary into a binary packet."""
    head = 4 + 12 + (4 * 4) + 8 + (8 * 2)
    host = u_zstr(ck['Domain'])
    p_host = head
    name = u_zstr(ck['Name'])
    p_name = p_host + len(host)
    path = u_zstr(ck['Path'])
    p_path = p_name + len(name)
    val = u_zstr(ck['Value'])
    p_val = p_path + len(path)
    size = head + len(host) + len(name) + len(path) + len(val)
    pkt = [
        u_lsize(size),
        u_bytes('\x00', 12),
        u_lsize(p_host),
        u_lsize(p_name),
        u_lsize(p_path),
        u_lsize(p_val),
        u_bytes('\x00', 8),
        u_dstamp(ck['Expires']),
        u_dstamp(ck['Created']),
        u_zstr(ck['Domain']),
        u_zstr(ck['Name']),
        u_zstr(ck['Path']),
        u_zstr(ck['Value']),
    ]
    return ''.join(pkt)


def bsize(data, pos):
    """Return a 4-byte unsigned integer read in network byte order."""
    v, pos = bytes(data, pos, 4)
    return struct.unpack('>I', v)[0], pos


def u_bsize(v):
    """Pack an unsigned integer size in network byte order."""
    if v < 0:
        raise ValueError("negative value")
    return struct.pack('>I', v)


def lsize(data, pos):
    """Return a 4-byte unsigned integer read in little-endian order."""
    v, pos = bytes(data, pos, 4)
    return struct.unpack('<I', v)[0], pos


def u_lsize(v):
    """Pack an unsigned integer size in little-endian order."""
    if v < 0:
        raise ValueError("negative value")
    return struct.pack('<I', v)


def bytes(data, pos, n):
    """Return a buffer of n bytes exactly; fails if not enough are available."""
    if pos + n > len(data):
        raise error("out of input at %d" % pos)
    return data[pos:pos + n], pos + n


def u_bytes(data, n):
    c = n // len(data)
    return data * c + data[:n % len(data)]


def dstamp(data, pos):
    """Return a datestamp encoded as a floating-point epoch time in seconds."""
    raw, pos = bytes(data, pos, 8)
    sec = struct.unpack('<d', raw)[0]
    return datetime.datetime.fromtimestamp(sec + mac_abs_epoch), pos


def u_dstamp(dt):
    """Unparse a datetime or epoch time."""
    if isinstance(dt, (int, float)):
        sec = dt - mac_abs_epoch
    else:
        sec = time.mktime(dt.timetuple()) - mac_abs_epoch
    return struct.pack('<d', sec)


def zstr(data, pos):
    """Return a zero-terminated string starting at pos."""
    start = pos
    while pos < len(data) and data[pos] != '\x00':
        pos += 1
    return data[start:pos]


def u_zstr(s):
    """Unparse a zero-terminated string."""
    if '\x00' in s:
        raise ValueError("string contains NUL")
    return s + '\x00'


# Here there be dragons
