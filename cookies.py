##
## Name:     cookies.py
## Purpose:  Read and write web cookies in various formats.
## Author:   M. J. Fromberger <http://spinning-yarns.org/michael/>
##

from sqlite3 import dbapi2 as sql
from datetime import datetime
import os, plistlib, pwd, struct, tempfile, time

# In order to support Apple binarycookies files, use the ObjectiveC bridge.
# The file format is a nasty combination of endian-sensitive binary sludge.  We
# could parse it, but writing it back out turns out to be hard, since the
# checksum algorithm is unspecified, and I'm too lazy to reverse-engineer it.
try:
    from Foundation import NSHTTPCookieStorage
except ImportError as e:
    NSHTTPCookieStorage = None


def get_user_home(user=None):
    """Find the specified user's home directory, or use the owner of
    the current process if none is specified.
    """
    if user is None:
        return pwd.getpwuid(os.geteuid()).pw_dir
    else:
        return pwd.getpwnam(user).pw_dir


## New style Apple binarycookies file

# This offset corresponds to 2001-01-01 00:00:00 +0000 in Unix time.
# As far as I can tell, the creation timestamp comes back in this format;
# unfortunately we can't get it in the "real" time layout.
osx_epoch_offset = 978336000


def get_apple_bincookie_path(user=None):
    """Return the path of the Apple binarycookies file for the specified user,
    or for the owner of the current process.

    Note: This function does not verify the existence of the file, it only
    computes the pathname.
    """
    return os.path.join(get_user_home(user), 'Library', 'Cookies',
                        'Cookies.binarycookies')


def read_binary_cookies(path):
    """Read a cookie list from an Apple binarycookies file.  Returns a list of
    dictionaries.
    """
    if NSHTTPCookieStorage is None:
        raise NotImplementedError(
            "Apple binary cookies are not supported on this system")

    storage = NSHTTPCookieStorage.sharedHTTPCookieStorage()
    cookies = []
    for raw_cookie in storage.cookies():
        props = raw_cookie.properties()
        created = float(props['Created']) + osx_epoch_offset
        expires = float(props['Expires'].timeIntervalSince1970())
        cookies.append({
            'raw': raw_cookie,
            'Created': datetime.fromtimestamp(created),
            'Domain': unicode(props['Domain']),
            'Expires': datetime.utcfromtimestamp(expires),
            'Name': unicode(props['Name']),
            'Path': unicode(props['Path']),
            'Secure': bool(raw_cookie.isSecure()),
            'Value': unicode(props['Value']),
        })
    return cookies


def write_binary_cookies(cookies, path):
    """Write a cookie list to an Apple binarycookies file.
    """
    if NSHTTPCookieStorage is None:
        raise NotImplementedError(
            "Apple binary cookies are not supported on this system")

    storage = NSHTTPCookieStorage.sharedHTTPCookieStorage()
    keep = set(cookie.get('raw') for cookie in cookies)
    keep.discard(None)
    kill = set(cookie for cookie in storage.cookies() if cookie not in keep)
    for cookie in kill:
        storage.deleteCookie_(cookie)
    storage = None


## Old-style Apple Safari cookies (plist)


def get_apple_cookie_path(user=None):
    """Return the path of the Apple cookies plist file for the specified user,
    or for the owner of the current process.

    Note: This function does not verify the existence of the file, it only
    computes the pathname.
    """
    return os.path.join(get_user_home(user), 'Library', 'Cookies',
                        'Cookies.plist')


def read_apple_cookies(path):
    """Read a cookie list from an Apple style plist file.  Returns a
    list of dictionaries.
    """
    return plistlib.readPlist(path)


def write_apple_cookies(cookies, path):
    """Write a cookie list to an Apple style plist file.
    """
    d = os.path.split(path)[0]

    fd, name = tempfile.mkstemp(dir=d, text=True)
    with os.fdopen(fd, 'wt') as ofp:
        plistlib.writePlist(cookies, ofp)

    try:
        os.rename(name, path)
    except OSError:
        os.unlink(name)
        raise


## Google cookies (sqlite3)


def get_google_cookie_path(user=None):
    """Return the path of the Google Chrome cookies database for the
    specified user, or for the owner of the current process.

    Note: This function does not verify the existence of the file, it
    only computes the pathname.
    """
    return os.path.join(get_user_home(user), 'Library', 'Application Support',
                        'Google', 'Chrome', 'Default', 'Cookies')


# Map from Google cookie table columns to canonical names.
gc_field_map = {
    'creation_utc': 'Created',
    'host_key': 'Domain',
    'name': 'Name',
    'value': 'Value',
    'path': 'Path',
    'expires_utc': 'Expires',
    'is_secure': 'Secure',
    'is_httponly': 'HttpOnly',
}

# Chrome uses the Windows proleptic epoch, 1/1/1600.
# This is the value of the Unix 1/1/70 epoch in that scheme.
gc_epoch_offset = 11644473600


def parse_gc_field(key, data, epoch=gc_epoch_offset):
    """Parse a single field in a Chrome cookie table, returning a pair
    of (key, value).  The value of epoch is used when parsing
    timestamp values, since Chrome uses the Windows epoch internally.
    """
    tkey = gc_field_map.get(key, key)
    if key == 'creation_utc':
        return (key, data)
    elif key.endswith('_utc'):
        try:
            tval = parse_utc(data, epoch)
        except ValueError:
            tval = data
    elif key in ('secure', 'httponly'):
        tval = bool(data)
    else:
        tval = data

    return tkey, tval


def parse_utc(data, epoch):
    """Parse a timestamp stored as an integer encoding seconds and
    milliseconds, with the latter stored in the low-order 6 decimal
    digits of the value.  Returns a datetime object.
    """
    sec = float(data // 10**6) - epoch
    usec = float(data % 10**6)
    tsec = sec + (usec / 10**6)
    return datetime.fromtimestamp(tsec)


def unparse_utc(dt, epoch):
    """Unparse a datetime object into an integer encoding seconds and
    milliseconds, with the latter stored in the low-order 6 decimal
    digits of the value.
    """
    sec = int(time.mktime(dt.utctimetuple())) + epoch
    tsec = (sec * 10**6) + dt.microsecond
    return tsec


def read_google_cookies(path):
    """Read a cookie list from a Google Chrome SQLite cookie file
    located at path.  Returns a list of dictionaries.
    """
    db = sql.connect(path)
    try:
        cur = db.cursor()
        fk = sorted(gc_field_map)
        q = 'SELECT %s FROM cookies' % ', '.join(fk)
        out = []
        for row in cur.execute(q):
            out.append(dict(parse_gc_field(k, v) for k, v in zip(fk, row)))

        return out
    finally:
        db.close()


def delete_google_cookies(cookies, path):
    """Delete the specified cookies from a Google Chrome SQLite cookie
    file located at path.
    """
    if not cookies:
        return

    # The created_utc field is a primary key for the cookies table, so
    # we only need its value in order to identify a row.
    db = sql.connect(path)
    try:
        cur = db.cursor()
        for cookie in cookies:
            cur.execute('DELETE FROM cookies WHERE creation_utc = ?',
                        (cookie['creation_utc'], ))
        db.commit()
    finally:
        db.close()


# Here there be dragons
