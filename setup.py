#!/usr/bin/env python
##
## Name:     setup.py
## Purpose:  Install washcookies.py
## Author:   M. J. Fromberger <michael.j.fromberger@gmail.com>
##
## Standard usage:  python setup.py install
##
from distutils.core import setup
from washcookies import __version__ as lib_version

setup(name = 'washcookies',
      version = lib_version,
      description = 'A tool to clean up MacOS browser cookies.',
      long_description = """
This tool examines the contents of the Safari and Chrome browser cookie stores
for the current user on a MacOS system, and removes any cookies that violate a
set of rules that are defined by the user of the tool.

There are three types of rules that may be defined: Allow rules specify that a
cookie should be permitted to remain.  Deny rules specify that a cookie should
be discarded.  Keep rules specify that a cookie MUST be retained.  Any cookie
that is not matched by some rule is discarded.""",
      author = 'M. J. Fromberger',
      author_email = "michael.j.fromberger@gmail.com",
      url = 'https://github.com/creachadair/washcookies',
      classifiers = ['Development Status :: 4 - Beta',
                     'License :: Public Domain',
                     'Operating System :: MacOS',
                     'Programming Language :: Python',
                     'Environment :: Console',
                     'Topic :: Utilities',
                     'Topic :: Text Processing'],
      py_modules = ['cookies'],
      scripts = ['washcookies.py'],
      )

# Here there be dragons
