# -*- coding: utf-8 -*-

"""
Network access control list (ACL) & firewall policy parsing library.

This library contains various modules that allow for parsing, manipulation,
and management of network access control lists (ACLs). It will parse a complete
ACL and return an ACL object that can be easily translated to any supported
vendor syntax.
"""

__author__ = 'Jathan McCollum'
__maintainer__ = 'Jathan McCollum'
__email__ = 'jathan.mccollum@teamaol.com'
__copyright__ = 'Copyright 2010-2013, AOL Inc.'
__version__ = (0, 2)

full_version = '.'.join(str(x) for x in __version__)
release = full_version
short_version = '.'.join(str(x) for x in __version__[0:3])

try:
    from .parser import *
except ImportError:
    print "Skipping parser imports"
    pass # So we can import __version__ :/

__all__ = ('parse', 'ACL', 'Term', 'Matches', 'RangeList', 'Comment')
