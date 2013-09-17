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
__email__ = 'jathanism@aol.com'
__copyright__ = 'Copyright 2010-2013, AOL Inc.'
__version__ = (0, 4)


__all__ = ['parser']

# Parser
try:
    from . import parser
    from parser import *
except ImportError:
    pass
else:
    __all__.extend(parser.__all__)

full_version = '.'.join(map(str, __version__[0:3])) + ''.join(__version__[3:])
release = full_version
short_version = '.'.join(str(x) for x in __version__[0:3])
