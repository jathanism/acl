# -*- coding: utf-8 -*-

"""
All custom exceptions used by ACL. Where possible built-in exceptions are used,
but sometimes we need more descriptive errors.
"""

__author__ = 'Jathan McCollum'
__maintainer__ = 'Jathan McCollum'
__email__ = 'jathan.mccollum@teamaol.com'
__copyright__ = 'Copyright 2012-2013, AOL Inc.'

from simpleparse.error import ParserSyntaxError


#####################
# ACL Exceptions
#####################
class ACLError(Exception):
    """A base exception for all ACL-related errors."""

class ParseError(ACLError):
    """
    Raised when there is an error parsing/normalizing an ACL that tries to tell
    you where it failed.
    """
    def __init__(self, reason, line=None, column=None):
        self.reason = reason
        self.line = line
        self.column = column

    def __str__(self):
        s = self.reason
        if self.line is not None and self.line > 1:
            s += ' at line %d' % self.line
        return s

# ACL validation/formating errors
class BadTermName(ACLError):
    """
    Raised when an invalid name is assigned to a `~acl.parser.Term`
    object
    """

class MissingTermName(ACLError):
    """
    Raised when a an un-named Term is output to a format that requires Terms to
    be named (e.g. Juniper).
    """

class VendorSupportLacking(ACLError):
    """Raised when a feature is not supported by a given vendor."""

# ACL naming errors
class ACLNameError(ACLError):
    """A base exception for all ACL naming errors."""

class MissingACLName(ACLNameError):
    """Raised when an ACL object is missing a name."""

class BadACLName(ACLNameError):
    """Raised when an ACL object is assigned an invalid name."""

# Misc. action errors
class ActionError(ACLError):
    """A base exception for all `~acl.parser.Term` action errors."""

class UnknownActionName(ActionError):
    """Raised when an action assigned to a ~acl.parser.Term` object is unknown."""

class BadRoutingInstanceName(ActionError):
    """
    Raised when a routing-instance name specified in an action is invalid.
    """

class BadRejectCode(ActionError):
    """Raised when an invalid rejection code is specified."""

class BadCounterName(ActionError):
    """Raised when a counter name is invalid."""

class BadForwardingClassName(ActionError):
    """Raised when a forwarding-class name is invalid."""

class BadIPSecSAName(ActionError):
    """Raised when an IPSec SA name is invalid."""

class BadPolicerName(ActionError):
    """Raised when a policer name is invalid."""

# Argument matching errors
class MatchError(ACLError):
    """
    A base exception for all errors related to Term
    `~acl.parser.Matches` objects.
    """

class BadMatchArgRange(MatchError):
    """
    Raised when a match condition argument does not fall within a specified
    range.
    """

class UnknownMatchType(MatchError):
    """Raised when an unknown match condition is specified."""

class UnknownMatchArg(MatchError):
    """Raised when an unknown match argument is specified."""

#####################
# NetScreen Exceptions
#####################
class NetScreenError(ACLError):
    """A general exception for NetScreen devices."""

class NetScreenParseError(NetScreenError):
    """Raised when a NetScreen policy cannot be parsed."""
