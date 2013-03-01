# -*- coding: utf-8 -*-

"""
Various tools for use in scripts or other modules. Heavy lifting from tools
that have matured over time have been moved into this module.
"""

__author__ = 'Jathan McCollum, Eileen Tschetter'
__maintainer__ = 'Jathan McCollum'
__email__ = 'jathan.mccollum@teamaol.com'
__copyright__ = 'Copyright 2010-2013, AOL Inc.'

from collections import defaultdict
import datetime
import IPy
import os
import re
import sys
import tempfile
from time import strftime, localtime

from .parser import *
from .rcs import RCS
# TODO (jathan): Implement a ``conf`` module similar to acl's
#from .conf import settings


# Defaults
# TODO (jathan): Move these to `~acl.conf.settings`
FIREWALL_DIR = '/data/firewalls'
DEBUG = False
DATE_FORMAT = "%Y-%m-%d"
DEFAULT_EXPIRE = 6 * 30 # 6 months
DEFAULT_ACTION = ('accept',)


# Exports
__all__ = ('create_acl_term', 'create_access', 'check_access', 'ACLScript',
           'get_comment_matches', 'write_tmpacl', 'diff_files', 'worklog',
           'insert_term_into_acl', 'create_new_acl')


# Functions
def create_acl_term(src_ips=None, dst_ips=None, src_ports=[], dst_ports=[],
                    protocols=None, action=None, name="generated_term"):
    """
    Constructs and returns a `~acl.Term` object from constituent parts.
    """
    if src_ips is None:
        src_ips = []
    if dst_ips is None:
        dst_ips = []
    if src_ports is None:
        src_ports = []
    if dst_ports is None:
        dst_ports = []
    if protocols is None:
        protocols = []
    if action is None:
        action = DEFAULT_ACTION

    term = Term(name=name, action=action)
    term.action = action
    term.name = name
    field_map = {
        'source-address': src_ips,
        'destination-address': dst_ips,
        'source-port': src_ports,
        'destination-port': dst_ports,
        'protocol': protocols,
    }
    for key, data in field_map.iteritems():
        for n in data:
            if key in term.match:
                term.match[key].append(n)
            else:
                term.match[key] = [n]
    return term

def check_access(terms_to_check, new_term, quiet=True, format='junos',
                 acl_name=None):
    """
    Determine whether access is permitted by a given ACL (list of terms).

    Tests a new term against a list of terms. Return True if access in new term
    is permitted, or False if not.

    Optionally displays the terms that apply and what edits are needed.

    :param terms_to_check:
        A list of Term objects to check

    :param new_term:
        The Term object used for the access test

    :param quiet:
        Toggle whether output is displayed

    :param format:
        The ACL format to use for output display

    :param acl_name:
        The ACL name to use for output display
    """
    permitted = None
    matches = {
        'source-address':       new_term.match.get('source-address',[]),
        'destination-address':  new_term.match.get('destination-address',[]),
        'protocol':             new_term.match.get('protocol',[]),
        'destination-port':     new_term.match.get('destination-port',[]),
        'source-port':          new_term.match.get('source-port',[]),
    }

    def _permitted_in_term(term, comment=' check_access: PERMITTED HERE'):
        """
        A little closure to re-use internally that returns a Boolean based
        on the given Term object's action.
        """
        action = term.action[0]
        if action == 'accept':
            is_permitted = True
            if not quiet:
                term.comments.append(Comment(comment))

        elif action in ('discard', 'reject'):
            is_permitted = False
            if not quiet:
                print '\n'.join(new_term.output(format, acl_name=acl_name))
        else:
            is_permitted = None

        return is_permitted

    for t in terms_to_check:
        hit = True
        complicated = False

        for comment in t.comments:
            if 'acl: make discard' in comment:
                t.setaction('discard') #.action[0] = 'discard'
                t.extra = ' altered from accept for display purposes '

        for k,v in t.match.iteritems():

            if k not in matches or not matches[k]:
                complicated = True

            else:
                for test in matches[k]:
                    if test not in v:
                        hit = False
                        break

        if hit and not t.inactive:
            # Simple access check. Elegant!
            if not complicated and permitted is None:
                permitted = _permitted_in_term(t)

            # Complicated checks should set hit=False unless you want
            # them to display and potentially confuse end-users
            # TODO (jathan): Factor this into a "better way"
            else:
                # Does the term have 'port' defined?
                if 'port' in t.match:
                    port_match = t.match.get('port')
                    match_fields = (matches['destination-port'], matches['source-port'])

                    # Iterate the fields, and then the ports for each field. If
                    # one of the port numbers is within port_match, check if
                    # the action permits/denies and set the permitted flag.
                    for field in match_fields:
                        for portnum in field:
                            if portnum in port_match:
                                permitted = _permitted_in_term(t)
                            else:
                                hit = False

                # Other complicated checks would go here...

            # If a complicated check happened and was not a hit, skip to the
            # next term
            if complicated and not hit:
                continue

            if not quiet:
                print '\n'.join(t.output(format, acl_name=acl_name))

    return permitted

def create_access(terms_to_check, new_term):
    """
    Breaks a new_term up into separate constituent parts so that they can be
    compared in a `~acl.tools.check_access` test.

    Returns a list of terms that should be inserted.
    """
    protocols = new_term.match.get('protocol', ['any'])
    src_ips = new_term.match.get('source-address', ['any'])
    dst_ips = new_term.match.get('destination-address', ['any'])
    src_ports = new_term.match.get('source-port', ['any'])
    dst_ports = new_term.match.get('destination-port', ['any'])

    ret = []
    # The beauty of the uber-nested iteration is no lost on me. THE INDENTATION!
    for proto in protocols:
        for src_ip in src_ips:
            for src_port in src_ports:
                for dst_ip in dst_ips:
                    for dst_port in dst_ports:
                        t = Term()
                        if str(proto) != 'any':
                            t.match['protocol'] = [proto]
                        if str(src_ip) != 'any':
                            t.match['source-address'] = [src_ip]
                        if str(dst_ip) != 'any':
                            t.match['destination-address'] = [dst_ip]
                        if str(src_port) != 'any':
                            t.match['source-port'] = [src_port]
                        if str(dst_port) != 'any':
                            t.match['destination-port'] = [dst_port]
                        if not check_access(terms_to_check, t):
                            ret.append(t)

    return ret

def insert_term_into_acl(new_term, aclobj, debug=False):
    """
    Return a new ACL object with the new_term added in the proper place based
    on the aclobj. Intended to recursively append to an interim ACL object
    based on a list of Term objects.

    It's safe to assume that this function is incomplete pending better
    documentation and examples.

    :param new_term:
        The Term object to use for comparison against aclobj

    :param aclobj:
        The original ACL object to use for creation of new_acl

    Example::

        import copy
        # terms_to_be_added is a list of Term objects that is to be added in
        # the "right place" into new_acl based on the contents of aclobj
        original_acl = parse(open('acl.original'))
        new_acl = copy.deepcopy(original_acl) # Dupe the original
        for term in terms_to_be_added:
            new_acl = generate_new_acl(term, new_acl)
    """
    new_acl = ACL(name=name, policers=policers, format=format) # ACL comes from acl.parser
    already_added = False

    for c in aclobj.comments:
        new_acl.comments.append(c)

    # The following logic is almost identical to that of check_access() except
    # that it tracks already_added and knows how to handle insertion of terms
    # before or after Terms with an action of 'discard' or 'reject'.
    for t in aclobj.terms:
        hit = True
        complicated = False
        permitted = None
        for k, v in t.match.iteritems():

            if debug:
                print "generate_new_acl(): k,v==",k,"and",v
            if k == 'protocol' and k not in new_term.match:
                continue
            if k not in new_term.match:
                complicated = True
                continue
            else:
                for test in new_term.match[k]:
                    if test not in v:
                        hit = False
                        break

            if not hit and k in ('source-port', 'destination-port',
                                 'source-address', 'destination-address'):
                # Here is where it gets odd: If we have multiple  IPs in this
                # new term, and one of them matches in a deny, we must set hit
                # to True.
                got_match = False
                if t.action[0] in ('discard', 'reject'):
                    for test in new_term.match[k]:
                        if test in v:
                            hit = True

        # Check whether access in new_term is permitted (a la check_access(),
        # track whether it's already been added into new_acl, and then add it
        # in the "right place".
        if hit and not t.inactive and already_added == False:
            if not complicated and permitted is None:
                for comment in t.comments:
                    if 'acl: make discard' in comment and \
                        new_term.action[0] == 'accept':
                        new_aca.terms.append(new_term)
                        already_added = True
                        permitted = True
                if t.action[0] in ('discard','reject') and \
                   new_term.action[0] in ('discard','reject'):
                    permitted = False
                elif t.action[0] in ('discard','reject'):
                    permitted = False
                    new_acl.terms.append(new_term)
                    already_added = True
                elif t.action[0] == 'accept' and \
                     new_term.action[0] in ('discard', 'reject'):
                       permitted = False
                       new_acl.terms.append(new_term)
                       already_added = True
                elif t.action[0] == 'accept' and \
                     new_term.action[0] == 'accept':
                       permitted = True
        if debug:
            print "PERMITTED?", permitted

        # Original term is always appended as we move on
        new_acl.terms.append(t)

    return new_acl

def create_new_acl(old_file, terms_to_be_added):
    """Given a list of Term objects call insert_term_into_acl() to determine
    what needs to be added in based on the contents of old_file. Returns a new
    ACL object."""
    aclobj = parse(open(old_file)) # Start with the original ACL contents
    new_acl = None
    for new_term in terms_to_be_added:
        new_acl = insert_term_into_acl(new_term, aclobj)

    return new_acl

def get_comment_matches(aclobj, requests):
    """Given an ACL object and a list of ticket numbers return a list of matching comments."""
    matches = set()
    for t in aclobj.terms:
        for req in requests:
            for c in t.comments:
                if req in c:
                    matches.add(t)
            #[matches.add(t) for c in t.comments if req in c]

    return matches

def update_expirations(matches, numdays=DEFAULT_EXPIRE):
    """Update expiration dates on matching terms. This modifies mutable objects, so use cautiously."""
    print 'matching terms:', [term.name for term in matches]
    for term in matches:
        date = None
        for comment in term.comments:
            try:
                date = re.search(r'(\d{4}\-\d\d\-\d\d)', comment.data).group()
            except AttributeError:
                #print 'No date match in term: %s, comment: %s' % (term.name, comment)
                continue

            try:
                dstamp = datetime.datetime.strptime(date, DATE_FORMAT)
            except ValueError, err:
                print 'BAD DATE FOR THIS COMMENT:'
                print 'comment:', comment.data
                print 'bad date:', date
                print err
                print 'Fix the date and start the job again!'
                import sys
                sys.exit()

            new_date = dstamp + datetime.timedelta(days=numdays)
            #print 'Before:\n' + comment.data + '\n'
            print 'Updated date for term: %s' % term.name
            comment.data = comment.data.replace(date, datetime.datetime.strftime(new_date, DATE_FORMAT))
            #print 'After:\n' + comment.data

def write_tmpacl(aclobj, suffix='_tmpacl'):
    """
    Write a temporary file to disk and return the filename.

    :param aclobj:
        An`~acl.ACL` object.

    :param suffix:
        A suffix to use for the temp files.
    """
    tmpfile = tempfile.mktemp() + suffix
    with open(tmpfile, 'w') as f:
        for x in aclobj.output(aclobj.format, replace=True):
            f.write(x + '\n')
    return tmpfile

def diff_files(old, new):
    """Return a unified diff between two files"""
    return os.popen('diff -Naur %s %s' % (old, new)).read()

def worklog(title, diff, log_string='updated by express-gen',
            firewall_dir=FIREWALL_DIR):
    """Save a diff to the ACL worklog"""

    date = strftime('%Y%m%d', localtime())
    filepath = os.path.join(firewall_dir, 'workdocs', 'workdoc.' + date)
    rcs = RCS(filepath)

    if not os.path.isfile(filepath):
        print 'Creating new worklog %s' % filepath
        with open(file, "w") as f:
            f.write("# vi:noai:\n\n")
        rcs.checkin('.')

    print 'inserting the diff into the worklog %s' % filepath
    rcs.lock_loop()
    with open(filename, "a") as fd:
        fd.write('"%s"\n' % title)
        fd.write(diff)
    rcs.checkin(log_string)

# Classes
class ACLScript:
    """
    Interface to generating or modifying access-lists. Intended for use in
    creating command-line utilities using the ACL API.
    """
    def __init__(self, acl=None, mode='insert', cmd='acl_script',
      show_mods=True, no_worklog=False, no_changes=False):
        self.src_ips   = []
        self.dst_ips     = []
        self.protocol     = []
        self.src_ports = []
        self.dst_ports   = []
        self.modify_terms = []
        self.bcomments    = []
        self.tempfiles    = []
        self.acl          = acl
        self.cmd          = cmd
        self.mode         = mode
        self.show_mods    = show_mods
        self.no_worklog   = no_worklog
        self.no_changes   = no_changes

    def cleanup(self):
        for file in self.tempfiles:
            os.remove(file)

    def genargs(self,interactive=False):
        if not self.acl:
            raise "need acl defined"

        argz = []
        argz.append('-a %s' % self.acl)

        if self.show_mods:
            argz.append('--show-mods')

        if self.no_worklog:
            argz.append('--no-worklog')

        if self.no_changes:
            argz.append('--no-changes')

        if not interactive:
            argz.append('--no-input')

        if self.mode == 'insert':
            argz.append('--insert-defined')

        elif self.mode == 'replace':
            argz.append('--replace-defined')

        else:
            raise "invalid mode"

        for k,v in {'--source-address-from-file':self.src_ips,
                    '--destination-address-from-file':self.dst_ips,
                   }.iteritems():
            if len(v) == 0:
                continue
            tmpf = tempfile.mktemp() + '_genacl'
            self.tempfiles.append(tmpf)
            try:
                f = open(tmpf,'w')
            except:
                print "UNABLE TO OPEN TMPFILE"
                raise "YIKES!"
            for x in v:
                f.write('%s\n' % x.strNormal())
            f.close()

            argz.append('%s %s' % (k,tmpf))

        for k,v in {'-p':self.src_ports,
                    '-P':self.dst_ports}.iteritems():

            if not len(v):
                continue

            for x in v:
                argz.append('%s %d' % (k,x))

        if len(self.modify_terms) and len(self.bcomments):
            msg = "Can only define either modify_terms or between comments"
            print msg
            raise msg

        if self.modify_terms:
            for x in self.modify_terms:
                argz.append('-t %s' % x)
        else:
            for x in self.bcomments:
                (b,e) = x
                argz.append('-c "%s" "%s"' % (b,e))

        for proto in self.protocol:
            argz.append('--protocol %s' % proto)

        return argz

    def parselog(self, log):
        return log

    def run(self, interactive=False):
        args = self.genargs(interactive=interactive)
        log = []
        #print self.cmd + ' ' + ' '.join(args)
        if interactive:
            os.system(self.cmd + ' ' + ' '.join(args))
        else:
            f = os.popen(self.cmd + ' ' + ' '.join(args))
            line = f.readline()
            while line:
                line = line.rstrip()
                log.append(line)
                line = f.readline()
        return log

    def errors_from_log(self, log):
        errors = ''
        for l in log:
            if '%%ERROR%%' in l:
                l = l.spit('%%ERROR%%')[1]
                errors += l[1:] + '\n'
        return errors

    def diff_from_log(self, log):
        diff = ""
        for l in log:
            if '%%DIFF%%' in l:
                l = l.split('%%DIFF%%')[1]
                diff += l[1:] + '\n'
        return diff

    def set_acl(self, acl):
        self.acl=acl

    def _add_addr(self, to, src):
        if isinstance(src,list):
            for x in src:
                if IPy.IP(x) not in to:
                    to.append(IPy.IP(x))
        else:
            if IPy.IP(src) not in to:
                to.append(IPy.IP(src))

    def _add_port(self, to, src):
        if isinstance(src, list):
            for x in src:
                if x not in to:
                    to.append(int(x))
        else:
            if int(src) not in to:
                to.append(int(src))

    def add_protocol(self, src):
        to = self.protocol
        if isinstance(src, list):
            for x in src:
                if x not in to:
                    to.append(x)
        else:
            if src not in to:
                to.append(src)

    def add_src_host(self, data):
        self._add_addr(self.src_ips, data)

    def add_dst_host(self, data):
        self._add_addr(self.dst_ips, data)

    def add_src_port(self, data):
        self._add_port(self.src_ports, data)

    def add_dst_port(self, data):
        self._add_port(self.dst_ports, data)

    def add_modify_between_comments(self, begin, end):
        del self.modify_terms
        self.modify_terms = []
        self.bcomments.append((begin,end))

    def add_modify_term(self, term):
        del self.bcomments
        self.bcomments = []
        if term not in self.modify_terms:
            self.modify_terms.append(term)

    def get_protocols(self):
        return self.protocol

    def get_src_hosts(self):
        return self.src_ips

    def get_dst_hosts(self):
        return self.dst_ips

    def get_src_ports(self):
        return self.src_ports

    def get_dst_ports(self):
        return self.dst_ports
