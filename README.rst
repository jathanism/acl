acl
===

Network access control list parsing library.

This is being forked from the ACL lib that is bundled with `Trigger
<https://github.com/aol/trigger>`_. The goal is to pull this out of Trigger and
have it be a stand-alone project. Once it becomes stable, it will be pulled out
of Trigger core and converted into an optional feature.

.. note:
    As of 2013-03-01 the ACL parser is working standalone! Let the refactoring
    begin!

Parsing Access-lists
~~~~~~~~~~~~~~~~~~~~

Let's start with a simple Cisco ACL::

    >>> from acl import parse
    >>> aclobj = parse("access-list 123 permit tcp any host 10.20.30.40 eq 80")
    >>> aclobj.terms
    [<Term: None>]
    >>> t = aclobj.terms[0]
    >>> t.match
    <Matches: destination-port [80], destination-address [IP('10.20.30.40')],
              protocol [<Protocol: tcp>]>

And convert it to Juniper format::

    >>> aclobj.name_terms() # Juniper policy terms must have names
    >>> aclobj.terms
    [<Term: T1>]
    >>> print '\n'.join(aclobj.output(format='junos'))
    filter 123 {
        term T1 {
            from {
                destination-address {
                    10.20.30.40/32;
                }
                protocol tcp;
                destination-port 80;
            }
            then {
                accept;
            }
        }
    }


Checking Access
~~~~~~~~~~~~~~~

Coming Soon(TM).
