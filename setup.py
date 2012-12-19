#!/usr/bin/env python

try:
    from setuptools import setup, find_packages, Command
except ImportError:
    raise SystemExit('We require setuptools. Sorry! Install it and try again: http://pypi.python.org/pypi/setuptools')
import os
import sys

# Get version from pkg index
from acl import full_version as __version__

# Names of required packages
requires = [
    #'foo',
]

class CleanCommand(Command):
    user_options = []
    def initialize_options(self):
        self.cwd = None
    def finalize_options(self):
        self.cwd = os.getcwd()
    def run(self):
        os.system ('rm -rf ./build ./dist ./*.pyc ./*.tgz ./*.egg-info')


desc = 'Network access control list parsing library.'
long_desc = desc + '''

This library contains various modules that allow for parsing, manipulation, and
management of network access control lists (ACLs). It will parse a complete ACL
and return an ACL object that can be easily translated to any supported vendor
syntax.'''

setup(
    name='acl',
    version=__version__,
    author='Jathan McCollum',
    author_email='jathanism@aol.com',
    packages=find_packages(exclude='tests'),
    license='APL 2.0',
    url='https://github.com/jathanism/acl',
    description=desc,
    long_description=long_desc,
    scripts=[],
    include_package_data=True,
    install_requires=requires,
    keywords = [
        'Configuration Management',
        'IANA',
        'IEEE',
        'IP',
        'IP Address',
        'IPv4',
        'IPv6',
        'Firewall',
        'Network Automation',
        'Networking',
        'Network Engineering',
        'Network Configuration',
        'Systems Administration',
        'Switch',
    ],
    classifiers = [
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Environment :: Console :: Curses',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: Education',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Other Audience',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Topic :: Internet',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Firewalls',
        'Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator',
        'Topic :: Security',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: System :: Operating System',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    cmdclass={
        'clean': CleanCommand
    }
)
