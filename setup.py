#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import flask_oauthres
from email.utils import parseaddr

author, author_email = parseaddr(flask_oauthres.__author__)

setup(
    name='Flask-OAuthRes',
    version=flask_oauthres.__version__,
    author=author,
    author_email=author_email,
    url=flask_oauthres.__homepage__,
    packages=[
        "flask_oauthres"
    ],
    description="OAuth Resource for Flask",
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    license='BSD',
    install_requires=[
        'Flask',
        'requests>=2.10'
    ],
    tests_require=['nose', 'mock'],
    test_suite='nose.collector',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
