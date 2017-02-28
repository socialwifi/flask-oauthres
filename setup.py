#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from email.utils import parseaddr

__version__ = "0.1.0"
__author__ = "Lukasz Marcin Podkalicki <lukasz.podkalicki@socialwifi.com>"
__homepage__ = 'https://github.com/socialwifi/flask-oauthres'
__license__ = 'BSD'

author, author_email = parseaddr(__author__)

setup(
    name='Flask-OAuthRes',
    version=__version__,
    author=author,
    author_email=author_email,
    url=__homepage__,
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
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
