#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="enocean",
    version="1.0.0",
    description="EnOcean serial protocol implementation",
    author="Pierre Leduc",
    author_email="p.leduc@etik.com",
    url="https://github.com/pledou/enocean",
    packages=[
        "enocean",
        "enocean.protocol",
        "enocean.communicators",
    ],
    scripts=[
        "examples/enocean_example.py",
    ],
    package_data={"": ["EEP.xml"]},
    install_requires=[
        "enum-compat>=0.0.2",
        "pyserial>=3.0",
        "beautifulsoup4>=4.3.2",
    ],
)
