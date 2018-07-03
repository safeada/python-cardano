#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

ext_modules = [Extension("cardano.cbits", sources=[
    "cardano/cbits.pyx",
    "cbits/encrypted_sign.c",
    "cbits/ed25519/ed25519.c",
    "cbits/cryptonite_chacha.c",
    "cbits/cryptonite_pbkdf2.c",
    "cbits/cryptonite_sha1.c",
    "cbits/cryptonite_sha256.c",
    "cbits/cryptonite_sha512.c",
], include_dirs=["cbits", "cbits/ed25519"])]
cmdclass = {'build_ext': build_ext}

setup(
    name='cardano-utils',
    version='1.0.0',
    packages=['cardano'],
    ext_modules=ext_modules,
    cmdclass=cmdclass,
    author='huangyi',
    author_email='yi.codeplayer@gmail.com',
    url='https://github.com/yihuang/cardano-utils',
    description='Python library for Cardano crypto primitives.',
    long_description=open('README.rst').read(),
)
