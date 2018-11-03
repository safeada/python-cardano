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
    "cbits/cryptonite_poly1305.c",
], include_dirs=["cbits", "cbits/ed25519"])]
cmdclass = {'build_ext': build_ext}

setup(
    name='python-cardano',
    version='1.0.1',
    license='MIT',
    platforms=['OS Independent'],
    packages=['cardano'],
    ext_modules=ext_modules,
    cmdclass=cmdclass,
    author='huangyi',
    author_email='yi.codeplayer@gmail.com',
    url='https://github.com/safeada/python-cardano',
    description='implement Cardano blockchain project in python',
    long_description=open('README.rst').read(),
    include_package_data=True,
    install_requires=(
        'Cython',
        'base58>=1.0.0',
        'gevent',
        'mnemonic>=0.18',
        'pbkdf2>=1.3',
        'recordclass>=0.5',
        'python-rocksdb>=0.6.9',
        'dnspython>=1.15.0',
        'PyYAML>=3.13',
        'appdirs>=1.4.3',
        'orderedset>=2.0.1',
    ),
    setup_requires=[
        'cython>=0.28.4',
    ],
)
