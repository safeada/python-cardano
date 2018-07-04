cardano-utils
=============

Python library for Cardano crypto primitives. Maybe could grows into a Cardano wallet in python.

The code is reverse engineered from cardano-sl, the cbits is copied from cardano-crypto and cryptonite shamelessly.

.. code-block:: shell

    $ virtualenv -p python3 .env
    $ source .env/bin/activate
    $ pip install -r requirements.txt
    $ python setup.py build_ext --inplace
    $ python -mcardano.utils
    wallet id Ae2tdPwUPEZKyArxpKiJu9qDf4yrBb8mJc6aNqiNi72NqRkJKTmCXHJqWVE
    experimental wallet id 12MM1pbyTk2WuZEnfiicX9gHF4YtFYL8ebUkr1hp
    first address DdzFFzCqr...dwHkv6aazr
