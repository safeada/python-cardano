cardano-utils
=============

Python library for Cardano crypto primitives. Maybe could grows into a Cardano wallet in python.

The code is reverse engineered from cardano-sl, the cbits is copied from cardano-crypto and cryptonite shamelessly.

.. code-block:: shell

    $ virtualenv -p python3 .env
    $ source .env/bin/activate
    $ pip install -r requirements.txt
    $ python setup.py build_ext --inplace
    $ python -mcardano.address
    wallet id Ae2tdPwUPEZKyArxpKiJu9qDf4yrBb8mJc6aNqiNi72NqRkJKTmCXHJqWVE
    experimental wallet id 12MM1pbyTk2WuZEnfiicX9gHF4YtFYL8ebUkr1hp
    first address DdzFFzCqr...dwHkv6aazr

Modules
-------

* ``cardano.address``

  Implement Cardano HD address derivation and encoding.

* ``cardano.transport``

  Implement Haskell's network-transport-tcp, multiplex lots of lightweight unidirectional connections on a single tcp connection.

* ``cardano.node``

  Implement cardano-sl's ``Node``, allow bidirectional conversation between endpoints.

* ``cardano.block``

  Block data structures.

* ``cardano.storage``

  Storage api of block and wallet's data.

* ``cardano.sync``

  Download block data with cardano-sl node.

* ``cardano.wallet``

  Implement wallet logic according to formal specification.
