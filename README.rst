Python-Cardano
==============

Python implementation of Cardano project, including network protocol, crypto primitives, wallet logic, and more.

Why This Project
----------------

* We want to explore alternate design decisions to support lightweight wallet, and start developing the mobile wallet for Cardano. Current official wallet node is not enough yet.
* Explore the design space of clustered wallet node.
* Provide alternative implementation of Cardano protocols and specifications in another programming language.
* In the future, it could be an alternative foundation for projects in Cardano ecosystem: wallets, side-chains, MPCs.

Why Python
----------

Python is still one of the most cleanly designed, developer friendly programming language out there, has a reputation of
executable pseudocode. And lightweight thread provided by gevent makes it suitable to write networking software, and easy
interoperability with C thanks to Cython enables us to improve performance incrementally.

With python, we can develop clean prototype very fast, with good performance. And in the future we can always move the CPU intensive code to C
after we indentified the hotspot.

Build & Test
------------

.. code-block:: shell

    $ virtualenv -p python3 .env
    $ source .env/bin/activate
    $ pip install -r requirements.txt
    $ python setup.py build_ext --inplace

    $ mkdir ./test_db
    $ python scripts/pycardano.py sync
    sync block data from mainnet...
    $ python scripts/pycardano.py wallet create default
    generate wallet

Features
--------

* Store block data of different epochs in seperate rocksdb database, provides better disk usage(fully synchronized mainchain takes 1.3G disk space), and allows faster synchronization in the future.
* ``pycardano.py sign`` sign a message with wallet, prove an wallet address belongs to you.
* ``pycardano.py verify`` verify a signed message.
* ``pycardano.py utxo stat`` Some statistics of global UTxOs.

Modules
-------

* ``cardano.address``

  Implement Cardano HD address derivation and encoding, and wallet recovering for lagacy address format.

* ``cardano.transport``

  Implement Haskell's network-transport-tcp, multiplex multiple lightweight unidirectional connections on a single tcp connection.

* ``cardano.node``

  Implement cardano-sl's ``Node``, allow bidirectional conversation between endpoints.

* ``cardano.storage``

  Storage api of block and wallet's data.

* ``cardano.block``

  Block data structures.

* ``cardano.logic``

  Workers and listeners of default node.

* ``cardano.sync``

  Download block data with cardano-sl mainnet.

* ``cardano.wallet``

  Implement wallet logic according to formal specification.

TODOs
-----

* wallet state storage, a simple solution first, hopefully something like Haskell's acid-state in the end.
* block verification.
* handle incoming block headers, handle forks.
* relay block data with stream api.
* wallet cli app.
* wallet V1 api and api for SPV light client.
* clustered wallet storage.
