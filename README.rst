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
interoperability with C thanks to Cython which  enables us to improve performance incrementally.

With python, we can develop clean prototype very fast, with good performance. And in the future we can always move the CPU intensive code to C
after we indentified the hotspot.

Install & Testing
------------------

.. code-block:: shell

    $ virtualenv -p python3 .env
    $ source .env/bin/activate
    $ pip install -r requirements.txt
    $ python setup.py build_ext --inplace

    $ mkdir ./test_db
    $ python -mcardano.sync ./test_db
    sync block data from mainnet...
    $ python -mcardano.address ./test_db
    recovering test wallet from local block data...

Modules
-------

* ``cardano.address``

  Implement Cardano HD address derivation and encoding, and wallet recovering for lagacy address format.

* ``cardano.transport``

  Implement Haskell's network-transport-tcp, multiplex lots of lightweight unidirectional connections on a single tcp connection.

* ``cardano.node``

  Implement cardano-sl's ``Node``, allow bidirectional conversation between endpoints.

* ``cardano.block``

  Block data structures.

* ``cardano.storage``

  Storage api of block and wallet's data.

* ``cardano.sync``

  Download block data with cardano-sl mainnet.

* ``cardano.wallet``

  Implement wallet logic according to formal specification.
