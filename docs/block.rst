header size
-----------

::

  protocol magic : n
  hash(prev header): 32
  body proof
    tx proof
      number : n
      tx root: 32
      hash(witnesses): 32
    mpc proof
       hash(data): 32
       hash(vss certificate): 32
    hash(delegate payload): 32
    hash(update payload): 32
  consensus data
    slotid: (n, n)
    leader public key: 64
    difficulty: n
    signature: 64 * 4
  extra block data: 0
