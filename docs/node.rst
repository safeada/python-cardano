A typical process
-----------------

A worker of C want to have a conversation with a listener in S.

* C calls ``connect(S)``
 > create lightweight connection ``conn`` to S with transport api, see `transport.rst`_.
 > find peer data is not yet sent, send it. (Other concurrently connecting request will wait for it to finish), see ``Node._peer_sending``.
 > C generate locally unique nonce, and send handshake message: ``(SYN, nonce)``.
 > Register an ``AsyncResult`` and wait for a ``Queue`` to arrive,
   will fired when S connects back, see ``Node._wait_ack``.
 > success, ``Conversation(conn, queue)``

* S server side.
 - new connection ``connid`` opened, record remote address, see ``Node._incoming_addr``.
 - receive the peer data if not exist, see ``Node._peer_received``.
 - if not handshaked, receive handshake and check, see ``Node._incoming_nonce``.
   * if it's ``(SYN, nonce)``, spawn a thread:
     > connect back to C, send peer data if necessary.
     > send handshake ``(ACK, nonce)``.
     > create ``Queue`` to receive message, associate it with ``connid``, see ``Node._incoming_queues``.
     > receive next message from the ``Queue``, decode it as message code.
     > index an listener with it and call it.
 - Normal messages is put to ``Node._incoming_queues[connid]``.

* C server side.
 - new connection ``connid`` opened, record remote address, see ``Node._incoming_addr``.
 - receive the peer data if not exist, see ``Node._peer_received``.
 - if not handshaked, receive handshake and check, see ``Node._incoming_nonce``.
   * if it's ``(ACK, nonce)``, then:
     > create ``Queue`` to receive message, associate it with ``connid``, see ``Node._incoming_queues``.
     > Put the ``Queue`` to ``AsyncResult`` registered above.
 - Normal message is put to ``Node._incoming_queues[connid]``.
