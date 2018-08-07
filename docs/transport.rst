Crossed Connection 
-------------------

Assuming A's address < B's address

* A.1 A send connect request to B, create RemoteEndPointB object
* B.1 B send connect request to A, create RemoteEndPointA object

* B.2 B get connect request from A, but find RemoteEndPointA object already exists,
      check local_addr(B) > remote_addr(A), should accept the request,
      wait for crossed Event which would be fired in step B.3,
      reply with Accepted,
      re-use the RemoteEndPoint object, and change state to Valid
      start processing messages.

* A.2 A get connect request from B, find out RemoteEndPointB object exists,
      and local_addr(A) < remote_addr(B), should reject the request,
      just reply with Crossed message.

* B.3 B's connect request get Crossed reply,
      (should we remove the RemoteEndPoint object, or just leave in Init state?),
      fire the crossed Event,
      close the socket,
      end with failure.
      (better if B can wait for step B.2 finish, and reuse the connection)

* A.3 A's connect request get Accepted reply,
      start processing messages.

Concurrently Connect
--------------------

* Thread 1 try to connect to A, create RemoteEndPoint object.
* Thread 2 try to connect to A, find RemoteEndPoint exists, wait for evt_resolve Event.
* Thread 1 finish connecting, notify evt_resolve Event.
* Thread 2 retry, reuse the established connection.

Closing Connection
------------------

* B send CreateConnection to A [1]
  * increase last_sent
  * increase outgoing

* A close last connection to B [2]
  * RemoteEndPoint enter Closing state.
  * send CloseSocket msg to B

* A create connection to B [3]
  * state = RemoteEndPointB (Closing)
  * wait for closing Event and retry.

* A received CreateConnection from B [4]
  * A is in Closing state, recover to valid state.
  * increase last_incoming

* B received CloseSocket from A
  * A.last_incoming != B.last_sent
  * just ignore it.

Closing Connection
------------------

* A send create connection 
  * increase outgoing and last_sent

* A send close connection 
  * decrease outgoing

* A send CloseSocket to B
  * enter Closing state.

* B send CloseSocket to A

* A receive CloseSocket
  * last_received != last_sent

Closing Connection
------------------

* A connect B
  A.next_lid = 1025
  A.outgoing = 1

* B connect A
  B.next_lid = 1025
  B.outgoing = 1

* A close connect
  send close connection to B
  A.outgoing = 0
  send CloseSocket to B (last_incoming=1024)
  enter Closing

* B close connect
  send close connection to A
  B.outgoing = 0
  send CloseSocket to A (last_incoming=1024)
  enter Closing

* B got connect from A
  recover from Closing state.
  incomings.add(1024)

* B got close connect from A
  incomings.remove(1024)

* A got connect from B
  recover from Closing state.
