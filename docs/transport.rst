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
