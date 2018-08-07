import gevent
from cardano.transport import Transport, Event, RemoteEndPoint


def test_simple():
    server = Transport(('127.0.0.1', 3000))
    ep1 = server.endpoint()

    client = Transport()
    ep2 = client.endpoint()
    conn = ep2.connect(ep1.addr)
    assert conn.remote.state.outgoing == 1

    assert isinstance(ep1.receive(), Event.ConnectionOpened)

    conn.send(b'test')
    cmd = ep1.receive()
    assert isinstance(cmd, Event.Received) and cmd.data == b'test'

    conn.close()
    assert isinstance(conn.remote.state, RemoteEndPoint.Closing)
    assert isinstance(ep1.receive(), Event.ConnectionClosed)

    server.close()


def test_cross_connection():

    t1 = Transport(('127.0.0.1', 3000))
    t2 = Transport(('127.0.0.1', 3001))

    ep1 = t1.endpoint()
    ep2 = t2.endpoint()

    def connect(ep, addr):
        conn = ep.connect(addr)
        assert conn is not None, 'connect failed.'
        assert conn.remote.valid_state.outgoing == 1
        # Verify underlying tcp connection is reused.
        assert conn.remote.valid_state.origin == ('us' if ep.addr < addr else 'them')
        conn.close()

    thread1 = gevent.spawn(connect, ep1, ep2.addr)
    thread2 = gevent.spawn(connect, ep2, ep1.addr)

    thread1.join()
    thread2.join()

    t1.close()
    t2.close()


def test_closing():
    t1 = Transport(('127.0.0.1', 3000))
    t2 = Transport(('127.0.0.1', 3001))

    ep1 = t1.endpoint()
    ep2 = t2.endpoint()

    print('ep1 connect ep2')
    conn1 = ep1.connect(ep2.addr)
    print('ep1 connect ep2')
    conn2 = ep1.connect(ep2.addr)
    print('ep2 connect ep1')
    conn3 = ep2.connect(ep1.addr)

    print('close conn1')
    conn1.close()
    print('close conn2')
    conn2.close()
    print('close conn3')
    conn3.close()

    gevent.sleep(0.1)
    print(ep1.valid_state._remotes[ep2.addr].state,
          ep2.valid_state._remotes[ep1.addr].state)


if __name__ == '__main__':
    test_simple()
    test_cross_connection()
    test_closing()
