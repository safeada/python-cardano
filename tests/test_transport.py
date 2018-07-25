from cardano.transport import Transport, Event

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
    assert conn.remote.state.outgoing == 0
    assert isinstance(ep1.receive(), Event.ConnectionClosed)

    server.close()

def test_cross_connection():
    import gevent

    t1 = Transport(('127.0.0.1', 3000))
    t2 = Transport(('127.0.0.1', 3001))

    ep1 = t1.endpoint()
    ep2 = t2.endpoint()

    def connect(ep, addr):
        conn = ep.connect(addr)
        assert conn != None, 'connect failed.'
        assert conn.remote.valid_state.outgoing == 1
        # Verify underlying tcp connection is reused.
        assert conn.remote.valid_state.origin == ('us' if ep.addr < addr else 'them')

    thread1 = gevent.spawn(connect, ep1, ep2.addr)
    thread2 = gevent.spawn(connect, ep2, ep1.addr)

    thread1.join()
    thread2.join()

if __name__ == '__main__':
    test_simple()
    test_cross_connection()
