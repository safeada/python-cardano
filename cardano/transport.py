'''
Multiplex lightweight unidirectional connections onto single tcp connection.

https://cardanodocs.com/technical/protocols/network-transport/
'''

# TODO all the evt.wait need to has timeout.

import struct
import enum
import random
import binascii
import uuid

import gevent.socket
import gevent.queue
import gevent.event
import gevent.server

import cbor
from recordclass import recordclass

from .constants import LIGHT_ID_MIN, HEAVY_ID_MIN, WAIT_TIMEOUT

PROTOCOL_VERSION = 0

# Utils

class ControlHeader(enum.IntEnum):
    CreatedNewConnection    = 0
    CloseConnection         = 1
    CloseSocket             = 2
    CloseEndPoint           = 3
    ProbeSocket             = 4
    ProbeSocketAck          = 5

class HandshakeResponse(enum.IntEnum):
    UnsupportedVersion = 0xFFFFFFFF
    Accepted           = 0x00000000
    InvalidRequest     = 0x00000001
    Crossed            = 0x00000002
    HostMismatch       = 0x00000003

def pack_u32(n):
    return struct.pack('>I', n)

def unpack_u32(s):
    return struct.unpack('>I', s)[0]

def prepend_length(s):
    return struct.pack('>I', len(s)) + s

def random_endpoint_address():
    return uuid.uuid4().hex

def endpoint_connect(addr, local_addr):
    host, port, id = addr.rsplit(b':', 2)
    id = int(id)
    try:
        sock = gevent.socket.create_connection((host, port))
    except e:
        return None, str(e)

    while True:
        msg = struct.pack('>I', PROTOCOL_VERSION) + prepend_length(
            struct.pack('>I', id) +
            (prepend_length(local_addr) if local_addr else struct.pack('>I', 0))
        )
        sock.sendall(msg)
        result = HandshakeResponse(unpack_u32(recv_exact(sock, 4)))
        if result == HandshakeResponse.UnsupportedVersion:
            version = unpack_u32(recv_exact(sock, 4))
            continue
        else:
            break
    return sock, result

def connection_id(hid, lid):
    'ConnectionId is unique within all incoming lightweight connections LocalEndPoint.'
    return (hid << 32) | lid

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        s = sock.recv(n - len(buf))
        assert s, 'connection closed'
        buf += s
    return buf

def send_many(o, *args):
    o.sendall(b''.join(args))

class Event(object):
    Received = recordclass('EventReceived', 'connid data')
    ConnectionOpened = recordclass('EventConnectionOpened', 'connid addr')
    ConnectionClosed = recordclass('EventConnectionClosed', 'connid')
    EndpointClosed = recordclass('EventEndpointClosed', '')
    Error = recordclass('EventError', 'error')
    ReceivedMulticast = recordclass('EventReceivedMulticast', '')

class RemoteEndPoint(object):
    '''
    Represent a heavyweight connection (incoming or outgoing) associated with a LocalEndPoint.
        id: unique index in associated LocalEndPoint
        addr: address of remote end of connection, "host:port:id"
        local: associated LocalEndPoint object
        state: current state object, one of RemoteEndPoint.State.
    '''

    # Different states
    Error = recordclass('Error', 'error')
    Init = recordclass('Init', 'evt_resolve origin') # origin: us | them
    Closing = recordclass('Closing', 'evt_resolve valid_state')
    Closed = recordclass('Closed', '')
    class Valid(object):
        def __init__(self, sock, origin):
            self.socket = sock
            self.origin = origin

            self.outgoing = 0  # number of lightweight connections.

            self.incomings = set()
            self.last_incoming = 0

            self.next_light_id = LIGHT_ID_MIN

            self.probing_thread = None

        def gen_next_light_id(self):
            n = self.next_light_id
            self.next_light_id += 1
            return n

        def do_probing(self):
            self.socket.sendall(pack_u32(ControlHeader.ProbeSocket))
            gevent.sleep(10)
            # close socket
            self.socket.close()

        def start_probing(self):
            self.probing_thread = gevent.spawn(self.do_probing)

        def stop_probing(self):
            if self.probing_thread:
                gevent.kill(self.probing_thread)
                self.probing_thread = None

    def __init__(self, local, addr, id, origin):
        self._id = id
        self._addr = addr
        self._state = RemoteEndPoint.Init(gevent.event.Event(), origin)
        self._local = local

    @property
    def addr(self):
        return self._addr

    @property
    def id(self):
        return self._id

    @property
    def state(self):
        return self._state

    @property
    def local(self):
        return self._local

    @property
    def valid_state(self):
        if isinstance(self._state, RemoteEndPoint.Valid):
            return self._state

    def resolve_init(self, st):
        'leaving init state, notify other listeners.'
        assert isinstance(self._state, RemoteEndPoint.Init), 'invalid state' + str(self._state)
        evt = self._state.evt_resolve
        if isinstance(st, RemoteEndPoint.Closed):
            del self.local._remotes[self._addr]
        self._state = st
        evt.set()

class LocalEndPoint(object):
    '''
    Represent an endpoint in current transport.
      transport: current associated transport.
      id: unique id in associated transport.
      addr: address of current endpoint, host:port:id.
      state: Closed | Valid
    '''
    Closed = recordclass('Closed', '')
    class Valid(object):
        '''
        Valid state of LocalEndPoint
          remotes: Current connected RemoteEndPoints.
          queue: Message queue of all incoming events.
        '''
        def __init__(self):
            self._remotes = {} # addr -> RemoteEndPoint, incoming unaddressable connection use random addr.
            self._next_remote_id = HEAVY_ID_MIN

            self._queue = gevent.queue.Queue(maxsize=128)

        @property
        def queue(self):
            return self._queue

        def gen_next_remote_id(self):
            n = self._next_remote_id
            self._next_remote_id += 1
            return n

        def remove_if_invalid(self, addr):
            ep = self._remotes.get(addr)
            if ep and isinstance(ep.state, RemoteEndPoint.Error):
                del self._remotes[addr]

    def __init__(self, transport, addr, id):
        self._transport = transport
        self._addr = addr
        self._id = id
        self._state = LocalEndPoint.Valid()

    @property
    def addr(self):
        return self._addr

    @property
    def id(self):
        return self._id

    @property
    def state(self):
        return self._state

    @property
    def valid_state(self):
        if isinstance(self._state, LocalEndPoint.Valid):
            return self._state

    def get_remote_endpoint(self, addr, origin):
        '''
        get or create shared RemoteEndPoint instance.
          origin: 'us' means outgoing connection, 'them' means incoming connection.
        '''
        lst = self.valid_state
        assert lst != None, 'local endpoint is closed.'
        addr = addr or random_endpoint_address()
        while True:
            remote = lst._remotes.get(addr)
            if not remote:
                id = lst.gen_next_remote_id()
                remote = RemoteEndPoint(self, addr, id, origin)
                lst._remotes[addr] = remote
                return remote, True
            else:
                st = remote.state
                if isinstance(st, RemoteEndPoint.Valid):
                    return remote, False
                elif isinstance(st, RemoteEndPoint.Init):
                    if origin == 'us':
                        # wait for ongoing init finish, no need to set timeout here, dependent on another connect request.
                        st.evt_resolve.wait()
                        continue # retry
                    elif st.origin == 'us':
                        if self.addr > addr:
                            return remote, True
                        else:
                            # Reject the connection request.
                            return remote, False
                    else:
                        assert False, 'already connected [impossible]'
                elif isinstance(st, RemoteEndPoint.Closing):
                    # Waiting for closing finish and retry.
                    st.evt_resolve.wait()
                    continue
                elif isinstance(st, RemoteEndPoint.Closed):
                    # Closed RemoteEndPoint should not in _remotes map.
                    assert False, 'impossible'
                else:
                    assert False, 'Invalid RemoteEndPoint state: ' + st.error

    def process_messages_loop(self, sock, remote):
        '''
        Process incoming messages in standalone thread, change RemoteEndPoint's state, put Event into LocalEndPoint's queue.
        '''
        q = self.valid_state.queue
        stream = sock.makefile('rb')
        while True:
            n = unpack_u32(stream.read(4))
            if n < LIGHT_ID_MIN:
                # command
                cmd = ControlHeader(n)
                if cmd == ControlHeader.CreatedNewConnection:
                    lid = unpack_u32(stream.read(4))
                    st = remote.valid_state
                    if st:
                        st.incomings.add(lid)
                        st.last_incoming = lid
                    else:
                        assert isinstance(remote.state, RemoteEndPointStateClosing), 'invalid state'
                        # recover closing state.
                        st = remote.state.valid_state
                        st.incomings.add(lid)
                        st.last_incoming = lid
                        remote.resolve_init(st)
                    q.put(Event.ConnectionOpened(connection_id(remote.id, lid), remote.addr))
                elif cmd == ControlHeader.CloseConnection:
                    q.put(Event.ConnectionClosed(connection_id(remote.id, unpack_u32(stream.read(4)))))
                elif cmd == ControlHeader.CloseSocket:
                    #q.put((cmd, unpack_u32(stream.read(4))))
                    pass
                elif cmd == ControlHeader.CloseEndPoint:
                    q.put(Event.EndpointClosed())
                elif cmd == ControlHeader.ProbeSocket:
                    sock.sendall(pack_u32(ControlHeader.ProbeSocketAck))
                elif cmd == ControlHeader.ProbeSocketAck:
                    remote.stop_probing()
            else:
                # data
                q.put(Event.Received(
                    connection_id(remote.id, n),
                    stream.read(unpack_u32(stream.read(4)))
                ))

    def connect(self, addr):
        'create new connection from local endpoint to remote endpoint address'
        st = self.state
        assert isinstance(st, LocalEndPoint.Valid), 'LocalEndPoint state is invalid: ' + str(st)
        st.remove_if_invalid(addr)

        remote, new = self.get_remote_endpoint(addr, 'us')
        if new:
            # Setup outgoing heavyweight connection, don't send unaddressable local address.
            sock, result = endpoint_connect(addr, self._transport.addr and self._addr or None)
            if sock:
                if result == HandshakeResponse.Accepted:
                    gevent.spawn(self.process_messages_loop, sock, remote)
                    remote.resolve_init(RemoteEndPoint.Valid(sock, 'us'))
                elif result == HandshakeResponse.Crossed:
                    if isinstance(remote.state, RemoteEndPoint.Init):
                        # Remote connection request has not came yet, remove the endpoint.
                        remote.resolve_init(RemoteEndPoint.Closed())
                        sock.close()
                        return
                    else:
                        # Remote connection already arrived, then re-use the connection.
                        assert isinstance(remote.state, RemoteEndPoint.Valid)
                        sock.close()
                else:
                    remote.resolve_init(RemoteEndPoint.Closed())
                    sock.close()
                    return
            else:
                remote.resolve_init(RemoteEndPoint.Error('connec failed'))

        # create lightweight connection.
        st = remote.state
        assert isinstance(st, RemoteEndPoint.Valid), 'RemoteEndPoint state is invalid: ' + str(st)
        st.outgoing += 1
        lid = st.gen_next_light_id()
        st.socket.sendall(pack_u32(ControlHeader.CreatedNewConnection) + pack_u32(lid))

        return Connection(self, remote, lid)

    def receive(self, *args):
        return self.valid_state.queue.get(*args)

class Connection(object):
    'A lightweight connection.'
    def __init__(self, local, remote, lid):
        self._local = local
        self._remote = remote
        self._lid = lid
        self._alive = True

    @property
    def local(self):
        return self._local

    @property
    def remote(self):
        return self._remote

    @property
    def id(self):
        return self._lid

    @property
    def alive(self):
        return self._alive

    def close(self):
        assert self._alive, 'close an inactive connection.'
        self._alive = False

        remote_st = self._remote.valid_state
        if not remote_st:
            print('invalid RemoteEndPoint state', self._remote.state)
            return

        remote_st.socket.sendall(pack_u32(ControlHeader.CloseConnection) + pack_u32(self._lid))
        # garbbage collection.
        remote_st.outgoing -= 1
        if remote_st.outgoing == 0 and not remote_st.incomings:
            remote_st.socket.sendall(pack_u32(ControlHeader.CloseSocket) + pack_u32(remote_st.last_incoming))
            remote_st.socket.close()

    def send(self, buf):
        assert self._alive, 'send to an inactive connection.'
        self._remote.valid_state.socket.sendall(pack_u32(self._lid) + prepend_length(buf))

class Transport(object):
    def __init__(self, addr=None):
        '''
        addr: (host, port).
              None means unaddressable.
        '''
        self._bind_addr = addr
        self._addr = None

        self._local_endpoints = {}
        self._next_endpoint_id = 0

        if addr:
            # Start listening server.
            self._server = gevent.server.StreamServer(addr, self.handle_connection)
            # Use read binded port.
            self._addr = (addr[0], self._server.address[1])
            self._server.start()

    def close(self):
        # TODO close all the endpoints and connections.
        self._server.stop()

    @property
    def addr(self):
        return self._addr

    def gen_next_endpoint_id(self):
        n = self._next_endpoint_id
        self._next_endpoint_id += 1
        return n

    def endpoint(self):
        'Create new local endpoint.'
        id = self.gen_next_endpoint_id()
        addr = b'%s:%d:%d' % (self._addr[0].encode(), self._addr[1], id) if self._addr else random_endpoint_address()
        local = LocalEndPoint(self, addr, id)
        self._local_endpoints[id] = local
        return local

    def handle_connection(self, sock, addr):
        while True:
            protocol_version = unpack_u32(recv_exact(sock, 4))
            handshake_len = unpack_u32(recv_exact(sock, 4))
            if protocol_version != 0:
                sock.sendall(pack_u32(HandshakeResponse.UnsupportedVersion) + pack_u32(0))
                recv_exact(sock, handshake_len)
                continue

            # endpoint id
            local = self._local_endpoints.get(unpack_u32(recv_exact(sock, 4)))
            if not local:
                sock.sendall(pack_u32(HandshakeResponse.InvalidRequest))
                break

            # remote address
            size = unpack_u32(recv_exact(sock, 4))
            remote_addr = None
            if size > 0:
                remote_addr = recv_exact(sock, size)
                (host, _, _) = remote_addr.rsplit(b':', 2)
                # check their host TODO getnameinfo
                num_host = addr[0].encode()
                if host != num_host:
                    # address mismatch
                    send_many(sock, 
                        pack_u32(HandshakeResponse.HostMismatch),
                        prepend_length(host),
                        prepend_length(num_host)
                    )
                    break

            if remote_addr:
                # local state has to be valid.
                local.valid_state.remove_if_invalid(remote_addr)

            remote, new = local.get_remote_endpoint(remote_addr, 'them')
            if not new:
                sock.sendall(pack_u32(HandshakeResponse.Crossed))
                # Maybe the connection is already closed at remote end, prob it.
                st = remote.valid_state
                if st:
                    st.start_probing()
            else:
                remote.resolve_init(RemoteEndPoint.Valid(sock, 'them'))

                # send success response
                sock.sendall(pack_u32(HandshakeResponse.Accepted))
                local.process_messages_loop(sock, remote)

            break

if __name__ == '__main__':
    from .config import MAINCHAIN_ADDR
    ep = Transport().endpoint() # Unaddressable transport.
    #ep = Transport(('127.0.0.1', 3000)).endpoint()
    print('connect')
    conn = ep.connect(MAINCHAIN_ADDR)

    # cardano node handshake.
    # send peer data.

    DEFAULT_PEER_DATA = [
        764824073, # protocol magic.
        [0,1,0],   # version
        {
            0x04:  [0, cbor.Tag(24, cbor.dumps(0x05))],
            0x05:  [0, cbor.Tag(24, cbor.dumps(0x04))],
            0x06:  [0, cbor.Tag(24, cbor.dumps(0x07))],
            0x22:  [0, cbor.Tag(24, cbor.dumps(0x5e))],
            0x25:  [0, cbor.Tag(24, cbor.dumps(0x5e))],
            0x2b:  [0, cbor.Tag(24, cbor.dumps(0x5d))],
            0x31:  [0, cbor.Tag(24, cbor.dumps(0x5c))],
            0x37:  [0, cbor.Tag(24, cbor.dumps(0x62))],
            0x3d:  [0, cbor.Tag(24, cbor.dumps(0x61))],
            0x43:  [0, cbor.Tag(24, cbor.dumps(0x60))],
            0x49:  [0, cbor.Tag(24, cbor.dumps(0x5f))],
            0x53:  [0, cbor.Tag(24, cbor.dumps(0x00))],
            0x5c:  [0, cbor.Tag(24, cbor.dumps(0x31))],
            0x5d:  [0, cbor.Tag(24, cbor.dumps(0x2b))],
            0x5e:  [0, cbor.Tag(24, cbor.dumps(0x25))],
            0x5f:  [0, cbor.Tag(24, cbor.dumps(0x49))],
            0x60:  [0, cbor.Tag(24, cbor.dumps(0x43))],
            0x61:  [0, cbor.Tag(24, cbor.dumps(0x3d))],
            0x62:  [0, cbor.Tag(24, cbor.dumps(0x37))],
        },
        {
            0x04:  [0, cbor.Tag(24, cbor.dumps(0x05))],
            0x05:  [0, cbor.Tag(24, cbor.dumps(0x04))],
            0x06:  [0, cbor.Tag(24, cbor.dumps(0x07))],
            0x0d:  [0, cbor.Tag(24, cbor.dumps(0x00))],
            0x0e:  [0, cbor.Tag(24, cbor.dumps(0x00))],
            0x25:  [0, cbor.Tag(24, cbor.dumps(0x5e))],
            0x2b:  [0, cbor.Tag(24, cbor.dumps(0x5d))],
            0x31:  [0, cbor.Tag(24, cbor.dumps(0x5c))],
            0x37:  [0, cbor.Tag(24, cbor.dumps(0x62))],
            0x3d:  [0, cbor.Tag(24, cbor.dumps(0x61))],
            0x43:  [0, cbor.Tag(24, cbor.dumps(0x60))],
            0x49:  [0, cbor.Tag(24, cbor.dumps(0x5f))],
            0x53:  [0, cbor.Tag(24, cbor.dumps(0x00))],
        },
    ]

    conn.send(cbor.dumps(DEFAULT_PEER_DATA, True))
    nonce = 1
    conn.send(b'S' + struct.pack('>Q', nonce))

    cmd = ep.receive() # create new connection
    assert isinstance(cmd, Event.ConnectionOpened), 'invalid response'
    connid = cmd.connid
    cmd = ep.receive() # peerdata
    assert isinstance(cmd, Event.Received) and connid == cmd.connid, 'invalid response'
    print('peer data response', cbor.loads(cmd.data))
    cmd = ep.receive() # nodeid
    assert isinstance(cmd, Event.Received) and connid == cmd.connid and cmd.data[:1] == b'A' and struct.unpack('>Q', cmd.data[1:])[0] == nonce, 'invalid response'

    print(ep.receive())
