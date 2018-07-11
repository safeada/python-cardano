'''
Support multiple lightweight connections in one tcp connection.

https://cardanodocs.com/technical/protocols/network-transport/
'''

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

PROTOCOL_VERSION = 0
LIGHT_ID_MIN = 1024
HEAVY_ID_MIN = 1

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

def random_remote_address():
    return uuid.uuid4().hex

def endpoint_connect(local_addr, addr):
    host, port, id = addr.rsplit(':', 2)
    id = int(id)
    print('connect endpoint', host, port, id)
    try:
        sock = gevent.socket.create_connection((host, port))
    except e:
        return None, str(e)

    while True:
        sock.sendall(struct.pack('>I', PROTOCOL_VERSION) + struct.pack('>III', 0, id, 0))
        #socket.sendall(prepend_length(
        #    struct.pack('>I', id) +
        #    prepend_length(local_addr) if local_addr else struct.pack('>I', 0)
        #))
        result = HandshakeResponse(unpack_u32(recv_exact(sock, 4)))
        if result == HandshakeResponse.UnsupportedVersion:
            version = unpack_u32(recv_exact(sock, 4))
            continue
        else:
            break
    return sock, result

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        s = sock.recv(n - len(buf))
        assert s, 'connection closed'
        buf += s
    return buf

def send_many(o, *args):
    o.sendall(b''.join(args))

RemoteEndPointStateError = recordclass('RemoteEndPointStateError', 'error')
RemoteEndPointStateInit = recordclass('RemoteEndPointStateInit', 'evt_resolve evt_crossed origin') # origin: us | them
RemoteEndPointStateClosing = recordclass('RemoteEndPointStateClosing', 'evt_resolve valid_state')
RemoteEndPointStateClosed = recordclass('RemoteEndPointStateClosed', '')

class RemoteEndPointStateValid(object):
    def __init__(self, sock):
        self.outgoing = 0  # number of lightweight connections.

        self.incomings = set()
        self.last_incoming = 0

        self.next_light_id = LIGHT_ID_MIN
        self.socket = sock

        self.probing_thread = None

    def gen_next_light_id(self):
        n = self.next_light_id
        self.next_light_id += 1
        return n

    def do_probing(self):
        self.socket.sendall(pack_u32(int(ControlHeader.ProbeSocket)))
        gevent.sleep(10)
        # close socket
        self.socket.close()

    def start_probing(self):
        self.probing_thread = gevent.spawn(self.do_probing)

    def stop_probing(self):
        if self.probing_thread:
            gevent.kill(self.probing_thread)
            self.probing_thread = None

class RemoteEndPoint(object):
    def __init__(self, local, addr, id, origin):
        self._id = id
        self._addr = addr
        self._state = RemoteEndPointStateInit(gevent.event.Event(), gevent.event.Event(), origin)
        self.local = local

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
        if isinstance(self._state, RemoteEndPointStateValid):
            return self._state

    def resolve_init(self, st):
        assert isinstance(self._state, RemoteEndPointStateInit), 'invalid state'
        evt = self._state.evt_resolve
        if isinstance(st, RemoteEndPointStateClosed):
            del self.local._conns[self._addr]
        self._state = st
        evt.set()

def process_messages_loop(o, q, ep):
    while True:
        n = unpack_u32(o.read(4))
        if n < LIGHT_ID_MIN:
            # command
            cmd = ControlHeader(n)
            if cmd == ControlHeader.CreatedNewConnection:
                lid = unpack_u32(o.read(4))
                q.put((cmd, lid))
            elif cmd == ControlHeader.CloseConnection:
                lid = unpack_u32(o.read(4))
                q.put((cmd, lid))
            elif cmd == ControlHeader.CloseSocket:
                lid = unpack_u32(o.read(4))
                q.put((cmd, lid))
            elif cmd == ControlHeader.CloseEndPoint:
                q.put((cmd, None))
            elif cmd == ControlHeader.ProbeSocket:
                o.socket.sendall(pack_u32(int(ControlHeader.ProbeSocketAck)))
            elif cmd == ControlHeader.ProbeSocketAck:
                ep.stop_probing()
        else:
            # data
            lid = n
            l = unpack_u32(o.read(4))
            s = o.read(l)
            q.put((lid, s))

class LocalEndPoint(object):
    'local endpoint'
    def __init__(self, addr, id):
        self._addr = addr
        self._id = id

        # states
        self._closed = False
        # current outgoing heavyweight connections.
        self._conns = {} # addr -> RemoteEndPoint, incoming unaddressable connection use random addr.
        self._next_conn_id = HEAVY_ID_MIN

        self._queue = gevent.queue.Queue(maxsize=1024)

    @property
    def addr(self):
        return self._addr

    @property
    def id(self):
        return self._id

    def gen_next_conn_id(self):
        n = self._next_conn_id
        self._next_conn_id += 1
        return n

    def remove_if_invalid(self, addr):
        ep = self._conns.get(addr)
        if ep and isinstance(ep.state, RemoteEndPointStateError):
            del self._conns[addr]
            
    def get_remote_endpoint(self, addr, origin):
        addr = addr or random_remote_address()
        while True:
            remote = self._conns.get(addr)
            if not remote:
                id = self.gen_next_conn_id()
                remote = RemoteEndPoint(self, addr, id, origin)
                self._conns[addr] = remote
                return remote, True
            else:
                st = remote.state
                if isinstance(st, RemoteEndPointStateValid):
                    if origin == 'us':
                        st.outgoing += 1
                    return remote, False
                elif isinstance(st, RemoteEndPointStateInit):
                    if origin == 'us':
                        st.evt_resolve.wait()
                        continue # retry
                    elif st.origin == 'us':
                        # cross connection.
                        assert False, 'TODO, handle cross connection.'
                    else:
                        assert False, 'already connected'
                elif isinstance(st, RemoteEndPointStateClosing):
                    st.evt_resolve.wait()
                    continue # retry
                elif isinstance(st, RemoteEndPointStateClosed):
                    assert False, 'impossible' # should remove from _conns already.
                else:
                    assert False, st.error

    def receive(self, *args):
        return self._queue.get(*args)

class Connection(object):
    'A connection from local endpoint to remote endpoint.'
    def __init__(self, local, remote, lid):
        '''
        stream: established endpoint tcp connection stream.
        '''
        self._local = local
        self._remote = remote
        self._lid = lid
        self._alive = True

    def close(self):
        assert self._alive, 'close an inactive connection.'
        remote_st = self._remote.valid_state
        send_many(remote_st.socket,
            pack_u32(ControlHeader.CloseConnection),
            pack_u32(self._lid)
        )

        self._alive = False
        remote_st.outgoing -= 1

        # garbbage collection.
        if remote_st.outgoing == 0 and not remote_st.incomings:
            send_many(remote_st.socket,
                pack_u32(ControlHeader.CloseSocket),
                pack_u32(remote_st.last_incoming),
            )

    def send(self, buf):
        assert self._alive, 'send to an inactive connection.'
        send_many(self._remote.valid_state.socket,
            pack_u32(self._lid),
            prepend_length(buf),
        )

    @property
    def id(self):
        return self._lid

class Transport(object):
    def __init__(self, addr=None):
        '''
        addr: (host, port).
              None means unaddressable.
        '''
        self._bind_addr = addr
        self._addr = None
        self._next_endpoint_id = 0
        self._local_endpoints = {}

        if addr:
            # start listening server.
            self._server = gevent.server.StreamServer(addr, self.handle_connection)
            self._addr = (addr[0], self._server.address[1])
            self._server.start()

    def gen_next_endpoint_id(self):
        n = self._next_endpoint_id
        self._next_endpoint_id += 1
        return n

    def endpoint(self):
        '''
        create new local endpoint.
        '''
        id = self.gen_next_endpoint_id()
        addr = '%s:%s:%d' % (self._addr[0], self._addr[1], id) if self._addr else None
        ep = LocalEndPoint(addr, id)
        self._local_endpoints[id] = ep
        return ep

    def connect(self, local, addr):
        'create new connection from local endpoint to remote endpoint address'
        local.remove_if_invalid(addr)
        ep, new = local.get_remote_endpoint(addr, 'us')

        if new:
            while True:
                # setup endpoint
                sock, result = endpoint_connect(local.addr, addr)
                if sock:
                    if result == HandshakeResponse.Accepted:
                        gevent.spawn(process_messages_loop, sock.makefile('rb'), local._queue, ep)
                        ep.resolve_init(RemoteEndPointStateValid(sock))
                    else:
                        # TODO handle socket closing.
                        raise NotImplementedError('connect fail: %s' % result)
                else:
                    ep.resolve_init(RemoteEndPointStateError('connec failed'))

                # retry
                return self.connect(local, addr)

        # create lightweight connection.
        st = ep.valid_state
        lid = st.gen_next_light_id()
        send_many(st.socket,
            pack_u32(ControlHeader.CreatedNewConnection),
            pack_u32(lid)
        )

        return Connection(local, ep, lid)

    def handle_connection(self, sock, addr):
        while True:
            protocol_version = unpack_u32(recv_exact(sock, 4))
            handshake_len = unpack_u32(recv_exact(sock, 4))
            if protocol_version != 0:
                sock.sendall(pack_u32(int(HandshakeResponse.UnsupportedVersion)) + pack_u32(0))
                recv_exact(sock, handshake_len)
                continue

            local = self._local_endpoints.get(unpack_u32(recv_exact(sock, 4)))
            if not local:
                sock.sendall(pack_u32(int(HandshakeResponse.InvalidRequest)))
                return

            # recv address
            size = unpack_u32(recv_exact(sock, 4))
            remote_addr = None
            if size:
                remote_addr = recv_exact(sock, size)
                (host, _, _) = remote_addr.rsplit(':', 2)
                # check their host TODO getnameinfo
                num_host = addr[0]
                if host != num_host:
                    # address mismatch
                    send_many(sock, 
                        pack_u32(int(HandshakeResponse.HostMismatch)),
                        prepend_length(host),
                        prepend_length(num_host)
                    )
                    return

            if remote_addr:
                local.remove_if_invalid(remote_addr)

            ep, new = local.get_remote_endpoint(remote_addr, 'their')
            if not new:
                sock.sendall(pack_u32(int(HandshakeResponse.Crossed)))
                st = ep.valid_state
                if st:
                    st.start_probing()
            else:
                process_messages_loop(sock.makefile('rb'), local._queue, ep)
                ep.resolve_init(RemoteEndPointStateValid(sock))

if __name__ == '__main__':
    #trans = Transport(('127.0.0.1', 3000))
    trans = Transport() # Unaddressable transport.
    ep = trans.endpoint()
    conn = trans.connect(ep, 'relays.cardano-mainnet.iohk.io:3000:0')

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

    cmd, arg = ep.receive() # create new connection
    assert cmd == ControlHeader.CreatedNewConnection and arg == conn.id, 'invalid response'
    lid, data = ep.receive() # peerdata
    assert lid == conn.id, 'invalid response'
    print('peer data response', cbor.loads(data))
    lid, data = ep.receive() # nodeid
    assert lid == conn.id and data[:1] == b'A' and struct.unpack('>Q', data[1:])[0] == nonce, 'invalid response'

    print(ep.receive())
