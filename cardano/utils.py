import getpass
import hashlib

import cbor2


def hash_serialized(s):
    return hashlib.blake2b(s, digest_size=32).digest()


def hash_data(v):
    return hash_serialized(cbor2.dumps(v))


def input_passphase():
    passphase = getpass.getpass("Input passphase:").encode()
    if passphase:
        return hashlib.blake2b(passphase, digest_size=32).digest()
    return passphase


SIGN_TAGS = {
    "test": b"\x00",
    "tx": b"\x01",
    "redeem_tx": b"\x02",
    "vss_cert": b"\x03",
    "us_proposal": b"\x04",
    "commitment": b"\x05",
    "us_vote": b"\x06",
    "mainblock": b"\x07",
    "mainblock_light": b"\x08",
    "mainblock_heavy": b"\x09",
    "proxy_sk": b"\x0a",
}


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        s = sock.recv(n - len(buf))
        assert s, "connection closed"
        buf += s
    return buf


def send_many(o, *args):
    o.sendall(b"".join(args))
