import gevent
from gevent import socket

from .transport import make_endpoint_addr, parse_endpoint_addr
from . import config

gevent.config.resolver = 'dnspython'


def resolve(domains):
    addrs = []
    for domain in domains:
        host, port, id = parse_endpoint_addr(domain)
        items = socket.getaddrinfo(host, port,
                                   socket.AF_INET,
                                   socket.SOCK_STREAM,
                                   socket.IPPROTO_TCP)
        for _, _, _, _, (ip, port) in items:
            addrs.append((ip.encode(), port, id))
    return addrs


def resolve_loop(domains):
    while True:
        addrs = resolve(domains)
        if not addrs:
            gevent.sleep(config.SLOT_DURATION)
            continue

        for ip, port, id in addrs:
            yield make_endpoint_addr(ip, port, id)


if __name__ == '__main__':
    for addr in resolve_loop([config.MAINCHAIN_ADDR]):
        print(addr)
        gevent.sleep(1)
