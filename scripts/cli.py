import sys
from collections import defaultdict
import argparse
import base58
import itertools

import rocksdb
from cardano.storage import Storage, iter_prefix, remove_prefix

def handle_sync(args):
    from cardano.sync import sync
    from cardano.node import Transport, default_node

    store = Storage(args.db)
    node = default_node(Transport().endpoint())
    try:
        sync(store, node, args.addr.encode(), args.genesis, args.genesis_prev)
    finally:
        # close database properly.
        store = None
        import gc
        gc.collect()

def handle_recache_utxo(args):
    store = Storage(args.db)
    print('Removing all cached utxo')
    remove_prefix(store.db, b'ut/t/')
    print('Iterating blocks')
    count = 0
    for block in store.blocks():
        batch = rocksdb.WriteBatch()
        store.utxo_apply_block(block, batch)
        store.db.write(batch)
        count += 1
        print('%d' % count, end='\r')

def handle_stat_utxo(args):
    store = Storage(args.db)
    total_coin = 0
    balances = defaultdict(int)
    print('Start iterating utxos')
    for txin, txout in store.iter_utxo():
        total_coin += txout.c
        balances[txout.addr] += txout.c
    top_balances = itertools.islice(sorted(balances.items(), key=lambda t: t[1], reverse=True), 10)
    print('total_coin', total_coin / (10**6))
    print('top addresses:')
    for addr, c in top_balances:
        print(' ', base58.b58encode(addr).decode(), c / (10**6))

parser = argparse.ArgumentParser(description='Tool to view UTxO data.')
parser.add_argument('--db', dest='db', default='./test_db', help='Root directory of database.')
subparsers = parser.add_subparsers(help='Choose sub-command to execute')

parser_sync = subparsers.add_parser('sync', help='Fill local database by syncing blocks from cardano mainchain.')
parser_sync.set_defaults(handler=handle_sync)
parser_sync.add_argument('--addr',
    dest='addr',
    default='relays.cardano-mainnet.iohk.io:3000:0',
    help='Address of node to connect.'
)
parser_sync.add_argument('--genesis',
    dest='genesis',
    default='89d9b5a5b8ddc8d7e5a6795e9774d97faf1efea59b2caf7eaf9f8c5b32059df4',
    help='hash of genesis block'
)
parser_sync.add_argument('--genesis-prev',
    dest='genesis_prev',
    default='5f20df933584822601f9e3f8c024eb5eb252fe8cefb24d1317dc3d432e940ebb',
    help='hash of prev of genesis block'
)

parser_re_cache_utxo = subparsers.add_parser('re-cache-utxo', help='Iterate blockchain in local database, re-create UTxO cache.')
parser_re_cache_utxo.set_defaults(handler=handle_recache_utxo)

parser_stat_utxo = subparsers.add_parser('stat-utxo', help='Output statistics of current UTxO.')
parser_stat_utxo.set_defaults(handler=handle_stat_utxo)

if __name__ == '__main__':
    args = parser.parse_args()
    if 'handler' in args:
        args.handler(args)
    else:
        parser.print_help()
