import os
import sys
import binascii
import json
from collections import defaultdict
import argparse
import itertools

import base58
import rocksdb
from cardano.storage import Storage, iter_prefix, remove_prefix

def input_passphase():
    import getpass
    passphase = None
    while not passphase:
        passphase = getpass.getpass('Input passphase:').encode()
    return passphase

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

def handle_run(args):
    from cardano.transport import Transport
    from cardano.node import default_node, Message

    transport = Transport()
    node = default_node(transport.endpoint())
    node.worker(Message.Subscribe, b'relays.cardano-mainnet.iohk.io:3000:0')()

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

def create_wallet_with_mnemonic(args, words, recover):
    from cardano.address import mnemonic_to_seed, gen_root_xpriv

    wallets_root = os.path.join(args.root, 'wallets')
    if not os.path.exists(wallets_root):
        os.mkdir(wallets_root)
    cfg_path = os.path.join(wallets_root, args.name + '.json')
    if os.path.exists(cfg_path):
        print('wallet config %s already exists.' % cfg_path)
        return

    # generate seed and mnemonic.
    passphase = input_passphase()
    xpriv = gen_root_xpriv(mnemonic_to_seed(words, args.language), passphase)
    wallet_config = {
        'name': args.name,
        'language': args.language,
        'root_key': binascii.hexlify(xpriv).decode(),
    }
    s = json.dumps(wallet_config)
    open(cfg_path, 'w').write(s)

def handle_wallet_create(args):
    from mnemonic import Mnemonic
    words = Mnemonic(args.language).generate()
    return create_wallet_with_mnemonic(args, words, False)

def handle_wallet_recover(args):
    return create_wallet_with_mnemonic(args, args.mnemonic, True)

def load_wallet_config(args):
    cfg_path = os.path.join(args.root, 'wallets', args.name+'.json')
    if not os.path.exists(cfg_path):
        print('wallet config is not exists:', args.name)
        return
    return json.load(open(cfg_path))

def handle_wallet_balance(args):
    cfg = load_wallet_config(args)
    root_key = binascii.unhexlify(cfg['root_key'])
    from cardano.address import derive_hdpassphase, xpriv_to_xpub, get_derive_path
    hdpass = derive_hdpassphase(xpriv_to_xpub(root_key))

    # iterate utxo.
    store = Storage(args.root)
    balance = 0
    for txin, txout in store.iter_utxo():
        if get_derive_path(txout.addr, hdpass):
            balance += txout.c

    print(balance)

def handle_wallet_list(args):
    wallet_dir = os.path.join(args.root, 'wallets')
    if not os.path.exists(wallet_dir):
        return

    for f in os.listdir(wallet_dir):
        if f.endswith('.json'):
            print(f[:-5])

def cli_parser():
    p_root = argparse.ArgumentParser(description='Python cardano cli.')
    p_root.add_argument('--root', dest='root', default='./test_db', help='root directory for storage.')
    sp_root = p_root.add_subparsers(help='choose sub-command to execute')

    p_sync = sp_root.add_parser('sync', help='Fill local database by syncing blocks from cardano mainchain.')
    p_sync.set_defaults(handler=handle_sync)
    p_sync.add_argument('--addr',
        dest='addr',
        default='relays.cardano-mainnet.iohk.io:3000:0',
        help='Address of node to connect.'
    )
    p_sync.add_argument('--genesis',
        dest='genesis',
        default='89d9b5a5b8ddc8d7e5a6795e9774d97faf1efea59b2caf7eaf9f8c5b32059df4',
        help='hash of genesis block'
    )
    p_sync.add_argument('--genesis-prev',
        dest='genesis_prev',
        default='5f20df933584822601f9e3f8c024eb5eb252fe8cefb24d1317dc3d432e940ebb',
        help='hash of prev of genesis block'
    )

    p_run = sp_root.add_parser('run', help='Run main node, sync and subscribe for new block automatically.')
    p_run.set_defaults(handler=handle_run)

    p_utxo = sp_root.add_parser('utxo', help='UTxO commands.')
    sp_utxo = p_utxo.add_subparsers(help='Choose wallet sub-command to execute')
    p = sp_utxo.add_parser('re-cache', help='Re-create UTxO cache, with block data in local storage.')
    p.set_defaults(handler=handle_recache_utxo)
    p = sp_utxo.add_parser('stat', help='View statistics of current UTxO cache.')
    p.set_defaults(handler=handle_stat_utxo)

    p_wallet = sp_root.add_parser('wallet', help='Wallet commands.')
    sp_wallet = p_wallet.add_subparsers(help='Choose wallet sub-command to execute')

    p = sp_wallet.add_parser('create', help='create wallet')
    p.set_defaults(handler=handle_wallet_create)
    p.add_argument('name',
        metavar = 'NAME',
        help = 'the name of the new wallet',
    )
    p.add_argument('--language',
        dest = 'language',
        default = 'english',
        help = 'use the given language for the mnemonic',
    )

    p = sp_wallet.add_parser('recover', help='recover wallet with mnemonic words')
    p.set_defaults(handler=handle_wallet_recover)
    p.add_argument('name',
        metavar = 'NAME',
        help = 'the name of the new wallet',
    )
    p.add_argument('--language',
        dest = 'language',
        default = 'english',
        help = 'use the given language for the mnemonic',
    )
    p.add_argument('--mnemonic',
        dest = 'mnemonic',
        required = True,
        help = 'mnemonic words for recovering the wallet',
    )

    p = sp_wallet.add_parser('balance', help='get wallet balance')
    p.set_defaults(handler=handle_wallet_balance)
    p.add_argument('name',
        metavar = 'NAME',
        help = 'the name of the wallet',
    )

    p = sp_wallet.add_parser('list', help='list wallets')
    p.set_defaults(handler=handle_wallet_list)
    return p_root

if __name__ == '__main__':
    p = cli_parser()
    args = p.parse_args()
    if 'handler' in args:
        args.handler(args)
    else:
        p.print_help()
