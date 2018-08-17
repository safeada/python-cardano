from collections import OrderedDict
import os.path
import json
import binascii
import cbor
import yaml


CONF_DIR = os.path.join(os.path.dirname(__file__), '../conf')


def load_conf():
    # try cache yaml result with cbor.
    conf_path = os.path.join(CONF_DIR, 'configuration.yaml')
    cache_path = os.path.join(CONF_DIR, 'cached_configuration.cbor')
    if os.path.exists(cache_path) and \
            os.path.getmtime(cache_path) > os.path.getmtime(conf_path):
        # cache is good.
        return cbor.load(open(cache_path, 'rb'))

    with open(conf_path) as fp:
        conf = yaml.load(fp)

    fp = open(cache_path, 'wb')
    try:
        fp.write(cbor.dumps(conf))
    except:  # noqa[W291]
        fp.close()
        os.remove(cache_path)
        raise
    else:
        fp.close()

    return conf


g_config = load_conf()


def hash_json(d):
    from .utils import hash_serialized
    dumped = json.dumps(d, separators=(',', ':'), sort_keys=True).encode()
    return binascii.hexlify(hash_serialized(dumped))


def use(key):
    g = globals()
    g['CLUSTER_ADDR'] = {
        'mainnet': b'relays.cardano-mainnet.iohk.io:3000:0',
        'mainnet-staging': b'relays.awstest.iohkdev.io',
        'testnet': b'relays.cardano-testnet.iohkdev.io',
    }[key]
    confkey = {
        'mainnet': 'mainnet_full',
        'mainnet-staging': 'mainnet_dryrun_full',
        'testnet': 'testnet_full',
    }[key]
    genesis_block_hash = {
        'mainnet': binascii.unhexlify(
            '89d9b5a5b8ddc8d7e5a6795e9774d97faf1efea59b2caf7eaf9f8c5b32059df4')
    }[key]
    cfg = g_config[confkey]
    g['CHAIN'] = cfg

    genesis_cfg = cfg['core']['genesis']['src']
    genesis = json.load(open(os.path.join(CONF_DIR, genesis_cfg['file'])),
                        object_pairs_hook=OrderedDict)
    genesis_hash = hash_json(genesis)
    assert genesis_hash == genesis_cfg['hash'].encode()

    g['GENESIS'] = genesis
    g['GENESIS_HASH'] = genesis_hash  # genesis block's prev_header
    g['GENESIS_BLOCK_HASH'] = genesis_block_hash  # FIXME generate genesis block ourself
    g['PROTOCOL_MAGIC'] = genesis['protocolConsts']['protocolMagic']
    g['SECURITY_PARAMETER_K'] = genesis['protocolConsts']['k']
    g['SLOT_DURATION'] = int(genesis['blockVersionData']['slotDuration'])
    g['START_TIME'] = genesis['startTime']
    g['MAX_BLOCK_SIZE'] = genesis['blockVersionData']['maxBlockSize']
    g['MAX_HEADER_SIZE'] = genesis['blockVersionData']['maxHeaderSize']


if __name__ == '__main__':
    use('mainnet')
