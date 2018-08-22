from .address import addr_hash
from .utils import hash_data, verify
from . import config


class VerifyException(Exception):
    pass


def body_proof(blk):
    if blk.is_genesis():
        return hash_data(blk.leaders())
    else:
        ()


def verify_header(
        hdr,
        header_no_unknown=False,
        prev_header=None,
        current_slot=None,
        leaders=None,
        max_header_size=None):
    if hdr.protocol_magic() != config.PROTOCOL_MAGIC:
        raise VerifyException('protocol magic')

    if prev_header is not None:
        if hdr.prev_header() != prev_header.hash():
            raise VerifyException('prev header hash')
        if hdr.difficulty() != prev_header.difficulty() + (0 if hdr.is_genesis() else 1):
            raise VerifyException('prev header difficulty')
        if hdr.slot() <= prev_header.slot():
            raise VerifyException('prev header slot')
        if not hdr.is_genesis() and hdr.slot()[0] != prev_header.slot()[0]:
            raise VerifyException('prev header epoch')

    if current_slot is not None and hdr.slot() > current_slot:
        raise VerifyException('slot in future')

    if leaders is not None and not hdr.is_genesis() and \
            leaders[hdr.slot()[1]] != addr_hash(hdr.leader_key()):
        raise VerifyException('leader')

    if header_no_unknown and hdr.unknowns():
        raise VerifyException('extra header data')


def verify_block_do(blk):
    if not blk.is_genesis():
        pass


def verify_block(
        blk,
        max_block_size=None,
        body_no_unknown=False,
        **kwargs):
    verify_block_do(blk)
    verify_header(blk.header(), **kwargs)

    if max_block_size is not None and len(blk.raw()) > max_block_size:
        raise VerifyException('block size')

    if body_no_unknown and blk.unknowns():
        raise VerifyException('extra block data')


def verify_blocks(blks):
    pass
