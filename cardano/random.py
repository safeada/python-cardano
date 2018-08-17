'''
chacha deterministic random.

seed:
    drgNewSeed . seedFromInteger . os2ip $ bytes
gen_bytes:
    chacha_generate(ctx, n)
'''

from . import cbits

SEED_LENGTH = 40


class Random(object):
    __slots__ = ('_ctx',)

    def __init__(self, bs):
        n = int.from_bytes(bs, 'big')
        n %= 2 ** (SEED_LENGTH * 8)
        bs = n.to_bytes(SEED_LENGTH, 'big')

        self._ctx = cbits.chacha_random_init(bs)

    def bytes(self, n):
        return cbits.chacha_random_generate(self._ctx, n)

    def number(self, n):
        assert n > 0
        size = max(4, (n.bit_length() + 7) // 8)
        start = (2 ** (size * 8)) % n
        while True:
            x = int.from_bytes(self.bytes(size), 'big')
            if x >= start:
                return x % n

    def range(self, start, stop):
        assert stop >= start
        return start + self.number(stop - start + 1)


if __name__ == '__main__':
    # seed
    from .utils import hash_data
    for i in range(10):
        rnd = Random(hash_data(i))
        for _ in range(10):
            print(rnd.number(10), end=' ')
        print()
