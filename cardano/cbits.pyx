import struct
from libc.stdint cimport uint8_t, uint32_t

cdef public enum derivation_scheme_mode:
    DERIVATION_V1 = 1
    DERIVATION_V2 = 2

cdef extern from *:
    int wallet_encrypted_derive_public(
        uint8_t *pub_in,
        uint8_t *cc_in,
        uint32_t index,
        uint8_t *pub_out,
        uint8_t *cc_out,
        derivation_scheme_mode mode
    )
    void wallet_encrypted_derive_private(
        uint8_t *in_,
        uint8_t *pass_, uint32_t pass_len,
        uint32_t index,
        uint8_t *out,
        derivation_scheme_mode mode
    )
    int wallet_encrypted_from_secret(
        uint8_t *pass_, uint32_t pass_len,
        uint8_t *seed,
        uint8_t *cc,
        uint8_t *out
    )
    void wallet_encrypted_sign(
        uint8_t *encrypted_key,
        uint8_t *pass_,
        uint32_t pass_len,
        uint8_t *data,
        uint32_t data_len,
        uint8_t *signature
    )
    int cardano_crypto_ed25519_sign_open(
        uint8_t *m,
        size_t mlen,
        uint8_t *pk,
        uint8_t *RS
    )
    void cryptonite_chacha_init(
        uint8_t *ctx,
        uint8_t nb_rounds,
        uint32_t keylen,
        uint8_t *key,
        uint32_t ivlen,
        uint8_t *iv
    )
    void cryptonite_chacha_combine(
        uint8_t *dst,
        uint8_t *ctx,
        uint8_t *src,
        uint32_t bytes
    )
    void cryptonite_chacha_generate(
        uint8_t *dst,
        uint8_t *ctx,
        uint32_t bytes
    )
    void cryptonite_chacha_random(
        uint32_t rounds,
        uint8_t *dst,
        uint8_t *st,  # cryptonite_chacha_state*
        uint32_t bytes
    )
    void cryptonite_poly1305_init(
        uint8_t *ctx,
        uint8_t *key
    )
    void cryptonite_poly1305_update(
        uint8_t *ctx,
        uint8_t *data,
        uint32_t length
    )
    void cryptonite_poly1305_finalize(
        uint8_t *mac8,
        uint8_t *ctx
    )
    void cryptonite_chacha_init_core(
        uint8_t *st,  # cryptonite_chacha_state*
        uint32_t keylen, uint8_t *key,
        uint32_t ivlen, uint8_t *iv
    )

def encrypted_derive_public(xpub, index, mode):
    pub_out = bytes(32)
    cc_out = bytes(32)
    if wallet_encrypted_derive_public(xpub[:32], xpub[32:], index, pub_out, cc_out, mode) == 0:
        return pub_out + cc_out

def encrypted_derive_private(skey, pass_, index, mode):
    cdef uint8_t* c_pass = pass_
    cdef uint32_t l_pass = len(pass_)
    out = bytes(128)
    wallet_encrypted_derive_private(skey, c_pass, l_pass, index, out, mode)
    return out

def encrypted_from_secret(pass_, seed, cc):
    cdef uint8_t* c_pass = pass_
    cdef uint32_t l_pass = len(pass_)
    out = bytes(128)
    if wallet_encrypted_from_secret(c_pass, l_pass, seed, cc, out) == 0:
        return out

def encrypted_sign(skey, pass_, msg):
    sig = bytes(64)
    wallet_encrypted_sign(skey, pass_, len(pass_), msg, len(msg), sig)
    return sig

def verify(pub, msg, sig):
    return cardano_crypto_ed25519_sign_open(msg, len(msg), pub, sig) == 0

def pad16(int n):
    cdef int m = n % 16
    if m == 0:
        return b'' 
    else:
        return b'\x00' * (16 - m)

def encrypt_chachapoly(nonce, key, header, plaintext):
    assert len(key) == 32
    assert len(nonce) == 12

    cdef uint8_t enc_state[132]
    cdef uint8_t mac_state[84]
    cdef uint8_t poly_key[64]

    cryptonite_chacha_init(enc_state, 20, len(key), key, len(nonce), nonce)
    cryptonite_chacha_generate(poly_key, enc_state, 64)
    cipher = bytes(len(plaintext))
    cryptonite_chacha_combine(cipher, enc_state, plaintext, len(plaintext))

    mac_data = b''.join([
        header, pad16(len(header)),
        cipher, pad16(len(cipher)),
        struct.pack('<QQ', len(header), len(cipher)),
    ])
    cryptonite_poly1305_init(mac_state, poly_key)
    cryptonite_poly1305_update(mac_state, mac_data, len(mac_data))

    auth = bytes(16)
    cryptonite_poly1305_finalize(auth, mac_state)
    return cipher + auth

def decrypt_chachapoly(nonce, key, header, cipher):
    cdef uint8_t enc_state[132]
    cdef uint8_t mac_state[84]
    cdef uint8_t poly_key[64]

    assert len(cipher) >= 16
    auth = cipher[-16:]
    cipher = cipher[:-16]

    cryptonite_chacha_init(enc_state, 20, len(key), key, len(nonce), nonce)
    cryptonite_chacha_generate(poly_key, enc_state, 64)
    plain = bytes(len(cipher))
    cryptonite_chacha_combine(plain, enc_state, cipher, len(cipher))

    mac_data = b''.join([
        header, pad16(len(header)),
        cipher, pad16(len(cipher)),
        struct.pack('<QQ', len(header), len(cipher)),
    ])
    cryptonite_poly1305_init(mac_state, poly_key)
    cryptonite_poly1305_update(mac_state, mac_data, len(mac_data))
    new_auth = bytes(16)
    cryptonite_poly1305_finalize(new_auth, mac_state)

    if new_auth != auth:
        return

    return plain

def chacha_random_init(seed):
    assert len(seed) == 40, 'length of seed need to be 40'
    ctx = bytearray(64)
    cryptonite_chacha_init_core(ctx, 32, seed, 8, seed[32:])
    return ctx

def chacha_random_generate(ctx, n):
    assert len(ctx) == 64
    dst = bytes(n)
    cryptonite_chacha_random(8, dst, ctx, n)
    return dst
