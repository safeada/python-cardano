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
        uint8_t *st,
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

def encrypted_derive_public(xpub, index, mode):
    pub_out = bytearray(32)
    cc_out = bytearray(32)
    if wallet_encrypted_derive_public(xpub[:32], xpub[32:], index, pub_out, cc_out, mode) == 0:
        return bytes(pub_out + cc_out)

def encrypted_derive_private(skey, pass_, index, mode):
    cdef uint8_t* c_pass = pass_
    cdef uint32_t l_pass = len(pass_)
    out = bytearray(128)
    wallet_encrypted_derive_private(skey, c_pass, l_pass, index, out, mode)
    return bytes(out)

def encrypted_from_secret(pass_, seed, cc):
    cdef uint8_t* c_pass = pass_
    cdef uint32_t l_pass = len(pass_)
    out = bytearray(128)
    if wallet_encrypted_from_secret(c_pass, l_pass, seed, cc, out) == 0:
        return bytes(out)

def encrypted_sign(skey, pass_, msg):
    sig = bytearray(64)
    wallet_encrypted_sign(skey, pass_, len(pass_), msg, len(msg), sig)
    return bytes(sig)

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
    cipher = bytearray(len(plaintext))
    cryptonite_chacha_combine(cipher, enc_state, plaintext, len(plaintext))
    cipher = bytes(cipher)

    mac_data = b''.join([
        header, pad16(len(header)),
        cipher, pad16(len(cipher)),
        struct.pack('<QQ', len(header), len(cipher)),
    ])
    cryptonite_poly1305_init(mac_state, poly_key)
    cryptonite_poly1305_update(mac_state, mac_data, len(mac_data))

    auth = bytearray(16)
    cryptonite_poly1305_finalize(auth, mac_state)
    return bytes(cipher + auth)

def decrypt_chachapoly(nonce, key, header, cipher):
    cdef uint8_t enc_state[132]
    cdef uint8_t mac_state[84]
    cdef uint8_t poly_key[64]

    assert len(cipher) >= 16
    auth = cipher[-16:]
    cipher = cipher[:-16]

    cryptonite_chacha_init(enc_state, 20, len(key), key, len(nonce), nonce)
    cryptonite_chacha_generate(poly_key, enc_state, 64)
    plain = bytearray(len(cipher))
    cryptonite_chacha_combine(plain, enc_state, cipher, len(cipher))
    plain = bytes(plain)

    mac_data = b''.join([
        header, pad16(len(header)),
        cipher, pad16(len(cipher)),
        struct.pack('<QQ', len(header), len(cipher)),
    ])
    cryptonite_poly1305_init(mac_state, poly_key)
    cryptonite_poly1305_update(mac_state, mac_data, len(mac_data))
    new_auth = bytearray(16)
    cryptonite_poly1305_finalize(new_auth, mac_state)

    if new_auth != auth:
        return

    return plain
