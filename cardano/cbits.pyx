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
    ) except 1
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
    ) except 1

def encrypted_derive_public(xpub, index, mode):
    pub_out = bytearray(32)
    cc_out = bytearray(32)
    wallet_encrypted_derive_public(xpub[:32], xpub[32:], index, pub_out, cc_out, mode)
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
    wallet_encrypted_from_secret(c_pass, l_pass, seed, cc, out)
    return bytes(out)
