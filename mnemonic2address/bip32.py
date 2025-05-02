import nayuki_crypto
from hashlib import pbkdf2_hmac

HARDENED_OFFSET = 0x80000000
CURVE_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

def to_int_list(b: bytes) -> list[int]:
    return list(b)

class BIP32Key:
    def __init__(self, privkey: bytes, chain_code: bytes, depth=0, index=0, parent_fingerprint=b'\x00\x00\x00\x00'):
        self.privkey = privkey
        self.chain_code = chain_code
        self.depth = depth
        self.index = index
        self.parent_fingerprint = parent_fingerprint

    @classmethod
    def from_seed(cls, seed: bytes):
        I = nayuki_crypto.hmac_sha512(b"Bitcoin seed", seed)
        return cls(I[:32], I[32:])

    def derive_child(self, index: int):
        if index >= HARDENED_OFFSET:
            data = b'\x00' + self.privkey + index.to_bytes(4, 'big')
        else:
            pubkey = nayuki_crypto.private_to_public(to_int_list(self.privkey))
            data = bytes(pubkey) + index.to_bytes(4, 'big')
        I = nayuki_crypto.hmac_sha512(self.chain_code, data)
        Il, Ir = I[:32], I[32:]
        child_priv_int = (int.from_bytes(Il, 'big') + int.from_bytes(self.privkey, 'big')) % CURVE_ORDER
        child_priv = child_priv_int.to_bytes(32, 'big')
        return BIP32Key(child_priv, Ir, self.depth + 1, index)
