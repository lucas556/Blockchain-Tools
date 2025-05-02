import base58
import nayuki_crypto

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def to_int_list(b: bytes) -> list[int]:
    return list(b)

class TronAddress:
    @staticmethod
    def public_key_from_private(private_key_bytes: bytes) -> bytes:
        pubkey = nayuki_crypto.private_to_public(to_int_list(private_key_bytes))
        prefix = pubkey[0]
        x = int.from_bytes(pubkey[1:33], 'big')
        y = TronAddress._recover_y(prefix, x)
        return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

    @staticmethod
    def _recover_y(prefix: int, x: int) -> int:
        y_sq = (x * x * x + 7) % SECP256K1_P
        y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
        if (y % 2) != (prefix & 1):
            y = SECP256K1_P - y
        return y

    @staticmethod
    def to_tron_address(pubkey_uncompressed: bytes) -> str:
        hash20 = nayuki_crypto.keccak256(pubkey_uncompressed[1:])[-20:]
        address_bytes = b'\x41' + hash20
        return base58.b58encode_check(address_bytes).decode()
