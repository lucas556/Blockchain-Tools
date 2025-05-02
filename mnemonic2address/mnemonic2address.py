import logging
import base58
import nayuki_crypto
from hashlib import pbkdf2_hmac
import json

HARDENED_OFFSET = 0x80000000
CURVE_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MnemonicValidator:
    def __init__(self, wordlist_path="english.txt"):
        self.wordlist = self._load_wordlist(wordlist_path)
        self.word_index = {word: i for i, word in enumerate(self.wordlist)}

    def _load_wordlist(self, path) -> list:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.readlines() if line.strip()]

    def is_valid(self, mnemonic: str) -> bool:
        words = mnemonic.strip().split()
        if len(words) not in [12, 15, 18, 21, 24]:
            return False
        try:
            indices = [self.word_index[w] for w in words]
        except ValueError:
            return False
        bit_str = ''.join(f"{index:011b}" for index in indices)
        entropy_length = len(bit_str) - len(bit_str) // 33
        entropy_bits = bit_str[:entropy_length]
        checksum_bits = bit_str[entropy_length:]
        entropy_bytes = int(entropy_bits, 2).to_bytes(entropy_length // 8, byteorder="big")
        hash_bytes = nayuki_crypto.sha256(entropy_bytes)
        hash_bits = bin(int.from_bytes(hash_bytes, "big"))[2:].zfill(256)
        expected_checksum = hash_bits[:len(checksum_bits)]
        return checksum_bits == expected_checksum

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
            pubkey = nayuki_crypto.private_to_public(list(self.privkey))
            data = bytes(pubkey) + index.to_bytes(4, 'big')
        I = nayuki_crypto.hmac_sha512(self.chain_code, data)
        Il, Ir = I[:32], I[32:]
        child_priv_int = (int.from_bytes(Il, 'big') + int.from_bytes(self.privkey, 'big')) % CURVE_ORDER
        child_priv = child_priv_int.to_bytes(32, 'big')
        return BIP32Key(child_priv, Ir, self.depth + 1, index)

class TronAddress:
    @staticmethod
    def public_key_from_private(private_key_bytes: bytes) -> bytes:
        pubkey = nayuki_crypto.private_to_public(list(private_key_bytes))
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

class TronWalletGenerator:
    def __init__(self, mnemonic: str, passphrase: str = "", path: list = None):
        self.mnemonic = mnemonic.strip()
        self.passphrase = passphrase
        self.path = path or [44 + HARDENED_OFFSET, 195 + HARDENED_OFFSET, 0 + HARDENED_OFFSET, 0, 0]
        self.mnemonic_validator = MnemonicValidator("english.txt")

        if not self.mnemonic_validator.is_valid(self.mnemonic):
            logger.error("助记词无效，请检查拼写或顺序。")
            raise ValueError("助记词无效，请检查拼写或顺序。")

        self.seed = self._mnemonic_to_seed()
        self.master_key = BIP32Key.from_seed(self.seed)
        logger.info("Wallet initialized successfully.")

    def _mnemonic_to_seed(self) -> bytes:
        salt = b"mnemonic" + self.passphrase.encode("utf-8")
        return pbkdf2_hmac('sha512', self.mnemonic.encode("utf-8"), salt, 2048, dklen=64)

    def generate(self) -> dict:
        key = self.master_key
        for index in self.path:
            key = key.derive_child(index)

        privkey = key.privkey
        chain_code = key.chain_code
        pubkey_uncompressed = TronAddress.public_key_from_private(privkey)
        address = TronAddress.to_tron_address(pubkey_uncompressed)

        return {
            "mnemonic": self.mnemonic,
            "private_key": privkey.hex(),
            "public_key": pubkey_uncompressed.hex(),
            "chain_code": chain_code.hex(),
            "address": address,
        }

if __name__ == "__main__":
    mnemonic = "aware report movie exile buyer drum poverty supreme gym oppose float elegant"
    wallet = TronWalletGenerator(mnemonic)
    info = wallet.generate()
    print(json.dumps(info, indent=2))
