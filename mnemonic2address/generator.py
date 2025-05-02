import logging
from hashlib import pbkdf2_hmac
from bip32 import BIP32Key, HARDENED_OFFSET
from validator import MnemonicValidator
from tron_address import TronAddress

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TronWalletGenerator:
    def __init__(self, mnemonic: str, passphrase: str = ""):
        self.mnemonic = mnemonic.strip()
        self.passphrase = passphrase
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

    def generate(self, path: list = None) -> dict:
        path = path or [44 + HARDENED_OFFSET, 195 + HARDENED_OFFSET, 0 + HARDENED_OFFSET, 0, 0]
        key = self.master_key
        for index in path:
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
