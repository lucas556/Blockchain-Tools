import hashlib
import hmac
import binascii
import ecdsa
import base58
from Crypto.Hash import keccak


def keccak256(data):
    hasher = keccak.new(digest_bits=256)
    hasher.update(data)
    return hasher.digest()


def get_signing_key(raw_priv):
    return ecdsa.SigningKey.from_string(raw_priv, curve=ecdsa.SECP256k1)


def verifying_key_to_addr(key):
    pub_key = key.to_string()
    primitive_addr = b'\x41' + keccak256(pub_key)[-20:]
    addr = base58.b58encode_check(primitive_addr)
    return addr


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic_normalized = ' '.join(mnemonic.split())
    passphrase_normalized = 'mnemonic' + passphrase
    seed = hashlib.pbkdf2_hmac('sha512', mnemonic_normalized.encode(), passphrase_normalized.encode(), 2048, dklen=64)
    return seed


# 示例助记词
mnemonic_words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
passphrase = ""

# 将助记词转换为种子
seed = mnemonic_to_seed(mnemonic_words, passphrase)
# print("种子:", binascii.hexlify(seed).decode())

# 使用种子的前32字节作为私钥
private_key = seed[:32]
print("64位私钥:", binascii.hexlify(private_key).decode())

signing_key = get_signing_key(private_key)

# 获取 Tron 地址
tron_address = verifying_key_to_addr(signing_key.get_verifying_key()).decode()
print('Tron 地址:', tron_address)
print('私钥:', binascii.hexlify(private_key).decode())
