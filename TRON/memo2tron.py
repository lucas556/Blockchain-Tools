import hashlib
import ecdsa
import base58
from Crypto.Hash import keccak
import bip32utils

def keccak256(data):
    """Compute the keccak256 hash of the input data."""
    hasher = keccak.new(digest_bits=256)
    hasher.update(data)
    return hasher.digest()

def pbkdf2_hmac_sha512(password, salt, iterations=2048, dklen=64):
    """PBKDF2-HMAC-SHA512 implementation."""
    return hashlib.pbkdf2_hmac('sha512', password, salt, iterations, dklen)

def get_signing_key(raw_priv):
    """Create a signing key from the raw private key."""
    return ecdsa.SigningKey.from_string(raw_priv, curve=ecdsa.SECP256k1)

def verifying_key_to_addr(key):
    """Convert a verifying key to an address."""
    pub_key = key.to_string()
    primitive_addr = b'\x41' + keccak256(pub_key)[-20:]
    addr = base58.b58encode_check(primitive_addr)
    return addr.decode()

def mnemonic_to_seed(mnemonic, passphrase=""):
    """Convert a mnemonic phrase to a seed using BIP-39."""
    mnemonic = mnemonic.strip()
    salt = b'mnemonic' + passphrase.encode('utf-8')
    seed = pbkdf2_hmac_sha512(mnemonic.encode('utf-8'), salt)
    return seed

# 助记词
mnemonic_words = "aware report movie exile buyer drum poverty supreme gym oppose float elegant"
passphrase = ""

# 从助记词生成种子
seed = mnemonic_to_seed(mnemonic_words, passphrase)
print("Seed:", seed.hex())

# 使用 bip32utils 生成根密钥
bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
root_extended_key = bip32_root_key.ExtendedKey()
chain_code = bip32_root_key.ChainCode().hex()

# 打印 BIP32 根密钥
print("BIP32 Root Key:")
print("Extended Key (hex):", root_extended_key)
print("Chain Code (hex):", chain_code)

# 根据 BIP-44 路径派生密钥（例如 m/44'/195'/0'/0/0）
# Tron 的币种标识符是 195，按照 BIP-44 规则派生
derivation_path = "m/44'/195'/0'/0/0"
path_parts = [int(part[:-1]) + 0x80000000 if part.endswith("'") else int(part) for part in derivation_path.split('/')[1:]]
child_key = bip32_root_key

for index in path_parts:
    child_key = child_key.ChildKey(index)

# 打印子密钥的详细信息
print("Child Key Information:")
print("Path:", derivation_path)
print("Extended Key (hex):", child_key.ExtendedKey())
print("Chain Code (hex):", child_key.ChainCode().hex())

# 获取私钥
private_key = child_key.PrivateKey()
print("Private Key (64 hex chars):", private_key.hex())

# 生成签名密钥
signing_key = get_signing_key(private_key)

# 获取 Tron 地址
tron_address = verifying_key_to_addr(signing_key.get_verifying_key())
print("Tron Address:", tron_address)
