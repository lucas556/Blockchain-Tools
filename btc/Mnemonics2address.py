from mnemonic import Mnemonic
import bip32utils
import hashlib
from bech32 import bech32_encode, convertbits

def hash160(public_key):
    """使用SHA256和RIPEMD160生成哈希160."""
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    return ripemd160.digest()

def encode_bech32_address(hrp, witver, witprog):
    """编码Bech32 SegWit地址."""
    # 转换为5位比特组格式
    witprog_converted = convertbits(witprog, 8, 5)
    return bech32_encode(hrp, [witver] + witprog_converted)

def generate_segwit_addresses_from_mnemonic(existing_mnemonic, num_addresses=5):
    # 创建助记词对象
    mnemo = Mnemonic("english")
    
    # 验证提供的助记词
    if not mnemo.check(existing_mnemonic):
        raise ValueError("提供的助记词无效，请检查后再试。")
    
    # 将助记词转换为种子
    seed = mnemo.to_seed(existing_mnemonic)
    
    # 使用种子生成BIP32根密钥
    root_key = bip32utils.BIP32Key.fromEntropy(seed)
    
    # 派生多个 SegWit 地址
    segwit_addresses = []
    for i in range(num_addresses):
        # 使用 BIP84 路径 m/84'/0'/0'/0/i 派生地址
        account_key = root_key.ChildKey(84 + bip32utils.BIP32_HARDEN)
        coin_key = account_key.ChildKey(0 + bip32utils.BIP32_HARDEN)
        account_key = coin_key.ChildKey(0 + bip32utils.BIP32_HARDEN)
        change_key = account_key.ChildKey(0)
        address_key = change_key.ChildKey(i)
        
        # 获取公钥
        public_key = address_key.PublicKey()
        
        # 计算哈希160
        hash160_result = hash160(public_key)
        segwit_address = encode_bech32_address('bc', 0, hash160_result)
        segwit_addresses.append(segwit_address)
    
    return segwit_addresses

# 示例助记词（替换为你自己的助记词）
existing_mnemonic = "......"
num_addresses_to_generate = 5  # 设定要生成的地址数量

try:
    segwit_addresses = generate_segwit_addresses_from_mnemonic(existing_mnemonic, num_addresses_to_generate)
    for index, address in enumerate(segwit_addresses):
        print(f"地址 {index + 1}: {address}")
except ValueError as e:
    print(e)
