'''
bech32_address 隔离见证
生成环境中请更换随机数生成方法以及库选择更好的
'''
import hashlib
import ecdsa
import bech32
import base58
import secrets

# 生成私钥（使用随机数）
def generate_private_key():
    return secrets.token_hex(32)

# 生成公钥
def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

# 生成隔离见证地址（Bech32格式）
def pubkey_to_segwit_address(pubkey, network='testnet'):
    pubkey_sha256 = hashlib.sha256(pubkey).digest()
    pubkey_hash160 = hashlib.new('ripemd160', pubkey_sha256).digest()

    witver = 0 
    witprog = pubkey_hash160

    if network == 'testnet':
        hrp = 'tb'  # 测试网前缀
    else:
        hrp = 'bc'  # 主网前缀

    return bech32.encode(hrp, witver, witprog)

# 将私钥转换为WIF格式
def private_key_to_wif(private_key, compressed=True, network='testnet'):
    if network == 'testnet':
        version_byte = b'\xEF'  # 测试网前缀
    else:
        version_byte = b'\x80'  # 主网前缀
    
    key_bytes = bytes.fromhex(private_key) + (b'\x01' if compressed else b'')
    extended_key = version_byte + key_bytes
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = extended_key + checksum

    # Base58Check 编码
    return base58.b58encode(wif).decode()

# 生成比特币地址和密钥的函数
def generate_bitcoin_keypair(network='mainnet'):
    if network not in ['mainnet', 'testnet']:
        raise ValueError("网络参数必须是 'mainnet' 或 'testnet'")
    
    # 生成私钥
    private_key = generate_private_key()
    public_key = private_key_to_public_key(private_key)
    wif_private_key = private_key_to_wif(private_key, network=network)
    address = pubkey_to_segwit_address(public_key, network=network)
    
    return {
        'private_key': private_key,
        'wif_private_key': wif_private_key,
        'public_key': public_key.hex(),
        'address': address
    }

def main(network='mainnet'):
    if network == 'mainnet':
        print("\n生成主网密钥对...\n")
    elif network == 'testnet':
        print("\n生成测试网密钥对...\n")
    else:
        print("无效网络类型，请选择 'mainnet' 或 'testnet'")
        return
      
    result = generate_bitcoin_keypair(network=network)
    
    # 显示结果
    print(f"私钥: {result['private_key']}")
    print(f"WIF格式私钥: {result['wif_private_key']}")
    print(f"公钥: {result['public_key']}")
    print(f"地址: {result['address']}")

if __name__ == "__main__":
    # main('mainnet')  # 默认生成主网密钥对
    main('testnet')  # 生成测试网密钥对
