import requests
from ecdsa import SigningKey, SECP256k1
from hashlib import sha256
import json
import base58
# TRON API 地址
create_transaction_url = "https://api.trongrid.io/wallet/createtransaction"
broadcast_url = "https://api.trongrid.io/wallet/broadcasttransaction"

# 私钥（替换为你的实际私钥）
private_key_hex = "0......"

# 转账参数
from_address = "T......"  # 发送方地址 (Base58)
to_address = "T......"   # 接收方地址 (Base58)
amount = 10 * 1_000_000  # 10 TRX

def base58_to_hex(base58_address):
    decoded = base58.b58decode_check(base58_address)
    hex_address = decoded.hex()
    if not hex_address.startswith('41'):
        raise ValueError("Invalid Tron address, should start with 41.")
    return hex_address

transaction_payload = {
    "to_address": base58_to_hex(to_address),
    "owner_address": base58_to_hex(from_address),
    "amount": amount,
    "visible": False  # 使用Base58地址
}

response = requests.post(create_transaction_url, json=transaction_payload)
transaction_data = response.json()
print(transaction_data)

if 'Error' in transaction_data:
    print(f"创建交易失败: {transaction_data['Error']}")
    exit(1)
else:
    print("成功创建交易，准备签名...")

def sign_transaction(raw_data_hex, private_key_hex):
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    tx_hash = sha256(bytes.fromhex(raw_data_hex)).digest()  # 计算交易哈希
    signature = sk.sign_digest(tx_hash, sigencode=lambda r, s, _: r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
    return signature.hex()

raw_data_hex = transaction_data['raw_data_hex']
signature = sign_transaction(raw_data_hex, private_key_hex)


signed_transaction = {
    "raw_data": transaction_data['raw_data'],  # 完整的 raw_data
    "raw_data_hex": raw_data_hex,
    "signature": [signature]  # 签名需要是列表
}
print(signed_transaction)
# 广播签名的交易
broadcast_response = requests.post(broadcast_url, json=signed_transaction)
print("广播结果:", broadcast_response.json())
