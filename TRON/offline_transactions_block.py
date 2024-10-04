import requests
from ecdsa import SigningKey, SECP256k1
from hashlib import sha256
import json
import base58
import time
import struct

# TRON API 地址
create_transaction_url = "https://api.trongrid.io/wallet/createtransaction"
broadcast_url = "https://api.trongrid.io/wallet/broadcasttransaction"
block_url = "https://api.trongrid.io/walletsolidity/getnowblock"
# 私钥（替换为你的实际私钥）
private_key_hex = "......"

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

block_response = requests.get(block_url)
block_data = block_response.json()

# Extracting block reference info
ref_block_bytes = block_data['block_header']['raw_data']['number'] % 65536  # 取模以确保不会溢出
ref_block_bytes_hex = ref_block_bytes.to_bytes(2, 'big').hex()  # 转为16进制
ref_block_hash = block_data['blockID'][:16]

transaction_raw_data = {
    "contract": [{
        "parameter": {
            "value": {
                "amount": amount,
                "owner_address": base58_to_hex(from_address),
                "to_address": base58_to_hex(to_address)
            },
            "type_url": "type.googleapis.com/protocol.TransferContract"
        },
        "type": "TransferContract"
    }],
    "ref_block_bytes": str(ref_block_bytes),
    "ref_block_hash": str(ref_block_hash),
    "expiration": int(time.time() * 1000) + 60 * 1000,  # 1-minute expiration
    "timestamp": int(time.time() * 1000)
}

def serialize_to_hex(data):
    raw_data_bytes = b'\x0a' + (len(data['contract'])).to_bytes(1, 'big')
    
    for contract in data['contract']:
        param_value = contract['parameter']['value']
        # 合并 owner_address, to_address 和 amount 的字节序列
        raw_data_bytes += (
            b'\x12' + struct.pack('>I', len(param_value['owner_address']) // 2)  # owner_address 长度
            + bytes.fromhex(param_value['owner_address'])  # 转换 owner_address 为字节
            + b'\x1a' + struct.pack('>I', len(param_value['to_address']) // 2)  # to_address 长度
            + bytes.fromhex(param_value['to_address'])  # 转换 to_address 为字节
            + b'\x20' + struct.pack('>Q', param_value['amount'])  # amount 作为 8 字节的整数
        )
    
    raw_data_bytes += (
        b'\x22' + struct.pack('>I', len(data['ref_block_bytes']) // 2) + bytes.fromhex(data['ref_block_bytes'])  # ref_block_bytes
        + b'\x28' + struct.pack('>I', len(data['ref_block_hash']) // 2) + bytes.fromhex(data['ref_block_hash'])  # ref_block_hash
    )
    
    # 序列化 expiration 和 timestamp
    raw_data_bytes += (
        b'\x30' + struct.pack('>Q', data['expiration'])  # expiration 为 8 字节
        + b'\x38' + struct.pack('>Q', data['timestamp'])  # timestamp 为 8 字节
    )
    
    return raw_data_bytes.hex()

raw_data_hex = serialize_to_hex(transaction_raw_data)

def sign_transaction(raw_data_hex, private_key_hex):
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    tx_hash = sha256(bytes.fromhex(raw_data_hex)).digest()  # 计算交易哈希
    signature = sk.sign_digest(tx_hash, sigencode=lambda r, s, _: r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
    return signature.hex()


signature = sign_transaction(raw_data_hex, private_key_hex)

# TXID
raw_data_serialized = json.dumps(transaction_raw_data, separators=(',', ':')).encode('utf-8')
txID = sha256(raw_data_serialized).hexdigest()


signed_transaction = {
    "txID": txID,
    "raw_data": transaction_raw_data,
    "raw_data_hex": raw_data_hex,
    "signature": [signature]
}


broadcast_response = requests.post(broadcast_url, json=signed_transaction)
print("Broadcast result:", broadcast_response.json())
