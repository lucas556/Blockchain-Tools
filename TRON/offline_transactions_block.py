import requests
import base58
import time
import struct
import orjson
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_private_key

def base58_to_hex(base58_address: str) -> str:
    try:
        decoded = base58.b58decode_check(base58_address)
    except ValueError:
        raise ValueError("Invalid Base58 address provided")
    
    hex_address = decoded.hex()
    if not hex_address.startswith('41'):
        raise ValueError("Invalid Tron address, should start with 41.")
    return hex_address

@dataclass
class Transaction:
    owner_address: str
    to_address: str
    amount: int
    ref_block_bytes: str
    ref_block_hash: str
    expiration: int
    timestamp: int

    def serialize_to_hex(self) -> str:
        raw_data_bytes = b'\x0a' + (1).to_bytes(1, 'big')
        
        raw_data_bytes += (
            b'\x12' + struct.pack('>I', len(self.owner_address) // 2)
            + bytes.fromhex(self.owner_address)
            + b'\x1a' + struct.pack('>I', len(self.to_address) // 2)
            + bytes.fromhex(self.to_address)
            + b'\x20' + struct.pack('>Q', self.amount)
        )
        
        raw_data_bytes += (
            b'\x22' + struct.pack('>I', len(self.ref_block_bytes) // 2) + bytes.fromhex(self.ref_block_bytes)
            + b'\x28' + struct.pack('>I', len(self.ref_block_hash) // 2) + bytes.fromhex(self.ref_block_hash)
        )
        
        raw_data_bytes += (
            b'\x30' + struct.pack('>Q', self.expiration)
            + b'\x38' + struct.pack('>Q', self.timestamp)
        )
        
        return raw_data_bytes.hex()

def sign_transaction(raw_data_hex: str, private_key_hex: str) -> str:
    private_key_bytes = bytes.fromhex(private_key_hex)
    private_key = load_der_private_key(private_key_bytes, password=None, backend=default_backend())
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(bytes.fromhex(raw_data_hex))
    tx_hash = digest.finalize()
    
    signature = private_key.sign(tx_hash, ec.ECDSA(hashes.SHA256()))
    
    return signature.hex()

def create_and_broadcast_transaction(private_key_hex: str, from_address: str, to_address: str, amount: int):
    block_url = "https://api.trongrid.io/walletsolidity/getnowblock"
    broadcast_url = "https://api.trongrid.io/wallet/broadcasttransaction"

    block_response = requests.get(block_url)
    if block_response.status_code != 200:
        raise Exception(f"Failed to fetch block data, status code: {block_response.status_code}")
    
    block_data = block_response.json()
    ref_block_bytes = block_data['block_header']['raw_data']['number'] % 65536
    ref_block_bytes_hex = ref_block_bytes.to_bytes(2, 'big').hex()
    ref_block_hash = block_data['blockID'][:16]

    current_time = int(time.time() * 1000)
    
    transaction = Transaction(
        owner_address=base58_to_hex(from_address),
        to_address=base58_to_hex(to_address),
        amount=amount,
        ref_block_bytes=ref_block_bytes_hex,
        ref_block_hash=ref_block_hash,
        expiration=current_time + 60 * 1000,
        timestamp=current_time
    )

    raw_data_hex = transaction.serialize_to_hex()
    signature = sign_transaction(raw_data_hex, private_key_hex)

    txID = hashes.Hash(hashes.SHA256(), backend=default_backend())
    txID.update(orjson.dumps(asdict(transaction), option=orjson.OPT_SORT_KEYS))
    txID_hex = txID.finalize().hex()
    
    signed_transaction = {
        "txID": txID_hex,
        "raw_data": asdict(transaction),
        "raw_data_hex": raw_data_hex,
        "signature": [signature]
    }

    broadcast_response = requests.post(broadcast_url, json=signed_transaction)
    response_data = broadcast_response.json()
    if broadcast_response.status_code != 200 or response_data.get("code") is not None:
        print(f"Broadcast failed: {response_data}")
    else:
        print("Broadcast successful:", response_data)

private_key_hex = "your_private_key_here"
from_address = "your_from_address_here"
to_address = "your_to_address_here"
amount = 10 * 1_000_000  # 10 TRX

create_and_broadcast_transaction(private_key_hex, from_address, to_address, amount)
