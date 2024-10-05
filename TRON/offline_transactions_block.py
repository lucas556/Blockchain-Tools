import requests
import base58
import time
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_private_key

# Global constants for API URLs
GETBLOCK_URL = "https://api.trongrid.io/walletsolidity/getblock"
BROADCAST_URL = "https://api.trongrid.io/wallet/broadcasttransaction"
# API_KEY = "your_getblock_api_key_here"  # Your GetBlock API Key

Transaction = {
    "contract": [{
        "parameter": {
            "value": {
                "amount": None,  # To be filled
                "owner_address": None,  # To be filled
                "to_address": None  # To be filled
            },
            "type_url": "type.googleapis.com/protocol.TransferContract"
        },
        "type": "TransferContract"
    }],
    "ref_block_bytes": None,  # To be filled
    "ref_block_hash": None,  # To be filled
    "expiration": None,  # To be filled
    "timestamp": None  # To be filled
}

# Helper function to convert Base58 to Hex
def base58_to_hex(base58_address: str) -> str:
    try:
        decoded = base58.b58decode_check(base58_address)
    except ValueError:
        raise ValueError("Invalid Base58 address provided")
    
    hex_address = decoded.hex()
    if not hex_address.startswith('41'):
        raise ValueError("Invalid Tron address, should start with 41.")
    return hex_address

# Class to encapsulate transaction creation and broadcasting
class TronTransactionHandler:
    def __init__(self, getblock_url: str = GETBLOCK_URL, broadcast_url: str = BROADCAST_URL, api_key: str = API_KEY):
        self.getblock_url = getblock_url
        self.broadcast_url = broadcast_url
        self.api_key = api_key

    def fetch_block_data(self):
        headers = {
            'accept': 'application/json',
            'content-type': 'application/json',
            # 'x-api-key': self.api_key
        }
        data = '{"detail":false}'
        response = requests.post(self.getblock_url, headers=headers, data=data)
        
        if response.status_code != 200:
            raise Exception(f"Failed to fetch block data, status code: {response.status_code}")
        
        block_data = response.json()
        ref_block_bytes = block_data['block_header']['raw_data']['number'] % 65536
        ref_block_bytes_hex = ref_block_bytes.to_bytes(2, 'big').hex()
        ref_block_hash = block_data['blockID'][:16]
        return ref_block_bytes_hex, ref_block_hash

    def create_transaction(self, private_key_hex: str, from_address: str, to_address: str, amount: int):
        transaction = Transaction.copy()
        ref_block_bytes_hex, ref_block_hash = self.fetch_block_data()
        
        current_time = int(time.time() * 1000)
        transaction["contract"][0]["parameter"]["value"]["amount"] = amount
        transaction["contract"][0]["parameter"]["value"]["owner_address"] = base58_to_hex(from_address)
        transaction["contract"][0]["parameter"]["value"]["to_address"] = base58_to_hex(to_address)
        transaction["ref_block_bytes"] = ref_block_bytes_hex
        transaction["ref_block_hash"] = ref_block_hash
        transaction["expiration"] = current_time + 60 * 1000
        transaction["timestamp"] = current_time

        raw_data_hex = self.serialize_to_hex(transaction)
        signature = self.sign_transaction(raw_data_hex, private_key_hex)

        txID_hex = self.calculate_txID(raw_data_hex)

        signed_transaction = {
            "txID": txID_hex,
            "raw_data": transaction,
            "raw_data_hex": raw_data_hex,
            "signature": [signature]
        }

        return signed_transaction

    def serialize_to_hex(self, transaction) -> str:
        raw_data_bytes = b'\x0a' + (1).to_bytes(1, 'big')
        
        param_value = transaction["contract"][0]["parameter"]["value"]
        # Serialize owner_address, to_address, and amount
        raw_data_bytes += (
            b'\x12' + struct.pack('>I', len(param_value["owner_address"]) // 2)
            + bytes.fromhex(param_value["owner_address"])
            + b'\x1a' + struct.pack('>I', len(param_value["to_address"]) // 2)
            + bytes.fromhex(param_value["to_address"])
            + b'\x20' + struct.pack('>Q', param_value["amount"])
        )
        
        # Serialize ref_block_bytes and ref_block_hash
        raw_data_bytes += (
            b'\x22' + struct.pack('>I', len(transaction["ref_block_bytes"]) // 2)
            + bytes.fromhex(transaction["ref_block_bytes"])
            + b'\x28' + struct.pack('>I', len(transaction["ref_block_hash"]) // 2)
            + bytes.fromhex(transaction["ref_block_hash"])
        )
        
        # Serialize expiration and timestamp
        raw_data_bytes += (
            b'\x30' + struct.pack('>Q', transaction["expiration"])
            + b'\x38' + struct.pack('>Q', transaction["timestamp"])
        )
        
        return raw_data_bytes.hex()

    def calculate_txID(self, raw_data_hex: str) -> str:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(raw_data_hex))
        return digest.finalize().hex()

    def sign_transaction(self, raw_data_hex: str, private_key_hex: str) -> str:
        private_key_bytes = bytes.fromhex(private_key_hex)
        private_key = load_der_private_key(private_key_bytes, password=None, backend=default_backend())

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(raw_data_hex))
        tx_hash = digest.finalize()

        signature = private_key.sign(tx_hash, ec.ECDSA(hashes.SHA256()))
        return signature.hex()

    def broadcast_transaction(self, signed_transaction):
        broadcast_response = requests.post(self.broadcast_url, json=signed_transaction)
        response_data = broadcast_response.json()
        if broadcast_response.status_code != 200 or response_data.get("code") is not None:
            print(f"Broadcast failed: {response_data}")
        else:
            print("Broadcast successful:", response_data)

# Example usage
private_key_hex = "your_private_key_here"
from_address = "your_from_address_here"
to_address = "your_to_address_here"
amount = 10 * 1_000_000  # 10 TRX

handler = TronTransactionHandler()
signed_transaction = handler.create_transaction(private_key_hex, from_address, to_address, amount)
handler.broadcast_transaction(signed_transaction)
