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

# Global constants for API URLs
BLOCK_URL = "https://api.trongrid.io/walletsolidity/getnowblock"
BROADCAST_URL = "https://api.trongrid.io/wallet/broadcasttransaction"

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

# Dataclass structure for Contract and Transaction
@dataclass
class ContractValue:
    amount: int
    owner_address: str
    to_address: str

@dataclass
class ContractParameter:
    value: ContractValue
    type_url: str

@dataclass
class Contract:
    parameter: ContractParameter
    type: str

@dataclass
class Transaction:
    contract: Contract
    ref_block_bytes: str
    ref_block_hash: str
    expiration: int
    timestamp: int

    def serialize_to_hex(self) -> str:
        raw_data_bytes = b'\x0a' + (1).to_bytes(1, 'big')
        
        # Serialize the owner_address, to_address, and amount
        raw_data_bytes += (
            b'\x12' + struct.pack('>I', len(self.contract.parameter.value.owner_address) // 2)
            + bytes.fromhex(self.contract.parameter.value.owner_address)
            + b'\x1a' + struct.pack('>I', len(self.contract.parameter.value.to_address) // 2)
            + bytes.fromhex(self.contract.parameter.value.to_address)
            + b'\x20' + struct.pack('>Q', self.contract.parameter.value.amount)
        )
        
        # Serialize ref_block_bytes and ref_block_hash
        raw_data_bytes += (
            b'\x22' + struct.pack('>I', len(self.ref_block_bytes) // 2) + bytes.fromhex(self.ref_block_bytes)
            + b'\x28' + struct.pack('>I', len(self.ref_block_hash) // 2) + bytes.fromhex(self.ref_block_hash)
        )
        
        # Serialize expiration and timestamp
        raw_data_bytes += (
            b'\x30' + struct.pack('>Q', self.expiration)
            + b'\x38' + struct.pack('>Q', self.timestamp)
        )
        
        return raw_data_bytes.hex()

    def calculate_txID(self) -> str:
        tx_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        tx_hash.update(bytes.fromhex(self.serialize_to_hex()))
        return tx_hash.finalize().hex()

    def sign_transaction(self, private_key_hex: str) -> str:
        private_key_bytes = bytes.fromhex(private_key_hex)
        private_key = load_der_private_key(private_key_bytes, password=None, backend=default_backend())
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.serialize_to_hex()))
        tx_hash = digest.finalize()
        
        signature = private_key.sign(tx_hash, ec.ECDSA(hashes.SHA256()))
        return signature.hex()

# Dataclass to represent signed transaction
@dataclass
class SignedTransaction:
    txID: str
    raw_data: dict
    raw_data_hex: str
    signature: list

# Class to encapsulate transaction creation and broadcasting
class TronTransactionHandler:
    def __init__(self, block_url: str = BLOCK_URL, broadcast_url: str = BROADCAST_URL):
        self.block_url = block_url
        self.broadcast_url = broadcast_url

    def fetch_block_data(self):
        # Fetch block data
        block_response = requests.get(self.block_url)
        if block_response.status_code != 200:
            raise Exception(f"Failed to fetch block data, status code: {block_response.status_code}")
        
        block_data = block_response.json()
        ref_block_bytes = block_data['block_header']['raw_data']['number'] % 65536
        ref_block_bytes_hex = ref_block_bytes.to_bytes(2, 'big').hex()
        ref_block_hash = block_data['blockID'][:16]
        return ref_block_bytes_hex, ref_block_hash

    def create_transaction(self, private_key_hex: str, from_address: str, to_address: str, amount: int):
        ref_block_bytes_hex, ref_block_hash = self.fetch_block_data()

        # Current time for expiration and timestamp
        current_time = int(time.time() * 1000)

        # Create transaction object using dataclass
        transaction = Transaction(
            contract=Contract(
                parameter=ContractParameter(
                    value=ContractValue(
                        amount=amount,
                        owner_address=base58_to_hex(from_address),
                        to_address=base58_to_hex(to_address)
                    ),
                    type_url="type.googleapis.com/protocol.TransferContract"
                ),
                type="TransferContract"
            ),
            ref_block_bytes=str(ref_block_bytes_hex),
            ref_block_hash=str(ref_block_hash),
            expiration=current_time + 60 * 1000,
            timestamp=current_time
        )

        # Serialize and sign transaction
        raw_data_hex = transaction.serialize_to_hex()
        signature = transaction.sign_transaction(private_key_hex)

        # Calculate txID
        txID_hex = transaction.calculate_txID()

        # Create signed transaction object using dataclass
        signed_transaction = SignedTransaction(
            txID=txID_hex,
            raw_data=asdict(transaction),
            raw_data_hex=raw_data_hex,
            signature=[signature]
        )

        return signed_transaction

    def broadcast_transaction(self, signed_transaction: SignedTransaction):
        # Broadcast transaction
        broadcast_response = requests.post(self.broadcast_url, json=asdict(signed_transaction))
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
