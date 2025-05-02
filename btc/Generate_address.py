'''
bech32_address 隔离见证
生成环境中请更换随机数生成方法以及库选择更好的
'''
import hashlib
import bech32
from bitcoinlib.keys import Key
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to convert public key to SegWit address (for both mainnet and testnet)
def pubkey_to_segwit_address(pubkey_bytes, network='mainnet'):
    pubkey_sha256 = hashlib.sha256(pubkey_bytes).digest()
    pubkey_hash160 = hashlib.new('ripemd160', pubkey_sha256).digest()

    witver = 0  # SegWit version number
    witprog = pubkey_hash160

    hrp = 'bc' if network == 'mainnet' else 'tb'  # Mainnet uses 'bc', Testnet uses 'tb'
    return bech32.encode(hrp, witver, witprog)

# Function to generate key and addresses for both mainnet and testnet
def generate_keypair_and_addresses():
    # Generate private key and public key using bitcoinlib
    key = Key()

    # Get private key in hex and WIF formats
    private_key_hex = key.private_hex
    wif_private_key = key.wif()

    # Get public key bytes
    public_key_bytes = key.public_byte

    # Generate SegWit addresses for mainnet and testnet
    mainnet_address = pubkey_to_segwit_address(public_key_bytes, network='mainnet')
    testnet_address = pubkey_to_segwit_address(public_key_bytes, network='testnet')

    # Output the keys and addresses
    logging.info(f"Private Key (Hex): {private_key_hex}")
    logging.info(f"WIF Private Key: {wif_private_key}")
    logging.info(f"Public Key (Hex): {public_key_bytes.hex()}")
    logging.info(f"Mainnet SegWit Address: {mainnet_address}")
    logging.info(f"Testnet SegWit Address: {testnet_address}")

    # Return the generated information
    return {
        'private_key_hex': private_key_hex,
        'wif_private_key': wif_private_key,
        'public_key_hex': public_key_bytes.hex(),
        'mainnet_address': mainnet_address,
        'testnet_address': testnet_address
    }

# Main function to call the key generation and address creation
if __name__ == "__main__":
    result = generate_keypair_and_addresses()

    # Print result
    print(f"Private Key (Hex): {result['private_key_hex']}")
    print(f"WIF Private Key: {result['wif_private_key']}")
    print(f"Public Key (Hex): {result['public_key_hex']}")
    print(f"Mainnet SegWit Address: {result['mainnet_address']}")
    print(f"Testnet SegWit Address: {result['testnet_address']}")
