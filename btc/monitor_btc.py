import aiohttp
import asyncio
import orjson
import logging
from bitcoinlib.keys import Key
from bitcoinlib.transactions import Transaction
import hashlib
import bech32

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# API key
API_KEY = '000000.......'

# Asynchronous request handler function
async def request_handle(session, url: str, method="GET", json=None, data=None, headers=None, retries=3):
    for attempt in range(1, retries + 1):
        try:
            async with session.request(method, url, json=json, data=data, headers=headers) as response:
                if 200 <= response.status < 300:
                    ret = await response.read()
                    try:
                        return orjson.loads(ret)
                    except orjson.JSONDecodeError:
                        logging.error(f"Failed to parse JSON: {ret}, URL: {url}")
                        return None
                else:
                    logging.error(f"Server returned an error; Status code: {response.status}; Message: {await response.text()}, URL: {url}")
        except asyncio.TimeoutError:
            logging.error(f"Attempt {attempt}: Request timeout {url}.")
        except aiohttp.ClientError as e:
            logging.error(f"Attempt {attempt} failed: {e}, URL: {url}")
        except aiohttp.InvalidURL:
            logging.error(f"Invalid URL: {url}")
            return None
        except aiohttp.TooManyRedirects:
            logging.error(f"Too many redirects: {url}")
            return None

        await asyncio.sleep(2 ** attempt)
    
    logging.error(f"Request failed after {retries} attempts, URL: {url}.")
    raise Exception(f"Request to {url} failed")

# Get balance for the address
async def get_balance(session, address):
    url = f'https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance?token={API_KEY}'
    return await request_handle(session, url)

# Get UTXO list
async def get_utxos(session, address):
    url = f'https://api.blockcypher.com/v1/btc/main/addrs/{address}?unspentOnly=true&token={API_KEY}'
    return await request_handle(session, url)

# Get network-recommended fee
async def get_network_fee(session):
    url = f'https://api.blockcypher.com/v1/btc/main'
    response = await request_handle(session, url)
    if response:
        fee_per_kb = response['high_fee_per_kb']  # Fetch the high priority fee (sat/kb)
        fee_per_byte = fee_per_kb / 1000
        estimated_fee = int(fee_per_byte * 300)  # Assuming a transaction size of 300 bytes
        logging.info(f"Recommended network fee: {estimated_fee} satoshis")
        return estimated_fee
    else:
        logging.error("Failed to get network fee")
        return None

# Broadcast transaction
async def broadcast_transaction(session, raw_transaction_hex):
    url = f'https://api.blockcypher.com/v1/btc/main/txs/push?token={API_KEY}'
    response = await request_handle(session, url, method="POST", json={"tx": raw_transaction_hex})
    if response:
        tx_hash = response.get('tx', {}).get('hash')
        if tx_hash:
            logging.info(f"Transaction broadcast successful, transaction hash: {tx_hash}")
            return tx_hash  # Return the transaction hash
        else:
            logging.error("Transaction broadcast succeeded, but failed to get the transaction hash")
            return None
    else:
        logging.error("Transaction broadcast failed")
        return None

# Check if the transaction is confirmed on the blockchain
async def check_transaction_confirmation(session, tx_hash, delay=60):
    url = f'https://api.blockcypher.com/v1/btc/main/txs/{tx_hash}?token={API_KEY}'
    
    while True:  # Infinite loop until confirmations > 1
        response = await request_handle(session, url)
        if response:
            confirmations = response.get('confirmations', 0)
            if confirmations > 1:
                logging.info(f"Transaction {tx_hash} confirmed, confirmations: {confirmations}")
                return True
            else:
                logging.info(f"Transaction {tx_hash} not confirmed yet, current confirmations: {confirmations}")
        else:
            logging.error(f"Failed to check transaction {tx_hash}")

        await asyncio.sleep(delay)

# Convert public key to SegWit address
def pubkey_to_segwit_address(pubkey_bytes, network='mainnet'):
    pubkey_sha256 = hashlib.sha256(pubkey_bytes).digest()
    pubkey_hash160 = hashlib.new('ripemd160', pubkey_sha256).digest()

    witver = 0  # SegWit version number
    witprog = pubkey_hash160

    hrp = 'bc' if network == 'mainnet' else 'tb'  # Mainnet 'bc', Testnet 'tb'
    return bech32.encode(hrp, witver, witprog)

# Create and sign the transaction
def create_transaction(key, recipient_address, amount_to_send, utxos, fee):
    try:
        tx = Transaction(network='mainnet', witness_type='segwit')
        total_utxo_value = 0

        # Add UTXO inputs
        for utxo in utxos:
            tx_hash = utxo.get('tx_hash')
            tx_output_n = utxo.get('tx_output_n')
            value = utxo.get('value')

            if tx_hash and tx_output_n is not None and value is not None:
                tx.add_input(tx_hash, tx_output_n, value=value, script_type='p2wpkh')  # Add SegWit script type
                total_utxo_value += value
            else:
                logging.error(f"Incomplete UTXO data: {utxo}")
                return None

        # Add output
        tx.add_output(amount_to_send, recipient_address)
        change_address = pubkey_to_segwit_address(key.public_byte, network='mainnet')  # Use key to generate change address
        logging.info(f"Change address: {change_address}")
        change_amount = total_utxo_value - amount_to_send - fee

        if change_amount > 0:
            tx.add_output(change_amount, change_address)  # Send the change back to wallet address

        # Sign the transaction with private key
        private_key = key.private_hex  # Get private key in hex format
        tx.sign([private_key])  # Sign transaction

        logging.info(f"Signed transaction HEX: {tx.raw_hex()}")  # Log the signed transaction
        return tx.raw_hex()
    except ValueError as e:
        logging.error(f"Failed to create transaction: {e}")
        logging.error("Stack trace:\n" + traceback.format_exc())
        return None

# Main function
async def main():
    sender_address = 'bc1q.......'  # Sender's mainnet address
    recipient_address = 'bc1q......'  # Recipient's address
    wif_private_key = '5k......'  # Private key in WIF format

    conn = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=conn) as session:
        balance_response = await get_balance(session, sender_address)
        if balance_response is None:
            logging.error("Failed to get balance")
            return

        balance = balance_response.get('balance', 0)  # Get balance
        logging.info(f"Balance for {sender_address}: {balance} satoshis")

        fee = await get_network_fee(session)
        if fee is None or balance < fee:
            logging.error("Failed to get network fee or insufficient balance to pay fee")
            return

        amount_to_send = balance - fee
        logging.info(f"Amount to send: {amount_to_send} satoshis")

        utxos_response = await get_utxos(session, sender_address)
        if not utxos_response:
            logging.error("No unspent outputs found, cannot proceed")
            return

        utxos = utxos_response.get('txrefs', [])
        key = Key.from_wif(wif_private_key)
        tx = create_transaction(key, recipient_address, amount_to_send, utxos, fee)
        if not tx:
            logging.error("Failed to create transaction")
            return

        tx_hash = await broadcast_transaction(session, tx)
        if tx_hash:
            await check_transaction_confirmation(session, tx_hash)

# Run the main function
asyncio.run(main())
