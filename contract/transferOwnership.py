from web3 import Web3
import json

eth = 'https://mainnet.infura.io/v3/000000000000'
web3 = Web3(Web3.HTTPProvider(eth))
contract_address = Web3.to_checksum_address(0x0000......)
private_key = '0xf000......'
with open("ABI.json") as f:
    token_abi = json.load(f)

contract = web3.eth.contract(address=contract_address, abi=token_abi)
from_account = '0xf000000......'

# 调用合约函数
new_owner_address = '0x0......'
gasPrice = web3.eth.gas_price
nonce = web3.eth.get_transaction_count(from_account)

tx = {
    'from': from_account,
    'nonce': nonce,
    'gas': 50000,
    'gasPrice' : gasPrice,
    'chainId': 1
}

print(tx)

txn = contract.functions.transferOwnership(new_owner_address).build_transaction(tx)
# Sign transaction
signed_tx = web3.eth.account.sign_transaction(txn, private_key)
# Send transaction
tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)

print(web3.to_hex(tx_hash))
