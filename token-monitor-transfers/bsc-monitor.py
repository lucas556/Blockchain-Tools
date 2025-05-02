# ETH USDT-TOKEN transfer
from decimal import Decimal
from web3 import Web3
import time
import json
import logging

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt = '%Y-%m-%d  %H:%M:%S %a'
                    )

infura = 'https://mainnet.infura.io/v3/00000......'
web3 = Web3(Web3.HTTPProvider(infura))
token_contract_address = '0xdAC17F958D2ee523a2206206994597C13D831ec7'

with open("usdt.json") as f:
    token_abi = json.load(f)

token = web3.eth.contract(address=token_contract_address, abi=token_abi)

def transfer_token(private_key, from_account, to, amount):
    gasPrice = web3.eth.gas_price
    nonce = web3.eth.get_transaction_count(from_account)
    print(nonce)
    tx = {
        'nonce': nonce,
        'value': 0,
        'gas': 0,
        'gasPrice': gasPrice,
        'chainId': 1
    }
    gas = web3.eth.estimate_gas(tx)
    tx.update({'gas': gas})
    transfer_value = int(Decimal(amount) * Decimal(10 ** token_decimals))
    txn = token.functions.transfer(to, transfer_value).build_transaction(tx)
    signed_tx = web3.eth.account.sign_transaction(txn, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    logging.info("tx_hash:",web3.to_hex(tx_hash))

# 查询代币的decimals
token_decimals = token.functions.decimals().call()

# 查询余额，转换成Decimal
def get_token_balance(address):
    balance_raw = token.functions.balanceOf(address).call()
    balance = Decimal(balance_raw) / Decimal(10 ** token_decimals)
    return balance

if __name__ == '__main__':
    private_key = '0x00000......'
    recipient = '0x00000......'
    sender = web3.eth.account.from_key(private_key).address
    # from account : 0x0......
    while True:
        transfer_amount = get_token_balance(sender)
        logging.info(transfer_amount)
        if transfer_amount > Decimal(10):
            transfer_token(private_key, sender, recipient, transfer_amount)
            logging.info("USDT transfer: " + str(transfer_amount))
            time.sleep(60)
            logging.info("Continue after 60s")
            continue
        else:
            logging.info("NOW USDT balance: " + str(transfer_amount))
            logging.info("Insufficient funds, 30 second init...")
            time.sleep(30)
