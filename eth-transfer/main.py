from web3 import Web3
from decimal import Decimal
import time

# 连接以太坊节点
w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/b72a1c135e1547629678850ce7caed27'))

def transfer(private_key, from_account, to, amount):
    gas_price = w3.eth.gas_price
    nonce = w3.eth.getTransactionCount(from_account)
    tx_params = {
        'nonce': nonce,
        'to': to,
        'value': w3.to_wei(amount, 'ether'),
        'gas': 21000,
        'gasPrice': gas_price,
        'chainId': 1  # 主网
    }
    # 签名交易并发送
    signed_txn = w3.eth.account.sign_transaction(tx_params, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    print(f'Transaction sent: {tx_hash.hex()}')

if __name__ == '__main__':
    sender_address = '0x0.......'
    sender_private_key = '0x0.......'

    recipient_address = '0xa......'

    while True:
        balance_eth = w3.from_wei(w3.eth.get_balance(sender_address), 'ether')
        transfer_amount = Decimal(balance_eth) - Decimal(0.1)
        # print(transfer_amount)
        if transfer_amount > 0.1:
            transfer(sender_private_key, sender_address, recipient_address, balance_eth)
            print("ETH transfer: " + str(balance_eth))
            time.sleep(15)
            print("Continue after 15s")
            continue
        else:
            print("NOW ETH balance: " + str(balance_eth))
            print("Insufficient funds, 3 second init...")
            time.sleep(3)
