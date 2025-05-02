from tronapi import Tron
from tronapi import HttpProvider
import json

full_node = HttpProvider('https://api.trongrid.io')
solidity_node = HttpProvider('https://api.trongrid.io')
event_server = HttpProvider('https://api.trongrid.io')

tron = Tron(full_node=full_node,
            solidity_node=solidity_node,
            event_server=event_server)

with open('/Users/lucas/Desktop/tron-address.json','r') as f:
    account_info = json.load(f)

TRX_Address = account_info['Address']
TRX_Private = account_info['Private Key']

print(account_info['Address'])

get_account = tron.trx.get_account('TNtoKBvB49X5QRLH9X5EqmeevWESWzn5sV')

#print(get_account)
print(json.dumps(get_account, indent=2))
#tron.private_key = 'private_key'
#tron.default_address = 'default address'

# added message
#send = tron.trx.send_transaction('to', 1)

#print(send)