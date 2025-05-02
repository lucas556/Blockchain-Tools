import base58

def tron_to_eth(tron_address):
    # 解码 Base58 编码的 TRON 地址
    decoded = base58.b58decode_check(tron_address)
    
    # 移除前缀 0x41 (即 TRON 主网标识)
    eth_address = decoded[1:].hex()
    
    # 添加以太坊地址前缀 0x
    return '0x' + eth_address

tron_address = 'TJ......'
eth_address = tron_to_eth(tron_address)
print('Ethereum Address:', eth_address)
