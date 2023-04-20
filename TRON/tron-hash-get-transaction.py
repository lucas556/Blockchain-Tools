import requests
import json

# TronGrid API URL
url = 'https://api.trongrid.io/v1/accounts/{address}/transactions/trc20'

# Tron 地址
address = 'TF......'

# 交易哈希 不加0x,否则无法解析
tx_hash = 'f2......'

# 发送请求
response = requests.get(url.format(address=address))

# 将响应解析为 JSON 对象
data = json.loads(response.text)
print(data)
# 从响应数据中获取交易信息数组
tx_list = data['data']

# 查找与交易哈希匹配的交易
tx = next((item for item in tx_list if item['transaction_id'] == tx_hash), None)

if tx:
    # 打印交易信息
    print('交易哈希：', tx['transaction_id'])
    print('发送方地址：', tx['from'])
    print('接收方地址：', tx['to'])
    print('交易金额：', tx['value'])
else:
    print('找不到与指定哈希匹配的交易')
