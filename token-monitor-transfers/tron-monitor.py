from tronpy import Tron
from tronpy.keys import PrivateKey
from decimal import Decimal
import time
import logging
from tronpy.providers import HTTPProvider

logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt='%Y-%m-%d %H:%M:%S %a'
                    )

provider = HTTPProvider(api_key='cc......')
client = Tron(provider=provider)

token_contract_address = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'

try:
    contract = client.get_contract(token_contract_address)
    token_decimals = contract.functions.decimals()
except Exception as e:
    logging.error(f"初始化合约或获取 decimals 出错: {e}")
    token_decimals = 6  # fallback 默认 USDT 是 6 位小数

# 获取余额函数（带异常处理）
def get_token_balance(address):
    try:
        balance_raw = contract.functions.balanceOf(address)
        balance = Decimal(balance_raw) / Decimal(10 ** token_decimals)
        return balance
    except Exception as e:
        logging.error(f"查询余额失败: {e}")
        return Decimal(0)

# 发送 TRC20 Token（带异常处理）
def transfer_token(private_key_hex, to, amount):
    try:
        priv_key = PrivateKey(bytes.fromhex(private_key_hex))
        from_addr = priv_key.public_key.to_base58check_address()
        amount_int = int(Decimal(str(amount)) * Decimal(10 ** token_decimals))

        txn = (
            contract.functions.transfer(to, amount_int)
            .with_owner(from_addr)
            .fee_limit(2_000_000)
            .build()
            .sign(priv_key)
        )
        result = txn.broadcast().wait()
        logging.info("USDT Transfer result: %s", result)
    except Exception as e:
        logging.error(f"转账失败: {e}")

# 主循环逻辑（包裹异常）
if __name__ == '__main__':
    private_key = 'a8......'
    recipient = 'TA......'
    try:
        sender = PrivateKey(bytes.fromhex(private_key)).public_key.to_base58check_address()
    except Exception as e:
        logging.error(f"私钥生成地址失败: {e}")
        exit(1)

    while True:
        try:
            balance = get_token_balance(sender)
            logging.info(f"当前余额: {balance} USDT")
            if balance > Decimal(100):
                transfer_token(private_key, recipient, balance)
                logging.info("USDT transfer: " + str(balance))
                time.sleep(50)
            else:
                logging.info("余额不足，15秒后重试...")
                time.sleep(15)
        except Exception as e:
            logging.error(f"主循环出错: {e}")
            time.sleep(15)
