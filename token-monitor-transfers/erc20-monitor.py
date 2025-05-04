import aiohttp, asyncio, orjson, logging
from logging.handlers import TimedRotatingFileHandler
from decimal import Decimal, getcontext
from web3 import Web3
import time

# ========== 常量配置 ==========
INFURA_URL = "https://mainnet.infura.io/v3/8......"
VALUE_THRESHOLD = Decimal("100")
CONTRACT_ADDRESS = "0x......"
WATCH_ADDRESS = "0x......"
PRIVATE_KEY = "<your_private_key_here>"
RECIPIENT_ADDRESS = "<recipient_address_here>"
DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 aiohttp-client"}

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
# ========== Web3 初始化 ==========
web3 = Web3(Web3.HTTPProvider(INFURA_URL))
token_contract = web3.eth.contract(
    address=web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=[
        {
            "constant": False,
            "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
            "name": "transfer",
            "outputs": [{"name": "", "type": "bool"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "symbol",
            "outputs": [{"name": "", "type": "string"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "decimals",
            "outputs": [{"name": "", "type": "uint8"}],
            "type": "function"
        }
    ]
)

# ========== 获取合约元信息 ==========
try:
    SYMBOL = token_contract.functions.symbol().call()
except Exception:
    SYMBOL = "TOKEN"
    logging.warning(f"获取 symbol() 失败 {e}，使用默认 TOKEN")

try:
    DECIMALS = token_contract.functions.decimals().call()
except Exception:
    DECIMALS = 6
    logging.warning(f"获取 decimals() 失败 {e}，使用默认 6")

# ========== JSON-RPC 模板 ==========
BLOCK_NUMBER_REQUEST = {
    "jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1
}

LOGS_REQUEST_TEMPLATE = lambda contract, block_hex: {
    "jsonrpc": "2.0", "method": "eth_getLogs",
    "params": [{
        "fromBlock": block_hex,
        "toBlock": block_hex,
        "address": contract,
        "topics": [TRANSFER_TOPIC]
    }],
    "id": 2
}

TX_BASE_TEMPLATE = lambda nonce, gas_price: {
    'nonce': nonce,
    'gasPrice': gas_price,
    'value': 0,
    'chainId': 1
}

getcontext().prec = 28

# ========== 通用请求 ==========
async def request_handle(session, url, json=None, retries=3):
    for attempt in range(1, retries + 1):
        try:
            async with session.post(url, json=json, headers=DEFAULT_HEADERS, ssl=False) as resp:
                if 200 <= resp.status < 300:
                    return orjson.loads(await resp.read())
                else:
                    logging.warning(f"HTTP {resp.status} - {await resp.text()}")
        except Exception as e:
            logging.warning(f"Request attempt {attempt} failed: {e}")
        await asyncio.sleep(2 ** attempt)
    raise Exception(f"请求失败: {url}")

# ========== 转账方法（含重试、估算 gas、nonce） ==========
def send_token(to_address: str, amount: Decimal):
    try:
        to_checksum = web3.to_checksum_address(to_address)
        sender = web3.eth.account.from_key(PRIVATE_KEY)
        nonce = web3.eth.get_transaction_count(sender.address)
        gas_price = web3.eth.gas_price

        value = int(amount * Decimal(10 ** DECIMALS))
        tx = token_contract.functions.transfer(to_checksum, value).build_transaction(
            TX_BASE_TEMPLATE(nonce, gas_price)
        )

        tx['gas'] = int(web3.eth.estimate_gas(tx) * 1.2)  # 加 buffer
        signed = web3.eth.account.sign_transaction(tx, PRIVATE_KEY)

        for attempt in range(1, 4):
            try:
                tx_hash = web3.eth.send_raw_transaction(signed.rawTransaction)
                logging.info(f"转账成功: {web3.to_hex(tx_hash)}")
                return
            except Exception as e:
                logging.warning(f"第 {attempt} 次发送失败: {e}")
                time.sleep(1)
    except Exception as e:
        logging.error(f"转账异常: {e}")

# ========== Token 监听器 ==========
class TokenMonitor:
    def __init__(self, contract, watch_addr=None):
        self.contract = contract.casefold()
        self.watch_addr = watch_addr.casefold() if watch_addr else None

    async def handle_block(self, session, block_hex, block_number):
        logs = await request_handle(session, INFURA_URL, json=LOGS_REQUEST_TEMPLATE(self.contract, block_hex))
        if not logs or not isinstance(logs.get("result"), list):
            logging.warning(f"无效日志响应: {logs}")
            return

        for log in logs["result"]:
            from_addr = "0x" + log['topics'][1][-40:].casefold()
            to_addr = "0x" + log['topics'][2][-40:].casefold()
            if self.watch_addr and to_addr != self.watch_addr:
                continue
            value = Decimal(int(log['data'], 16)) / Decimal(10 ** DECIMALS)
            if value > VALUE_THRESHOLD:
                logging.info(f"区块 {block_number} | {value:.2f} {SYMBOL} from {from_addr} → {to_addr}")
                send_token(RECIPIENT_ADDRESS, value)

# ========== 主循环 ==========
async def main_loop():
    monitor = TokenMonitor(CONTRACT_ADDRESS, WATCH_ADDRESS)
    last_block = None
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                resp = await request_handle(session, INFURA_URL, json=BLOCK_NUMBER_REQUEST)
                block_num = int(resp["result"], 16)
                if last_block is None:
                    last_block = block_num - 1
                for bn in range(last_block + 1, block_num + 1):
                    logging.info(f"扫描区块 {bn}")
                    await monitor.handle_block(session, hex(bn), bn)
                last_block = block_num
            except Exception as e:
                logging.error(f"主循环错误: {e}")
            await asyncio.sleep(3)

# ========== 日志配置与启动 ==========
if __name__ == "__main__":
    handler = TimedRotatingFileHandler("monitor.log", when="midnight", backupCount=7, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler, logging.StreamHandler()])
    asyncio.run(main_loop())
