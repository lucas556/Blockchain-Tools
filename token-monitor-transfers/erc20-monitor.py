## 使用eth_getLogs监控收款
import aiohttp, asyncio, orjson, logging
from logging.handlers import TimedRotatingFileHandler
from decimal import Decimal, getcontext
from web3 import Web3

# ========== 常量配置 ==========
INFURA_URL = "https://mainnet.infura.io/v3/8......"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
CONTRACT_ADDRESS = "0x......"
WATCH_ADDRESS = "0xa......"
PRIVATE_KEY = "<your_private_key_here>"
RECIPIENT_ADDRESS = "<recipient_address_here>"
DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 aiohttp-client"}

# ========== 全局 JSON-RPC 模板 ==========
BLOCK_NUMBER_REQUEST = {
    "jsonrpc": "2.0",
    "method": "eth_blockNumber",
    "params": [],
    "id": 1
}

LOGS_REQUEST_TEMPLATE = lambda contract, block_hex: {
    "jsonrpc": "2.0",
    "method": "eth_getLogs",
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
    'value': 0,
    'gasPrice': gas_price,
    'chainId': 1
}

# ========== ABI ==========
ERC20_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_from", "type": "address"},
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"}
        ],
        "name": "transferFrom",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    }
]

getcontext().prec = 28  # 精度提升，避免浮点误差

# ========== 通用请求函数 ==========
async def request_handle(session, url, method="POST", json=None, data=None, headers=None, retries=3, timeout=10, verify_ssl=True):
    headers = headers or DEFAULT_HEADERS
    for attempt in range(1, retries + 1):
        try:
            async with session.request(method, url, json=json, data=data, headers=headers, timeout=timeout, ssl=verify_ssl) as r:
                content = await r.read()
                if 200 <= r.status < 300:
                    try:
                        return orjson.loads(content)
                    except orjson.JSONDecodeError:
                        logging.warning(f"[{attempt}] JSON decode failed: {url}")
                        return None
                else:
                    logging.error(f"[{attempt}] HTTP {r.status}: {await r.text()} | {url}")
        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            logging.warning(f"[{attempt}] Request error: {e}")
        await asyncio.sleep(min(2 ** attempt, 10))
    raise Exception(f"Request failed after {retries} attempts: {url}")

# ========== 通用转账方法 ==========
def send_erc20_transaction(web3, token_contract, private_key, from_account, to_address, amount, token_decimals, method="transfer", from_address=None):
    try:
        nonce = web3.eth.get_transaction_count(from_account)
        gas_price = web3.eth.gas_price
        value = int(Decimal(amount) * Decimal(10 ** token_decimals))

        if method == "transferFrom" and from_address:
            tx = token_contract.functions.transferFrom(from_address, to_address, value).build_transaction(
                TX_BASE_TEMPLATE(nonce, gas_price)
            )
        else:
            tx = token_contract.functions.transfer(to_address, value).build_transaction(
                TX_BASE_TEMPLATE(nonce, gas_price)
            )

        tx['gas'] = web3.eth.estimate_gas(tx)
        signed_tx = web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        logging.info(f"{method} sent, tx_hash: {web3.to_hex(tx_hash)}")
    except Exception as e:
        logging.error(f"Error during {method}: {e}")

# ========== 主监听类 ==========
class TokenMonitor:
    def __init__(self, contract_address, watch_address=None):
        self.web3 = Web3(Web3.HTTPProvider(INFURA_URL))
        self.contract_address = contract_address.casefold()
        self.watch_address = watch_address.casefold() if watch_address else None
        self.token_contract = self.web3.eth.contract(address=self.web3.to_checksum_address(contract_address), abi=ERC20_ABI)
        self.from_account = self.web3.eth.account.from_key(PRIVATE_KEY).address

    async def get_contract_transfers(self, session, block_hex, block_num):
        try:
            logs = await request_handle(session, INFURA_URL, json=LOGS_REQUEST_TEMPLATE(self.contract_address, block_hex), verify_ssl=False)
            if not logs or not isinstance(logs.get("result"), list):
                logging.warning(f"无效日志响应: {logs}")
                return

            for log in logs.get("result"):
                from_addr = "0x" + log['topics'][1][-40:].casefold()
                to_addr = "0x" + log['topics'][2][-40:].casefold()
                if self.watch_address and to_addr != self.watch_address:
                    continue
                value = Decimal(int(log['data'], 16)) / Decimal(10 ** DECIMALS)
                if value > VALUE_THRESHOLD:
                    logging.info(f"区块 {block_num} | 💸 {value:.2f} {SYMBOL} from {from_addr} → {to_addr}")
                    send_erc20_transaction(self.web3, self.token_contract, PRIVATE_KEY, self.from_account, Web3.to_checksum_address(RECIPIENT_ADDRESS), value, DECIMALS)
        except Exception as e:
            logging.error(f"处理区块 {block_num} 出错: {e}")


# ========== 主循环 ==========
async def main_loop(interval=3):
    monitor = TokenMonitor(CONTRACT_ADDRESS, watch_address=WATCH_ADDRESS)
    last_block = None
    async with aiohttp.ClientSession() as session:
        while True:
            try:
                latest_block = await request_handle(session, INFURA_URL, json=BLOCK_NUMBER_REQUEST, verify_ssl=False)
                block_num = int(latest_block["result"], 16)
                if last_block is None:
                    last_block = block_num - 1

                for bn in range(last_block + 1, block_num + 1):
                    logging.info(f"⏳ 正在处理区块: {bn}")
                    await monitor.get_contract_transfers(session, hex(bn), bn)
                last_block = block_num
            except Exception as e:
                logging.error(f"主循环出错: {e}")
            await asyncio.sleep(interval)


# ========== 日志配置与启动 ==========
if __name__ == "__main__":
    file_handler = TimedRotatingFileHandler("monitor.log", when="midnight", backupCount=7, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))

    logging.basicConfig(level=logging.INFO, handlers=[file_handler, console_handler])
    asyncio.run(main_loop())
