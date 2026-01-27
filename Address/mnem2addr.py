#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
mnem2addr.py

用途:
  - 从 BIP39 助记词（可选 passphrase）派生 BIP32 私钥，并生成 ETH / TRON 地址
  - 支持批量派生路径 m/44'/60'/0'/0/i (ETH) 与 m/44'/195'/0'/0/i (TRON)
  - 支持随机生成助记词（12/15/18/21/24 词或 128/160/192/224/256 bits）
  - 支持随机生成 secp256k1 私钥并直接生成对应地址（不走助记词派生）

注意:
  - 本脚本会在终端输出 privkey(hex)。请勿把输出粘贴到日志/聊天/工单等不安全位置。
  - --gen-privkey 模式下不会使用 --passphrase（会提示已忽略）。
  - --mnemonic 输入会在 mnemonic2derive() 内进行 BIP39 合法性校验（checksum/词表）。

依赖:
  pip install cryptography coincurve pycryptodomex base58 mnemonic

示例:
  # 同时输出 ETH+TRON（默认）
  python3 mnem2addr_eth_tron.py --mnemonic "word1 ... word12" --count 3

  # 只输出 ETH
  python3 mnem2addr_eth_tron.py --mnemonic "..." --coin eth --start 0 --count 5

  # 随机生成 12 词助记词（不带参数默认 12）
  python3 mnem2addr_eth_tron.py --gen-mnemonic

  # 随机生成私钥并输出地址
  python3 mnem2addr_eth_tron.py --gen-privkey
"""

import argparse
import secrets
import struct
from typing import Dict, Any, List, Tuple

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from coincurve import PublicKey  # pip install coincurve
from Cryptodome.Hash import keccak  # pip install pycryptodomex
import base58  # pip install base58
from mnemonic import Mnemonic  # pip install mnemonic


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HARDENED = 0x80000000


# -------------------- helpers --------------------
def normalize_mnemonic(m: str) -> str:
    # normalize whitespace: "  a  b   c " -> "a b c"
    return " ".join((m or "").strip().split())


def validate_mnemonic(mnemonic: str, lang: str = "english") -> str:
    """
    Returns normalized mnemonic if valid, otherwise raises ValueError.
    """
    m = normalize_mnemonic(mnemonic)
    if not m:
        raise ValueError("Empty mnemonic")

    mn = Mnemonic(lang)

    # Basic word count check
    wc = len(m.split())
    if wc not in (12, 15, 18, 21, 24):
        raise ValueError(f"Invalid mnemonic word count: {wc} (must be 12/15/18/21/24)")

    if not mn.check(m):
        raise ValueError("Invalid BIP39 mnemonic checksum / words (mnemonic.check() failed)")

    return m


def parse_path(path_str: str) -> List[int]:
    """
    Parse "m/44'/60'/0'/0/0" or "44'/..." into a list of uint32 indices with hardened bit applied.
    """
    path_str = (path_str or "").strip()
    if path_str.startswith(("m/", "M/")):
        path_str = path_str[2:]
    if path_str == "":
        return []

    out: List[int] = []
    for part in path_str.split("/"):
        part = part.strip()
        if not part:
            continue

        hardened = part.endswith("'")
        num_str = part[:-1] if hardened else part

        idx = int(num_str)
        if idx < 0 or idx >= HARDENED:
            raise ValueError(f"Invalid path index: {part} (must be 0 <= idx < 2^31)")

        out.append(idx + HARDENED if hardened else idx)

    return out


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def priv2pubkeys(priv32: bytes) -> Dict[str, bytes]:
    pk = PublicKey.from_secret(priv32)
    return {
        "uncompressed": pk.format(compressed=False),  # 65B 0x04+X+Y
        "compressed": pk.format(compressed=True),     # 33B 0x02/0x03+X
    }


def uncompressed2addr(coin: str, pub65: bytes) -> str:
    """
    coin: "eth" or "tron"
    pub65: 65B, 0x04 + X32 + Y32

    ETH:  0x + keccak256(pub_xy)[-20:]
    TRON: Base58Check( 0x41 + keccak256(pub_xy)[-20:] )
    """
    coin = coin.lower()
    if len(pub65) != 65 or pub65[0] != 0x04:
        raise ValueError("pub65 must be 65 bytes uncompressed starting with 0x04")

    h20 = keccak256(pub65[1:])[-20:]

    if coin == "eth":
        return "0x" + h20.hex()
    if coin == "tron":
        raw = b"\x41" + h20
        return base58.b58encode_check(raw).decode("ascii")

    raise ValueError(f"Unsupported coin: {coin}")


def coin_path(coin: str, i: int) -> str:
    coin = coin.lower()
    if coin == "tron":
        return f"m/44'/195'/0'/0/{i}"
    if coin == "eth":
        return f"m/44'/60'/0'/0/{i}"
    raise ValueError(f"Unsupported coin: {coin}")


def rand_privkey32() -> bytes:
    """
    Generate a valid secp256k1 private key in [1, n-1].
    """
    while True:
        b = secrets.token_bytes(32)
        x = int.from_bytes(b, "big")
        if 1 <= x < SECP256K1_N:
            return b


# -------------------- BIP39 --------------------
def mnemonic2seed(mnemonic_str: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + (passphrase or "")).encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=2048,
    )
    return kdf.derive(mnemonic_str.encode("utf-8"))


# -------------------- BIP32 CKDpriv --------------------
def bip32_derive(parent_key: bytes, parent_chain_code: bytes, index: int):
    n = SECP256K1_N

    is_hardened = index >= HARDENED
    if is_hardened:
        data = b"\x00" + parent_key + struct.pack(">I", index)
    else:
        pub = PublicKey.from_secret(parent_key).format(compressed=True)
        data = pub + struct.pack(">I", index)

    hh = hmac.HMAC(parent_chain_code, hashes.SHA512())
    hh.update(data)
    i_64 = hh.finalize()

    IL = int.from_bytes(i_64[:32], "big")
    if IL == 0 or IL >= n:
        return None

    kpar = int.from_bytes(parent_key, "big")
    child = (IL + kpar) % n
    if child == 0:
        return None

    return child.to_bytes(32, "big"), i_64[32:]


# -------------------- master + derive --------------------
def seed2master(seed: bytes) -> Tuple[bytes, bytes]:
    hh = hmac.HMAC(b"Bitcoin seed", hashes.SHA512())
    hh.update(seed)
    m_data = hh.finalize()
    m_priv, m_chain = m_data[:32], m_data[32:]

    IL = int.from_bytes(m_priv, "big")
    if IL == 0 or IL >= SECP256K1_N:
        raise ValueError("Invalid BIP32 master key (IL==0 or IL>=n)")

    return m_priv, m_chain


def master2privkey(master_priv: bytes, master_chain: bytes, path_str: str) -> bytes:
    curr_priv, curr_chain = master_priv, master_chain
    for index in parse_path(path_str):
        derived = bip32_derive(curr_priv, curr_chain, index)
        if derived is None:
            raise ValueError(f"Invalid BIP32 derivation at index {index} (IL>=n or child==0)")
        curr_priv, curr_chain = derived
    return curr_priv


# -------------------- outputs --------------------
def mnemonic2derive(
    mnemonic: str,
    passphrase: str,
    coins: List[str],
    start_index: int,
    count: int,
    lang: str = "english",
) -> List[Dict[str, Any]]:
    # only validate here (CLI won't duplicate)
    mnemonic = validate_mnemonic(mnemonic, lang)

    seed = mnemonic2seed(mnemonic, passphrase)
    master_priv, master_chain = seed2master(seed)

    out: List[Dict[str, Any]] = []
    for i in range(start_index, start_index + count):
        if i < 0 or i >= HARDENED:
            raise ValueError(f"Invalid address index i={i} (must be 0 <= i < 2^31)")
        for coin in coins:
            path = coin_path(coin, i)
            priv = master2privkey(master_priv, master_chain, path)
            pubs = priv2pubkeys(priv)
            addr = uncompressed2addr(coin, pubs["uncompressed"])
            out.append(
                {
                    "mode": "mnemonic",
                    "coin": coin,
                    "i": i,
                    "path": path,
                    "priv_hex": priv.hex(),
                    "pub65_hex": pubs["uncompressed"].hex(),
                    "pub33_hex": pubs["compressed"].hex(),
                    "address": addr,
                }
            )
    return out


def priv2addrs(priv32: bytes, coins: List[str]) -> List[Dict[str, Any]]:
    pubs = priv2pubkeys(priv32)
    out: List[Dict[str, Any]] = []
    for coin in coins:
        out.append(
            {
                "mode": "privkey",
                "coin": coin,
                "priv_hex": priv32.hex(),
                "pub65_hex": pubs["uncompressed"].hex(),
                "pub33_hex": pubs["compressed"].hex(),
                "address": uncompressed2addr(coin, pubs["uncompressed"]),
            }
        )
    return out


# -------------------- CLI --------------------
def main():
    ap = argparse.ArgumentParser(
        description="BIP39/BIP32 derive ETH/TRON addresses, with mnemonic validation and optional random generation."
    )

    src = ap.add_mutually_exclusive_group(required=False)
    src.add_argument("--mnemonic", help="BIP39 mnemonic words (quoted string)")
    src.add_argument(
        "--gen-mnemonic",
        type=int,
        nargs="?",
        const=12,  # no-arg => default 12 words
        help="Generate random mnemonic. Accepts words(12/15/18/21/24) or strength bits(128/160/192/224/256). Default: 12 words.",
    )
    src.add_argument("--gen-privkey", action="store_true", help="Generate random secp256k1 private key (32B)")

    ap.add_argument("--passphrase", default="", help="BIP39 passphrase (optional, used only with mnemonic modes)")
    ap.add_argument(
        "--coin",
        choices=["eth", "tron", "both"],
        default="both",
        help='Which coin address to output: "eth", "tron", or "both" (default: both)',
    )
    ap.add_argument("--start", type=int, default=0, help="Start index i for mnemonic derivation (default: 0)")
    ap.add_argument("--count", type=int, default=5, help="How many indices for mnemonic derivation (default: 5)")
    ap.add_argument("--lang", default="english", help="BIP39 wordlist language for validation/generation (default: english)")

    args = ap.parse_args()

    coins = ["eth", "tron"] if args.coin == "both" else [args.coin]

    # Guardrails
    if args.start < 0:
        raise SystemExit("--start must be >= 0")
    if args.count <= 0:
        raise SystemExit("--count must be > 0")

    results: List[Dict[str, Any]] = []

    # --- mode selection ---
    if args.gen_privkey:
        if args.passphrase:
            print("[!] Note: --passphrase is ignored when using --gen-privkey")
        priv = rand_privkey32()
        results = priv2addrs(priv, coins)

    elif args.gen_mnemonic is not None:
        val = int(args.gen_mnemonic)  # could be words or strength bits

        words_to_strength = {12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
        allowed_strengths = {128, 160, 192, 224, 256}

        if val in words_to_strength:
            strength = words_to_strength[val]
        elif val in allowed_strengths:
            strength = val
        else:
            raise SystemExit(
                "--gen-mnemonic must be one of words: 12,15,18,21,24 "
                "or strength bits: 128,160,192,224,256"
            )

        mn = Mnemonic(args.lang)
        mnemonic = mn.generate(strength=strength)

        print("Generated mnemonic:", mnemonic)
        print("-" * 80)

        results = mnemonic2derive(
            mnemonic=mnemonic,
            passphrase=args.passphrase,
            coins=coins,
            start_index=args.start,
            count=args.count,
            lang=args.lang,
        )

    else:
        if not args.mnemonic:
            raise SystemExit("Provide --mnemonic, or use --gen-mnemonic / --gen-privkey")

        # No duplicate validation here; mnemonic2derive() will validate.
        results = mnemonic2derive(
            mnemonic=args.mnemonic,
            passphrase=args.passphrase,
            coins=coins,
            start_index=args.start,
            count=args.count,
            lang=args.lang,
        )

    # --- print ---
    for r in results:
        print("=" * 80)
        print("mode       :", r["mode"])
        print("coin       :", r["coin"])

        if r["mode"] == "mnemonic":
            print("index      :", r["i"])
            print("path       :", r["path"])

        print("priv (hex) :", r["priv_hex"])
        print("pub65(hex) :", r["pub65_hex"])
        print("pub33(hex) :", r["pub33_hex"])
        print("address    :", r["address"])


if __name__ == "__main__":
    main()
