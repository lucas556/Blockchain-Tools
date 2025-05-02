import nayuki_crypto

class MnemonicValidator:
    def __init__(self, wordlist_path="english.txt"):
        self.wordlist = self._load_wordlist(wordlist_path)

    def _load_wordlist(self, path) -> list:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.readlines() if line.strip()]

    def is_valid(self, mnemonic: str) -> bool:
        words = mnemonic.strip().split()
        if len(words) not in [12, 15, 18, 21, 24] or len(set(words)) != len(words):
            return False
        try:
            indices = [self.wordlist.index(w) for w in words]
        except ValueError:
            return False
        bit_str = ''.join(f"{index:011b}" for index in indices)
        entropy_length = len(bit_str) - len(bit_str) // 33
        entropy_bits = bit_str[:entropy_length]
        checksum_bits = bit_str[entropy_length:]
        entropy_bytes = int(entropy_bits, 2).to_bytes(entropy_length // 8, byteorder="big")
        hash_bytes = nayuki_crypto.sha256(entropy_bytes)
        hash_bits = bin(int.from_bytes(hash_bytes, "big"))[2:].zfill(256)
        expected_checksum = hash_bits[:len(checksum_bits)]
        return checksum_bits == expected_checksum
