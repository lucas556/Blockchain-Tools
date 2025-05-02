import os
from functools import reduce

def randomUInt32() -> int:
    # 生成一个随机的32位无符号整数
    return int.from_bytes(os.urandom(4), byteorder='little', signed=False)

def randomUInt32Array(count: int) -> list[int]:
    # 生成一个包含count个32位无符号整数的数组
    return [randomUInt32() for _ in range(count)]

def key_to_hex(k: list[int]) -> str:
    # 将32位无符号整数数组转换为十六进制字符串表示
    return reduce(lambda s, t: str(s) + t.to_bytes(4, byteorder='big').hex(), k[1:], k[0].to_bytes(4, byteorder='big').hex())

if __name__ == "__main__":
    # 生成包含8个32位无符号整数的私钥（256位）
    random_key_array = randomUInt32Array(8)
    
    # 将生成的随机数数组转换为十六进制私钥
    private_key_hex = key_to_hex(random_key_array)
    
    # 输出生成的私钥
    print(f"Generated Random Key (Private Key): {private_key_hex}")
