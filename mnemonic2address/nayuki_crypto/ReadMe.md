## 安装pybind 
```python
pip3 install pybind
```

## 下载 Bitcoin-Cryptography-Library 和 nayuki_crypto
```shell
https://github.com/nayuki/Bitcoin-Cryptography-Library.git
cd Bitcoin-Cryptography-Library/cpp
cp ../nayuki_crypto/binding.cpp ./
cp ../nayuki_crypto/CMakeLists.txt ./
```

## 编译

```shell
mkdir -p build && cd build
cmake ..
make -j
```

## 测试
```
import nayuki_crypto
print(nayuki_crypto.keccak256(b"hello world").hex())
```
