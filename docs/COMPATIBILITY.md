# 兼容性矩阵

## 签名算法

| 算法 | 摘要 | 签名 | 验签 | 备注 |
| --- | --- | --- | --- | --- |
| RSA PKCS#1 v1.5 | SHA-256 | ✅ | ✅ | 默认 |
| RSA PKCS#1 v1.5 | SHA-384 / SHA-512 | ✅ | ✅ | 库 API 可用，CLI 暂固定 SHA-256 |
| RSA PKCS#1 v1.5 | SHA-1 | ❌ | ❌ | 不支持（安全原因） |
| ECDSA P-256 | SHA-256 | ✅ | ✅ | 确定性签名（RFC 6979） |
| ECDSA P-256 | SHA-384 / SHA-512 | ❌ | ❌ | mooncry 目前只有 SHA-256 版本 |
| SM2 / SM3 | SM3 | 规划 | 规划 | 0.2 之后 |

## PDF 特性

| 特性 | 状态 |
| --- | --- |
| 无 AcroForm 的普通 PDF | ✅ 自动创建 |
| 已有 AcroForm 的 PDF | ✅ 追加字段 |
| 带已有签名的 PDF | ❌ 暂不支持追加（会用新文件覆盖旧签名） |
| 加密 PDF | ❌ 明确拒绝 |
| 线性化 PDF | ✅ 重写后正常 |
| 多页 PDF | ✅ 签名放在第一页 |
| 可见签名外观 | ✅ `--visible`（Form XObject + Helvetica） |

## 证书链

| 检查 | 状态 |
| --- | --- |
| 签名者证书链到指定信任根 | ✅ `--anchors` |
| BasicConstraints（CA、pathLen） | ✅ |
| KeyUsage（keyCertSign） | ✅ |
| 证书有效期 | ✅ |
| CRL 吊销检查 | ✅ `--crl`（校验 CRL 签名与有效期） |
| OCSP 吊销检查 | ✅ `--ocsp`（校验响应签名、有效期、OCSPSigning EKU） |
| AIA 自动下载中间证书 | ❌ |

## 时间戳

| 能力 | 状态 |
| --- | --- |
| RFC 3161 请求生成 | ✅ `tsa-request` |
| 响应解析与 imprint 校验 | ✅ |
| 写入 unsignedAttrs（B-T） | ✅ `tsa-embed` |
| TSA 证书链校验 | ✅ `tsa-embed --anchors`（含 timeStamping EKU） |
| 直接联网调用 TSA | ❌（用 curl 等工具发送请求） |

## PKCS#12

| 加密方式 | 状态 |
| --- | --- |
| PBES2 + PBKDF2（SHA-1/SHA-256）+ AES-128/192/256-CBC | ✅ |
| MAC：SHA-1 / SHA-256 | ✅ |
| 旧式 RC2 / 3DES | ❌（明确报错） |

## 验证器

| 验证器 | 版本 | 结果 | 方式 |
| --- | --- | --- | --- |
| OpenSSL | 3.0.18 / 3.5.7 | ✅ | `openssl cms -verify`（CI 每次跑） |
| pyHanko | 最新版 | ✅ | 双向：它验我们的签名 + 我们验它的签名（CI 每次跑） |
| Adobe Acrobat | 待人工 | ⏳ | 发布前人工确认一次 |
| 福昕 / WPS | 待人工 | ⏳ | 发布前人工确认一次 |

> "OpenSSL 通过"的含义：MoonSign 生成的 CMS，以及它覆盖的 PDF 字节，能被一个独立的、成熟的密码学工具验证通过。这比"自己验自己"更有说服力。

## 命令行

| 命令 | 状态 |
| --- | --- |
| `moonsign sign` | ✅ |
| `moonsign verify` | ✅ 签名校验；带 `--anchors` 时额外做证书链（退出码 3 = 有效但不可信） |
| `moonsign info` | ✅ |
| `--json` | ✅（sign / verify / info 的基础字段） |

## 平台

| 平台 | 测试 |
| --- | --- |
| Linux x86_64 | ✅ CI |
| macOS (arm64) | ✅ CI |
| Windows x86_64 | ✅ CI |
| wasm-gc | ✅ CI（核心库） |
