# 规范对照表

MoonSign 的实现对照了下面这些公开规范。列出"哪条规范 → 哪个模块"，方便评审和后续维护。

| 规范 | 内容 | 对应模块 | 完成度 |
| --- | --- | --- | --- |
| RFC 5652 | Cryptographic Message Syntax (CMS) | `cms/` | SignedData 构造、解析、验签；detached 模式 |
| RFC 5035 | ESS signingCertificateV2 | `cms/build.mbt` | 已实现（SHA-256 证书指纹） |
| RFC 5280 | X.509 证书与 CRL | `x509/`、`trust/` | 解析、有效期、公钥、BasicConstraints、KeyUsage、路径构建、CRL；OCSP 待做 |
| RFC 3161 | 时间戳协议 | `tsa/` | 请求生成、响应解析、B-T 嵌入；TSA 证书链待做 |
| RFC 8017 | PKCS#1 v1.5 / PSS | `crypto/` | v1.5 签名与验签（SHA-1/256/384/512） |
| RFC 6979 | 确定性 ECDSA | `crypto/` | 由 mooncry 提供（SHA-256） |
| ETSI EN 319 142-1 | PAdES 基线 | `pades/` | B-B；B-T / B-LT 待做 |
| ISO 32000-1 §12.8 | PDF 签名与 AcroForm | `pdf/` | 签名域、Widget、ByteRange、Contents |
| ISO 32000-2 §7.6.4 | 签名覆盖范围 | `pdf/` | ByteRange 回填与校验 |
| RFC 7468 | PEM 文本编码 | `pem/` | 私钥、证书；PKCS#8 / PKCS#1 / SEC1 |
| RFC 3161 | 时间戳 | `pades/`（规划） | 未实现 |
| RFC 6960 / 5280 | OCSP / CRL | `trust/`（规划） | 未实现 |

## 已知偏差

- 0.1 采用"整篇重写"而不是增量更新（见 `DESIGN.md` 的说明）。
- CMS 只支持 SHA-256 / SHA-384 / SHA-512（RSA）与 SHA-256（ECDSA P-256）。
- 不支持 SHA-1 签名（验签时也未开放，后续加开关）。
- 没有实现证书链校验和吊销检查，因此 `verify` 只回答"签名与证书是否匹配"，不回答"这张证书是否可信"。
