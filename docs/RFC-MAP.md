# 规范对照表

MoonSign 的实现对照了下面这些公开规范。列出"哪条规范 → 哪个模块"，方便评审和后续维护。

| 规范 | 内容 | 对应模块 | 完成度 |
| --- | --- | --- | --- |
| RFC 5652 | Cryptographic Message Syntax (CMS) | `cms/` | SignedData 构造、解析、验签；detached 模式 |
| RFC 5035 | ESS signingCertificateV2 | `cms/build.mbt` | 已实现（SHA-256 证书指纹） |
| RFC 5280 | X.509 证书与 CRL | `x509/`、`trust/` | 解析、有效期、公钥、BasicConstraints、KeyUsage、路径构建、CRL；OCSP 见 `ocsp/` |
| RFC 6960 | OCSP | `ocsp/` | 响应解析、签名/有效期/证书匹配检查；联网获取响应待做 |
| RFC 8017 | PKCS#1 v1.5 / PSS | `crypto/` | v1.5 签名与验签（SHA-1/256/384/512） |
| RFC 6979 | 确定性 ECDSA | `crypto/` | 由 mooncry 提供（SHA-256） |
| ETSI EN 319 142-1 | PAdES 基线 | `pades/` | B-B；B-T（RFC 3161）；B-LT 待做 |
| ISO 32000-1 §12.8 | PDF 签名与 AcroForm | `pdf/` | 签名域、Widget、ByteRange、Contents |
| ISO 32000-2 §7.6.4 | 签名覆盖范围 | `pdf/` | ByteRange 回填与校验 |
| RFC 7468 | PEM 文本编码 | `pem/` | 私钥、证书；PKCS#8 / PKCS#1 / SEC1 |
| RFC 3161 | 时间戳 | `tsa/` | 请求生成、响应解析、B-T 嵌入、TSA 签名/EKU/证书链 |

## 已知偏差

- 采用"整篇重写"而不是增量更新（见 `DESIGN.md`），因此不能给已签名 PDF 追加第二个签名。
- CMS 只支持 SHA-256 / SHA-384 / SHA-512（RSA）与 SHA-256（ECDSA P-256）。
- 不支持 SHA-1 签名。
- 不支持加密 PDF。
- OCSP 与时间戳需要调用方自备响应文件，库本身不联网。
- 证书链、CRL、OCSP、TSA 链都已实现；B-LT 和"多签名追加"还没做。
