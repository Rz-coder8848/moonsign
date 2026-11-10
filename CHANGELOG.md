# 更新日志

## 0.5.0（2026-11-10）

- 新增 RFC 3161 时间戳（PAdES B-T）：
  - `tsa-request` 从已签名 PDF 生成时间戳请求；
  - `tsa-embed` 校验并嵌入 TSA 响应；
  - 库 API `pades.sign_pdf_with_timestamp`（transport 回调）；
  - CI 用 OpenSSL TSA 做端到端验证；
- 49 个测试。

## 0.4.0（2026-11-10）

- 签名时可以写入签名说明：`--reason`、`--location`、`--contact`；
- 签名字典写入 `/M`（签署时间），可用 `--signing-time` 指定；
- `info` 增加 `byteRange` 输出（人和 JSON 都有）；
- 新增签名元数据测试。

## 0.3.0（2026-11-10）

- 支持 X.509 CRL：解析、校验 CRL 签名、检查证书是否被吊销；
- `verify --crl <crl.pem>`：被吊销时返回 `VALID but NOT TRUSTED`（退出码 3）；
- 新增 CRL 测试与 CI 吊销路径。

## 0.2.0（2026-11-10）

- 新增证书链校验：`verify --anchors <ca.pem>`；
- 检查 BasicConstraints、KeyUsage、pathLen、有效期、签名链；
- 结论分三档：`VALID and TRUSTED` / `VALID but NOT TRUSTED` / `INVALID`；
- `sign --chain` 可嵌入中间证书；
- 新增可运行示例 `examples/sign-and-verify/run.sh`。

## 0.1.0（2026-11-04）

- 首个版本：DER/ASN.1、X.509 解析、CMS SignedData、PDF 签名与验签；
- CLI：`sign` / `verify` / `info`；
- RSA PKCS#1 v1.5 与 ECDSA P-256（SHA-256）；
- 与 OpenSSL、pyHanko 双向互操作。
