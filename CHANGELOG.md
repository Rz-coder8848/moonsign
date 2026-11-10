# 更新日志

## 0.8.0（2026-11-10）

- 新增 OCSP 支持：
  - 解析 OCSP 响应（成功/吊销/未知）；
  - 校验响应签名、有效期、证书匹配和 OCSPSigning EKU；
  - `verify --ocsp <response.der>`，被吊销时退出码 3；
- 53 个测试，CI 覆盖 good 与 revoked 两条路径。

## 0.7.0（2026-11-10）

- `verify` 会显示时间戳状态；`--tsa-anchors` 校验时间戳证书链；
- 证书链校验改用签名里的 `signingTime`（没有则用当前时间），避免证书到期后旧签名误报；
- 新增 `cms.signing_time` 与 `pades.verify_timestamp_at`；
- 50 个测试，CI 覆盖"带时间戳 PDF 的验证"。

## 0.6.0（2026-11-10）

- 时间戳增加信任校验：
  - 验证 TSA 对时间戳令牌的 CMS 签名；
  - 校验 TSA 证书的 timeStamping EKU；
  - `tsa-embed --anchors <tsa-ca.pem>` 校验证书链；
- 新增 EKU 解析；
- 50 个测试，CI 用 OpenSSL TSA 端到端验证信任路径。

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
