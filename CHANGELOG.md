# 更新日志

## 未发布

- `verify` 输出签名者姓名（证书 CN）和签名时间；JSON 增加 `signer`、`signing_time` 字段；

## 0.22.0（2026-11-17）

- 可见签名可以选择页码：`--page <n>`（从 1 开始）；
- 多页 PDF 上可以把签名框放到任意页；
- 71 个测试，CI 覆盖"三页 PDF 第 2 页签名"。

## 0.21.0（2026-11-16）

- DSS 增加 VRI（每个签名单独的验证材料索引）：
  - 用签名值的 SHA-1 十六进制作为键；
  - 每个 VRI 条目带 `/Cert`、`/CRL`、`/OCSP`；
  - 更接近 PAdES B-LT 的长期验证结构；
- CI 校验 DSS 里同时出现 `/DSS` 和 `/VRI`。

## 0.20.0（2026-11-16）

- `verify` 自动使用 PDF 中的 DSS：
  - DSS 里的中间证书用于补全证书链；
  - DSS 里的 CRL / OCSP 用于吊销检查；
  - 命令行参数仍可覆盖；
- CI 覆盖"只有叶子证书，靠 DSS 补全链"和"DSS 里的 CRL 判定吊销"。

## 0.19.0（2026-11-16）

- 支持填写已有的空白签名域：
  - `--field` 指定的名字在表单里已有空白 `/Sig` 字段时，直接填入；
  - 不会重复创建同名字段；
  - 与 pyHanko/Adobe 预制的签名表单更兼容；
- 70 个测试，CI 覆盖"填空白签名域 → 验签"。

## 0.18.0（2026-11-16）

- 新增 DSS（Document Security Store）嵌入：
  - `dss` 命令把证书、CRL、OCSP 响应写进 PDF；
  - 使用增量更新，不破坏已有签名；
  - 为 B-LT 长期验证提供材料；
- 69 个测试，CI 覆盖"DSS 嵌入后签名仍有效"。

## 0.17.0（2026-11-16）

- 支持加密 PDF 输入：`--pdf-password` 解密后签名，输出为解密后的 PDF；
- 错误密码会明确报错；
- `mkpdf --encrypt` 可生成加密测试 PDF；
- 68 个测试，CI 覆盖"加密 PDF 签名 → 验签"。

## 0.16.0（2026-11-15）

- 国密支持：
  - SM2 签名/验签（标准签名 ID，DER 编码），SM3 摘要；
  - PEM/PKCS#8 中的 SM2 私钥自动识别；
  - 用 SM2 密钥签名时自动使用 SM3，无需额外参数；
  - 证书链校验支持 SM2 证书签名；
- 67 个测试，CI 覆盖 SM2 签名/验签路径。

## 0.15.0（2026-11-15）

- 跨工具追加签名：对 pyHanko 签过的 PDF 追加 MoonSign 签名，两个签名都能验证，pyHanko 也确认原签名仍然完整；
- 追加时字段名自动避让（`Signature1` 已存在则用 `Signature2`）；
- CI 增加跨工具追加测试；
- 62 个测试。

## 0.14.0（2026-11-12）

- `verify` 默认验证 PDF 里的所有签名，逐个输出结果；
- `--signature <n>` 仍可只验证某一个；
- JSON 输出改为 `results` 数组（每个签名一项）；
- 62 个测试，CI 覆盖"一次验两个签名"。

## 0.13.0（2026-11-12）

- 支持给已签名 PDF 追加第二个签名：
  - 追加时使用增量更新，旧字节不变，旧签名仍然有效；
  - `sign` 自动检测已有签名并切换为追加模式；
  - `verify --signature <n>` 可指定验证第几个签名；
- 62 个测试，CI 签名两次并分别验签。

## 0.12.0（2026-11-12）

- 签名框自动显示证书姓名：
  - 新增 `x509.Certificate::common_name()`（支持 UTF8String / PrintableString / BMPString）；
  - `--visible` 默认文字为 `Digitally signed by <CN>`；
  - 非 ASCII 的 CN 回退为 `Digitally signed`（Helvetica 不含中文字形）；
- 61 个测试，CI 校验签名框里出现证书 CN。

## 0.11.0（2026-11-12）

- 可见签名外观：
  - `sign --visible` 在页面上画签名框；
  - `--rect x1,y1,x2,y2` 自定义位置；
  - `--appearance-text` 自定义第一行文字；
  - 外观使用 PDF Form XObject（Helvetica），不影响签名本身；
- 60 个测试，CI 覆盖可见签名路径。

## 0.10.0（2026-11-10）

- 新增 PKCS#12（.p12 / .pfx）支持：
  - PBES2 + PBKDF2（HMAC-SHA1/SHA256）+ AES-128/192/256-CBC；
  - 校验 MAC（SHA-1/SHA-256）；
  - `sign --p12 <file> --p12-password <pass>`；
  - 密码也可用 `MOONSIGN_P12_PASSWORD`；
- 58 个测试，CI 覆盖 PKCS#12 签名路径。

## 0.9.0（2026-11-10）

- 新增 `cmd/bench` 性能基准：生成 1 到 10,000 页 PDF，测签名/验签耗时；
- 新增 `pdf.paged_pdf`（生成多页空白 PDF）和 `mkpdf --pages N`；
- CI 增加 native 基准任务；
- 新增 `docs/PERFORMANCE.md`（含 CI 实测数据）。

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
