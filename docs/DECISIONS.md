# 关键技术决策

本文件记录 Phase 0 的依赖调研结论，以及由此确定的实现选择。每一条都要有可复核的依据（源码位置或验证结果）。

## D1. PDF 引擎：`moonbitlang/pdflite@0.4.1`

- 许可证 Apache-2.0；官方维护；README 明确支持"incremental updates"。
- 关键 API（来自 `pkg.generated.mbti`）：
  - `pdf_read_document_from_bytes(Bytes) -> PdfDocument raise PdfError`
  - `pdf_write_document_incremental_update(Bytes, PdfDocument) -> Bytes raise PdfError`
  - `pdf_write_document_incremental_update_with_xref_stream(...)`
  - `PdfDocument` 暴露对象表、页树、注解、trailer、revision 元数据。
- 结论：用 pdflite 负责解析、对象表、增量修订写出；**ByteRange 与 `/Contents` 占位符回填由 MoonSign 自己控制**（签名需要字节级确定性，不能依赖高层封装）。

## D2. 密码学：`cc06b/mooncry@0.95.0`

- 许可证 Apache-2.0；纯 MoonBit；README 声称 1177 个测试，覆盖 NIST/FIPS/RFC 向量。
- 关键 API（`lib/*.mbt`）：
  - `sha256(Bytes) -> Bytes`、`sha256_new/update/finalize`（流式，适合大 PDF 的两段 ByteRange）
  - `rsa_pkcs1_v15_sign(message, n, d) -> Bytes`：内部做 SHA-256 + DigestInfo，正好对应 CMS 对 signedAttrs 的签名方式
  - `rsa_pkcs1_v15_sign_with(message, n, d, hash)`：可选 SHA-1/256/384/512
  - `rsa_pkcs1_v15_verify_with(message, sig, n, e, hash) -> Bool`
  - `ecdsa_p256_sign(private_key, message) -> Bytes`：返回 **64 字节 `r||s`**，不是 DER；CMS 需要 `SEQUENCE{INTEGER r, INTEGER s}`，需自行转换
  - `ecdsa_p256_verify(public_key, message, sig)`：同样吃 64 字节形式
  - `sm2_sign(sk, msg, id, ...)`、`sm2_verify(pk, msg, id, sig)`
  - `sm3(Bytes) -> Bytes`
- 结论：签名层只做"算法适配 + 编码转换"，不自造密码学。

## D3. DER / X.509：自研，不引入运行时依赖

- 候选 `oilleelssq-wq/MoonBit-PKI@0.2.0` 提供 ASN.1 DER + X.509，但版本低（0.2.0）、API 面未验证。
- CMS 需要精确控制 context-specific tag、SET OF 排序、以及"同一份 DER 既用于签名又用于哈希"的字节级一致性，外包给低版本包风险更高。
- 结论：`der/`、`x509/` 自研（约 800–1200 行），只依赖 `moonbitlang/core`。MoonBit-PKI 仅作为测试期的交叉校验工具，不进 `moon.mod`。

## D4. 核心接口：`Bytes -> Bytes`

- 库不碰文件、不碰网络、不读系统时钟：输入输出都是 `Bytes`，时间与 TSA 通过参数/端口注入。
- 好处：native/wasm-gc/js 都能跑；测试可完全确定性；CLI 只是薄壳。

## D5. 工具链

- 本机初始为 `0.1.20260915`，无法解析 `moonbitlang/async@0.22.5` 的 `moon.pkg` 键 `max_concurrent_tests`。
- 处理：用官方 installer 升级到 latest（`moon upgrade` 在非 TTY 下会报 "not a terminal"，不可用）。
- CI 不锁死具体版本，装 latest 并打印 `moon version --all`；本仓库记录"最后一次验证通过的版本"。

## D6. README 形式

- `moon new` 在 Windows 上创建 `README.md -> README.mbt.md` 符号链接失败（需要开发者模式）。
- 结论：`README.md` 用真实文件；`moon.mod` 的 `readme` 指向它。带测试的代码块放 `examples/*.mbt.md`，不依赖符号链接。
