# MoonSign

用纯 MoonBit 写的 PDF 数字签名工具：**给 PDF 签名，并验证它有没有被改过。**

> 当前是 0.12 开发版，功能可用但还不适合直接用于有法律效力的正式签署。

## 它解决什么问题

合同、发票、录用通知、检测报告这类 PDF，发出去之后需要证明两件事：

1. 这份文件确实是某个单位/个人签的；
2. 签完之后内容没有被改过。

国际通用的做法叫 **PAdES**（PDF 的数字签名标准）。MoonBit 生态里已经有 PDF 解析库和密码学库，但中间"把签名写进 PDF、再验回来"的这一层一直空着。MoonSign 补的就是这一层。

## 三个使用场景

1. **发合同 / Offer**：业务系统生成 PDF，用公司证书签一次，对方用 Adobe、福昕或 WPS 打开就能看到"签名有效"。
2. **电子发票 / 证明归档**：发布时签一次，几年后重新验签，能证明文件没有被改动。
3. **CI 产物签名**：构建流程里自动给 PDF 报告签名，作为可追溯的交付凭证。

## 现在能做什么

| 能力 | 状态 |
| --- | --- |
| 签名算法 | RSA PKCS#1 v1.5、ECDSA P-256，SHA-256 |
| 私钥格式 | PEM（PKCS#8/PKCS#1/SEC1）；PKCS#12（.p12/.pfx，PBES2 + AES-CBC） |
| 签名格式 | PAdES B-B（`ETSI.CAdES.detached`），CMS SignedData；可附加 B-T 时间戳 |
| 验签 | 检查字节范围、摘要、签名；文件被改一个字节就失败 |
| 证书链 | `--anchors` 指定信任根，检查签名者证书能否链到它 |
| 吊销检查 | `--crl` 指定 CRL（PEM），拒绝已被吊销的证书 |
| OCSP | `--ocsp` 指定 OCSP 响应（DER），检查在线吊销状态 |
| 命令行 | `sign` / `verify` / `info` |
| 可见签名 | `--visible` 在页面上画签名框（含文字与日期） |
| 互操作 | OpenSSL 与 pyHanko 双向验证（CI 每次都跑） |
| 时间戳 | RFC 3161：请求、嵌入、校验证书链（B-T）；`verify --tsa-anchors` 可复查 |
| 平台 | Linux / macOS / Windows（CI 三平台跑测试） |
| 发布 | mooncakes.io：[Rz-coder8848/moonsign@0.12.0](https://mooncakes.io/docs/Rz-coder8848/moonsign@0.12.0) |

## 快速开始

作为依赖使用：`moon add Rz-coder8848/moonsign@0.12.0`。

先准备一张空白 PDF 和一张测试证书（正式使用请换成你自己的证书）：

```sh
moon run cmd/mkpdf -- blank.pdf

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=MoonSign Demo"

moon run cmd/moonsign -- sign blank.pdf --key key.pem --cert cert.pem --out signed.pdf

moon run cmd/moonsign -- verify signed.pdf --cert cert.pem

moon run cmd/moonsign -- info signed.pdf
```

如果手上是 `.p12` / `.pfx`（很多机构直接给这种）：

```sh
moon run cmd/moonsign -- sign blank.pdf --p12 cert.p12 \
  --p12-password 你的密码 --out signed.pdf
```

密码也可以放在环境变量 `MOONSIGN_P12_PASSWORD` 里，避免出现在命令历史。

想在 PDF 页面上看到签名框：

```sh
moon run cmd/moonsign -- sign blank.pdf --key key.pem --cert cert.pem \
  --visible --rect 36,36,300,120 --appearance-text "Digitally signed" --out visible.pdf
```

不给 `--appearance-text` 时，会自动写"Digitally signed by <证书里的 CN>"（CN 是中文时只显示 "Digitally signed"）。

签名成功会看到：

```
Signed: signed.pdf
Field: Signature1
Digest: SHA-256
```

验签成功会看到：

```
Signature 1: Signature1
  subfilter: ETSI.CAdES.detached
Result: VALID
  The document has not changed since signing.
```

如果有人改了 PDF 里的内容，`verify` 会输出 `INVALID`，并以退出码 2 结束，方便脚本判断。

### 检查"这张证书是不是可信的"

只看签名，只能说明"文件和证书对得上"。要判断签名者是不是你信任的机构，需要给出信任根：

```sh
# 签名时把中间证书一起放进去
moon run cmd/moonsign -- sign blank.pdf --key leaf.key --cert leaf.crt \
  --chain intermediate.crt --out chain-signed.pdf

# 验签时指定你信任的根证书
moon run cmd/moonsign -- verify chain-signed.pdf --anchors root-ca.crt
```

结果有三种：

- `VALID and TRUSTED`：签名有效，且证书链能走到你给的根（退出码 0）；
- `VALID but NOT TRUSTED`：签名有效，但链不到你给的根（退出码 3）；
- `INVALID`：文件被改过或签名不对（退出码 2）。

### 检查证书有没有被吊销

如果签发机构把证书作废了，可以附上一份 CRL（证书吊销列表）：

```sh
moon run cmd/moonsign -- verify signed.pdf \
  --anchors root-ca.pem --crl issuer.crl.pem
```

证书被吊销时，结果会是 `VALID but NOT TRUSTED`，原因写 `certificate has been revoked`（退出码 3）。

### 查 OCSP（在线吊销）

OCSP 是另一种吊销查询方式。MoonSign 不直接联网，需要先把响应保存成文件（用 curl、浏览器或机构提供的工具），再交给它检查：

```sh
moon run cmd/moonsign -- verify signed.pdf \
  --anchors root-ca.pem --ocsp ocsp-response.der
```

输出会多一行 `OCSP: good`、`OCSP: REVOKED at ...` 或 `OCSP: unknown`。被吊销时退出码为 3。

### 加时间戳（B-T）

时间戳用来证明"这个签名是什么时候做的"。MoonSign 不直接联网，分三步：

```sh
# 1. 从已签名的 PDF 生成时间戳请求
moon run cmd/moonsign -- tsa-request signed.pdf --out req.der

# 2. 把 req.der 发给任意 RFC 3161 时间戳服务（curl 示例）
curl -H "Content-Type: application/timestamp-query" \
  --data-binary @req.der https://your-tsa.example/ -o resp.der

# 3. 把响应嵌进 PDF（--anchors 用来验证 TSA 的证书链）
moon run cmd/moonsign -- tsa-embed signed.pdf --response resp.der \
  --anchors tsa-ca.pem --out stamped.pdf
```

签名本身不变，只是多了时间戳附件；`verify` 仍然通过。嵌入前会检查时间戳确实对应这个签名；给了 `--anchors` 时还会检查 TSA 证书链和 timeStamping 用途。

验证时也可以检查时间戳：

```sh
moon run cmd/moonsign -- verify stamped.pdf --cert cert.pem --tsa-anchors tsa-ca.pem
```

输出里会多一行 `timestamp: VALID and TRUSTED`（或 `VALID (TSA chain not checked)`）。

## 在代码里使用

```moonbit
let signed = @pades.sign_pdf(
  pdf_bytes,
  @pades.SigningKey::Rsa(modulus, private_exponent),
  certificate,
  extra_certificates,
  {
    field_name: "Signature1",
    contents_chars: 16384,
    signing_time: None,
    hash: @crypto.Hash::Sha256,
  },
)

let ok = @pades.verify_pdf(signed, certificate)
```

## 项目结构

```
der/      DER / ASN.1 基础编码（CMS、证书都靠它）
x509/     证书解析、公钥提取
crypto/   摘要、RSA、ECDSA（基于 mooncry）
cms/      CMS SignedData 的构造、解析、验签
pdf/      在 PDF 里放签名域、写 ByteRange、填签名
pades/    对外入口：sign_pdf / verify_pdf
pem/      读 PEM 格式的私钥和证书
cmd/      命令行程序
```

## 现在明确不做

- 不做 PDF 渲染/排版；
- 不做证书颁发、时间戳服务、信任列表（这些是另一套系统）；
- 暂不支持加密 PDF；
- 暂不支持给"已经有签名"的 PDF 追加第二个签名（路线图里有）；
- 0.1 版本没有经过安全审计。

## 怎么验证它真的能用

- 仓库里的 30 多个测试覆盖：编码、证书解析、CMS 构造/验签、PDF 签名、篡改检测；
- CI 在 Linux / macOS / Windows 上跑测试；
- CI 还会把 MoonSign 生成的 CMS 和 PDF 交给 OpenSSL 验签，确保不是"自己验自己"。

## 更多文档

- [使用手册](docs/USAGE.md)（全部命令与参数）
- [性能基准](docs/PERFORMANCE.md)
- [更新日志](CHANGELOG.md)
- [关键技术决策](docs/DECISIONS.md)
- [RFC 对照表](docs/RFC-MAP.md)
- [兼容性矩阵](docs/COMPATIBILITY.md)
- [安全说明](docs/SECURITY.md)

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
