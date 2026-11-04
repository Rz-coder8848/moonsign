# MoonSign

用纯 MoonBit 写的 PDF 数字签名工具：**给 PDF 签名，并验证它有没有被改过。**

> 当前是 0.1 开发版，功能可用但还不适合直接用于有法律效力的正式签署。

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
| 签名格式 | PAdES B-B（`ETSI.CAdES.detached`），CMS SignedData |
| 验签 | 检查字节范围、摘要、签名；文件被改一个字节就失败 |
| 命令行 | `sign` / `verify` / `info` |
| 互操作 | 生成的签名能被 OpenSSL 验证（CI 每次都跑） |
| 平台 | Linux / macOS / Windows（CI 三平台跑测试） |

## 快速开始

先准备一张空白 PDF 和一张测试证书（正式使用请换成你自己的证书）：

```sh
moon run cmd/mkpdf -- blank.pdf

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=MoonSign Demo"

moon run cmd/moonsign -- sign blank.pdf --key key.pem --cert cert.pem --out signed.pdf

moon run cmd/moonsign -- verify signed.pdf --cert cert.pem

moon run cmd/moonsign -- info signed.pdf
```

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

- [关键技术决策](docs/DECISIONS.md)
- 设计说明、RFC 对照表、兼容性矩阵、安全说明：0.1 发布前补齐

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
