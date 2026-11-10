# 使用手册

## 安装

作为 MoonBit 依赖：

```sh
moon add Rz-coder8848/moonsign@0.4.0
```

从源码运行命令行（需要 MoonBit 工具链）：

```sh
moon run cmd/moonsign -- help
```

## 命令总览

```
moonsign sign   <in.pdf> --key <key.pem> --cert <cert.pem> [options]
moonsign verify <in.pdf> --cert <cert.pem> [--json]
moonsign verify <in.pdf> --anchors <ca.pem> [--crl <crl.pem>] [--json]
moonsign info   <in.pdf> [--json]
```

退出码：

| 退出码 | 含义 |
| --- | --- |
| 0 | 成功；验签通过（带 `--anchors` 时表示已链到信任根） |
| 2 | 验签失败（文件被改、签名不对） |
| 3 | 签名有效，但证书链不可信（链不到根、被吊销等） |
| 1 | 用法错误、文件读写失败、格式不支持 |

## sign

| 参数 | 说明 |
| --- | --- |
| `--key <pem>` | 私钥（PKCS#8 / PKCS#1 / SEC1，未加密） |
| `--cert <pem>` | 签名者证书（叶子证书） |
| `--out <pdf>` | 输出文件，默认 `<输入>.signed.pdf` |
| `--chain <pem>` | 额外证书（中间证书），可包含多张 |
| `--field <name>` | 签名字段名，默认 `Signature1` |
| `--reason <text>` | 签名原因（写入签名字典） |
| `--location <text>` | 签署地点 |
| `--contact <text>` | 签署人联系方式 |
| `--signing-time <unix>` | 指定签署时间（Unix 秒），默认当前时间 |
| `--json` | 输出机器可读结果 |

## verify

| 参数 | 说明 |
| --- | --- |
| `--cert <pem>` | 只检查"签名和这张证书是否匹配"，不判断信任 |
| `--anchors <pem>` | 给一个或多个信任根，检查证书链 |
| `--crl <pem>` | 吊销列表（PEM，可包含多个 `X509 CRL` 块） |
| `--json` | 输出机器可读结果（含 `valid`、`trusted`、`chain_length`） |

`--cert` 和 `--anchors` 至少给一个。

## info

列出 PDF 里的签名：字段名、subfilter、预留字节数、`ByteRange`。不会验证签名。

## 常见问题

**"签名有效"到底说明什么？**

说明两件事：文件里签名的覆盖范围没有被改过；签名值能用你给的证书验证通过。

**怎么判断签名者可信？**

用 `--anchors` 给出你信任的根证书。程序会检查：证书链、有效期、CA 资格、KeyUsage、路径长度，以及可选的 CRL 吊销。

**证书被吊销了怎么办？**

用 `--crl` 给出签发机构发布的 CRL。被吊销时会输出 `VALID but NOT TRUSTED`，原因写 `certificate has been revoked`。

**为什么不能给已有签名的 PDF 再加一个签名？**

0.x 采用"整篇重写"的方式规避 PDF 增量更新的兼容问题，所以已有签名会失效。这一点会在后续版本解决。

## 在代码里使用

```moonbit
let options : @pades.SignOptions = {
  field_name: "Signature1",
  contents_chars: 16384,
  signing_time: Some(1793793600L),
  reason: Some("approved"),
  location: None,
  contact: None,
  hash: @crypto.Hash::Sha256,
}
let signed = @pades.sign_pdf(pdf, key, cert, [], options)

// 只验签名
let ok = @pades.verify_pdf(signed, cert)

// 验签名 + 证书链
let outcome = @pades.verify_pdf_with_anchors(signed, [root], now)
```

## 限制

- 时间戳（B-T）、长期验证（B-LT）未实现；
- 不支持加密 PDF；
- 不支持已有签名的 PDF 追加签名；
- 只支持 RSA PKCS#1 v1.5、ECDSA P-256 与 SHA-256（RSA 也支持 SHA-384/512）。
