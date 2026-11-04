# MoonSign

纯 MoonBit 实现的 PDF 数字签名与验签库（PAdES / CMS）。

> **状态：Phase 0（工程脚手架）。** API 尚未稳定，暂不可用于生产环境。

## 为什么做这个项目

MoonBit 生态已经有两块关键积木：

- [`moonbitlang/pdflite`](https://github.com/moonbitlang/pdflite)：PDF 解析、对象表、增量更新、注解；
- [`cc06b/mooncry`](https://github.com/cc06b/mooncry)：SHA-2/SM3、RSA、ECDSA P-256、SM2 等密码学原语。

但两者之间缺一层"可信文档"的基础设施：CMS `SignedData`、PDF `/ByteRange`、PAdES 基线、证书链校验、以及一份人能读懂、机器能解析的验签报告。MoonSign 补的就是这一层。

## 计划能力

| 能力 | 状态 |
| --- | --- |
| PAdES B-B（`ETSI.CAdES.detached`） | 计划中 |
| RSA PKCS#1 v1.5 + SHA-256 | 计划中 |
| ECDSA P-256 + SHA-256 | 计划中 |
| 验签与篡改检测 | 计划中 |
| 验签报告（`moonsign.report/1`） | 计划中 |
| B-T（RFC 3161 时间戳） | 计划中 |
| B-LT（DSS/VRI、证书链、吊销） | 计划中 |
| SM2/SM3 国密签名 | 计划中 |

**明确不做**：PDF 渲染与排版、文档权限加密、GUI、Adobe 认证声明。

## 构建

需要 MoonBit 工具链（`moon`）。

```sh
moon check
moon test
moon run cmd/main
```

## 目录结构

```
der/       DER / ASN.1 基础编码
cms/       CMS SignedData 构造、解析与验签
pdf/       签名域、增量修订、ByteRange
pades/     PAdES 编排（B-B / B-T / B-LT）
report/    moonsign.report/1 报告模型
cli/       命令行实现
cmd/main/  可执行入口
docs/      设计、RFC 对照、兼容性、安全说明
```

## 文档

- [设计说明](docs/DESIGN.md)（待写）
- [RFC 对照表](docs/RFC-MAP.md)（待写）
- [兼容性矩阵](docs/COMPATIBILITY.md)（待写）
- [安全说明](docs/SECURITY.md)（待写）

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。

## 安全提示

本项目仍在开发中，**尚未经过安全审计**。在 1.0 之前，请勿用于具有法律效力的签署场景。
