# 示例：给一张 PDF 签名，再验签

这个脚本演示三件事：

1. 生成一张空白 PDF，并用 OpenSSL 生成一张测试证书；
2. 用 MoonSign 签名，然后验签（应该通过）；
3. 改掉 PDF 里的一个字节，再验签（应该失败）。

运行：

```sh
bash examples/sign-and-verify/run.sh
```

需要本机有 `moon`、`openssl`、`python3`。脚本只在临时目录里写文件，不会改动仓库。
