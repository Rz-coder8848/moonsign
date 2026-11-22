# 验收演示

一条命令跑完主要能力，并输出 `[PASS]` / `[FAIL]` 表格：

```sh
bash demo/acceptance.sh
```

覆盖：

1. 生成两页、带文字和链接的 PDF；
2. 在第 2 页签可见签名；
3. 验签（显示签名者和时间）；
4. 改一个字节后验签失败（退出码 2）；
5. 追加第二个签名，两个都有效；
6. 用 DSS 补全证书链（`VALID and TRUSTED`）；
7. 用 DSS 里的 CRL 判定吊销（退出码 3）；
8. 加密 PDF 签名后验签；
9. SM2/SM3 签名与验签。

默认用 `moon run` 的 native 目标；如果本机没有 native 后端，可以：

```sh
MOON_TARGET=wasm-gc bash demo/acceptance.sh
```

脚本只在临时目录写文件，结束后自动清理。
