# MoonSign

鐢ㄧ函 MoonBit 鍐欑殑 PDF 鏁板瓧绛惧悕宸ュ叿锛?*缁?PDF 绛惧悕锛屽苟楠岃瘉瀹冩湁娌℃湁琚敼杩囥€?*

> 褰撳墠鏄?0.1 寮€鍙戠増锛屽姛鑳藉彲鐢ㄤ絾杩樹笉閫傚悎鐩存帴鐢ㄤ簬鏈夋硶寰嬫晥鍔涚殑姝ｅ紡绛剧讲銆?
## 瀹冭В鍐充粈涔堥棶棰?
鍚堝悓銆佸彂绁ㄣ€佸綍鐢ㄩ€氱煡銆佹娴嬫姤鍛婅繖绫?PDF锛屽彂鍑哄幓涔嬪悗闇€瑕佽瘉鏄庝袱浠朵簨锛?
1. 杩欎唤鏂囦欢纭疄鏄煇涓崟浣?涓汉绛剧殑锛?2. 绛惧畬涔嬪悗鍐呭娌℃湁琚敼杩囥€?
鍥介檯閫氱敤鐨勫仛娉曞彨 **PAdES**锛圥DF 鐨勬暟瀛楃鍚嶆爣鍑嗭級銆侻oonBit 鐢熸€侀噷宸茬粡鏈?PDF 瑙ｆ瀽搴撳拰瀵嗙爜瀛﹀簱锛屼絾涓棿"鎶婄鍚嶅啓杩?PDF銆佸啀楠屽洖鏉?鐨勮繖涓€灞備竴鐩寸┖鐫€銆侻oonSign 琛ョ殑灏辨槸杩欎竴灞傘€?
## 涓変釜浣跨敤鍦烘櫙

1. **鍙戝悎鍚?/ Offer**锛氫笟鍔＄郴缁熺敓鎴?PDF锛岀敤鍏徃璇佷功绛句竴娆★紝瀵规柟鐢?Adobe銆佺鏄曟垨 WPS 鎵撳紑灏辫兘鐪嬪埌"绛惧悕鏈夋晥"銆?2. **鐢靛瓙鍙戠エ / 璇佹槑褰掓。**锛氬彂甯冩椂绛句竴娆★紝鍑犲勾鍚庨噸鏂伴獙绛撅紝鑳借瘉鏄庢枃浠舵病鏈夎鏀瑰姩銆?3. **CI 浜х墿绛惧悕**锛氭瀯寤烘祦绋嬮噷鑷姩缁?PDF 鎶ュ憡绛惧悕锛屼綔涓哄彲杩芥函鐨勪氦浠樺嚟璇併€?
## 鐜板湪鑳藉仛浠€涔?
| 鑳藉姏 | 鐘舵€?|
| --- | --- |
| 绛惧悕绠楁硶 | RSA PKCS#1 v1.5銆丒CDSA P-256锛孲HA-256 |
| 绛惧悕鏍煎紡 | PAdES B-B锛坄ETSI.CAdES.detached`锛夛紝CMS SignedData |
| 楠岀 | 妫€鏌ュ瓧鑺傝寖鍥淬€佹憳瑕併€佺鍚嶏紱鏂囦欢琚敼涓€涓瓧鑺傚氨澶辫触 |
| 鍛戒护琛?| `sign` / `verify` / `info` |
| 浜掓搷浣?| 鐢熸垚鐨勭鍚嶈兘琚?OpenSSL 楠岃瘉锛圕I 姣忔閮借窇锛?|
| 骞冲彴 | Linux / macOS / Windows锛圕I 涓夊钩鍙拌窇娴嬭瘯锛?|

## 蹇€熷紑濮?
鍏堝噯澶囦竴寮犵┖鐧?PDF 鍜屼竴寮犳祴璇曡瘉涔︼紙姝ｅ紡浣跨敤璇锋崲鎴愪綘鑷繁鐨勮瘉涔︼級锛?
```sh
moon run cmd/mkpdf -- blank.pdf

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=MoonSign Demo"

moon run cmd/moonsign -- sign blank.pdf --key key.pem --cert cert.pem --out signed.pdf

moon run cmd/moonsign -- verify signed.pdf --cert cert.pem

moon run cmd/moonsign -- info signed.pdf
```

绛惧悕鎴愬姛浼氱湅鍒帮細

```
Signed: signed.pdf
Field: Signature1
Digest: SHA-256
```

楠岀鎴愬姛浼氱湅鍒帮細

```
Signature 1: Signature1
  subfilter: ETSI.CAdES.detached
Result: VALID
  The document has not changed since signing.
```

濡傛灉鏈変汉鏀逛簡 PDF 閲岀殑鍐呭锛宍verify` 浼氳緭鍑?`INVALID`锛屽苟浠ラ€€鍑虹爜 2 缁撴潫锛屾柟渚胯剼鏈垽鏂€?
## 鍦ㄤ唬鐮侀噷浣跨敤

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

## 椤圭洰缁撴瀯

```
der/      DER / ASN.1 鍩虹缂栫爜锛圕MS銆佽瘉涔﹂兘闈犲畠锛?x509/     璇佷功瑙ｆ瀽銆佸叕閽ユ彁鍙?crypto/   鎽樿銆丷SA銆丒CDSA锛堝熀浜?mooncry锛?cms/      CMS SignedData 鐨勬瀯閫犮€佽В鏋愩€侀獙绛?pdf/      鍦?PDF 閲屾斁绛惧悕鍩熴€佸啓 ByteRange銆佸～绛惧悕
pades/    瀵瑰鍏ュ彛锛歴ign_pdf / verify_pdf
pem/      璇?PEM 鏍煎紡鐨勭閽ュ拰璇佷功
cmd/      鍛戒护琛岀▼搴?```

## 鐜板湪鏄庣‘涓嶅仛

- 涓嶅仛 PDF 娓叉煋/鎺掔増锛?- 涓嶅仛璇佷功棰佸彂銆佹椂闂存埑鏈嶅姟銆佷俊浠诲垪琛紙杩欎簺鏄彟涓€濂楃郴缁燂級锛?- 鏆備笉鏀寔鍔犲瘑 PDF锛?- 鏆備笉鏀寔缁?宸茬粡鏈夌鍚?鐨?PDF 杩藉姞绗簩涓鍚嶏紙璺嚎鍥鹃噷鏈夛級锛?- 0.1 鐗堟湰娌℃湁缁忚繃瀹夊叏瀹¤銆?
## 鎬庝箞楠岃瘉瀹冪湡鐨勮兘鐢?
- 浠撳簱閲岀殑 30 澶氫釜娴嬭瘯瑕嗙洊锛氱紪鐮併€佽瘉涔﹁В鏋愩€丆MS 鏋勯€?楠岀銆丳DF 绛惧悕銆佺鏀规娴嬶紱
- CI 鍦?Linux / macOS / Windows 涓婅窇娴嬭瘯锛?- CI 杩樹細鎶?MoonSign 鐢熸垚鐨?CMS 鍜?PDF 浜ょ粰 OpenSSL 楠岀锛岀‘淇濅笉鏄?鑷繁楠岃嚜宸?銆?
## 鏇村鏂囨。

- [鍏抽敭鎶€鏈喅绛朷(docs/DECISIONS.md)
- 璁捐璇存槑銆丷FC 瀵圭収琛ㄣ€佸吋瀹规€х煩闃点€佸畨鍏ㄨ鏄庯細0.1 鍙戝竷鍓嶈ˉ榻?
## 璁稿彲璇?
Apache-2.0锛岃 [LICENSE](LICENSE)銆?